package detector

import (
	"C"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"
	"github.com/vtolstov/go-ioctl"
)

const (
	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h
	// and its backwards-compatible successor
	// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html
	TYPE_INIT          = 0x80
	CTAPHID_MSG        = TYPE_INIT | 0x03
	CTAPHID_KEEPALIVE  = TYPE_INIT | 0x3b
	FIDO_USAGE_PAGE    = 0xf1d0
	FIDO_USAGE_CTAPHID = 0x01
	STATUS_UPNEEDED    = 0x02

	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f.h
	U2F_SW_CONDITIONS_NOT_SATISFIED = 0x6985

	// https://github.com/LudovicRousseau/CCID/blob/master/src/ccid.h
	HID_ITEM_TYPE_GLOBAL           = 1
	HID_ITEM_TYPE_LOCAL            = 2
	HID_GLOBAL_ITEM_TAG_USAGE_PAGE = 0
	HID_LOCAL_ITEM_TAG_USAGE       = 0
)

// https://github.com/LudovicRousseau/CCID/blob/master/src/ccid.h

type ccidDescriptor struct {
	pbSeq                     uint8
	realBSeq                  uint8
	readerID                  int32
	dwMaxCCIDMessageLength    uint32
	dwMaxIFSD                 int32
	dwFeatures                int32
	bPINSupport               int8
	wLcdLayout                uint32
	dwDefaultClock            int32
	dwMaxDataRate             uint32
	bMaxSlotIndex             int8
	bCurrentSlotIndex         int8
	arrayOfSupportedDataRates uint8
	readTimeout               uint32
	cardProtocol              int32
	dwProtocols               int32
	bInterfaceProtocol        int32
	bNumEndpoints             int32
	dwSlotStatus              int32
	bVoltageSupport           int32
	sIFD_serial_number        uint8
	sIFD_iManufacturer        uint8
	IFD_bcdDevice             int32
	gemalto_firmware_features uint8
}

var (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h
	CCIDDESCSIZE = ioctl.IOR('H', 1, unsafe.Sizeof(ccidDescriptor{}))
	// HIDIOCGRDESC = ioctl.IOR('H', 2, unsafe.Sizeof(hidrawDescriptor{}))
)

// WatchCCID watches when YubiKey is waiting for a touch on a CCID request
func WatchCCID(notifiers *sync.Map) {
	checkAndInitWatcher := func(devicePath string) {
		if isCCIDDevice(devicePath) {
			go runCCIDWatcher(devicePath, notifiers)
		}
	}

	devicesEvents := initInotifyWatcher("CCID", "/dev", notify.Create)
	defer notify.Stop(devicesEvents)

	if devices, err := ioutil.ReadDir("/dev"); err == nil {
		for _, device := range devices {
			checkAndInitWatcher(path.Join("/dev", device.Name()))
		}
	} else {
		log.Errorf("Cannot list devices in '/dev' to find connected YubiKeys: %v", err)
	}

	for {
		select {
		case event := <-devicesEvents:
			// Give a second for device to initialize before establishing a watcher
			time.Sleep(1 * time.Second)
			checkAndInitWatcher(event.Path())
		}
	}
}

func isCCIDDevice(devicePath string) bool {
	if !strings.HasPrefix(devicePath, "/dev/hidraw") {
		return false
	}

	device, err := os.Open(devicePath)
	if err != nil {
		return false
	}
	defer device.Close()

	var size uint32
	err = ioctl.IOCTL(device.Fd(), CCIDDESCSIZE, uintptr(unsafe.Pointer(&size)))
	if err != nil {
		log.Warnf("Cannot get descriptor size for device '%v': %v", devicePath, err)
		return false
	}

	data := ccidDescriptor{}
	isCCID := false
	for i := uint32(0); i < size; {
		prefix := data.Value[i]
		tag := (prefix & 0b11110000) >> 4
		typ := (prefix & 0b00001100) >> 2
		size := prefix & 0b00000011

		val1b := data.Value[i+1]
		val2b := int(data.Value[i+1]) | (int(data.Value[i+2]) << 8)

		if typ == HID_ITEM_TYPE_GLOBAL && tag == HID_GLOBAL_ITEM_TAG_USAGE_PAGE && val2b == FIDO_USAGE_PAGE {
			isCCID = true
		}

		i += uint32(size) + 1
	}

	return false
}

func runU2FWatcher(devicePath string, notifiers *sync.Map) {
	device, err := os.Open(devicePath)
	if err != nil {
		log.Errorf("Cannot open device '%v' to run U2F watcher: %v", devicePath, err)
		return
	}
	defer device.Close()

	payload := make([]byte, 64)
	lastMessage := notifier.U2F_OFF
	var u2fOffTimer *time.Timer
	for {
		_, err = device.Read(payload)
		if err != nil {
			if u2fOffTimer != nil {
				u2fOffTimer.Stop()
			}
			if lastMessage != notifier.U2F_OFF {
				notifiers.Range(func(k, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_OFF
					return true
				})
			}
			return
		}

		val1b := payload[7]
		val2b := (int(payload[7]) << 8) | int(payload[8])
		isU2F := payload[4] == CTAPHID_MSG && val2b == U2F_SW_CONDITIONS_NOT_SATISFIED
		isFIDO2 := payload[4] == CTAPHID_KEEPALIVE && val1b == STATUS_UPNEEDED

		// Cancel previous U2F_OFF timer
		if u2fOffTimer != nil {
			u2fOffTimer.Stop()
		}

		// If an unknown message is received, most probably YubiKey was touched.
		// But it's possible that some intermediate pings are being sent.
		// Wait just a tiny little bit more to see if no new U2F_ON messages arrive.
		u2fOffTimerDuration := 200 * time.Millisecond

		if isU2F || isFIDO2 {
			// Signify U2F_ON if this is the first time we receive it
			if lastMessage != notifier.U2F_ON {
				notifiers.Range(func(k, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_ON
					return true
				})
				lastMessage = notifier.U2F_ON
			}

			// Extend U2F_OFF timer duration because the last message was U2F_ON
			u2fOffTimerDuration = 2 * time.Second
		}

		// Signify U2F_OFF if no new messages arrive soon
		u2fOffTimer = time.AfterFunc(u2fOffTimerDuration, func() {
			if lastMessage != notifier.U2F_OFF {
				notifiers.Range(func(k, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_OFF
					return true
				})
				lastMessage = notifier.U2F_OFF
			}
		})
	}
}
