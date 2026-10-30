package winplatform

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TCPPortSetting preserves null properties for templates which inherit their
// range. The values come from the documented MSFT_NetTCPSetting provider.
// https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-nettcpsetting
type TCPPortSetting struct {
	SettingName                     string
	DynamicPortRangeStartPort       *uint32
	DynamicPortRangeNumberOfPorts   *uint32
	AutoReusePortRangeStartPort     *uint32
	AutoReusePortRangeNumberOfPorts *uint32
}

var iidWbemLocator = windows.GUID{Data1: 0xdc12a687, Data2: 0x737f, Data3: 0x11cf, Data4: [8]byte{0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}

func setProxyBlanket(o *comObject) error {
	r, _, _ := ole32.NewProc("CoSetProxyBlanket").Call(uintptr(unsafe.Pointer(o)), 10, 0, 0, 3, 3, 0, 0)
	return hresult(r)
}

func wbemProperty(item *comObject, name string) (variant, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return variant{}, err
	}
	var v variant
	if _, err := item.invokeSlot(4, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&v)), 0, 0); err != nil {
		return variant{}, err
	}
	return v, nil
}

// readTCPPortSettings runs only in a disposable, supervised read worker. WMI
// calls may block; the parent owns the deadline and the worker's kill-on-close job.
// Use CLSID_WbemLocator (ThreadingModel=Both) rather than WbemScripting.SWbemLocator
// (ThreadingModel=Apartment) so MTA read workers never spin up a host STA window
// on Session 0's restricted service window station.
func readTCPPortSettings() (any, error) {
	return comThread(func() (any, error) {
		locator, err := comCreate("{4590f811-1d3a-11d0-891f-00aa004b2e24}", &iidWbemLocator)
		if err != nil {
			return nil, err
		}
		defer locator.release()
		ns, err := bstr(`root\StandardCimv2`)
		if err != nil {
			return nil, err
		}
		defer oleaut.NewProc("SysFreeString").Call(ns)
		var service *comObject
		if _, err := locator.invokeSlot(3, ns, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&service))); err != nil {
			return nil, err
		}
		defer service.release()
		if err := setProxyBlanket(service); err != nil {
			return nil, err
		}
		wql, err := bstr("WQL")
		if err != nil {
			return nil, err
		}
		defer oleaut.NewProc("SysFreeString").Call(wql)
		query, err := bstr("SELECT SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts FROM MSFT_NetTCPSetting")
		if err != nil {
			return nil, err
		}
		defer oleaut.NewProc("SysFreeString").Call(query)
		var enum *comObject
		if _, err := service.invokeSlot(20, wql, query, 0x30, 0, uintptr(unsafe.Pointer(&enum))); err != nil {
			return nil, err
		}
		defer enum.release()
		if err := setProxyBlanket(enum); err != nil {
			return nil, err
		}
		rows := []TCPPortSetting{}
		for len(rows) <= 256 {
			var item *comObject
			var returned uint32
			hr, err := enum.invokeSlot(4, 0xffffffff, 1, uintptr(unsafe.Pointer(&item)), uintptr(unsafe.Pointer(&returned)))
			if err != nil {
				return nil, err
			}
			if hr == 1 || returned == 0 || item == nil {
				if item != nil {
					item.release()
				}
				break
			}
			row, err := tcpPortSetting(item)
			item.release()
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		if len(rows) == 0 || len(rows) > 256 {
			return nil, fmt.Errorf("unexpected TCP setting count %d", len(rows))
		}
		return rows, nil
	})
}

func tcpPortSetting(item *comObject) (row TCPPortSetting, err error) {
	name, err := wbemProperty(item, "SettingName")
	if err != nil {
		return row, err
	}
	if name.vt != 8 {
		name.clear()
		return row, fmt.Errorf("SettingName is not text")
	}
	row.SettingName = bstrText(*(**uint16)(unsafe.Pointer(&name.data)))
	name.clear()
	for _, property := range []struct {
		name string
		dest **uint32
	}{
		{"DynamicPortRangeStartPort", &row.DynamicPortRangeStartPort},
		{"DynamicPortRangeNumberOfPorts", &row.DynamicPortRangeNumberOfPorts},
		{"AutoReusePortRangeStartPort", &row.AutoReusePortRangeStartPort},
		{"AutoReusePortRangeNumberOfPorts", &row.AutoReusePortRangeNumberOfPorts},
	} {
		v, err := wbemProperty(item, property.name)
		if err != nil {
			return row, err
		}
		switch v.vt {
		case 0, 1: // VT_EMPTY / VT_NULL: inherited, not a made-up zero.
		case 2, 3, 17, 18, 19, 22, 23:
			value := uint32(v.data)
			if value > 65535 {
				err = fmt.Errorf("invalid %s: %d", property.name, value)
			} else {
				*property.dest = &value
			}
		default:
			err = fmt.Errorf("%s is not an integer or null (variant %d)", property.name, v.vt)
		}
		v.clear()
		if err != nil {
			return row, err
		}
	}
	return row, nil
}
