package worker

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The marker is not an account and grants no resource access. It identifies
// one restricted worker in WFP's token access check, even when all workers
// share the same executable and SYSTEM user SID.
func workerNetworkMarker() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("S-1-5-21-%d-%d-%d-1001", binary.LittleEndian.Uint32(b[:4]), binary.LittleEndian.Uint32(b[4:8]), binary.LittleEndian.Uint32(b[8:])), nil
}

type networkDisplay struct{ name, description *uint16 }
type networkBlob struct {
	size uint32
	data *byte
}
type networkValue struct {
	kind  uint32
	value uintptr
}
type networkCondition struct {
	field windows.GUID
	match uint32
	value networkValue
}
type networkAction struct {
	kind uint32
	key  windows.GUID
}
type networkFilter struct {
	key             windows.GUID
	display         networkDisplay
	flags           uint32
	provider        *windows.GUID
	data            networkBlob
	layer, sublayer windows.GUID
	weight          networkValue
	count           uint32
	conditions      *networkCondition
	action          networkAction
	context         [2]uint64
	reserved        *windows.GUID
	id              uint64
	effective       networkValue
}
type networkSubLayer struct {
	key      windows.GUID
	display  networkDisplay
	flags    uint32
	provider *windows.GUID
	data     networkBlob
	weight   uint16
}
type networkFence struct {
	engine   windows.Handle
	filters  []uint64
	sublayer *windows.GUID
}

var networkDLL = windows.NewLazySystemDLL("fwpuclnt.dll")

//go:uintptrescapes
func networkCall(name string, args ...uintptr) error {
	proc := networkDLL.NewProc(name)
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	r, _, _ := proc.Call(args...)
	if uint32(r) != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(uint32(r)))
	}
	return nil
}

func (f *networkFence) close() error {
	var errs []error
	for _, id := range f.filters {
		if err := networkCall("FwpmFilterDeleteById0", uintptr(f.engine), uintptr(id)); err != nil {
			errs = append(errs, err)
		}
	}
	if f.sublayer != nil {
		errs = append(errs, networkCall("FwpmSubLayerDeleteByKey0", uintptr(f.engine), uintptr(unsafe.Pointer(f.sublayer))))
	}
	if f.engine != 0 {
		errs = append(errs, networkCall("FwpmEngineClose0", uintptr(f.engine)))
	}
	f.engine = 0
	f.filters = nil
	return errors.Join(errs...)
}

func fenceWorkerNetwork(executable, marker string) (_ *networkFence, err error) {
	f := &networkFence{}
	// Static, not dynamic: a parent crash must not remove the filter before
	// Windows finishes terminating the child through its kill-on-close job.
	if err := networkCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&f.engine))); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.close())
		}
	}()
	path, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	var app *networkBlob
	if err := networkCall("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&app))); err != nil {
		return nil, err
	}
	defer networkDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&app)))
	// WFP evaluates MATCH_FILTER (1) against this descriptor. Only a token
	// bearing this worker's marker should fail it. NOT_EQUAL then blocks that
	// worker, while Control and network probes using the same image pass.
	sd, err := windows.SecurityDescriptorFromString("D:(D;;0x1;;;" + marker + ")(A;;0x1;;;WD)(A;;0x1;;;RC)(A;;0x1;;;AU)(A;;0x1;;;BU)")
	if err != nil {
		return nil, err
	}
	blob := networkBlob{size: sd.Length(), data: (*byte)(unsafe.Pointer(sd))}
	appID, err := windows.GUIDFromString("{d78e1e87-8644-4ea5-9437-d809ecefc971}")
	if err != nil {
		return nil, err
	}
	userID, err := windows.GUIDFromString("{af043a0a-b34d-4f86-979c-c90371af6e66}")
	if err != nil {
		return nil, err
	}
	sublayer, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString("NetSwitch restricted worker network denial")
	conditions := [2]networkCondition{
		{field: appID, value: networkValue{kind: 12, value: uintptr(unsafe.Pointer(app))}},
		{field: userID, match: 10, value: networkValue{kind: 14, value: uintptr(unsafe.Pointer(&blob))}},
	}
	// Union pointer payloads must not move during the native calls.
	var pins runtime.Pinner
	pins.Pin(&blob)
	pins.Pin(sd)
	defer pins.Unpin()
	if err := networkCall("FwpmTransactionBegin0", uintptr(f.engine), 0); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = networkCall("FwpmTransactionAbort0", uintptr(f.engine))
			f.filters = nil
			f.sublayer = nil
		}
	}()
	sub := networkSubLayer{key: sublayer, display: networkDisplay{name: name}, weight: 65535}
	if err := networkCall("FwpmSubLayerAdd0", uintptr(f.engine), uintptr(unsafe.Pointer(&sub)), 0); err != nil {
		return nil, err
	}
	f.sublayer = &sublayer
	for _, text := range []string{"{c38d57d1-05a7-4c33-904f-7fbceee60e82}", "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}"} {
		layer, parseErr := windows.GUIDFromString(text)
		if parseErr != nil {
			return nil, parseErr
		}
		filter := networkFilter{display: networkDisplay{name: name}, layer: layer, sublayer: sublayer,
			weight: networkValue{kind: 1, value: 15}, count: 2, conditions: &conditions[0], action: networkAction{kind: 0x1001}}
		var id uint64
		if err := networkCall("FwpmFilterAdd0", uintptr(f.engine), uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id))); err != nil {
			return nil, err
		}
		f.filters = append(f.filters, id)
	}
	if err := networkCall("FwpmTransactionCommit0", uintptr(f.engine)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(sd)
	runtime.KeepAlive(conditions)
	return f, nil
}
