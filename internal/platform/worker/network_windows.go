package worker

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
type networkFence struct {
	engine  windows.Handle
	filters []uint64
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
		if err := networkCall("FwpmFilterDeleteById0", uintptr(f.engine), uintptr(id)); err != nil && !errors.Is(err, windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)) {
			errs = append(errs, err)
		}
	}
	if f.engine != 0 {
		errs = append(errs, networkCall("FwpmEngineClose0", uintptr(f.engine)))
	}
	f.engine = 0
	f.filters = nil
	return errors.Join(errs...)
}

const networkFenceName = "NetSwitch restricted worker network denial"

func fenceTag(w *workerImage) []byte {
	return []byte("NetSwitch/read-worker/v1:" + filepath.Base(w.directory))
}

func fenceWorkerNetwork(w *workerImage) (_ *networkFence, err error) {
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
	path, err := windows.UTF16PtrFromString(w.executable)
	if err != nil {
		return nil, err
	}
	var app *networkBlob
	if err := networkCall("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&app))); err != nil {
		return nil, err
	}
	defer networkDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&app)))
	appID, err := windows.GUIDFromString("{d78e1e87-8644-4ea5-9437-d809ecefc971}")
	if err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(networkFenceName)
	conditions := [1]networkCondition{
		{field: appID, value: networkValue{kind: 12, value: uintptr(unsafe.Pointer(app))}},
	}
	tag := fenceTag(w)
	data := networkBlob{size: uint32(len(tag)), data: &tag[0]}
	if err := networkCall("FwpmTransactionBegin0", uintptr(f.engine), 0); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = networkCall("FwpmTransactionAbort0", uintptr(f.engine))
			f.filters = nil
		}
	}()
	for i, text := range []string{"{c38d57d1-05a7-4c33-904f-7fbceee60e82}", "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}"} {
		layer, parseErr := windows.GUIDFromString(text)
		if parseErr != nil {
			return nil, parseErr
		}
		filter := networkFilter{key: w.policy.Filters[i], display: networkDisplay{name: name}, data: data, layer: layer,
			weight: networkValue{kind: 1, value: 15}, count: 1, conditions: &conditions[0], action: networkAction{kind: 0x1001}}
		var id uint64
		if err := networkCall("FwpmFilterAdd0", uintptr(f.engine), uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id))); err != nil {
			return nil, err
		}
		f.filters = append(f.filters, id)
	}
	if err := networkCall("FwpmTransactionCommit0", uintptr(f.engine)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(name)
	runtime.KeepAlive(tag)
	runtime.KeepAlive(conditions)
	return f, nil
}

func sameFenceTag(blob networkBlob, w *workerImage) bool {
	tag := fenceTag(w)
	return blob.data != nil && blob.size == uint32(len(tag)) && bytes.Equal(unsafe.Slice(blob.data, int(blob.size)), tag)
}

// Recovery has first proved the recorded child incarnation dead (or its owner
// dead before a child was recorded). Match
// native ownership metadata before deleting by the durable keys; never adopt
// another provider's object merely because a record contains its GUID.
func removeImageFence(w *workerImage) (err error) {
	zero := windows.GUID{}
	if w.policy.Filters[0] == zero || w.policy.Filters[1] == zero || w.policy.Filters[0] == w.policy.Filters[1] {
		return fmt.Errorf("invalid worker network policy keys")
	}
	var engine windows.Handle
	if err = networkCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&engine))); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, networkCall("FwpmEngineClose0", uintptr(engine))) }()
	for i := range w.policy.Filters {
		var filter *networkFilter
		err = networkCall("FwpmFilterGetByKey0", uintptr(engine), uintptr(unsafe.Pointer(&w.policy.Filters[i])), uintptr(unsafe.Pointer(&filter)))
		if errors.Is(err, windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)) {
			continue
		}
		if err != nil {
			return err
		}
		valid := filter.key == w.policy.Filters[i] && filter.action.kind == 0x1001 && sameFenceTag(filter.data, w) && windows.UTF16PtrToString(filter.display.name) == networkFenceName
		networkDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&filter)))
		if !valid {
			return fmt.Errorf("worker filter ownership mismatch")
		}
		if err = networkCall("FwpmFilterDeleteByKey0", uintptr(engine), uintptr(unsafe.Pointer(&w.policy.Filters[i]))); err != nil {
			return err
		}
	}
	return nil
}
