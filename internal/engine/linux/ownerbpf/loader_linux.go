//go:build linux

package ownerbpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Probe owns every FD. No pin, tracefs event, legacy cgroup attachment,
// replacement, service change or route change is created by this loader.
type Probe struct {
	Collection *ebpf.Collection
	links      []*link.RawLink
	perf       []int
}

func (p *Probe) Close() error {
	var errs []error
	for i := len(p.perf) - 1; i >= 0; i-- {
		errs = append(errs, unix.Close(p.perf[i]))
	}
	p.perf = nil
	for i := len(p.links) - 1; i >= 0; i-- {
		errs = append(errs, p.links[i].Close())
	}
	p.links = nil
	if p.Collection != nil {
		p.Collection.Close()
		p.Collection = nil
	}
	return errors.Join(errs...)
}

// Load accepts an object produced by scripts/generate-owner-bpf.mjs. Loading
// an arbitrary object is not a public trust boundary: this is a hosted fixture.
// cgroup must be the dedicated leaf containing ONLY the fixture's processes.
func Load(object, cgroup string) (_ *Probe, err error) {
	return load(object, cgroup, nil)
}

// afterAttach is used only by the opt-in fixture to fail after actual kernel
// attachments exist, exercising the same unwind as a later attachment error.
func load(object, cgroup string, afterAttach func(string, *Probe) error) (_ *Probe, err error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("owner proof: unsupported architecture %s", runtime.GOARCH)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, fmt.Errorf("read owner proof ELF: %w", err)
	}
	if err := checkSpec(spec); err != nil {
		return nil, err
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 64 << 10},
	})
	if err != nil {
		// The concise error retains errno and the verifier's bounded tail.
		return nil, loadError("load owner proof programs/maps (BTF/helpers/verifier)", err)
	}
	p := &Probe{Collection: collection}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	dir, err := os.Open(cgroup)
	if err != nil {
		return nil, fmt.Errorf("open proof cgroup: %w", err)
	}
	defer dir.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(dir.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("proof requires cgroup v2: type=%x: %w", fs.Type, errors.Join(err, unix.EINVAL))
	}
	if err = collection.Maps["scope"].Update(uint32(0), stat.Ino, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("set exact proof cgroup: %w", err)
	}
	for _, a := range []struct {
		name string
		kind ebpf.AttachType
	}{{"initialize_cookie", ebpf.AttachCGroupInetSockCreate}, {"observe_packet", ebpf.AttachCGroupInetEgress}} {
		l, e := link.AttachRawLink(link.RawLinkOptions{Target: int(dir.Fd()), Program: collection.Programs[a.name], Attach: a.kind})
		if e != nil {
			return nil, fmt.Errorf("BPF_LINK_CREATE %s (no legacy fallback): %w", a.name, e)
		}
		p.links = append(p.links, l)
		if afterAttach != nil {
			if err = afterAttach(a.name, p); err != nil {
				return nil, err
			}
		}
	}
	if err = p.attachPMU(collection.Programs["observe_send"], "udp_sendmsg"); err != nil {
		return nil, err
	}
	if afterAttach != nil {
		if err = afterAttach("pmu", p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func checkSpec(s *ebpf.CollectionSpec) error {
	if len(s.Programs) != 3 || len(s.Maps) != 4 {
		return errors.New("owner proof ELF: unexpected program/map set")
	}
	for name, want := range map[string][3]uint32{
		"actors": {32, 32, RecordLimit}, "tuples": {12, 16, RecordLimit},
		"counters": {4, 8, 7}, "scope": {4, 8, 1},
	} {
		m := s.Maps[name]
		if m == nil || m.KeySize != want[0] || m.ValueSize != want[1] || m.MaxEntries != want[2] {
			return fmt.Errorf("owner proof ELF: incompatible %s ABI/bound", name)
		}
	}
	for name, kind := range map[string]ebpf.ProgramType{
		"initialize_cookie": ebpf.CGroupSock, "observe_packet": ebpf.CGroupSKB, "observe_send": ebpf.Kprobe,
	} {
		if p := s.Programs[name]; p == nil || p.Type != kind || p.License != "Dual MIT/GPL" {
			return fmt.Errorf("owner proof ELF: incompatible %s program/license", name)
		}
	}
	return nil
}

// Use the perf_event_open PMU ABI directly. cilium/link.Kprobe can silently
// choose tracefs; checking sysfs then calling it would still allow that fallback.
func (p *Probe) attachPMU(program *ebpf.Program, symbol string) error {
	b, err := os.ReadFile("/sys/bus/event_source/devices/kprobe/type")
	if err != nil {
		return fmt.Errorf("kprobe PMU type: %w", err)
	}
	kind, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return fmt.Errorf("kprobe PMU type: %w", err)
	}
	name, err := unix.BytePtrFromString(symbol)
	if err != nil {
		return err
	}
	// One PMU event creates one local trace kprobe. In 5.8 and 6.17,
	// kprobe_perf_func runs trace_call_bpf BEFORE the per-CPU perf event list
	// check. Opening one event per CPU therefore duplicates BPF execution
	// globally; cpu=0 is not a BPF execution filter. Match cilium v0.22.0's
	// single system-wide PMU event (pid=-1, cpu=0), without its fallback.
	attr := unix.PerfEventAttr{Type: uint32(kind), Size: unix.PERF_ATTR_SIZE_VER1,
		Bits: unix.PerfBitDisabled, Ext1: uint64(uintptr(unsafe.Pointer(name)))}
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	runtime.KeepAlive(name)
	if err != nil {
		return fmt.Errorf("perf_event_open PMU %s cpu=0: %w", symbol, err)
	}
	p.perf = append(p.perf, fd)
	if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, program.FD()); err != nil {
		return fmt.Errorf("PERF_EVENT_IOC_SET_BPF %s: %w", symbol, err)
	}
	if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("PERF_EVENT_IOC_ENABLE %s: %w", symbol, err)
	}
	return nil
}

func onlineCPUs(s string) ([]int, error) {
	var result []int
	last := -1
	for _, part := range strings.Split(s, ",") {
		a, b, rangeOK := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		hi := lo
		if rangeOK && err == nil {
			hi, err = strconv.Atoi(b)
		}
		if err != nil || lo <= last || hi < lo || hi >= 512 {
			return nil, fmt.Errorf("unsupported online CPU list %q (proof bound 512)", s)
		}
		for cpu := lo; cpu <= hi; cpu++ {
			result = append(result, cpu)
		}
		last = hi
	}
	return result, nil
}

func (p *Probe) Counts() (Counters, error) {
	values := [7]uint64{}
	for i := range values {
		if err := p.Collection.Maps["counters"].Lookup(uint32(i), &values[i]); err != nil {
			return Counters{}, fmt.Errorf("read counter %d: %w", i, err)
		}
	}
	return Counters{values[0], values[1], values[2], values[3], values[4], values[5], values[6]}, nil
}
