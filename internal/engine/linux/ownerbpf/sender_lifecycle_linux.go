//go:build linux

package ownerbpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	TunFCSUM   = 0x01
	TunFTSO4   = 0x02
	TunFTSO6   = 0x04
	TunFTSOECN = 0x08
	TunFUFO    = 0x10
	TunFUSO4   = 0x20
	TunFUSO6   = 0x40
)

// AcceptedSenderSymbols lists the exported Linux 5.8–7.0 kernel functions
// taking struct sock *sk as their first parameter (PT_REGS_PARM1) that execute
// only after length, destination, and route checks succeed and before skb
// transmission.
var AcceptedSenderSymbols = []string{
	"ip_make_skb",
	"ip6_make_skb",
	"ip_append_data",
	"ip6_append_data",
	"tcp_v4_connect",
	"tcp_v6_connect",
	"tcp_sendmsg",
}

// NewMmapSocketSlotTable allocates a kernel BPF_F_MMAPABLE array map of
// SocketStateSlot entries and mmaps it into userspace for lock-free atomic XADD
// and coherent (v1, c1) -> owner -> (v2, c2) reads.
func NewMmapSocketSlotTable(maxSlots int) (*SocketSlotTable, error) {
	if maxSlots <= 0 {
		maxSlots = DefaultMaxSocketSlots
	}
	slotSize := int(unsafe.Sizeof(SocketStateSlot{}))
	spec := &ebpf.MapSpec{
		Name:       "ns_sock_slots",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(slotSize),
		MaxEntries: uint32(maxSlots),
		Flags:      unix.BPF_F_MMAPABLE,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("create BPF_F_MMAPABLE socket slot map: %w", err)
	}
	rawBytes := maxSlots * slotSize
	pageSize := unix.Getpagesize()
	mmapLen := (rawBytes + pageSize - 1) &^ (pageSize - 1)
	mem, err := unix.Mmap(m.FD(), 0, mmapLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("mmap socket slot map: %w", err)
	}
	slots := unsafe.Slice((*SocketStateSlot)(unsafe.Pointer(&mem[0])), maxSlots)
	closeFn := func() error {
		err1 := unix.Munmap(mem)
		err2 := m.Close()
		return errors.Join(err1, err2)
	}
	return newSocketSlotTableFromBacking(slots, closeFn), nil
}

// AcceptedSenderProbe extends Probe with cgroup BPF_F_ALLOW_MULTI links across
// connect4/connect6/sendmsg4/sendmsg6/sock_ops and accepted-send PMU kprobes.
type AcceptedSenderProbe struct {
	*Probe
	auxPrograms []*ebpf.Program
}

func (ap *AcceptedSenderProbe) Close() error {
	if ap == nil {
		return nil
	}
	var errs []error
	if ap.Probe != nil {
		errs = append(errs, ap.Probe.Close())
	}
	for i := len(ap.auxPrograms) - 1; i >= 0; i-- {
		errs = append(errs, ap.auxPrograms[i].Close())
	}
	ap.auxPrograms = nil
	return errors.Join(errs...)
}

func LoadAcceptedSenderProbe(object, cgroup string) (*AcceptedSenderProbe, error) {
	return loadAcceptedSenderProbe(object, cgroup, nil)
}

func loadAcceptedSenderProbe(object, cgroup string, afterAttach func(string, *AcceptedSenderProbe) error) (_ *AcceptedSenderProbe, err error) {
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
		return nil, loadError("load owner proof programs/maps (BTF/helpers/verifier)", err)
	}
	ap := &AcceptedSenderProbe{
		Probe: &Probe{Collection: collection},
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ap.Close())
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
	}{
		{"initialize_cookie", ebpf.AttachCGroupInetSockCreate},
		{"observe_packet", ebpf.AttachCGroupInetEgress},
	} {
		l, e := link.AttachRawLink(link.RawLinkOptions{
			Target:  int(dir.Fd()),
			Program: collection.Programs[a.name],
			Attach:  a.kind,
		})
		if e != nil {
			return nil, fmt.Errorf("BPF_LINK_CREATE %s: %w", a.name, e)
		}
		ap.links = append(ap.links, l)
		if afterAttach != nil {
			if err = afterAttach(a.name, ap); err != nil {
				return nil, err
			}
		}
	}

	// Attach cgroup sender hooks (connect4, connect6, sendmsg4, sendmsg6, sock_ops)
	// via BPF_LINK_CREATE with BPF_F_ALLOW_MULTI.
	for _, cgHook := range []struct {
		name     string
		progType ebpf.ProgramType
		attach   ebpf.AttachType
	}{
		{"cg_connect4", ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect},
		{"cg_connect6", ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect},
		{"cg_sendmsg4", ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP4Sendmsg},
		{"cg_sendmsg6", ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP6Sendmsg},
		{"cg_sock_ops", ebpf.SockOps, ebpf.AttachCGroupSockOps},
	} {
		prog, e := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:       cgHook.name,
			Type:       cgHook.progType,
			AttachType: cgHook.attach,
			License:    "Dual MIT/GPL",
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.Return(),
			},
		})
		if e != nil {
			return nil, fmt.Errorf("load %s: %w", cgHook.name, e)
		}
		ap.auxPrograms = append(ap.auxPrograms, prog)
		l, e := link.AttachRawLink(link.RawLinkOptions{
			Target:  int(dir.Fd()),
			Program: prog,
			Attach:  cgHook.attach,
		})
		if e != nil {
			return nil, fmt.Errorf("BPF_LINK_CREATE %s: %w", cgHook.name, e)
		}
		ap.links = append(ap.links, l)
		if afterAttach != nil {
			if err = afterAttach(cgHook.name, ap); err != nil {
				return nil, err
			}
		}
	}

	for _, sym := range AcceptedSenderSymbols {
		if err = ap.attachPMU(collection.Programs["observe_send"], sym); err != nil {
			return nil, err
		}
		if afterAttach != nil {
			if err = afterAttach("pmu:"+sym, ap); err != nil {
				return nil, err
			}
		}
	}
	return ap, nil
}

// PeerCgroupFilter represents an independent cgroup_skb/egress filter program
// (such as systemd IPAddressDeny=/IPAccounting=) attached with BPF_F_ALLOW_MULTI.
type PeerCgroupFilter struct {
	Program *ebpf.Program
	Link    *link.RawLink
	Hits    *ebpf.Map
}

func (pf *PeerCgroupFilter) Close() error {
	if pf == nil {
		return nil
	}
	var errs []error
	if pf.Link != nil {
		errs = append(errs, pf.Link.Close())
	}
	if pf.Program != nil {
		errs = append(errs, pf.Program.Close())
	}
	if pf.Hits != nil {
		errs = append(errs, pf.Hits.Close())
	}
	return errors.Join(errs...)
}

func (pf *PeerCgroupFilter) HitCount() (uint64, error) {
	var count uint64
	if err := pf.Hits.Lookup(uint32(0), &count); err != nil {
		return 0, err
	}
	return count, nil
}

// AttachPeerCgroupEgressFilter attaches an independent cgroup_skb/egress
// program with BPF_F_ALLOW_MULTI to verify multi-program coexistence on the
// same cgroup.
func AttachPeerCgroupEgressFilter(cgroup string) (*PeerCgroupFilter, error) {
	hits, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "peer_cg_hits",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		return nil, err
	}
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, hits.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "peer_egress",
		Type:         ebpf.CGroupSKB,
		AttachType:   ebpf.AttachCGroupInetEgress,
		License:      "Dual MIT/GPL",
		Instructions: insns,
	})
	if err != nil {
		_ = hits.Close()
		return nil, err
	}
	dir, err := os.Open(cgroup)
	if err != nil {
		_ = prog.Close()
		_ = hits.Close()
		return nil, err
	}
	defer dir.Close()

	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(dir.Fd()),
		Program: prog,
		Attach:  ebpf.AttachCGroupInetEgress,
	})
	if err != nil {
		_ = prog.Close()
		_ = hits.Close()
		return nil, err
	}
	return &PeerCgroupFilter{
		Program: prog,
		Link:    l,
		Hits:    hits,
	}, nil
}

// NegotiateTUNOffloads configures TUNSETOFFLOAD on tunFD. When enable is true,
// it negotiates the maximal supported virtio offload set (probing 6.2+ USO4/USO6
// first and falling back cleanly to the 5.8 CSUM|TSO4|TSO6|TSO_ECN|UFO set).
// When enable is false, it sets TUNSETOFFLOAD(0) so the kernel performs software
// segmentation (skb_gso_segment) before net_dev_start_xmit.
func NegotiateTUNOffloads(tunFD int, enable bool) (uint32, error) {
	if !enable {
		if err := unix.IoctlSetInt(tunFD, unix.TUNSETOFFLOAD, 0); err != nil {
			return 0, fmt.Errorf("TUNSETOFFLOAD(0): %w", err)
		}
		return 0, nil
	}
	candidates := []uint32{
		TunFCSUM | TunFTSO4 | TunFTSO6 | TunFTSOECN | TunFUFO | TunFUSO4 | TunFUSO6,
		TunFCSUM | TunFTSO4 | TunFTSO6 | TunFTSOECN | TunFUSO4 | TunFUSO6,
		TunFCSUM | TunFTSO4 | TunFTSO6 | TunFTSOECN | TunFUFO,
		TunFCSUM | TunFTSO4 | TunFTSO6 | TunFTSOECN,
	}
	var lastErr error
	for _, mask := range candidates {
		if err := unix.IoctlSetInt(tunFD, unix.TUNSETOFFLOAD, int(mask)); err == nil {
			return mask, nil
		} else {
			lastErr = err
		}
	}
	return 0, fmt.Errorf("TUNSETOFFLOAD negotiation failed: %w", lastErr)
}

// ConfigureDeterministicIPv6OnSidecar enables IPv6 on ifname with RA, autoconf,
// DAD, and router solicitations disabled and assigns cidr with IFA_F_NODAD so
// zero unsolicited ICMPv6 frames are emitted onto the TUN device.
func ConfigureDeterministicIPv6OnSidecar(ifname, cidr string) error {
	base := filepath.Join("/proc/sys/net/ipv6/conf", ifname)
	for _, kv := range [][2]string{
		{"accept_ra", "0\n"},
		{"autoconf", "0\n"},
		{"dad_transmits", "0\n"},
		{"router_solicitations", "0\n"},
		{"forwarding", "0\n"},
		{"disable_ipv6", "0\n"},
	} {
		p := filepath.Join(base, kv[0])
		if err := os.WriteFile(p, []byte(kv[1]), 0o644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	nlLink, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("LinkByName(%s): %w", ifname, err)
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ParseCIDR(%s): %w", cidr, err)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: ipNet.Mask},
		Flags: unix.IFA_F_NODAD | unix.IFA_F_PERMANENT,
	}
	if err := netlink.AddrReplace(nlLink, addr); err != nil {
		return fmt.Errorf("AddrReplace(%s): %w", cidr, err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: nlLink.Attrs().Index,
		Dst:       ipNet,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("RouteReplace(%s): %w", ipNet, err)
	}
	return nil
}
