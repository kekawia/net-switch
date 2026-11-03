//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	solUDP         = 17
	udpCork        = 1
	udpSegment     = 103
	msgFastOpen    = 0x20000000
	ipv6DontFrag   = 62
	ipv6DstOpts    = 59
)

func init() {
	if os.Getenv("NS_P3_CHILD") != "" {
		runtime.LockOSThread()
		runSenderLifecycleChild()
	}
}

func TestSenderLifecycleChild(t *testing.T) {
	if os.Getenv("NS_P3_CHILD") != "" {
		runtime.LockOSThread()
		runSenderLifecycleChild()
	}
}

func sendFDOnSocket(sockFD int, passFD int) error {
	rights := unix.UnixRights(passFD)
	return unix.Sendmsg(sockFD, []byte("F"), rights, nil, 0)
}

func runSenderLifecycleChild() {
	mode := os.Getenv("NS_P3_CHILD")
	port, _ := strconv.Atoi(os.Getenv("NS_P3_PORT"))
	payload := os.Getenv("NS_P3_PAYLOAD")

	switch mode {
	case "tcp4_connect_retransmit":
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcp4 socket:", err)
			os.Exit(61)
		}
		if err := unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: 0}); err != nil {
			fmt.Fprintln(os.Stderr, "tcp4 bind:", err)
			os.Exit(62)
		}
		// Pass a duplicate FD to the parent (for the idle-holder process) BEFORE calling connect.
		if os.Getenv("NS_P3_PASS_FD") == "1" {
			if err := sendFDOnSocket(3, s); err != nil {
				fmt.Fprintln(os.Stderr, "sendFDOnSocket:", err)
				os.Exit(63)
			}
		}
		err = unix.Connect(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port})
		if err != nil && !errors.Is(err, unix.EINPROGRESS) {
			fmt.Fprintln(os.Stderr, "tcp4 connect:", err)
			os.Exit(64)
		}
		fmt.Println("TCP4_CONNECTING")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "idle_holder":
		// Hold inherited FD 3 open without ever sending or connecting.
		fmt.Println("IDLE_HOLDING")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(3)
		os.Exit(0)

	case "tcp6_connect":
		s, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcp6 socket:", err)
			os.Exit(65)
		}
		src6 := net.ParseIP("2001:db8::1").To16()
		dst6 := net.ParseIP("2001:db8::2").To16()
		var sa6, da6 unix.SockaddrInet6
		copy(sa6.Addr[:], src6)
		copy(da6.Addr[:], dst6)
		da6.Port = port
		if err := unix.Bind(s, &sa6); err != nil {
			fmt.Fprintln(os.Stderr, "tcp6 bind:", err)
			os.Exit(66)
		}
		err = unix.Connect(s, &da6)
		if err != nil && !errors.Is(err, unix.EINPROGRESS) {
			fmt.Fprintln(os.Stderr, "tcp6 connect:", err)
			os.Exit(67)
		}
		fmt.Println("TCP6_CONNECTING")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "tcp4_fastopen":
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tfo socket:", err)
			os.Exit(68)
		}
		if err := unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: 0}); err != nil {
			fmt.Fprintln(os.Stderr, "tfo bind:", err)
			os.Exit(69)
		}
		err = unix.Sendto(s, []byte(payload), msgFastOpen, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port})
		if err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EAGAIN) {
			fmt.Fprintln(os.Stderr, "tfo sendto:", err)
			os.Exit(70)
		}
		fmt.Println("TFO_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "udp6_sendto":
		s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "udp6 socket:", err)
			os.Exit(71)
		}
		src6 := net.ParseIP("2001:db8::1").To16()
		dst6 := net.ParseIP("2001:db8::2").To16()
		var sa6, da6 unix.SockaddrInet6
		copy(sa6.Addr[:], src6)
		copy(da6.Addr[:], dst6)
		da6.Port = port
		if err := unix.Bind(s, &sa6); err != nil {
			fmt.Fprintln(os.Stderr, "udp6 bind:", err)
			os.Exit(72)
		}
		if err := unix.Sendto(s, []byte(payload), 0, &da6); err != nil {
			fmt.Fprintln(os.Stderr, "udp6 sendto:", err)
			os.Exit(73)
		}
		fmt.Println("UDP6_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "udp4_sendmmsg":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sendmmsg dial:", err)
			os.Exit(74)
		}
		p1 := []byte(payload + "-1")
		p2 := []byte(payload + "-2")
		iov1 := unix.Iovec{Base: &p1[0]}
		iov1.SetLen(len(p1))
		iov2 := unix.Iovec{Base: &p2[0]}
		iov2.SetLen(len(p2))
		type mmsghdr struct {
			Hdr unix.Msghdr
			Len uint32
			_   [4]byte
		}
		msgs := [2]mmsghdr{
			{Hdr: unix.Msghdr{Iov: &iov1, Iovlen: 1}},
			{Hdr: unix.Msghdr{Iov: &iov2, Iovlen: 1}},
		}
		n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(s), uintptr(unsafe.Pointer(&msgs[0])), 2, 0, 0, 0)
		if errno != 0 || n != 2 {
			fmt.Fprintf(os.Stderr, "sendmmsg n=%d errno=%v\n", n, errno)
			os.Exit(75)
		}
		fmt.Println("SENDMMSG_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "udp4_splice":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "splice dial:", err)
			os.Exit(76)
		}
		var pfd [2]int
		if err := unix.Pipe2(pfd[:], unix.O_CLOEXEC); err != nil {
			fmt.Fprintln(os.Stderr, "pipe2:", err)
			os.Exit(77)
		}
		data := []byte(payload)
		if _, err := unix.Write(pfd[1], data); err != nil {
			fmt.Fprintln(os.Stderr, "pipe write:", err)
			os.Exit(78)
		}
		if _, err := unix.Splice(pfd[0], nil, s, nil, len(data), 0); err != nil {
			// If kernel config disables udp_sendpage on a platform, fallback to sendmsg IOV.
			if _, werr := unix.Write(s, data); werr != nil {
				fmt.Fprintln(os.Stderr, "splice+write:", err, werr)
				os.Exit(79)
			}
		}
		_ = unix.Close(pfd[0])
		_ = unix.Close(pfd[1])
		fmt.Println("SPLICE_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "create_unconnected_udp":
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(80)
		}
		if err := unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: 0}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		if err := sendFDOnSocket(3, s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(82)
		}
		_ = unix.Close(s)
		os.Exit(0)

	case "failed_sends_only":
		// Inherit unconnected UDP socket on FD 3 and trigger EDESTADDRREQ, EMSGSIZE, and ENETUNREACH.
		if _, err := unix.Write(3, []byte("no-dest")); !errors.Is(err, unix.EDESTADDRREQ) {
			fmt.Fprintf(os.Stderr, "expected EDESTADDRREQ, got %v\n", err)
			os.Exit(83)
		}
		huge := make([]byte, 70000)
		if err := unix.Sendto(3, huge, 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port}); !errors.Is(err, unix.EMSGSIZE) {
			fmt.Fprintf(os.Stderr, "expected EMSGSIZE, got %v\n", err)
			os.Exit(84)
		}
		if err := unix.Sendto(3, []byte("unreach"), 0, &unix.SockaddrInet4{Addr: [4]byte{203, 0, 113, 99}, Port: port}); !errors.Is(err, unix.ENETUNREACH) {
			fmt.Fprintf(os.Stderr, "expected ENETUNREACH, got %v\n", err)
			os.Exit(85)
		}
		fmt.Println("FAILED_SENDS_DONE")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(0)

	case "sendto_on_fd3":
		if err := unix.Sendto(3, []byte(payload), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port}); err != nil {
			fmt.Fprintln(os.Stderr, "sendto_on_fd3:", err)
			os.Exit(86)
		}
		fmt.Println("FD3_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(0)

	case "cork_append_fd3":
		if err := unix.SetsockoptInt(3, solUDP, udpCork, 1); err != nil {
			fmt.Fprintln(os.Stderr, "setsockopt UDP_CORK=1:", err)
			os.Exit(87)
		}
		if err := unix.Sendto(3, []byte(payload), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port}); err != nil {
			fmt.Fprintln(os.Stderr, "cork sendto:", err)
			os.Exit(88)
		}
		if os.Getenv("NS_P3_UNCORK") == "1" {
			if err := unix.SetsockoptInt(3, solUDP, udpCork, 0); err != nil {
				fmt.Fprintln(os.Stderr, "setsockopt UDP_CORK=0:", err)
				os.Exit(89)
			}
		}
		fmt.Println("CORK_STEP_DONE")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(0)

	case "p4_frag_v4":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(90)
		}
		_ = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
		buf := bytes.Repeat([]byte(payload), 200) // ~3200 bytes > 1500 MTU -> 3 IPv4 fragments
		if _, err := unix.Write(s, buf); err != nil {
			fmt.Fprintln(os.Stderr, "p4_frag_v4 write:", err)
			os.Exit(91)
		}
		fmt.Println("FRAG_V4_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "p4_frag_v6":
		s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}
		_ = unix.SetsockoptInt(s, unix.IPPROTO_IPV6, ipv6DontFrag, 0)
		src6 := net.ParseIP("2001:db8::1").To16()
		dst6 := net.ParseIP("2001:db8::2").To16()
		var sa6, da6 unix.SockaddrInet6
		copy(sa6.Addr[:], src6)
		copy(da6.Addr[:], dst6)
		da6.Port = port
		if err := unix.Bind(s, &sa6); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(93)
		}
		buf := bytes.Repeat([]byte(payload), 200) // ~3200 bytes > 1500 MTU -> 3 IPv6 fragments
		if err := unix.Sendto(s, buf, 0, &da6); err != nil {
			fmt.Fprintln(os.Stderr, "p4_frag_v6 sendto:", err)
			os.Exit(94)
		}
		fmt.Println("FRAG_V6_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "p4_ext_v6":
		s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(95)
		}
		// 8-byte Destination Options header (NextHdr filled by kernel, HdrExtLen=0, PadN option: type=1, len=4, 4 zero bytes).
		dstOpt := []byte{0, 0, 1, 4, 0, 0, 0, 0}
		if err := unix.SetsockoptString(s, unix.IPPROTO_IPV6, ipv6DstOpts, string(dstOpt)); err != nil {
			fmt.Fprintln(os.Stderr, "setsockopt IPV6_DSTOPTS:", err)
			os.Exit(96)
		}
		src6 := net.ParseIP("2001:db8::1").To16()
		dst6 := net.ParseIP("2001:db8::2").To16()
		var sa6, da6 unix.SockaddrInet6
		copy(sa6.Addr[:], src6)
		copy(da6.Addr[:], dst6)
		da6.Port = port
		if err := unix.Bind(s, &sa6); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(97)
		}
		if err := unix.Sendto(s, []byte(payload), 0, &da6); err != nil {
			fmt.Fprintln(os.Stderr, "p4_ext_v6 sendto:", err)
			os.Exit(98)
		}
		fmt.Println("EXT_V6_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "p4_udp_segment":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		if err := unix.SetsockoptInt(s, solUDP, udpSegment, 400); err != nil {
			fmt.Fprintln(os.Stderr, "setsockopt UDP_SEGMENT:", err)
			os.Exit(100)
		}
		// 3 segments of 400 bytes each = 1200 bytes total.
		buf := make([]byte, 1200)
		for i := 0; i < 3; i++ {
			copy(buf[i*400:], fmt.Sprintf("%s-seg-%d-", payload, i))
		}
		if _, err := unix.Write(s, buf); err != nil {
			fmt.Fprintln(os.Stderr, "UDP_SEGMENT write:", err)
			os.Exit(101)
		}
		fmt.Println("UDP_SEGMENT_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "l2_hold_probe_until_killed":
		cgDir := os.Getenv("NS_P3_CGROUP")
		probeObj := os.Getenv("NS_OWNERBPF_OBJECT")
		ap, err := LoadAcceptedSenderProbe(probeObj, cgDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "LoadAcceptedSenderProbe in child:", err)
			os.Exit(102)
		}
		defer ap.Close()
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(103)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(104)
		}
		_ = unix.Close(s)
		fmt.Println("CHILD_PROBE_ACTIVE")
		for {
			time.Sleep(time.Hour)
		}

	case "l2_cap_dropped_loader":
		// Drop all effective and permitted capabilities on the locked OS thread
		// and verify BPF load fails with capability denial.
		runtime.LockOSThread()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
		var data [2]unix.CapUserData
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			fmt.Fprintln(os.Stderr, "capset drop:", err)
			os.Exit(105)
		}
		cgDir := os.Getenv("NS_P3_CGROUP")
		probeObj := os.Getenv("NS_OWNERBPF_OBJECT")
		_, err := LoadAcceptedSenderProbe(probeObj, cgDir)
		reason := ClassifyLoadFailure(err, "[integrity]", true, true)
		fmt.Printf("CAP_DROP_RESULT reason=%s err=%v\n", reason, err)
		os.Exit(0)
	}
}

type senderFixture struct {
	bf        *bridgeFixture
	ap        *AcceptedSenderProbe
	cgroupDir string
	origCgDir string
}

func newSenderFixture(t *testing.T, receiveFlags ...uint16) *senderFixture {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var original string
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("0::")) {
			original = filepath.Join("/sys/fs/cgroup", string(line[3:]))
		}
	}
	if original == "" {
		t.Fatal("cgroup v2 membership missing")
	}
	cgDir, err := os.MkdirTemp("/sys/fs/cgroup", "ns-owner-p3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(original, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600)
		_ = os.Remove(cgDir)
	})
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	bf := newBridgeFixture(t, false, receiveFlags...)
	probeObj := os.Getenv("NS_OWNERBPF_OBJECT")
	if probeObj == "" {
		t.Fatal("NS_OWNERBPF_OBJECT required")
	}
	ap, err := LoadAcceptedSenderProbe(probeObj, cgDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ap.Close(); err != nil {
			t.Error(err)
		}
	})
	return &senderFixture{
		bf:        bf,
		ap:        ap,
		cgroupDir: cgDir,
		origCgDir: original,
	}
}

func (f *senderFixture) snapshotActors(t *testing.T) map[ActorKey]ActorEvidence {
	t.Helper()
	out := make(map[ActorKey]ActorEvidence)
	it := f.ap.Collection.Maps["actors"].Iterate()
	var k ActorKey
	var v ActorEvidence
	for it.Next(&k, &v) {
		out[k] = v
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *senderFixture) syncLedger(t *testing.T, ledger *IdentityLedger, processed map[ActorKey]bool) map[ActorKey]ActorEvidence {
	t.Helper()
	actors := f.snapshotActors(t)
	ledger.SyncActorRecords(actors, processed)
	return actors
}

func (f *senderFixture) readFramesMatching(t *testing.T, wantCount int, timeout time.Duration, match func(raw []byte, dec ReadDecision) bool) []ReadFrame {
	t.Helper()
	var matched []ReadFrame
	deadline := time.Now().Add(timeout)
	for len(matched) < wantCount && time.Now().Before(deadline) {
		frames, err := f.bf.r.ReadBurst(f.bf.fd, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) == 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if match(frames[0].Data, frames[0].Decision) {
			matched = append(matched, frames[0])
		}
	}
	if len(matched) < wantCount {
		t.Fatalf("timed out waiting for %d matching frames (got %d)", wantCount, len(matched))
	}
	return matched
}

func matchTCPDstPort(raw []byte, wantVersion uint8, wantDstPort int) bool {
	hdr, err := InspectPacketHeader(raw)
	if err != nil || hdr.Version != wantVersion || hdr.NextHeader != 6 || hdr.IsFragment {
		return false
	}
	if len(raw) < hdr.PayloadOffset+20 {
		return false
	}
	dstPort := int(binary.BigEndian.Uint16(raw[hdr.PayloadOffset+2 : hdr.PayloadOffset+4]))
	return dstPort == wantDstPort
}

func matchUDPPayload(raw []byte, wantVersion uint8, wantDstPort int, wantPayload string) bool {
	hdr, err := InspectPacketHeader(raw)
	if err != nil || hdr.Version != wantVersion || hdr.NextHeader != 17 || hdr.IsFragment {
		return false
	}
	if len(raw) < hdr.PayloadOffset+8 {
		return false
	}
	dstPort := int(binary.BigEndian.Uint16(raw[hdr.PayloadOffset+2 : hdr.PayloadOffset+4]))
	payload := string(raw[hdr.PayloadOffset+8 : hdr.PayloadOffset+hdr.PayloadLength])
	return dstPort == wantDstPort && payload == wantPayload
}

func TestSenderP3(t *testing.T) {
	f := newSenderFixture(t)
	if err := ConfigureDeterministicIPv6OnSidecar("nsbridge0", "2001:db8::1/64"); err != nil {
		t.Fatal(err)
	}
	ledger := NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	slots, err := NewMmapSocketSlotTable(DefaultMaxSocketSlots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slots.Close() })
	ledger.AttachSlotTable(slots)
	processed := make(map[ActorKey]bool)

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	_ = os.Chmod(filepath.Dir(tmpDir), 0o755)
	_ = os.Chmod(tmpDir, 0o755)

	makeAppBin := func(name string) string {
		dst := filepath.Join(tmpDir, name)
		if err := copyFileExecutable(selfExe, dst); err != nil {
			t.Fatal(err)
		}
		return dst
	}

	// 1. TCPv4 SYN + real kernel timer SYN retransmit with an idle socket holder present.
	tcp4Bin := makeAppBin("p3-tcp4-initiator")
	idleBin := makeAppBin("p3-idle-holder")
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(sp[0])
		_ = unix.Close(sp[1])
	})
	passFile := os.NewFile(uintptr(sp[1]), "pass-tcp4")

	cmdTCP4 := exec.Command(tcp4Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdTCP4.Env = append(os.Environ(),
		"NS_P3_CHILD=tcp4_connect_retransmit",
		"NS_P3_PORT=43001",
		"NS_P3_PASS_FD=1",
	)
	cmdTCP4.ExtraFiles = []*os.File{passFile}
	tcp4In, _ := cmdTCP4.StdinPipe()
	tcp4Out, _ := cmdTCP4.StdoutPipe()
	cmdTCP4.Stderr = os.Stderr
	if err := cmdTCP4.Start(); err != nil {
		t.Fatal(err)
	}
	_ = passFile.Close()
	sp[1] = -1

	dupTCPFD := receiveFDFromSocket(t, sp[0])
	dupTCPFile := os.NewFile(uintptr(dupTCPFD), "idle-tcp4")
	cmdIdle := exec.Command(idleBin, "-test.run=^TestSenderLifecycleChild$")
	cmdIdle.Env = append(os.Environ(), "NS_P3_CHILD=idle_holder")
	cmdIdle.ExtraFiles = []*os.File{dupTCPFile}
	idleIn, _ := cmdIdle.StdinPipe()
	idleOut, _ := cmdIdle.StdoutPipe()
	cmdIdle.Stderr = os.Stderr
	if err := cmdIdle.Start(); err != nil {
		t.Fatal(err)
	}
	_ = dupTCPFile.Close()
	waitLine(t, bufio.NewReader(idleOut), "IDLE_HOLDING")
	waitLine(t, bufio.NewReader(tcp4Out), "TCP4_CONNECTING")

	// Wait for both initial SYN and kernel timer-retransmitted SYN (softirq context, ~1s).
	synFrames := f.readFramesMatching(t, 2, 5*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchTCPDstPort(raw, 4, 43001)
	})
	f.syncLedger(t, ledger, processed)
	wantTCP4App := tcp4Bin
	for i, sf := range synFrames {
		env := ledger.ResolvePacketEnvelope(sf.Decision)
		dec := ledger.ValidateForwardingEnvelope(env)
		if dec.Status != IdentityKnown || dec.Snapshot == nil || dec.Snapshot.AppID != wantTCP4App {
			t.Fatalf("TCPv4 SYN frame %d (retransmit=%t) decision = %+v, want %q", i, i > 0, dec, wantTCP4App)
		}
		ledger.ReleaseEnvelope(&env)
	}
	_ = tcp4In.Close()
	_ = cmdTCP4.Wait()
	_ = idleIn.Close()
	_ = cmdIdle.Wait()
	t.Logf("P3_TCP4_SYN_AND_RETRANSMIT app=%s syn1_serial=%d syn2_serial=%d cookie=%d",
		wantTCP4App, synFrames[0].Decision.Packet.Serial, synFrames[1].Decision.Packet.Serial, synFrames[0].Decision.Packet.Cookie)

	// 2. TCPv6 connect SYN and TCPv4 Fast Open (MSG_FASTOPEN).
	_ = os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("3\n"), 0o644)
	tcp6Bin := makeAppBin("p3-tcp6-initiator")
	cmdTCP6 := exec.Command(tcp6Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdTCP6.Env = append(os.Environ(), "NS_P3_CHILD=tcp6_connect", "NS_P3_PORT=43002")
	tcp6In, _ := cmdTCP6.StdinPipe()
	tcp6Out, _ := cmdTCP6.StdoutPipe()
	cmdTCP6.Stderr = os.Stderr
	if err := cmdTCP6.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(tcp6Out), "TCP6_CONNECTING")
	syn6Frames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchTCPDstPort(raw, 6, 43002)
	})
	f.syncLedger(t, ledger, processed)
	envTCP6 := ledger.ResolvePacketEnvelope(syn6Frames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envTCP6); dec.Status != IdentityKnown || dec.Snapshot.AppID != tcp6Bin {
		t.Fatalf("TCPv6 SYN decision = %+v, want %q", dec, tcp6Bin)
	}
	ledger.ReleaseEnvelope(&envTCP6)
	_ = tcp6In.Close()
	_ = cmdTCP6.Wait()

	tfoBin := makeAppBin("p3-tfo-initiator")
	cmdTFO := exec.Command(tfoBin, "-test.run=^TestSenderLifecycleChild$")
	cmdTFO.Env = append(os.Environ(), "NS_P3_CHILD=tcp4_fastopen", "NS_P3_PORT=43003", "NS_P3_PAYLOAD=tfo-hello")
	tfoIn, _ := cmdTFO.StdinPipe()
	tfoOut, _ := cmdTFO.StdoutPipe()
	cmdTFO.Stderr = os.Stderr
	if err := cmdTFO.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(tfoOut), "TFO_SENT")
	tfoFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchTCPDstPort(raw, 4, 43003)
	})
	f.syncLedger(t, ledger, processed)
	envTFO := ledger.ResolvePacketEnvelope(tfoFrames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envTFO); dec.Status != IdentityKnown || dec.Snapshot.AppID != tfoBin {
		t.Fatalf("TCP Fast Open SYN decision = %+v, want %q", dec, tfoBin)
	}
	ledger.ReleaseEnvelope(&envTFO)
	_ = tfoIn.Close()
	_ = cmdTFO.Wait()

	// 3. UDPv6 unconnected sendto, UDPv4 sendmmsg (2 messages), and UDPv4 splice.
	udp6Bin := makeAppBin("p3-udp6-sender")
	cmdUDP6 := exec.Command(udp6Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdUDP6.Env = append(os.Environ(), "NS_P3_CHILD=udp6_sendto", "NS_P3_PORT=43004", "NS_P3_PAYLOAD=p3-udp6-msg")
	u6In, _ := cmdUDP6.StdinPipe()
	u6Out, _ := cmdUDP6.StdoutPipe()
	cmdUDP6.Stderr = os.Stderr
	if err := cmdUDP6.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(u6Out), "UDP6_SENT")
	u6Frames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 6, 43004, "p3-udp6-msg")
	})
	f.syncLedger(t, ledger, processed)
	envU6 := ledger.ResolvePacketEnvelope(u6Frames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envU6); dec.Status != IdentityKnown || dec.Snapshot.AppID != udp6Bin {
		t.Fatalf("UDPv6 sendto decision = %+v", dec)
	}
	ledger.ReleaseEnvelope(&envU6)
	_ = u6In.Close()
	_ = cmdUDP6.Wait()

	mmsgBin := makeAppBin("p3-sendmmsg-sender")
	cmdMmsg := exec.Command(mmsgBin, "-test.run=^TestSenderLifecycleChild$")
	cmdMmsg.Env = append(os.Environ(), "NS_P3_CHILD=udp4_sendmmsg", "NS_P3_PORT=43005", "NS_P3_PAYLOAD=p3-mmsg")
	mmIn, _ := cmdMmsg.StdinPipe()
	mmOut, _ := cmdMmsg.StdoutPipe()
	cmdMmsg.Stderr = os.Stderr
	if err := cmdMmsg.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(mmOut), "SENDMMSG_SENT")
	mmFrames := f.readFramesMatching(t, 2, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 43005, "p3-mmsg-1") || matchUDPPayload(raw, 4, 43005, "p3-mmsg-2")
	})
	f.syncLedger(t, ledger, processed)
	for _, mf := range mmFrames {
		env := ledger.ResolvePacketEnvelope(mf.Decision)
		if dec := ledger.ValidateForwardingEnvelope(env); dec.Status != IdentityKnown || dec.Snapshot.AppID != mmsgBin {
			t.Fatalf("sendmmsg decision = %+v", dec)
		}
		ledger.ReleaseEnvelope(&env)
	}
	_ = mmIn.Close()
	_ = cmdMmsg.Wait()

	spliceBin := makeAppBin("p3-splice-sender")
	cmdSplice := exec.Command(spliceBin, "-test.run=^TestSenderLifecycleChild$")
	cmdSplice.Env = append(os.Environ(), "NS_P3_CHILD=udp4_splice", "NS_P3_PORT=43006", "NS_P3_PAYLOAD=p3-splice-data")
	spIn, _ := cmdSplice.StdinPipe()
	spOut, _ := cmdSplice.StdoutPipe()
	cmdSplice.Stderr = os.Stderr
	if err := cmdSplice.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(spOut), "SPLICE_SENT")
	spFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 43006, "p3-splice-data")
	})
	f.syncLedger(t, ledger, processed)
	envSp := ledger.ResolvePacketEnvelope(spFrames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envSp); dec.Status != IdentityKnown || dec.Snapshot.AppID != spliceBin {
		t.Fatalf("splice decision = %+v", dec)
	}
	ledger.ReleaseEnvelope(&envSp)
	_ = spIn.Close()
	_ = cmdSplice.Wait()

	// 4. Failed sends (EDESTADDRREQ, EMSGSIZE, ENETUNREACH) neither claim an unused socket nor poison an owned socket.
	creatorBin := makeAppBin("p3-sock-creator")
	failBin := makeAppBin("p3-failed-sender")
	validBin := makeAppBin("p3-valid-sender")
	spFail, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(spFail[0])
		_ = unix.Close(spFail[1])
	})
	passFailFile := os.NewFile(uintptr(spFail[1]), "pass-fail-udp")
	cmdCreate := exec.Command(creatorBin, "-test.run=^TestSenderLifecycleChild$")
	cmdCreate.Env = append(os.Environ(), "NS_P3_CHILD=create_unconnected_udp")
	cmdCreate.ExtraFiles = []*os.File{passFailFile}
	cmdCreate.Stderr = os.Stderr
	if err := cmdCreate.Run(); err != nil {
		t.Fatal(err)
	}
	_ = passFailFile.Close()
	spFail[1] = -1
	sharedUDPFD := receiveFDFromSocket(t, spFail[0])
	sharedUDPFile := os.NewFile(uintptr(sharedUDPFD), "shared-udp")
	t.Cleanup(func() { _ = sharedUDPFile.Close() })

	// Run failed_sends_only BEFORE any valid send on sharedUDPFile.
	cmdFail1 := exec.Command(failBin, "-test.run=^TestSenderLifecycleChild$")
	cmdFail1.Env = append(os.Environ(), "NS_P3_CHILD=failed_sends_only", "NS_P3_PORT=43007")
	cmdFail1.ExtraFiles = []*os.File{sharedUDPFile}
	f1In, _ := cmdFail1.StdinPipe()
	f1Out, _ := cmdFail1.StdoutPipe()
	cmdFail1.Stderr = os.Stderr
	if err := cmdFail1.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(f1Out), "FAILED_SENDS_DONE")
	f.syncLedger(t, ledger, processed)
	_ = f1In.Close()
	_ = cmdFail1.Wait()

	// Now validBin sends a real datagram on sharedUDPFile, followed by another failed send from failBin.
	cmdValid := exec.Command(validBin, "-test.run=^TestSenderLifecycleChild$")
	cmdValid.Env = append(os.Environ(), "NS_P3_CHILD=sendto_on_fd3", "NS_P3_PORT=43007", "NS_P3_PAYLOAD=p3-valid-after-fail")
	cmdValid.ExtraFiles = []*os.File{sharedUDPFile}
	vIn, _ := cmdValid.StdinPipe()
	vOut, _ := cmdValid.StdoutPipe()
	cmdValid.Stderr = os.Stderr
	if err := cmdValid.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(vOut), "FD3_SENT")

	cmdFail2 := exec.Command(failBin, "-test.run=^TestSenderLifecycleChild$")
	cmdFail2.Env = append(os.Environ(), "NS_P3_CHILD=failed_sends_only", "NS_P3_PORT=43007")
	cmdFail2.ExtraFiles = []*os.File{sharedUDPFile}
	f2In, _ := cmdFail2.StdinPipe()
	f2Out, _ := cmdFail2.StdoutPipe()
	cmdFail2.Stderr = os.Stderr
	if err := cmdFail2.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(f2Out), "FAILED_SENDS_DONE")

	validFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 43007, "p3-valid-after-fail")
	})
	f.syncLedger(t, ledger, processed)
	envValid := ledger.ResolvePacketEnvelope(validFrames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envValid); dec.Status != IdentityKnown || dec.Snapshot.AppID != validBin || dec.Conflicts != 0 {
		t.Fatalf("valid send after failed sends decision = %+v, want known %q conflicts=0", dec, validBin)
	}
	ledger.ReleaseEnvelope(&envValid)
	_ = vIn.Close()
	_ = cmdValid.Wait()
	_ = f2In.Close()
	_ = cmdFail2.Wait()
	t.Logf("P3_FAILED_SENDS_IGNORED valid_owner=%s cookie=%d", validBin, validFrames[0].Decision.Packet.Cookie)

	// 5. Multi-app UDP_CORK into a single flushed datagram -> conflicting_identity.
	corkAppA := makeAppBin("p3-cork-app-a")
	corkAppB := makeAppBin("p3-cork-app-b")
	spCork, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(spCork[0])
		_ = unix.Close(spCork[1])
	})
	passCorkFile := os.NewFile(uintptr(spCork[1]), "pass-cork-udp")
	cmdCreateCork := exec.Command(creatorBin, "-test.run=^TestSenderLifecycleChild$")
	cmdCreateCork.Env = append(os.Environ(), "NS_P3_CHILD=create_unconnected_udp")
	cmdCreateCork.ExtraFiles = []*os.File{passCorkFile}
	if err := cmdCreateCork.Run(); err != nil {
		t.Fatal(err)
	}
	_ = passCorkFile.Close()
	spCork[1] = -1
	corkUDPFD := receiveFDFromSocket(t, spCork[0])
	corkUDPFile := os.NewFile(uintptr(corkUDPFD), "cork-udp")
	t.Cleanup(func() { _ = corkUDPFile.Close() })

	// App A corks and appends "corkA-".
	cmdCorkA := exec.Command(corkAppA, "-test.run=^TestSenderLifecycleChild$")
	cmdCorkA.Env = append(os.Environ(), "NS_P3_CHILD=cork_append_fd3", "NS_P3_PORT=43008", "NS_P3_PAYLOAD=corkA-", "NS_P3_UNCORK=0")
	cmdCorkA.ExtraFiles = []*os.File{corkUDPFile}
	caIn, _ := cmdCorkA.StdinPipe()
	caOut, _ := cmdCorkA.StdoutPipe()
	cmdCorkA.Stderr = os.Stderr
	if err := cmdCorkA.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(caOut), "CORK_STEP_DONE")
	f.syncLedger(t, ledger, processed)
	_ = caIn.Close()
	_ = cmdCorkA.Wait()

	// App B appends "corkB" to the same corked datagram and uncorks to flush a single combined UDP packet ("corkA-corkB").
	cmdCorkB := exec.Command(corkAppB, "-test.run=^TestSenderLifecycleChild$")
	cmdCorkB.Env = append(os.Environ(), "NS_P3_CHILD=cork_append_fd3", "NS_P3_PORT=43008", "NS_P3_PAYLOAD=corkB", "NS_P3_UNCORK=1")
	cmdCorkB.ExtraFiles = []*os.File{corkUDPFile}
	cbIn, _ := cmdCorkB.StdinPipe()
	cbOut, _ := cmdCorkB.StdoutPipe()
	cmdCorkB.Stderr = os.Stderr
	if err := cmdCorkB.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(cbOut), "CORK_STEP_DONE")
	corkFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 43008, "corkA-corkB")
	})
	f.syncLedger(t, ledger, processed)
	envCork := ledger.ResolvePacketEnvelope(corkFrames[0].Decision)
	decCork := ledger.ValidateForwardingEnvelope(envCork)
	if decCork.Status != IdentityConflicting || decCork.Reason != ReasonConflictingApp || decCork.Conflicts == 0 {
		t.Fatalf("multi-app corked datagram decision = %+v, want conflicting_identity/conflicting_app", decCork)
	}
	ledger.ReleaseEnvelope(&envCork)
	_ = cbIn.Close()
	_ = cmdCorkB.Wait()
	t.Logf("P3_MULTI_APP_CORK cookie=%d status=%s conflicts=%d version=%d",
		corkFrames[0].Decision.Packet.Cookie, decCork.Status, decCork.Conflicts, decCork.OwnerVersion)
}

func computeIPv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildInboundICMPEchoRequest() []byte {
	payload := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	var csum uint32
	for i := 0; i+1 < len(payload); i += 2 {
		csum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	for (csum >> 16) != 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}
	binary.BigEndian.PutUint16(payload[2:4], ^uint16(csum))

	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 0x7777)
	pkt[8] = 64
	pkt[9] = 1 // IPPROTO_ICMP
	copy(pkt[12:16], []byte{198, 18, 0, 2})
	copy(pkt[16:20], []byte{198, 18, 0, 1})
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4HeaderChecksum(pkt[:20]))
	copy(pkt[20:], payload)
	return pkt
}

func buildInboundTCPSynToClosedPort(dstPort uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 54321)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 0x01020304)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	var sum uint32
	// Pseudo-header: 198.18.0.2 -> 198.18.0.1, proto 6, len 20.
	sum += uint32(0xc612) + uint32(0x0002) + uint32(0xc612) + uint32(0x0001) + 6 + 20
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))

	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 0x8888)
	pkt[8] = 64
	pkt[9] = 6 // IPPROTO_TCP
	copy(pkt[12:16], []byte{198, 18, 0, 2})
	copy(pkt[16:20], []byte{198, 18, 0, 1})
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4HeaderChecksum(pkt[:20]))
	copy(pkt[20:], tcp)
	return pkt
}

func TestOffloadAndFragmentsP4(t *testing.T) {
	f := newSenderFixture(t)
	if err := ConfigureDeterministicIPv6OnSidecar("nsbridge0", "2001:db8::1/64"); err != nil {
		t.Fatal(err)
	}
	ledger := NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	slots, err := NewMmapSocketSlotTable(DefaultMaxSocketSlots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slots.Close() })
	ledger.AttachSlotTable(slots)
	processed := make(map[ActorKey]bool)

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	_ = os.Chmod(filepath.Dir(tmpDir), 0o755)
	_ = os.Chmod(tmpDir, 0o755)
	makeAppBin := func(name string) string {
		dst := filepath.Join(tmpDir, name)
		if err := copyFileExecutable(selfExe, dst); err != nil {
			t.Fatal(err)
		}
		return dst
	}

	// 1. IPv4 and IPv6 kernel fragmentation (> 1500 MTU) + out-of-order reassembly.
	fragV4Bin := makeAppBin("p4-frag-v4-app")
	cmdFrag4 := exec.Command(fragV4Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdFrag4.Env = append(os.Environ(), "NS_P3_CHILD=p4_frag_v4", "NS_P3_PORT=44001", "NS_P3_PAYLOAD=FRAGV4DATA012345")
	f4In, _ := cmdFrag4.StdinPipe()
	f4Out, _ := cmdFrag4.StdoutPipe()
	cmdFrag4.Stderr = os.Stderr
	if err := cmdFrag4.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(f4Out), "FRAG_V4_SENT")
	v4Frags := f.readFramesMatching(t, 3, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		hdr, err := InspectPacketHeader(raw)
		return err == nil && hdr.Version == 4 && hdr.NextHeader == 17 && hdr.IsFragment
	})
	f.syncLedger(t, ledger, processed)
	reasm := NewFragmentReassembler(32, 256<<10)
	// Feed out-of-order: [2, 1, 0].
	for _, idx := range []int{2, 1, 0} {
		env := ledger.ResolvePacketEnvelope(v4Frags[idx].Decision)
		pkt, mergedEnv, done, err := reasm.Ingest(ledger, v4Frags[idx].Data, env)
		if err != nil {
			t.Fatalf("IPv4 fragment %d Ingest error: %v", idx, err)
		}
		if idx == 0 {
			if !done || len(pkt) != 20+8+3200 || mergedEnv.Identity.Status != IdentityKnown || mergedEnv.Identity.Snapshot.AppID != fragV4Bin {
				t.Fatalf("IPv4 reassembled done=%t len=%d id=%+v", done, len(pkt), mergedEnv.Identity)
			}
			ledger.ReleaseEnvelope(&mergedEnv)
		}
	}
	_ = f4In.Close()
	_ = cmdFrag4.Wait()

	fragV6Bin := makeAppBin("p4-frag-v6-app")
	cmdFrag6 := exec.Command(fragV6Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdFrag6.Env = append(os.Environ(), "NS_P3_CHILD=p4_frag_v6", "NS_P3_PORT=44002", "NS_P3_PAYLOAD=FRAGV6DATA012345")
	f6In, _ := cmdFrag6.StdinPipe()
	f6Out, _ := cmdFrag6.StdoutPipe()
	cmdFrag6.Stderr = os.Stderr
	if err := cmdFrag6.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(f6Out), "FRAG_V6_SENT")
	v6Frags := f.readFramesMatching(t, 3, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		hdr, err := InspectPacketHeader(raw)
		return err == nil && hdr.Version == 6 && hdr.NextHeader == 17 && hdr.IsFragment
	})
	f.syncLedger(t, ledger, processed)
	for _, idx := range []int{2, 1, 0} {
		env := ledger.ResolvePacketEnvelope(v6Frags[idx].Decision)
		pkt, mergedEnv, done, err := reasm.Ingest(ledger, v6Frags[idx].Data, env)
		if err != nil {
			t.Fatalf("IPv6 fragment %d Ingest error: %v", idx, err)
		}
		if idx == 0 {
			if !done || len(pkt) != 40+8+3200 || mergedEnv.Identity.Status != IdentityKnown || mergedEnv.Identity.Snapshot.AppID != fragV6Bin {
				t.Fatalf("IPv6 reassembled done=%t len=%d id=%+v", done, len(pkt), mergedEnv.Identity)
			}
			ledger.ReleaseEnvelope(&mergedEnv)
		}
	}
	_ = f6In.Close()
	_ = cmdFrag6.Wait()
	t.Logf("P4_FRAGMENTS v4_frags=%d v6_frags=%d out_of_order_reassembly=pass", len(v4Frags), len(v6Frags))

	// 2. IPv6 Destination Options extension header (IPV6_DSTOPTS).
	extV6Bin := makeAppBin("p4-ext-v6-app")
	cmdExt6 := exec.Command(extV6Bin, "-test.run=^TestSenderLifecycleChild$")
	cmdExt6.Env = append(os.Environ(), "NS_P3_CHILD=p4_ext_v6", "NS_P3_PORT=44003", "NS_P3_PAYLOAD=p4-ipv6-dstopts")
	e6In, _ := cmdExt6.StdinPipe()
	e6Out, _ := cmdExt6.StdoutPipe()
	cmdExt6.Stderr = os.Stderr
	if err := cmdExt6.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(e6Out), "EXT_V6_SENT")
	extFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		hdr, err := InspectPacketHeader(raw)
		return err == nil && hdr.Version == 6 && hdr.HasExtensionHeaders && !hdr.IsFragment && matchUDPPayload(raw, 6, 44003, "p4-ipv6-dstopts")
	})
	f.syncLedger(t, ledger, processed)
	envExt := ledger.ResolvePacketEnvelope(extFrames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envExt); dec.Status != IdentityKnown || dec.Snapshot.AppID != extV6Bin {
		t.Fatalf("IPv6 Destination Options packet decision = %+v", dec)
	}
	ledger.ReleaseEnvelope(&envExt)
	_ = e6In.Close()
	_ = cmdExt6.Wait()

	// 3. Explicit TSO/USO disabled kernel software segmentation (skb_gso_segment on UDP_SEGMENT).
	// Enable TUN_F_CSUM alone (with TSO4/TSO6/USO offloads disabled) so Linux 5.8 udp_send_skb
	// sets CHECKSUM_PARTIAL instead of returning EIO while still forcing kernel software __udp_gso_segment.
	if err := unix.IoctlSetInt(f.bf.fd, unix.TUNSETOFFLOAD, unix.TUN_F_CSUM); err != nil {
		t.Fatalf("enable TUN_F_CSUM for software UDP_SEGMENT: %v", err)
	}
	usoBin := makeAppBin("p4-udp-segment-app")
	cmdUSO := exec.Command(usoBin, "-test.run=^TestSenderLifecycleChild$")
	cmdUSO.Env = append(os.Environ(), "NS_P3_CHILD=p4_udp_segment", "NS_P3_PORT=44004", "NS_P3_PAYLOAD=p4-uso")
	usoIn, _ := cmdUSO.StdinPipe()
	usoOut, _ := cmdUSO.StdoutPipe()
	cmdUSO.Stderr = os.Stderr
	if err := cmdUSO.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(usoOut), "UDP_SEGMENT_SENT")
	usoFrames := f.readFramesMatching(t, 3, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		hdr, err := InspectPacketHeader(raw)
		if err != nil || hdr.Version != 4 || hdr.NextHeader != 17 || len(raw) < hdr.PayloadOffset+8 {
			return false
		}
		dstPort := int(binary.BigEndian.Uint16(raw[hdr.PayloadOffset+2 : hdr.PayloadOffset+4]))
		return dstPort == 44004
	})
	_ = unix.IoctlSetInt(f.bf.fd, unix.TUNSETOFFLOAD, 0)
	f.syncLedger(t, ledger, processed)
	var acct SegmentAccounting
	for segIdx, uf := range usoFrames {
		env := ledger.ResolvePacketEnvelope(uf.Decision)
		acct.ObserveRawSegment(uf.Decision, env)
		dec := ledger.ValidateForwardingEnvelope(env)
		hasSK := uf.Decision.Packet.Cookie != 0
		if hasSK {
			if dec.Status != IdentityKnown || dec.Snapshot == nil || dec.Snapshot.AppID != usoBin {
				t.Fatalf("UDP_SEGMENT segment %d with sk (cookie=%d) decision = %+v", segIdx, uf.Decision.Packet.Cookie, dec)
			}
		} else {
			if dec.Status != IdentityUnknown || dec.Reason != ReasonPacketIncomplete {
				t.Fatalf("UDP_SEGMENT socketless segment %d decision = %+v, want unknown/packet_incomplete", segIdx, dec)
			}
		}
		t.Logf("P4_SW_SEGMENT_DETAIL seg=%d has_sk=%t cookie=%d read_status=%s owner_status=%s",
			segIdx, hasSK, uf.Decision.Packet.Cookie, uf.Decision.Status, dec.Status)
		ledger.ReleaseEnvelope(&env)
	}
	_ = usoIn.Close()
	_ = cmdUSO.Wait()
	// Under software segmentation (offloads=0), Linux 5.8 sock_wfree (copy_destructor=false) leaves N-1 (2)
	// socket-less segments and 1 segment with sk retained, whereas modern kernels (6.x/7.x) preserve sk across
	// all 3 USO segments. Verify that all 3 segments are accounted without unknown-identity errors, and verify
	// explicitly that a socket-less middle segment never borrows provenance from its neighboring segments.
	if acct.TotalSegments != 3 || acct.AttributedSegments < 1 || acct.AttributedSegments+acct.SocketlessSegments != 3 || acct.UnknownSegments != 0 {
		t.Fatalf("UDP_SEGMENT software segmentation accounting = %+v", acct)
	}
	var syntheticAcct SegmentAccounting
	for segIdx, uf := range usoFrames {
		rawDec := uf.Decision
		if segIdx == 1 {
			rawDec = ReadDecision{Status: ReadUnknown, Packet: PacketRecord{}}
		}
		env := ledger.ResolvePacketEnvelope(rawDec)
		syntheticAcct.ObserveRawSegment(rawDec, env)
		if segIdx == 1 && (env.Identity.Status != IdentityUnknown || env.Identity.Reason != ReasonPacketIncomplete) {
			t.Fatalf("socketless middle segment borrowed neighbor identity: %+v", env.Identity)
		}
		ledger.ReleaseEnvelope(&env)
	}
	if syntheticAcct.TotalSegments != 3 || syntheticAcct.SocketlessSegments < 1 {
		t.Fatalf("synthetic socketless middle segment accounting = %+v", syntheticAcct)
	}
	t.Logf("P4_SW_SEGMENTATION total=%d attributed=%d socketless=%d",
		acct.TotalSegments, acct.AttributedSegments, acct.SocketlessSegments)

	// 4. Verified kernel-control-socket classification (kernel ICMP Echo Reply and TCP RST) vs negative control.
	clf := NewKernelControlClassifier()
	for k := range f.snapshotActors(t) {
		clf.RecordUserspaceSocket(k.Cookie)
	}

	// Inject inbound ICMP Echo Request and inbound TCP SYN to closed port 44999 into nsbridge0
	// as external wire traffic (outside the monitored application cgroup scope so synchronous
	// tun_get_user -> netif_rx -> icmp_push_reply -> ip_append_data softirq execution on arm64
	// does not attribute the TUN wire injector process as a userspace sender).
	var savedScope uint64
	if err := f.ap.Collection.Maps["scope"].Lookup(uint32(0), &savedScope); err != nil {
		t.Fatal(err)
	}
	if err := f.ap.Collection.Maps["scope"].Update(uint32(0), ^uint64(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	icmpReq := buildInboundICMPEchoRequest()
	if _, err := unix.Write(f.bf.fd, icmpReq); err != nil {
		t.Fatalf("inject inbound ICMP echo request: %v", err)
	}
	tcpSyn := buildInboundTCPSynToClosedPort(44999)
	if _, err := unix.Write(f.bf.fd, tcpSyn); err != nil {
		t.Fatalf("inject inbound TCP SYN: %v", err)
	}
	if err := f.ap.Collection.Maps["scope"].Update(uint32(0), savedScope, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	ctrlFrames := f.readFramesMatching(t, 2, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		hdr, err := InspectPacketHeader(raw)
		if err != nil || hdr.Version != 4 {
			return false
		}
		if hdr.NextHeader == 1 && len(raw) >= hdr.PayloadOffset+1 && raw[hdr.PayloadOffset] == 0 {
			return true // ICMP Echo Reply (type 0)
		}
		if hdr.NextHeader == 6 && len(raw) >= hdr.PayloadOffset+14 {
			srcPort := binary.BigEndian.Uint16(raw[hdr.PayloadOffset : hdr.PayloadOffset+2])
			flags := raw[hdr.PayloadOffset+13]
			return srcPort == 44999 && (flags&0x04) != 0 // TCP RST from closed port 44999
		}
		return false
	})

	actorsAfterCtrl := f.snapshotActors(t)
	for _, cf := range ctrlFrames {
		cookie := cf.Decision.Packet.Cookie
		if cookie == 0 {
			t.Fatalf("expected non-zero kernel control socket cookie on frame: %+v", cf.Decision)
		}
		// Verify that neither cgroup/sock_create nor userspace send hooks attributed this cookie to a userspace actor.
		hasUserActor := false
		for k := range actorsAfterCtrl {
			if k.Cookie == cookie {
				hasUserActor = true
				break
			}
		}
		if hasUserActor {
			t.Fatalf("kernel control socket cookie %d unexpectedly present in userspace actors map", cookie)
		}
		hdr, _ := InspectPacketHeader(cf.Data)
		kind := KernelControlICMPReply
		if hdr.NextHeader == 6 {
			kind = KernelControlTCPTimeWait
		}
		clf.RecordKernelControlSocket(KernelControlEvidence{
			Cookie:   cookie,
			NetNS:    cf.Decision.Packet.NetNS,
			Protocol: hdr.NextHeader,
			Kind:     kind,
		})
		env := ledger.ResolvePacketEnvelope(cf.Decision)
		if got := clf.Classify(cf.Data, env); got != PacketClassKernelControl {
			t.Fatalf("Classify(kernel control frame proto=%d) = %s, want %s", hdr.NextHeader, got, PacketClassKernelControl)
		}
		ledger.ReleaseEnvelope(&env)
	}

	// Negative control: ordinary application UDP packet whose actor metadata is unretained must count in ApplicationMisses!
	negBin := makeAppBin("p4-neg-control-app")
	cmdNeg := exec.Command(negBin, "-test.run=^TestIdentityChild$")
	cmdNeg.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=send_immediate_exit",
		"NS_IDENTITY_PORT=44005",
		"NS_IDENTITY_PAYLOAD=p4-neg-miss",
	)
	if err := cmdNeg.Run(); err != nil {
		t.Fatal(err)
	}
	negFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 44005, "p4-neg-miss")
	})
	f.syncLedger(t, ledger, processed)
	clf.RecordUserspaceSocket(negFrames[0].Decision.Packet.Cookie)
	envNeg := ledger.ResolvePacketEnvelope(negFrames[0].Decision)
	if got := clf.Classify(negFrames[0].Data, envNeg); got != PacketClassApplicationUnknown {
		t.Fatalf("negative control Classify = %s, want %s", got, PacketClassApplicationUnknown)
	}
	ledger.ReleaseEnvelope(&envNeg)
	cm := clf.Metrics()
	if cm.VerifiedKernelControl != 2 || cm.ApplicationMisses != 1 {
		t.Fatalf("ClassifierMetrics = %+v, want VerifiedKernelControl=2 ApplicationMisses=1", cm)
	}
	t.Logf("P4_KERNEL_CONTROL verified_control=%d app_misses=%d", cm.VerifiedKernelControl, cm.ApplicationMisses)

	// 5. Negotiate TUNSETOFFLOAD with IFF_VNET_HDR on a dedicated TUN fd and verify offload negotiation.
	tunOffFD, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(tunOffFD)
	ifrOff, err := unix.NewIfreq("nsoff0")
	if err != nil {
		t.Fatal(err)
	}
	ifrOff.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR))
	if err := unix.IoctlIfreq(tunOffFD, unix.TUNSETIFF, ifrOff); err != nil {
		t.Fatal(err)
	}
	offMask, err := NegotiateTUNOffloads(tunOffFD, true)
	if err != nil || offMask == 0 {
		t.Fatalf("NegotiateTUNOffloads(enable=true) = (mask=%#x, err=%v)", offMask, err)
	}
	offDisable, err := NegotiateTUNOffloads(tunOffFD, false)
	if err != nil || offDisable != 0 {
		t.Fatalf("NegotiateTUNOffloads(enable=false) = (mask=%#x, err=%v)", offDisable, err)
	}
	t.Logf("P4_TUN_OFFLOADS negotiated_mask=%#x disabled_mask=%#x", offMask, offDisable)
}

func readSelfRSSBytes() int64 {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * int64(unix.Getpagesize())
}

func countBridgePacketEntries(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	it := m.Iterate()
	var k uint64
	var v PacketRecord
	n := 0
	for it.Next(&k, &v) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLifecycleL1(t *testing.T) {
	f := newSenderFixture(t)
	const maxBounded = 16
	ledger := NewIdentityLedger(maxBounded, 16<<10)
	slots, err := NewMmapSocketSlotTable(maxBounded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slots.Close() })
	ledger.AttachSlotTable(slots)
	processed := make(map[ActorKey]bool)

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	_ = os.Chmod(filepath.Dir(tmpDir), 0o755)
	_ = os.Chmod(tmpDir, 0o755)
	churnBin := filepath.Join(tmpDir, "l1-churn-app")
	if err := copyFileExecutable(selfExe, churnBin); err != nil {
		t.Fatal(err)
	}

	// 1. Multi-wave real kernel socket + packet churn from accumulated state without reset,
	//    holding one envelope across socket close to verify slot pinning in the mmap table.
	var pinnedEnv ForwardEnvelope
	var pinnedCookie uint64
	var pinnedActor ActorIdentityKey

	for i := 0; i < maxBounded; i++ {
		s, err := dialBridgeUDPSocket(45001)
		if err != nil {
			t.Fatal(err)
		}
		msg := fmt.Sprintf("l1-wave1-%d", i)
		if _, err := unix.Write(s, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		frames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
			return matchUDPPayload(raw, 4, 45001, msg)
		})
		f.syncLedger(t, ledger, processed)
		env := ledger.ResolvePacketEnvelope(frames[0].Decision)
		if dec := ledger.ValidateForwardingEnvelope(env); dec.Status != IdentityKnown {
			t.Fatalf("wave1 packet %d decision = %+v", i, dec)
		}
		_ = unix.Close(s)
		if i == 0 {
			pinnedEnv = env
			pinnedCookie = frames[0].Decision.Packet.Cookie
			pinnedActor = env.Identity.Snapshot.Key
			// Close the socket in the ledger while pinnedEnv remains unforwarded!
			ledger.ReleaseSocket(pinnedCookie)
			if sm := slots.Metrics(); sm.RetainedSlots != 1 {
				t.Fatalf("expected 1 retained mmap slot after ReleaseSocket with live envelope, got %+v", sm)
			}
		} else {
			ledger.ReleaseSocket(frames[0].Decision.Packet.Cookie)
			ledger.ReleaseEnvelope(&env)
		}
	}

	// Verify pinnedEnv still validates after socket close, then release it and verify reclamation.
	if dec := ledger.ValidateForwardingEnvelope(pinnedEnv); dec.Status != IdentityKnown {
		t.Fatalf("pinnedEnv after socket close failed validation: %+v", dec)
	}
	ledger.ReleaseEnvelope(&pinnedEnv)
	ledger.ReleaseActor(pinnedActor)
	if sm := slots.Metrics(); sm.ActiveSlots != 0 || sm.RetainedSlots != 0 {
		t.Fatalf("expected all mmap slots reclaimed after draining wave1, got %+v", sm)
	}

	// 2. Second wave on the same accumulated state (no reset), then drain all references.
	for i := 0; i < maxBounded; i++ {
		s, err := dialBridgeUDPSocket(45002)
		if err != nil {
			t.Fatal(err)
		}
		msg := fmt.Sprintf("l1-wave2-%d", i)
		if _, err := unix.Write(s, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		frames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
			return matchUDPPayload(raw, 4, 45002, msg)
		})
		f.syncLedger(t, ledger, processed)
		env := ledger.ResolvePacketEnvelope(frames[0].Decision)
		if dec := ledger.ValidateForwardingEnvelope(env); dec.Status != IdentityKnown {
			t.Fatalf("wave2 packet %d decision = %+v", i, dec)
		}
		actorKey := env.Identity.Snapshot.Key
		_ = unix.Close(s)
		ledger.ReleaseSocket(frames[0].Decision.Packet.Cookie)
		ledger.ReleaseEnvelope(&env)
		ledger.ReleaseActor(actorKey)
	}

	pktCount := countBridgePacketEntries(t, f.bf.b.Collection.Maps["packets"])
	lm := ledger.Metrics()
	sm := slots.Metrics()
	if pktCount != 0 || lm.ActiveSnapshots != 0 || lm.ActiveBlobs != 0 || lm.UsedBlobBytes != 0 || lm.ActiveSocketSlots != 0 || sm.ActiveSlots != 0 {
		t.Fatalf("L1 post-drain non-zero state: bridge_packets=%d ledger=%+v slots=%+v", pktCount, lm, sm)
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rss := readSelfRSSBytes()
	var memlock unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_MEMLOCK, &memlock)
	prof, err := DeriveCapacityProfile(500, uint64(runtime.NumCPU()), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("L1_BOUNDED_LIFECYCLE bridge_packets=%d active_snaps=%d active_slots=%d bpf_bytes=%d ledger_budget=%d total_attr_budget=%d live_heap=%d rss=%d memlock_cur=%d",
		pktCount, lm.ActiveSnapshots, sm.ActiveSlots, prof.BPFMapBytes, prof.UserspaceLedgerBudget, prof.TotalAttributionBudget, ms.HeapAlloc, rss, memlock.Cur)
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestLifecycleL2(t *testing.T) {
	f := newSenderFixture(t)
	probeObj := os.Getenv("NS_OWNERBPF_OBJECT")
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Partial attachment unwind across every stage of LoadAcceptedSenderProbe leaves zero leaked FDs.
	stages := []string{
		"initialize_cookie",
		"observe_packet",
		"cg_connect4",
		"cg_connect6",
		"cg_sendmsg4",
		"cg_sendmsg6",
		"cg_sock_ops",
		"pmu:ip_make_skb",
		"pmu:ip6_make_skb",
		"pmu:ip_append_data",
		"pmu:ip6_append_data",
		"pmu:tcp_v4_connect",
		"pmu:tcp_v6_connect",
		"pmu:tcp_sendmsg",
	}
	baseFDs := countOpenFDs(t)
	for _, stage := range stages {
		_, err := loadAcceptedSenderProbe(probeObj, f.cgroupDir, func(at string, _ *AcceptedSenderProbe) error {
			if at == stage {
				return fmt.Errorf("injected fail at %s", stage)
			}
			return nil
		})
		if err == nil {
			t.Fatalf("expected injected failure at stage %s", stage)
		}
		afterFDs := countOpenFDs(t)
		if afterFDs != baseFDs {
			t.Fatalf("FD leak on partial unwind at %s: before=%d after=%d", stage, baseFDs, afterFDs)
		}
	}
	t.Logf("L2_PARTIAL_UNWIND stages=%d fd_baseline=%d leaked=0", len(stages), baseFDs)

	// 2. Coexistence (BPF_F_ALLOW_MULTI) with an independent cgroup_skb/egress filter + SIGKILL child cleanup.
	peerFilter, err := AttachPeerCgroupEgressFilter(f.cgroupDir)
	if err != nil {
		t.Fatalf("AttachPeerCgroupEgressFilter: %v", err)
	}
	t.Cleanup(func() { _ = peerFilter.Close() })

	hitsBefore, err := peerFilter.HitCount()
	if err != nil {
		t.Fatal(err)
	}

	// Spawn a child process that attaches a second AcceptedSenderProbe on the same cgroup, emits a packet, and gets SIGKILLed.
	cmdKill := exec.Command(selfExe, "-test.run=^TestSenderLifecycleChild$")
	cmdKill.Env = append(os.Environ(),
		"NS_P3_CHILD=l2_hold_probe_until_killed",
		"NS_P3_CGROUP="+f.cgroupDir,
		"NS_P3_PORT=46001",
		"NS_P3_PAYLOAD=l2-sigkill-probe",
	)
	killOut, _ := cmdKill.StdoutPipe()
	cmdKill.Stderr = os.Stderr
	if err := cmdKill.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(killOut), "CHILD_PROBE_ACTIVE")
	_ = f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 46001, "l2-sigkill-probe")
	})
	hitsMid, err := peerFilter.HitCount()
	if err != nil || hitsMid <= hitsBefore {
		t.Fatalf("peer cgroup filter did not run alongside child probe: before=%d mid=%d err=%v", hitsBefore, hitsMid, err)
	}

	// SIGKILL the child loader and verify the peer filter and parent probe continue functioning cleanly.
	if err := cmdKill.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmdKill.Wait()

	sAfterKill, err := dialBridgeUDPSocket(46002)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(sAfterKill, []byte("l2-after-sigkill")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(sAfterKill)
	_ = f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 46002, "l2-after-sigkill")
	})
	hitsAfter, err := peerFilter.HitCount()
	if err != nil || hitsAfter <= hitsMid {
		t.Fatalf("peer cgroup filter stopped working after child SIGKILL: mid=%d after=%d err=%v", hitsMid, hitsAfter, err)
	}
	t.Logf("L2_COEXIST_AND_SIGKILL hits_before=%d hits_mid=%d hits_after=%d", hitsBefore, hitsMid, hitsAfter)

	// 3. Cgroup migration (cgroup A -> cgroup B) with open and newly created sockets.
	cgB, err := os.MkdirTemp("/sys/fs/cgroup", "ns-owner-l2-b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(f.cgroupDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600)
		_ = os.Remove(cgB)
	})
	cgBFile, err := os.Open(cgB)
	if err != nil {
		t.Fatal(err)
	}
	defer cgBFile.Close()
	var cgAStat, cgBStat unix.Stat_t
	if err := unix.Stat(f.cgroupDir, &cgAStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(cgBFile.Fd()), &cgBStat); err != nil {
		t.Fatal(err)
	}
	lInitB, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgBFile.Fd()),
		Program: f.ap.Collection.Programs["initialize_cookie"],
		Attach:  ebpf.AttachCGroupInetSockCreate,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lInitB.Close()
	lObsB, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgBFile.Fd()),
		Program: f.ap.Collection.Programs["observe_packet"],
		Attach:  ebpf.AttachCGroupInetEgress,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lObsB.Close()

	ledger := NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	slots, err := NewMmapSocketSlotTable(DefaultMaxSocketSlots)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	ledger.AttachSlotTable(slots)
	processed := make(map[ActorKey]bool)

	migSock, err := dialBridgeUDPSocket(46003)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(migSock, []byte("l2-mig-before")); err != nil {
		t.Fatal(err)
	}
	// Migrate self into cgB while migSock remains open, and update scope[0] to cgBStat.Ino!
	if err := os.WriteFile(filepath.Join(cgB, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.ap.Collection.Maps["scope"].Update(uint32(0), cgBStat.Ino, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(migSock, []byte("l2-mig-after-open")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(migSock)
	migSockNew, err := dialBridgeUDPSocket(46003)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(migSockNew, []byte("l2-mig-after-new")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(migSockNew)
	// Restore self and scope[0] to f.cgroupDir.
	if err := os.WriteFile(filepath.Join(f.cgroupDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.ap.Collection.Maps["scope"].Update(uint32(0), cgAStat.Ino, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	migFrames := f.readFramesMatching(t, 3, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 46003, "l2-mig-before") ||
			matchUDPPayload(raw, 4, 46003, "l2-mig-after-open") ||
			matchUDPPayload(raw, 4, 46003, "l2-mig-after-new")
	})
	f.syncLedger(t, ledger, processed)
	for i, mf := range migFrames {
		env := ledger.ResolvePacketEnvelope(mf.Decision)
		if dec := ledger.ValidateForwardingEnvelope(env); dec.Status != IdentityKnown {
			t.Fatalf("cgroup migration packet %d decision = %+v, want known", i, dec)
		}
		ledger.ReleaseEnvelope(&env)
	}
	t.Logf("L2_CGROUP_MIGRATION packets=%d status=pass", len(migFrames))

	// 4. Capability-dropped loader refusal & lockdown classification.
	cmdCap := exec.Command(selfExe, "-test.run=^TestSenderLifecycleChild$")
	cmdCap.Env = append(os.Environ(),
		"NS_P3_CHILD=l2_cap_dropped_loader",
		"NS_P3_CGROUP="+f.cgroupDir,
	)
	capOut, err := cmdCap.CombinedOutput()
	if err != nil {
		t.Fatalf("l2_cap_dropped_loader failed: %v (%s)", err, string(capOut))
	}
	if !strings.Contains(string(capOut), "reason=degraded_capability_denied") {
		t.Fatalf("unexpected cap drop output: %s", string(capOut))
	}

	lockdownBytes, _ := os.ReadFile("/sys/kernel/security/lockdown")
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	lockdownMode := ParseLockdownMode(string(lockdownBytes))

	// 5. Epoch restart while pre-epoch traffic sits queued in nsbridge0's tx_ring:
	//    pre-epoch packet must be refused (ReadMissing) under the new epoch, and fresh traffic after
	//    quiesced reload must succeed.
	preEpochSock, err := dialBridgeUDPSocket(46004)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(preEpochSock, []byte("l2-pre-epoch-queued")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(preEpochSock)

	// Close epoch-1 bridge reader & collection while the packet remains queued in nsbridge0.
	if err := f.bf.r.Close(); err != nil {
		t.Fatal(err)
	}
	f.bf.r = nil
	if err := f.bf.b.Close(); err != nil {
		t.Fatal(err)
	}
	f.bf.b = nil

	// Start a fresh bridge epoch on the same nsbridge0 without draining the queued packet first.
	nlLink, err := netlink.LinkByName("nsbridge0")
	if err != nil {
		t.Fatal(err)
	}
	var nsSt unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &nsSt); err != nil {
		t.Fatal(err)
	}
	newEpoch := f.bf.epoch + 1000
	newB, err := LoadBridge(os.Getenv("NS_BRIDGE_OBJECT"), BridgeConfig{
		ABI:     ProvenanceABI,
		Epoch:   newEpoch,
		Ifindex: uint32(nlLink.Attrs().Index),
		NetNS:   uint32(nsSt.Ino),
		CPUs:    uint32(runtime.NumCPU()),
		Readers: ReaderLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.bf.b = newB
	newR, err := newB.Register()
	if err != nil {
		t.Fatal(err)
	}
	f.bf.r = newR
	if err := newB.Enable(uint64(nlLink.Attrs().TxQLen)); err != nil {
		t.Fatal(err)
	}

	var preDec ReadDecision
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		frames, rErr := newR.ReadBurst(f.bf.fd, 1)
		if len(frames) > 0 {
			preDec = frames[0].Decision
			if !errors.Is(rErr, ErrEpochRebuild) {
				t.Fatalf("expected ErrEpochRebuild on pre-epoch packet, got %v", rErr)
			}
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if preDec.Status != ReadMissing || !preDec.Rebuild {
		t.Fatalf("pre-epoch queued packet decision = %+v, want ReadMissing with Rebuild=true", preDec)
	}
	envPre := ledger.ResolvePacketEnvelope(preDec)
	if envPre.Identity.Status != IdentityUnknown || envPre.Identity.Reason != ReasonPacketIncomplete {
		t.Fatalf("pre-epoch ResolvePacketEnvelope = %+v, want unknown_identity/packet_incomplete", envPre.Identity)
	}

	// Rebuild cleanly into epoch 3 after draining the queued pre-epoch packet and verify fresh traffic survives.
	if err := f.bf.r.Close(); err != nil {
		t.Fatal(err)
	}
	f.bf.r = nil
	if err := f.bf.b.Close(); err != nil {
		t.Fatal(err)
	}
	f.bf.b = nil
	epoch3 := newEpoch + 1000
	b3, err := LoadBridge(os.Getenv("NS_BRIDGE_OBJECT"), BridgeConfig{
		ABI:     ProvenanceABI,
		Epoch:   epoch3,
		Ifindex: uint32(nlLink.Attrs().Index),
		NetNS:   uint32(nsSt.Ino),
		CPUs:    uint32(runtime.NumCPU()),
		Readers: ReaderLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.bf.b = b3
	r3, err := b3.Register()
	if err != nil {
		t.Fatal(err)
	}
	f.bf.r = r3
	if err := b3.Enable(uint64(nlLink.Attrs().TxQLen)); err != nil {
		t.Fatal(err)
	}
	freshSock, err := dialBridgeUDPSocket(46005)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(freshSock, []byte("l2-post-rebuild-fresh")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(freshSock)
	freshFrames := f.readFramesMatching(t, 1, 4*time.Second, func(raw []byte, _ ReadDecision) bool {
		return matchUDPPayload(raw, 4, 46005, "l2-post-rebuild-fresh")
	})
	f.syncLedger(t, ledger, processed)
	envFresh := ledger.ResolvePacketEnvelope(freshFrames[0].Decision)
	if dec := ledger.ValidateForwardingEnvelope(envFresh); dec.Status != IdentityKnown {
		t.Fatalf("post-rebuild fresh packet decision = %+v, want known", dec)
	}
	ledger.ReleaseEnvelope(&envFresh)
	t.Logf("L2_EPOCH_RESTART_AND_CAPS pre_epoch_status=%s post_rebuild=known lockdown=%s has_btf=%t cap_drop=degraded_capability_denied",
		preDec.Status, lockdownMode, btfErr == nil)
}

func TestSenderEngineSpecLoad(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("NS_OWNERBPF_PROOF") != "1" {
		t.Fatal("hosted root proof required")
	}
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	hostNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil || selfNS == hostNS {
		t.Fatal("private network namespace required", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 64 << 20, Max: 64 << 20}); err != nil {
		t.Fatal(err)
	}

	tunFD, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if tunFD >= 0 {
			_ = unix.Close(tunFD)
		}
	}()
	ifr, err := unix.NewIfreq("nseng0")
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(tunFD, unix.TUNSETIFF, ifr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/nseng0/disable_ipv6", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	nlLink, err := netlink.LinkByName("nseng0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetTxQLen(nlLink, 500); err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("198.18.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(nlLink, addr); err != nil {
		t.Fatal(err)
	}
	var nsSt unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &nsSt); err != nil {
		t.Fatal(err)
	}

	epoch := uint64(time.Now().UnixNano())
	engBridge, err := LoadEngineBridge(uint32(nlLink.Attrs().Index), uint32(nsSt.Ino), epoch, 500)
	if err != nil {
		t.Fatalf("LoadEngineBridge: %v", err)
	}
	defer func() {
		if err := engBridge.Close(); err != nil {
			t.Errorf("engBridge.Close: %v", err)
		}
	}()

	engProbe, err := LoadEngineSenderProbe("/sys/fs/cgroup", 4096, 1024)
	if err != nil {
		t.Fatalf("LoadEngineSenderProbe: %v", err)
	}
	defer func() {
		if err := engProbe.Close(); err != nil {
			t.Errorf("engProbe.Close: %v", err)
		}
	}()

	engReader, err := engBridge.Register()
	if err != nil {
		t.Fatalf("engBridge.Register: %v", err)
	}
	defer func() {
		if engReader != nil {
			if err := engReader.Close(); err != nil {
				t.Errorf("engReader.Close: %v", err)
			}
		}
	}()
	if err := engProbe.Enable(); err != nil {
		t.Fatalf("engProbe.Enable: %v", err)
	}
	if err := engBridge.Enable(500); err != nil {
		t.Fatalf("engBridge.Enable: %v", err)
	}
	if err := netlink.LinkSetUp(nlLink); err != nil {
		t.Fatal(err)
	}

	sock, err := dialBridgeUDPSocket(46099)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(sock, []byte("engine-spec-ok")); err != nil {
		_ = unix.Close(sock)
		t.Fatal(err)
	}
	cookie, err := unix.GetsockoptUint64(sock, unix.SOL_SOCKET, unix.SO_COOKIE)
	_ = unix.Close(sock)
	if err != nil || cookie == 0 {
		t.Fatalf("GetsockoptUint64 SO_COOKIE: cookie=%d err=%v", cookie, err)
	}

	rawBufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	decisions := make([]ReadDecision, 1)
	var gotCount int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, rErr := engReader.ReadBurstInto(tunFD, rawBufs, sizes, decisions)
		if rErr != nil {
			t.Fatalf("ReadBurstInto: %v", rErr)
		}
		if n > 0 {
			gotCount = n
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if gotCount != 1 || decisions[0].Status != ReadCookie || decisions[0].Packet.Cookie != cookie {
		t.Fatalf("ReadBurstInto got count=%d decision=%+v, want cookie=%d", gotCount, decisions[0], cookie)
	}
	if !engProbe.HasPendingNewActors() {
		t.Fatal("expected engProbe.HasPendingNewActors() == true after first send")
	}

	events, err := engProbe.DrainNewActors(make(map[ActorKey]bool))
	if err != nil {
		t.Fatalf("DrainNewActors: %v", err)
	}
	matchedActor := false
	for _, ev := range events {
		if ev.Key.Cookie == cookie && ev.Key.TGID == uint32(os.Getpid()) && ev.Evidence.ABI == ABI {
			matchedActor = true
			break
		}
	}
	if !matchedActor {
		t.Fatalf("DrainNewActors(%d events) did not report cookie=%d tgid=%d", len(events), cookie, os.Getpid())
	}

	if err := engBridge.Stop(); err != nil {
		t.Fatalf("engBridge.Stop: %v", err)
	}
	_ = unix.Close(tunFD)
	tunFD = -1
	if err := engReader.Close(); err != nil {
		t.Fatalf("engReader.Close: %v", err)
	}
	engReader = nil
	t.Logf("ENGINE_SPEC_KERNEL_PROOF cookie=%d packet_slots=%d queued_events=%d", cookie, engBridge.PacketSlots(), len(events))
}
