//go:build linux && ownerbpfproof

package ownerbpf

import (
	"bytes"
	"context"
	"encoding/json"
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

// This opt-in suite fails missing infrastructure; it never skips a proof.
// The child writes directly to an inherited connected socket. The socket's
// creator, idle holder and sender are therefore independently known by the test.
func TestProofChild(t *testing.T) {
	mode := os.Getenv("NS_OWNER_CHILD")
	if mode == "" {
		return
	}
	if mode == "loader" {
		p, err := Load(os.Getenv("NS_OWNERBPF_OBJECT"), os.Getenv("NS_OWNER_CGROUP"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(73)
		}
		ids := attachmentIDs{PerfFDs: len(p.perf)}
		for _, l := range p.links {
			info, err := l.Info()
			if err != nil {
				os.Exit(74)
			}
			ids.Links = append(ids.Links, info.ID)
		}
		for _, prog := range p.Collection.Programs {
			info, err := prog.Info()
			if err != nil {
				os.Exit(75)
			}
			id, ok := info.ID()
			if !ok {
				os.Exit(76)
			}
			ids.Programs = append(ids.Programs, id)
		}
		if err := json.NewEncoder(os.Stdout).Encode(ids); err != nil {
			os.Exit(77)
		}
		for {
			time.Sleep(time.Hour)
			runtime.KeepAlive(p)
		}
	}
	if mode == "barrier" {
		var release [1]byte
		if _, err := unix.Read(4, release[:]); err != nil {
			os.Exit(78)
		}
	}
	if _, err := unix.Write(3, []byte("same-datagram")); err != nil {
		os.Exit(71)
	}
	if mode == "exec" {
		if err := os.Setenv("NS_OWNER_CHILD", "exit"); err != nil {
			os.Exit(72)
		}
		exe, _ := os.Executable()
		if err := unix.Exec(exe, []string{exe, "-test.run=^TestProofChild$"}, os.Environ()); err != nil {
			os.Exit(72)
		}
	}
	os.Exit(0)
}

func TestKernelProof(t *testing.T) {
	if os.Getenv("NS_OWNERBPF_PROOF") != "1" || os.Geteuid() != 0 {
		t.Fatal("unmet: run the reviewed hosted proof as root in a private network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == host {
		t.Fatal("unmet: private network namespace required", err)
	}
	object := os.Getenv("NS_OWNERBPF_OBJECT")
	if object == "" {
		t.Fatal("unmet: generated object path required")
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual kernel=%s architecture=%s; backend=bpf-proof-v1; notification reader=absent", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Machine[:]))
	if required := os.Getenv("NS_OWNERBPF_KERNEL"); required != "" && unix.ByteSliceToString(uts.Release[:]) != required {
		t.Fatalf("unmet floor: actual kernel differs from required %s", required)
	}
	// Retain the original membership so cleanup doesn't remove an occupied cgroup.
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
		t.Fatal("unmet: cgroup v2 membership missing")
	}
	dir, err := os.MkdirTemp("/sys/fs/cgroup", "ns-owner-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(original, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Error(err)
		}
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 32 << 20, Max: 32 << 20}); err != nil {
		t.Fatal(err)
	}
	p, err := Load(object, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}

	t.Run("creator-idle-holder-sender-exec-exit", func(t *testing.T) {
		receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer sender.Close()
		f, err := sender.File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cookie, err := unix.GetsockoptUint64(int(f.Fd()), unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		exe, _ := os.Executable()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestProofChild$")
		cmd.ExtraFiles = []*os.File{f}
		cmd.Env = append(os.Environ(), "NS_OWNER_CHILD=exec")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		pid := uint32(cmd.Process.Pid)
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); !os.IsNotExist(err) {
			t.Fatalf("exit precondition: %v", err)
		}
		var key ActorKey
		var evidence ActorEvidence
		var generations []ActorKey
		iter := p.Collection.Maps["actors"].Iterate()
		for iter.Next(&key, &evidence) {
			if key.Cookie != cookie {
				continue
			}
			if key.TGID != pid || evidence.ABI != ABI || evidence.Inode == 0 || key.Start == 0 {
				t.Fatalf("wrong actor evidence: %+v %+v", key, evidence)
			}
			generations = append(generations, key)
		}
		if err := iter.Err(); err != nil {
			t.Fatal(err)
		}
		if len(generations) != 2 || generations[0].Exec == generations[1].Exec || generations[0].Start != generations[1].Start {
			t.Fatalf("exec history not retained: %+v", generations)
		}
		for range 2 {
			_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 64)
			if n, _, err := receiver.ReadFromUDP(b); err != nil || string(b[:n]) != "same-datagram" {
				t.Fatalf("accepted data missing: %d %v", n, err)
			}
		}
		counts, err := p.Counts()
		if err != nil {
			t.Fatal(err)
		}
		r := Decide(context.Background(), time.Now(), counts, &TupleEvidence{FirstCookie: cookie})
		if r.Status != IncompleteIdentity || r.AllowsScanner() {
			t.Fatal(r)
		}
		t.Log("sender-to-cookie and retained exec evidence present; complete app identities=0/2 (UNMET, not PID hits)")
	})
	t.Run("queued-tuple-reuse", func(t *testing.T) { queuedReuse(t, p) })
	t.Run("concurrent-same-executable-senders", func(t *testing.T) {
		receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer sender.Close()
		f, err := sender.File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cookie, err := unix.GetsockoptUint64(int(f.Fd()), unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		exe, _ := os.Executable()
		var commands []*exec.Cmd
		pids := map[uint32]bool{}
		gateRead, gateWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer gateRead.Close()
		defer gateWrite.Close()
		for range 2 {
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestProofChild$")
			cmd.ExtraFiles = []*os.File{f, gateRead}
			cmd.Env = append(os.Environ(), "NS_OWNER_CHILD=barrier")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			commands = append(commands, cmd)
			pids[uint32(cmd.Process.Pid)] = true
		}
		// Both children exist before the shared EOF releases either sender.
		if err := gateWrite.Close(); err != nil {
			t.Fatal(err)
		}
		for _, cmd := range commands {
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		}
		var key ActorKey
		var value ActorEvidence
		it := p.Collection.Maps["actors"].Iterate()
		seen := map[uint32]bool{}
		for it.Next(&key, &value) {
			if key.Cookie == cookie {
				if !pids[key.TGID] {
					t.Fatalf("creator/idle holder substituted for sender: %+v", key)
				}
				seen[key.TGID] = true
			}
		}
		if err := it.Err(); err != nil || len(seen) != 2 {
			t.Fatalf("concurrent evidence lost: %v %v", seen, err)
		}
		for range 2 {
			_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 64)
			if n, _, err := receiver.ReadFromUDP(b); err != nil || string(b[:n]) != "same-datagram" {
				t.Fatalf("sender data missing: %d %v", n, err)
			}
		}
		t.Log("two processes of the same executable retained independently; app-equivalence/conflicting-app decision remains UNMET")
	})
	t.Run("failed-first-send-is-only-an-attempt", func(t *testing.T) {
		s, err := net.Dial("udp4", "127.0.0.1:9")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		before, err := p.Counts()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(make([]byte, 65536)); err == nil {
			t.Fatal("oversized datagram unexpectedly accepted")
		}
		after, err := p.Counts()
		if err != nil {
			t.Fatal(err)
		}
		if after.Attempts != before.Attempts+1 || after.Packets != before.Packets {
			t.Fatalf("attempt/packet separation: before=%+v after=%+v", before, after)
		}
		t.Log("failed first send recorded only as attempt; no owner claim or egress record")
	})
	t.Run("one-callback-per-online-cpu", func(t *testing.T) { callbackEveryCPU(t, p) })
	t.Run("sigkill-and-coexistence", func(t *testing.T) { crashCleanup(t, p, dir) })
	t.Run("partial-load-unwind", func(t *testing.T) {
		for _, stage := range []string{"initialize_cookie", "observe_packet", "pmu"} {
			t.Run(stage, func(t *testing.T) {
				injected := errors.New("fixture attachment failure")
				var ids attachmentIDs
				got, err := load(object, dir, func(at string, partial *Probe) error {
					if at != stage {
						return nil
					}
					wantPerf := 0
					if at == "pmu" {
						wantPerf = 1
					}
					if len(partial.perf) != wantPerf {
						return fmt.Errorf("partial PMU ownership: got %d want %d", len(partial.perf), wantPerf)
					}
					for _, l := range partial.links {
						info, e := l.Info()
						if e != nil {
							return e
						}
						ids.Links = append(ids.Links, info.ID)
					}
					for _, prog := range partial.Collection.Programs {
						info, e := prog.Info()
						if e != nil {
							return e
						}
						id, ok := info.ID()
						if !ok {
							return errors.New("program ID missing")
						}
						ids.Programs = append(ids.Programs, id)
					}
					return injected
				})
				if got != nil {
					_ = got.Close()
					t.Fatal("partial load unexpectedly succeeded")
				}
				if !errors.Is(err, injected) || len(ids.Links) == 0 || len(ids.Programs) != 3 {
					t.Fatalf("partial attachment precondition not reached: %+v %v", ids, err)
				}
				assertAttachmentsGone(t, ids)
			})
		}
	})
	t.Run("bounded-map-exhaustion", func(t *testing.T) {
		// Accumulated state from previous fixtures is deliberately retained.
		m := p.Collection.Maps["actors"]
		for i := uint64(1); i <= RecordLimit; i++ {
			if err := m.Update(ActorKey{Cookie: i, Start: 1}, ActorEvidence{ABI: ABI}, ebpf.UpdateNoExist); err != nil {
				break
			}
		}
		var k ActorKey
		var v ActorEvidence
		it, n := m.Iterate(), 0
		for it.Next(&k, &v) {
			n++
		}
		if err := it.Err(); err != nil || n != RecordLimit {
			t.Fatalf("full precondition: n=%d err=%v", n, err)
		}
		s, err := net.Dial("udp4", "127.0.0.1:9")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		_, _ = s.Write([]byte("pressure"))
		counts, err := p.Counts()
		if err != nil || counts.InsertFailure == 0 || counts.Poison == 0 {
			t.Fatalf("overflow not latched: %+v %v", counts, err)
		}
		if r := Decide(context.Background(), time.Now(), counts, &TupleEvidence{FirstCookie: 1}); r.Status != Poisoned || r.AllowsScanner() {
			t.Fatal(r)
		}
		t.Logf("bounded actor slots=%d counters=%+v; no reclamation/TTL; poisoned until collection destroyed", n, counts)
	})
}

type attachmentIDs struct {
	Links    []link.ID
	Programs []ebpf.ProgramID
	PerfFDs  int
}

func crashCleanup(t *testing.T, existing *Probe, cgroup string) {
	exe, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestProofChild$")
	cmd.Env = append(os.Environ(), "NS_OWNER_CHILD=loader", "NS_OWNER_CGROUP="+cgroup)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var ids attachmentIDs
	if err := json.NewDecoder(stdout).Decode(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids.Links) != 2 || len(ids.Programs) != 3 || ids.PerfFDs != 1 {
		t.Fatalf("attachments absent before kill: %+v", ids)
	}
	for _, id := range ids.Links {
		l, err := link.NewFromID(id)
		if err != nil {
			t.Fatalf("live link %d absent: %v", id, err)
		}
		_ = l.Close()
	}
	for _, id := range ids.Programs {
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			t.Fatalf("live program %d absent: %v", id, err)
		}
		_ = prog.Close()
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child wasn't killed")
	}
	assertAttachmentsGone(t, ids)
	for _, l := range existing.links {
		if _, err := l.Info(); err != nil {
			t.Fatalf("coexisting link was removed: %v", err)
		}
	}
	// An open link FD alone doesn't prove that the surviving hooks still run.
	// Use a fresh socket/tuple and check both actual data and its observations.
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	payload := []byte(fmt.Sprintf("after-sigkill:%d:%s", cmd.Process.Pid, sender.LocalAddr()))
	before, err := existing.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := sender.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("fresh coexistence send: %d %v", n, err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	n, from, err := receiver.ReadFromUDP(data)
	if err != nil || !bytes.Equal(data[:n], payload) || from.String() != sender.LocalAddr().String() {
		t.Fatalf("fresh coexistence receive: bytes=%q source=%v err=%v", data[:n], from, err)
	}
	after, err := existing.Counts()
	if err != nil || after.Attempts != before.Attempts+1 || after.Packets != before.Packets+1 {
		t.Fatalf("surviving hooks not observed: before=%+v after=%+v err=%v", before, after, err)
	}
	assertAttachmentsGone(t, ids)
	t.Log("child objects existed before SIGKILL and remain gone; original collection observed and delivered a fresh checked datagram")
}

func assertAttachmentsGone(t *testing.T, ids attachmentIDs) {
	t.Helper()
	// Kernel RCU disposal can lag FD closure. Bounded cleanup observation is
	// not a retry of an attribution miss; assert all resources existed first.
	deadline := time.Now().Add(2 * time.Second)
	for {
		alive := false
		for _, id := range ids.Links {
			l, err := link.NewFromID(id)
			if err == nil {
				alive = true
				_ = l.Close()
			} else if !errors.Is(err, unix.ENOENT) {
				t.Fatal(err)
			}
		}
		for _, id := range ids.Programs {
			prog, err := ebpf.NewProgramFromID(id)
			if err == nil {
				alive = true
				_ = prog.Close()
			} else if !errors.Is(err, unix.ENOENT) {
				t.Fatal(err)
			}
		}
		if !alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owned attachments/programs survived SIGKILL: %+v", ids)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func queuedReuse(t *testing.T, p *Probe) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("nsproof0")
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatal(err)
	}
	l, err := netlink.LinkByName("nsproof0")
	if err != nil {
		t.Fatal(err)
	}
	// Only this newly created, still-down interface in the private netns.
	// Prevent IPv6 router solicitations; do not drain unrelated frames until
	// the expected IPv4 packets happen to appear.
	ipv6 := "/proc/sys/net/ipv6/conf/nsproof0/disable_ipv6"
	if err := os.WriteFile(ipv6, []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(ipv6); err != nil || strings.TrimSpace(string(value)) != "1" {
		t.Fatalf("private TUN IPv4-only precondition: value=%q err=%v", value, err)
	}
	addr, _ := netlink.ParseAddr("198.18.0.1/24")
	if err := netlink.AddrAdd(l, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	port := 0
	cookies := [2]uint64{}
	second := -1
	defer func() {
		if second >= 0 {
			_ = unix.Close(second)
		}
	}()
	for i := range 2 {
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			keep := false
			defer func() {
				if !keep {
					if err := unix.Close(s); err != nil {
						t.Error(err)
					}
				}
			}()
			if err := unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: port}); err != nil {
				t.Fatal(err)
			}
			// Keep inet_daddr zero: connected DF sockets use a per-socket IP
			// ID in both 5.8 and modern kernels. Unconnected DF sends use ID 0.
			if err := unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
				t.Fatal(err)
			}
			bound, err := unix.Getsockname(s)
			if err != nil {
				t.Fatal(err)
			}
			port = bound.(*unix.SockaddrInet4).Port
			cookies[i], err = unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_COOKIE)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Sendto(s, []byte("identical"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				t.Fatal(err)
			}
			if i == 1 {
				second, keep = s, true
			}
		}()
		if i == 0 {
			// No intervening FD allocation: prove A was closed before B binds.
			if _, err := unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_COOKIE); !errors.Is(err, unix.EBADF) {
				t.Fatalf("first socket wasn't closed: %v", err)
			}
		}
	}
	if cookies[0] == cookies[1] || cookies[0] == 0 || cookies[1] == 0 {
		t.Fatal("distinct socket generation precondition", cookies)
	}
	key := TupleKey{Source: [4]byte{198, 18, 0, 1}, Destination: [4]byte{198, 18, 0, 2}, Ports: [4]byte{byte(port >> 8), byte(port), 0x23, 0x28}}
	var tuple TupleEvidence
	if err := p.Collection.Maps["tuples"].Lookup(key, &tuple); err != nil {
		t.Fatal(err)
	}
	if tuple.FirstCookie != cookies[0] || tuple.Conflicts == 0 {
		t.Fatalf("overlap not retained before any TUN read: %+v cookies=%v", tuple, cookies)
	}
	checkSecond := func() {
		t.Helper()
		if cookie, err := unix.GetsockoptUint64(second, unix.SOL_SOCKET, unix.SO_COOKIE); err != nil || cookie != cookies[1] {
			t.Fatalf("second generation no longer live: cookie=%d want=%d err=%v", cookie, cookies[1], err)
		}
	}
	checkSecond()
	var packets [2][]byte
	for i := range packets {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, err := unix.Poll(poll, 1000); err != nil || n != 1 {
			t.Fatalf("queued packet missing: %d %v", n, err)
		}
		b := make([]byte, 2048)
		n, err := unix.Read(fd, b)
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = b[:n]
		if n != 37 || b[0] != 0x45 || b[9] != 17 || b[6] != 0x40 || b[7] != 0 || b[4] != 0 || b[5] != 0 ||
			!bytes.Equal(b[12:16], key.Source[:]) || !bytes.Equal(b[16:20], key.Destination[:]) || !bytes.Equal(b[20:24], key.Ports[:]) || string(b[28:n]) != "identical" {
			t.Fatalf("queued packet tuple/DF/ID/payload precondition failed: %x", b[:n])
		}
	}
	checkSecond()
	if !bytes.Equal(packets[0], packets[1]) {
		t.Fatalf("identical-packet precondition failed:\n%x\n%x", packets[0], packets[1])
	}
	t.Logf("counterexample: cookies=%v, identical queued packets=%x, tuple=%+v; latest-cookie would misattribute packet 1", cookies, packets[0], tuple)
}

func callbackEveryCPU(t *testing.T, p *Probe) {
	if len(p.perf) != 1 {
		t.Fatalf("expected one owned PMU FD, got %d", len(p.perf))
	}
	online, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		t.Fatal(err)
	}
	cpus, err := onlineCPUs(strings.TrimSpace(string(online)))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	f, err := sender.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// One socket/process keeps map occupancy constant even on a large host.
	// Affinity and getcpu bracket the synchronous send on the locked OS thread.
	runtime.LockOSThread()
	var original unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &original); err != nil {
			t.Errorf("restore original CPU affinity: %v", err)
			// Do not return a restricted thread to the runtime's thread pool.
			return
		}
		runtime.UnlockOSThread()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for _, cpu := range cpus {
		if !original.IsSet(cpu) {
			t.Fatalf("unmet CPU coverage: online CPU %d is outside original affinity", cpu)
		}
		if !time.Now().Before(deadline) {
			t.Fatal("per-CPU callback proof exceeded 10-second budget")
		}
		var mask unix.CPUSet
		mask.Set(cpu)
		if err := unix.SchedSetaffinity(0, &mask); err != nil {
			t.Fatal(err)
		}
		checkCPU := func() {
			var actual uint32
			_, _, errno := unix.RawSyscall(unix.SYS_GETCPU, uintptr(unsafe.Pointer(&actual)), 0, 0)
			if errno != 0 || int(actual) != cpu {
				t.Fatalf("CPU execution precondition: got=%d want=%d errno=%v", actual, cpu, errno)
			}
		}
		before, err := p.Counts()
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte(fmt.Sprintf("callback-on-cpu-%d", cpu))
		checkCPU()
		if n, err := unix.Write(int(f.Fd()), payload); err != nil || n != len(payload) {
			t.Fatalf("CPU %d send: %d %v", cpu, n, err)
		}
		checkCPU()
		after, err := p.Counts()
		if err != nil || after.Attempts != before.Attempts+1 || after.Packets != before.Packets+1 {
			t.Fatalf("CPU %d callback multiplicity: before=%+v after=%+v err=%v", cpu, before, after, err)
		}
		readDeadline := time.Now().Add(time.Second)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		if err := receiver.SetReadDeadline(readDeadline); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 128)
		n, from, err := receiver.ReadFromUDP(data)
		if err != nil || !bytes.Equal(data[:n], payload) || from.String() != sender.LocalAddr().String() {
			t.Fatalf("CPU %d datagram mismatch: bytes=%q source=%v err=%v", cpu, data[:n], from, err)
		}
		t.Logf("cpu=%d attempts_delta=1 packets_delta=1 received=%q", cpu, data[:n])
	}
	if now, err := os.ReadFile("/sys/devices/system/cpu/online"); err != nil || !bytes.Equal(now, online) {
		t.Fatalf("online CPU set changed during proof: before=%q after=%q err=%v", online, now, err)
	}
}
