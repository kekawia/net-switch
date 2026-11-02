//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ioringSetupSQPoll    = 1 << 1
	ioringSqNeedWakeup   = 1 << 0
	ioringEnterGetEvents = 1 << 0
	ioringEnterSqWakeup  = 1 << 1
	ioringRegisterFiles  = 2

	ioringOffSqRing = 0
	ioringOffCqRing = 0x8000000
	ioringOffSqes   = 0x10000000

	ioringOpSend   = 26
	iosqeFixedFile = 1 << 0
	iosqeAsync     = 1 << 4
)

type ioSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

type ioCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	Resv2       uint64
}

type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFD         uint32
	Resv         [3]uint32
	SqOff        ioSqringOffsets
	CqOff        ioCqringOffsets
}

type ioUringSQE struct {
	Opcode   uint8
	Flags    uint8
	Ioprio   uint16
	FD       int32
	Off      uint64
	Addr     uint64
	Len      uint32
	MsgFlags uint32
	UserData uint64
	Pad      [3]uint64
}

func dialBridgeUDPSocket(port int) (int, error) {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: 0}); err != nil {
		_ = unix.Close(s)
		return -1, err
	}
	if err := unix.Connect(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: port}); err != nil {
		_ = unix.Close(s)
		return -1, err
	}
	return s, nil
}

func copyFileExecutable(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

func submitSharedRingSQE(sqRing, sqeMem []byte, sqOff ioSqringOffsets, opcode, flags uint8, fd int32, addr uint64, length uint32, userData uint64) {
	tailPtr := (*uint32)(unsafe.Pointer(&sqRing[sqOff.Tail]))
	mask := *(*uint32)(unsafe.Pointer(&sqRing[sqOff.RingMask]))
	arrayBase := sqOff.Array
	tail := atomic.LoadUint32(tailPtr)
	idx := tail & mask

	sqes := unsafe.Slice((*ioUringSQE)(unsafe.Pointer(&sqeMem[0])), mask+1)
	sqes[idx] = ioUringSQE{
		Opcode:   opcode,
		Flags:    flags,
		FD:       fd,
		Addr:     addr,
		Len:      length,
		UserData: userData,
	}
	slotPtr := (*uint32)(unsafe.Pointer(&sqRing[arrayBase+idx*4]))
	atomic.StoreUint32(slotPtr, idx)
	atomic.StoreUint32(tailPtr, tail+1)
}

func TestIdentityChild(t *testing.T) {
	mode := os.Getenv("NS_IDENTITY_CHILD")
	if mode == "" {
		return
	}
	port, _ := strconv.Atoi(os.Getenv("NS_IDENTITY_PORT"))
	payload := os.Getenv("NS_IDENTITY_PAYLOAD")
	payload2 := os.Getenv("NS_IDENTITY_PAYLOAD2")

	switch mode {
	case "two_step_send":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(82)
		}
		fmt.Println("STEP1")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		if payload2 != "" {
			if _, err := unix.Write(s, []byte(payload2)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(83)
			}
		}
		_ = unix.Close(s)
		os.Exit(0)

	case "send_immediate_exit":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(84)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(85)
		}
		_ = unix.Close(s)
		os.Exit(0)

	case "flatpak_setup":
		if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
			fmt.Fprintln(os.Stderr, "ms_private:", err)
			os.Exit(86)
		}
		selfExe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(87)
		}
		targetExe := os.Getenv("NS_IDENTITY_TARGET_EXE")
		if err := copyFileExecutable(selfExe, targetExe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(88)
		}
		_ = os.Remove("/.flatpak-info")
		infoMode := os.Getenv("NS_IDENTITY_FLATPAK_MODE")
		switch infoMode {
		case "verified":
			content := "[Application]\nname=org.netswitch.i1flatpak\nruntime=org.freedesktop.Platform/x86_64/23.08\n"
			if err := os.WriteFile("/.flatpak-info", []byte(content), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(89)
			}
		case "symlink":
			fakeTarget := filepath.Join(os.TempDir(), "fake-flatpak-info")
			_ = os.WriteFile(fakeTarget, []byte("[Application]\nname=org.netswitch.spoof\n"), 0o644)
			if err := os.Symlink(fakeTarget, "/.flatpak-info"); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(90)
			}
		case "missing":
			// Leave /.flatpak-info absent while executing from /app/bin/*.
		}
		if err := os.Setenv("NS_IDENTITY_CHILD", "two_step_send"); err != nil {
			os.Exit(91)
		}
		if err := unix.Exec(targetExe, []string{targetExe, "-test.run=^TestIdentityChild$"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}

	case "snap_setup":
		_ = os.Remove("/.flatpak-info")
		if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(93)
		}
		snapRoot := "/snap/i1snap/42"
		if err := os.MkdirAll(snapRoot, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(94)
		}
		if err := unix.Mount("/var/lib/snapd/snaps/i1snap_42.snap", snapRoot, "tmpfs", 0, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(95)
		}
		selfExe, err := os.Executable()
		if err != nil {
			os.Exit(96)
		}
		targetExe := filepath.Join(snapRoot, "bin", "snap-sender")
		if err := copyFileExecutable(selfExe, targetExe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(97)
		}
		_ = os.Setenv("NS_IDENTITY_CHILD", "two_step_send")
		if err := unix.Exec(targetExe, []string{targetExe, "-test.run=^TestIdentityChild$"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(98)
		}

	case "appimage_setup":
		_ = os.Remove("/.flatpak-info")
		if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		appImgFile := os.Getenv("NS_IDENTITY_APPIMAGE_FILE")
		appDir := os.Getenv("NS_IDENTITY_APPDIR")
		if err := os.MkdirAll(appDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(100)
		}
		if err := unix.Mount(appImgFile, appDir, "tmpfs", 0, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(101)
		}
		selfExe, err := os.Executable()
		if err != nil {
			os.Exit(102)
		}
		targetExe := filepath.Join(appDir, "usr", "bin", "appimage-sender")
		if err := copyFileExecutable(selfExe, targetExe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(103)
		}
		_ = os.Setenv("APPIMAGE", appImgFile)
		_ = os.Setenv("APPDIR", appDir)
		_ = os.Setenv("NS_IDENTITY_CHILD", "two_step_send")
		if err := unix.Exec(targetExe, []string{targetExe, "-test.run=^TestIdentityChild$"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(104)
		}

	case "fork_no_exec":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(105)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(106)
		}
		fmt.Printf("PARENT_SENT pid=%d\n", os.Getpid())
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])

		r1, _, errno := unix.Syscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
		if errno != 0 {
			fmt.Fprintln(os.Stderr, "clone:", errno)
			os.Exit(107)
		}
		if r1 == 0 {
			if _, err := unix.Write(s, []byte(payload2)); err != nil {
				os.Exit(108)
			}
			time.Sleep(10 * time.Second)
			os.Exit(0)
		}
		childPID := int(r1)
		fmt.Printf("CHILD_FORKED pid=%d\n", childPID)
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Kill(childPID, unix.SIGKILL)
		var ws unix.WaitStatus
		_, _ = unix.Wait4(childPID, &ws, 0, nil)
		_ = unix.Close(s)
		os.Exit(0)

	case "exec_twice_gen1":
		s1, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(109)
		}
		if _, err := unix.Write(s1, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(110)
		}
		_ = unix.Close(s1)
		gen2Exe := os.Getenv("NS_IDENTITY_GEN2_EXE")
		_ = os.Setenv("NS_IDENTITY_CHILD", "exec_twice_gen2")
		if err := unix.Exec(gen2Exe, []string{gen2Exe, "-test.run=^TestIdentityChild$"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(111)
		}

	case "exec_twice_gen2":
		port2, _ := strconv.Atoi(os.Getenv("NS_IDENTITY_PORT2"))
		s2, err := dialBridgeUDPSocket(port2)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(112)
		}
		if _, err := unix.Write(s2, []byte(payload2)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(113)
		}
		fmt.Printf("GEN2_SENT pid=%d\n", os.Getpid())
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s2)
		os.Exit(0)

	case "unlink_and_replace":
		selfPath := os.Getenv("NS_IDENTITY_SELF_PATH")
		if err := os.Remove(selfPath); err != nil {
			fmt.Fprintln(os.Stderr, "remove self:", err)
			os.Exit(114)
		}
		if err := os.WriteFile(selfPath, []byte("replacement-binary-different-inode"), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "write replacement:", err)
			os.Exit(115)
		}
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(116)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(117)
		}
		fmt.Println("UNLINK_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "unshare_on_signal":
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(118)
		}
		if _, err := unix.Write(s, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(119)
		}
		fmt.Println("BEFORE_READY")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(120)
		}
		fmt.Println("AFTER_UNSHARE")
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(s)
		os.Exit(0)

	case "scm_creator":
		// fd 3 is AF_UNIX socketpair endpoint to pass the newly created UDP socket.
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(121)
		}
		rights := unix.UnixRights(s)
		if err := unix.Sendmsg(3, []byte("F"), rights, nil, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(122)
		}
		_ = unix.Close(s)
		os.Exit(0)

	case "scm_sender":
		// fd 3 is the inherited UDP socket passed via SCM_RIGHTS.
		if _, err := unix.Write(3, []byte(payload)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(123)
		}
		fmt.Println("SCM_SENT")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		_ = unix.Close(3)
		os.Exit(0)

	case "i2_ring_owner":
		shmPath := os.Getenv("NS_IDENTITY_SHM")
		peerBin := os.Getenv("NS_IDENTITY_PEER_BIN")
		useSQPoll := os.Getenv("NS_IDENTITY_SQPOLL") == "1"
		s, err := dialBridgeUDPSocket(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dial:", err)
			os.Exit(130)
		}
		if os.Getenv("NS_IDENTITY_PRE_SENDTO") == "1" {
			if _, err := unix.Write(s, []byte(os.Getenv("NS_IDENTITY_PRE_PAYLOAD"))); err != nil {
				fmt.Fprintln(os.Stderr, "pre-write:", err)
				os.Exit(131)
			}
			fmt.Println("PRE_SENDTO_DONE")
			var syncByte [1]byte
			_, _ = os.Stdin.Read(syncByte[:])
		}
		shmFD, err := unix.Open(shmPath, unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open shm:", err)
			os.Exit(132)
		}
		shmData, err := unix.Mmap(shmFD, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		_ = unix.Close(shmFD)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mmap shm:", err)
			os.Exit(133)
		}

		var params ioUringParams
		if useSQPoll {
			params.Flags = ioringSetupSQPoll
			params.SqThreadIdle = 5000
		}
		r1, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 8, uintptr(unsafe.Pointer(&params)), 0)
		if errno != 0 {
			fmt.Fprintln(os.Stderr, "io_uring_setup:", errno)
			os.Exit(134)
		}
		ringFD := int(r1)

		regFD := int32(s)
		_, _, errno = unix.Syscall6(unix.SYS_IO_URING_REGISTER, uintptr(ringFD), ioringRegisterFiles, uintptr(unsafe.Pointer(&regFD)), 1, 0, 0)
		if errno != 0 {
			fmt.Fprintln(os.Stderr, "io_uring_register files:", errno)
			os.Exit(135)
		}

		sqRingSize := int(params.SqOff.Array + params.SqEntries*4)
		sqRing, err := unix.Mmap(ringFD, ioringOffSqRing, sqRingSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mmap sqring:", err)
			os.Exit(136)
		}
		sqeSize := int(uintptr(params.SqEntries) * unsafe.Sizeof(ioUringSQE{}))
		sqeMem, err := unix.Mmap(ringFD, ioringOffSqes, sqeSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mmap sqes:", err)
			os.Exit(137)
		}

		baseAddr := uint64(uintptr(unsafe.Pointer(&shmData[0])))
		binary.LittleEndian.PutUint64(shmData[0:8], baseAddr)
		binary.LittleEndian.PutUint32(shmData[8:12], uint32(sqRingSize))
		binary.LittleEndian.PutUint32(shmData[12:16], uint32(sqeSize))
		*(*ioSqringOffsets)(unsafe.Pointer(&shmData[64])) = params.SqOff

		copy(shmData[256:], payload)
		sqeFlags := uint8(iosqeFixedFile)
		if !useSQPoll {
			sqeFlags |= iosqeAsync
		}
		submitSharedRingSQE(sqRing, sqeMem, params.SqOff, ioringOpSend, sqeFlags, 0, baseAddr+256, uint32(len(payload)), 1)
		if useSQPoll {
			_, _, errno = unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(ringFD), 0, 1, ioringEnterSqWakeup|ioringEnterGetEvents, 0, 0)
			if errno != 0 {
				fmt.Fprintln(os.Stderr, "io_uring_enter sqpoll app-a:", errno)
				os.Exit(138)
			}
		} else {
			_, _, errno = unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(ringFD), 1, 1, ioringEnterGetEvents, 0, 0)
			if errno != 0 {
				fmt.Fprintln(os.Stderr, "io_uring_enter app-a:", errno)
				os.Exit(138)
			}
		}

		// Spawn separate executable i2-app-b with inherited ringFD (fd 3); UDP socket s has SOCK_CLOEXEC so i2-app-b never receives s.
		ringFile := os.NewFile(uintptr(ringFD), "shared-ring")
		cmdPeer := exec.Command(peerBin, "-test.run=^TestIdentityChild$")
		cmdPeer.Env = append(os.Environ(),
			"NS_IDENTITY_CHILD=i2_ring_peer",
			"NS_IDENTITY_SHM="+shmPath,
			"NS_IDENTITY_SQPOLL="+os.Getenv("NS_IDENTITY_SQPOLL"),
			"NS_IDENTITY_PAYLOAD="+payload2,
		)
		cmdPeer.ExtraFiles = []*os.File{ringFile}
		cmdPeer.Stderr = os.Stderr
		if err := cmdPeer.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "run i2_ring_peer:", err)
			os.Exit(139)
		}

		// Drive and wait for completion of the second SQE enqueued by i2-app-b (cq.head is 0, so min_complete=2 waits for both CQEs).
		if useSQPoll {
			_, _, errno = unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(ringFD), 0, 2, ioringEnterSqWakeup|ioringEnterGetEvents, 0, 0)
			if errno != 0 {
				fmt.Fprintln(os.Stderr, "io_uring_enter sqpoll app-b:", errno)
				os.Exit(140)
			}
		} else {
			_, _, errno = unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(ringFD), 1, 2, ioringEnterGetEvents, 0, 0)
			if errno != 0 {
				fmt.Fprintln(os.Stderr, "io_uring_enter app-b:", errno)
				os.Exit(140)
			}
		}
		fmt.Println("RING_READY")
		var step [1]byte
		_, _ = os.Stdin.Read(step[:])
		_ = ringFile.Name()
		os.Exit(0)

	case "i2_ring_peer":
		// fd 3 is the inherited shared ringFD; this process never touches the UDP socket fd directly.
		ringFD := 3
		shmPath := os.Getenv("NS_IDENTITY_SHM")
		useSQPoll := os.Getenv("NS_IDENTITY_SQPOLL") == "1"
		shmFD, err := unix.Open(shmPath, unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "peer open shm:", err)
			os.Exit(141)
		}
		shmData, err := unix.Mmap(shmFD, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		_ = unix.Close(shmFD)
		if err != nil {
			fmt.Fprintln(os.Stderr, "peer mmap shm:", err)
			os.Exit(142)
		}
		baseAddr := binary.LittleEndian.Uint64(shmData[0:8])
		sqRingSize := int(binary.LittleEndian.Uint32(shmData[8:12]))
		sqeSize := int(binary.LittleEndian.Uint32(shmData[12:16]))
		sqOff := *(*ioSqringOffsets)(unsafe.Pointer(&shmData[64]))

		sqRing, err := unix.Mmap(ringFD, ioringOffSqRing, sqRingSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			fmt.Fprintln(os.Stderr, "peer mmap sqring:", err)
			os.Exit(143)
		}
		sqeMem, err := unix.Mmap(ringFD, ioringOffSqes, sqeSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			fmt.Fprintln(os.Stderr, "peer mmap sqes:", err)
			os.Exit(144)
		}
		copy(shmData[512:], payload)
		sqeFlags := uint8(iosqeFixedFile)
		if !useSQPoll {
			sqeFlags |= iosqeAsync
		}
		submitSharedRingSQE(sqRing, sqeMem, sqOff, ioringOpSend, sqeFlags, 0, baseAddr+512, uint32(len(payload)), 2)
		os.Exit(0)
	}
}

type identityFixture struct {
	bf        *bridgeFixture
	probe     *Probe
	cgroupDir string
}

func newIdentityFixture(t *testing.T) *identityFixture {
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
	cgDir, err := os.MkdirTemp("/sys/fs/cgroup", "ns-owner-id-")
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
	bf := newBridgeFixture(t, false)
	probeObj := os.Getenv("NS_OWNERBPF_OBJECT")
	if probeObj == "" {
		t.Fatal("NS_OWNERBPF_OBJECT required")
	}
	probe, err := Load(probeObj, cgDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := probe.Close(); err != nil {
			t.Error(err)
		}
	})
	return &identityFixture{
		bf:        bf,
		probe:     probe,
		cgroupDir: cgDir,
	}
}

func (f *identityFixture) snapshotActors(t *testing.T) map[ActorKey]ActorEvidence {
	t.Helper()
	out := make(map[ActorKey]ActorEvidence)
	it := f.probe.Collection.Maps["actors"].Iterate()
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

func (f *identityFixture) syncLedger(t *testing.T, ledger *IdentityLedger, processed map[ActorKey]bool) map[ActorKey]ActorEvidence {
	t.Helper()
	actors := f.snapshotActors(t)
	ledger.SyncActorRecords(actors, processed)
	return actors
}

func (f *identityFixture) readUDPSet(t *testing.T, wantPort int, wantPayloads ...string) map[string]ReadDecision {
	t.Helper()
	want := make(map[string]bool, len(wantPayloads))
	for _, p := range wantPayloads {
		want[p] = true
	}
	got := make(map[string]ReadDecision, len(wantPayloads))
	deadline := time.Now().Add(8 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		frames, err := f.bf.r.ReadBurst(f.bf.fd, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) == 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		frame := frames[0]
		raw := frame.Data
		if len(raw) >= 28 && raw[0]>>4 == 4 && raw[9] == 17 {
			dstPort := int(binary.BigEndian.Uint16(raw[22:24]))
			payload := string(raw[28:])
			if dstPort == wantPort && want[payload] {
				got[payload] = frame.Decision
			}
		}
	}
	if len(got) < len(want) {
		t.Fatalf("timed out waiting for UDP payloads on port %d: got=%v want=%v", wantPort, got, wantPayloads)
	}
	return got
}

func (f *identityFixture) readUDPByPayload(t *testing.T, wantPayload string, wantPort int) ReadDecision {
	t.Helper()
	return f.readUDPSet(t, wantPort, wantPayload)[wantPayload]
}

func waitLine(t *testing.T, r *bufio.Reader, prefix string) string {
	t.Helper()
	type lineResult struct {
		line string
		err  error
	}
	ch := make(chan lineResult, 1)
	go func() {
		s, err := r.ReadString('\n')
		ch <- lineResult{line: strings.TrimSpace(s), err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("waiting for %q: %v (line=%q)", prefix, res.err, res.line)
		}
		if !strings.HasPrefix(res.line, prefix) {
			t.Fatalf("unexpected child line %q, want prefix %q", res.line, prefix)
		}
		return res.line
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for child line prefix %q", prefix)
		return ""
	}
}

func receiveFDFromSocket(t *testing.T, sockFD int) int {
	t.Helper()
	if err := unix.SetNonblock(sockFD, false); err != nil {
		t.Fatal(err)
	}
	_ = unix.SetsockoptTimeval(sockFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10})
	buf := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		t.Fatalf("recvmsg fd: %v", err)
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) == 0 {
		t.Fatalf("parse scm: %v (len=%d)", err, len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) == 0 {
		t.Fatalf("parse rights: %v", err)
	}
	return fds[0]
}

func TestIdentityI1(t *testing.T) {
	f := newIdentityFixture(t)
	ledger := NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	processed := make(map[ActorKey]bool)
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	_ = os.Chmod(filepath.Dir(tmpDir), 0o755)
	_ = os.Chmod(tmpDir, 0o755)

	// 1. Cold unique native executable enriched while live, followed by warm retained exit.
	nativeBin := filepath.Join(tmpDir, "cold-native-app")
	if err := copyFileExecutable(selfExe, nativeBin); err != nil {
		t.Fatal(err)
	}
	cmd1 := exec.Command(nativeBin, "-test.run=^TestIdentityChild$")
	cmd1.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=two_step_send",
		"NS_IDENTITY_PORT=41001",
		"NS_IDENTITY_PAYLOAD=i1-native-live",
		"NS_IDENTITY_PAYLOAD2=i1-native-after-exit",
	)
	stdin1, err := cmd1.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout1, err := cmd1.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd1.Stderr = os.Stderr
	if err := cmd1.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd1.Process != nil {
			_ = cmd1.Process.Kill()
			_ = cmd1.Wait()
		}
	})
	reader1 := bufio.NewReader(stdout1)
	waitLine(t, reader1, "STEP1")

	f.syncLedger(t, ledger, processed)
	rdec1 := f.readUDPByPayload(t, "i1-native-live", 41001)
	idec1 := ledger.ResolvePacket(rdec1)
	if idec1.Status != IdentityKnown || idec1.Reason != ReasonValidated || idec1.Snapshot == nil {
		t.Fatalf("cold native live decision = %+v", idec1)
	}
	wantNativePath := strings.ToLower(nativeBin)
	if idec1.Snapshot.Path != wantNativePath || idec1.Snapshot.AppID != wantNativePath || idec1.Snapshot.Sandbox != SandboxNone {
		t.Fatalf("cold native identity mismatch: path=%q app=%q sandbox=%q want=%q", idec1.Snapshot.Path, idec1.Snapshot.AppID, idec1.Snapshot.Sandbox, wantNativePath)
	}
	ledger.ReleasePacket(idec1.Snapshot)

	// Let child send second packet and exit completely before reading packet 2.
	_ = stdin1.Close()
	if err := cmd1.Wait(); err != nil {
		t.Fatalf("cold native wait: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join("/proc", strconv.Itoa(cmd1.Process.Pid))); !os.IsNotExist(statErr) {
		t.Fatalf("expected /proc/%d to be gone after exit, err=%v", cmd1.Process.Pid, statErr)
	}
	f.syncLedger(t, ledger, processed)
	rdec2 := f.readUDPByPayload(t, "i1-native-after-exit", 41001)
	idec2 := ledger.ResolvePacket(rdec2)
	if idec2.Status != IdentityKnown || idec2.Snapshot == nil || idec2.Snapshot.Path != wantNativePath || idec2.Snapshot.AppID != wantNativePath {
		t.Fatalf("warm retained after exit decision = %+v", idec2)
	}
	ledger.ReleasePacket(idec2.Snapshot)
	t.Logf("I1_COLD_AND_WARM pid=%d path=%s app_id=%s cookie=%d", cmd1.Process.Pid, idec2.Snapshot.Path, idec2.Snapshot.AppID, idec2.Cookie)

	// 2. Sandbox proofs: verified Flatpak, missing .flatpak-info on /app/bin, symlink .flatpak-info, verified Snap, verified Registered AppImage, spoofed APPIMAGE=.
	runSandboxCase := func(childMode string, port int, payload string, extraEnv ...string) PacketIdentityDecision {
		t.Helper()
		c := exec.Command(selfExe, "-test.run=^TestIdentityChild$")
		c.Env = append(os.Environ(),
			"NS_IDENTITY_CHILD="+childMode,
			"NS_IDENTITY_PORT="+strconv.Itoa(port),
			"NS_IDENTITY_PAYLOAD="+payload,
		)
		c.Env = append(c.Env, extraEnv...)
		c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
		inPipe, err := c.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		outPipe, err := c.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = inPipe.Close()
			_ = c.Wait()
			_ = os.Remove("/.flatpak-info")
		}()
		waitLine(t, bufio.NewReader(outPipe), "STEP1")
		f.syncLedger(t, ledger, processed)
		rd := f.readUDPByPayload(t, payload, port)
		id := ledger.ResolvePacket(rd)
		if id.Snapshot != nil {
			defer ledger.ReleasePacket(id.Snapshot)
		}
		return id
	}

	fpVerified := runSandboxCase("flatpak_setup", 41002, "i1-flatpak-ok",
		"NS_IDENTITY_TARGET_EXE=/app/bin/flatpak-sender",
		"NS_IDENTITY_FLATPAK_MODE=verified",
	)
	if fpVerified.Status != IdentityKnown || fpVerified.Snapshot == nil ||
		fpVerified.Snapshot.Sandbox != SandboxFlatpak ||
		fpVerified.Snapshot.Path != "/app/bin/flatpak-sender" ||
		fpVerified.Snapshot.AppID != "flatpak:org.netswitch.i1flatpak" {
		t.Fatalf("verified flatpak decision = %+v, snap=%+v", fpVerified, fpVerified.Snapshot)
	}

	fpMissing := runSandboxCase("flatpak_setup", 41002, "i1-flatpak-missing",
		"NS_IDENTITY_TARGET_EXE=/app/bin/unverified-sender",
		"NS_IDENTITY_FLATPAK_MODE=missing",
	)
	if fpMissing.Status != IdentityUnknown || fpMissing.Reason != ReasonSandboxUnverified {
		t.Fatalf("unverified /app/bin without .flatpak-info must be rejected: %+v", fpMissing)
	}

	fpSymlink := runSandboxCase("flatpak_setup", 41002, "i1-flatpak-symlink",
		"NS_IDENTITY_TARGET_EXE=/app/bin/symlink-sender",
		"NS_IDENTITY_FLATPAK_MODE=symlink",
	)
	if fpSymlink.Status != IdentityUnknown || fpSymlink.Reason != ReasonSandboxUnverified {
		t.Fatalf("symlink .flatpak-info must be rejected: %+v", fpSymlink)
	}

	snapVerified := runSandboxCase("snap_setup", 41002, "i1-snap-ok")
	if snapVerified.Status != IdentityKnown || snapVerified.Snapshot == nil ||
		snapVerified.Snapshot.Sandbox != SandboxSnap ||
		snapVerified.Snapshot.Path != "i1snap" ||
		snapVerified.Snapshot.AppID != "snap:i1snap" {
		t.Fatalf("verified snap decision = %+v, snap=%+v", snapVerified, snapVerified.Snapshot)
	}

	appImgFile := filepath.Join(tmpDir, "I1Registered.AppImage")
	if err := os.WriteFile(appImgFile, []byte("ELF-AppImage-Payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(tmpDir, ".mount_i1registered")
	appImgVerified := runSandboxCase("appimage_setup", 41002, "i1-appimage-ok",
		"NS_IDENTITY_APPIMAGE_FILE="+appImgFile,
		"NS_IDENTITY_APPDIR="+appDir,
	)
	wantAppImgPath := strings.ToLower(appImgFile)
	if appImgVerified.Status != IdentityKnown || appImgVerified.Snapshot == nil ||
		appImgVerified.Snapshot.Sandbox != SandboxAppImage ||
		appImgVerified.Snapshot.Path != wantAppImgPath ||
		appImgVerified.Snapshot.AppID != "appimage:i1registered" {
		t.Fatalf("verified appimage decision = %+v, snap=%+v", appImgVerified, appImgVerified.Snapshot)
	}

	// Spoofed APPIMAGE= pointing to the real regular file while running an ordinary binary outside the mount.
	spoofBin := filepath.Join(tmpDir, "spoof-appimage-bin")
	if err := copyFileExecutable(selfExe, spoofBin); err != nil {
		t.Fatal(err)
	}
	appImgSpoof := runSandboxCase("two_step_send", 41002, "i1-appimage-spoof",
		"APPIMAGE="+appImgFile,
		"APPDIR="+tmpDir,
	)
	if appImgSpoof.Status != IdentityUnknown || appImgSpoof.Reason != ReasonSandboxUnverified {
		t.Fatalf("spoofed APPIMAGE env without registered AppImage mount must fail: %+v", appImgSpoof)
	}
	t.Logf("I1_SANDBOX flatpak=%s snap=%s appimage=%s spoof_rejected=%s",
		fpVerified.Snapshot.AppID, snapVerified.Snapshot.AppID, appImgVerified.Snapshot.AppID, appImgSpoof.Reason)

	// 3. Cold immediate exit while enrichment is paused -> identity_unretained (never known from inode/device alone).
	unretainedBin := filepath.Join(tmpDir, "cold-unretained-app")
	if err := copyFileExecutable(selfExe, unretainedBin); err != nil {
		t.Fatal(err)
	}
	cmdUnretained := exec.Command(unretainedBin, "-test.run=^TestIdentityChild$")
	cmdUnretained.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=send_immediate_exit",
		"NS_IDENTITY_PORT=41003",
		"NS_IDENTITY_PAYLOAD=i1-cold-unretained",
	)
	cmdUnretained.Stderr = os.Stderr
	if err := cmdUnretained.Run(); err != nil {
		t.Fatalf("cold unretained run: %v", err)
	}
	// Enrichment runs only after the cold unseen process has already exited.
	f.syncLedger(t, ledger, processed)
	rdecUnretained := f.readUDPByPayload(t, "i1-cold-unretained", 41003)
	idecUnretained := ledger.ResolvePacket(rdecUnretained)
	if idecUnretained.Status != IdentityUnknown || idecUnretained.Reason != ReasonIdentityUnretained {
		t.Fatalf("cold unretained decision = %+v, want unknown/identity_unretained", idecUnretained)
	}
	t.Logf("I1_COLD_UNRETAINED pid=%d status=%s reason=%s", cmdUnretained.Process.Pid, idecUnretained.Status, idecUnretained.Reason)

	// 4. Fork without exec inherits parent validated identity on the shared socket without conflict.
	forkBin := filepath.Join(tmpDir, "fork-parent-app")
	if err := copyFileExecutable(selfExe, forkBin); err != nil {
		t.Fatal(err)
	}
	cmdFork := exec.Command(forkBin, "-test.run=^TestIdentityChild$")
	cmdFork.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=fork_no_exec",
		"NS_IDENTITY_PORT=41004",
		"NS_IDENTITY_PAYLOAD=i1-fork-parent",
		"NS_IDENTITY_PAYLOAD2=i1-fork-child",
	)
	forkIn, err := cmdFork.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	forkOut, err := cmdFork.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdFork.Stderr = os.Stderr
	if err := cmdFork.Start(); err != nil {
		t.Fatal(err)
	}
	forkReader := bufio.NewReader(forkOut)
	waitLine(t, forkReader, "PARENT_SENT")
	f.syncLedger(t, ledger, processed)
	rdecParent := f.readUDPByPayload(t, "i1-fork-parent", 41004)
	idecParent := ledger.ResolvePacket(rdecParent)
	if idecParent.Status != IdentityKnown || idecParent.Snapshot == nil {
		t.Fatalf("fork parent decision = %+v", idecParent)
	}
	parentActorKey := idecParent.Snapshot.Key
	ledger.ReleasePacket(idecParent.Snapshot)

	// Trigger clone(SIGCHLD) without exec in child.
	_, _ = forkIn.Write([]byte("G"))
	childLine := waitLine(t, forkReader, "CHILD_FORKED")
	var forkedPID int
	if _, err := fmt.Sscanf(childLine, "CHILD_FORKED pid=%d", &forkedPID); err != nil || forkedPID <= 0 {
		t.Fatalf("parse forked pid from %q: %v", childLine, err)
	}
	rdecChild := f.readUDPByPayload(t, "i1-fork-child", 41004)
	recAfterFork := f.snapshotActors(t)
	var foundChildKey ActorKey
	var foundChildEv ActorEvidence
	for k, ev := range recAfterFork {
		if k.TGID == uint32(forkedPID) && k.Cookie == rdecParent.Packet.Cookie {
			foundChildKey = k
			foundChildEv = ev
			processed[k] = true
			break
		}
	}
	if foundChildKey.TGID == 0 {
		t.Fatalf("missing BPF actor record for forked child pid=%d on cookie=%d", forkedPID, rdecParent.Packet.Cookie)
	}
	childCtx, _, err := SampleExecutionContext(foundChildKey.TGID, foundChildKey.Start, foundChildKey.Exec)
	if err != nil {
		t.Fatalf("SampleExecutionContext forked child: %v", err)
	}
	if _, reason := ledger.InheritFork(parentActorKey, foundChildKey, foundChildEv, childCtx); reason != ReasonInheritedValidated {
		t.Fatalf("InheritFork reason = %s, want %s", reason, ReasonInheritedValidated)
	}
	idecChild := ledger.ResolvePacket(rdecChild)
	if idecChild.Status != IdentityKnown || idecChild.Conflicts != 0 || idecChild.Snapshot == nil ||
		idecChild.Snapshot.AppID != strings.ToLower(forkBin) {
		t.Fatalf("fork child packet decision = %+v", idecChild)
	}
	ledger.ReleasePacket(idecChild.Snapshot)
	_, _ = forkIn.Write([]byte("X"))
	_ = forkIn.Close()
	_ = cmdFork.Wait()
	t.Logf("I1_FORK_INHERIT parent_pid=%d child_pid=%d app_id=%s conflicts=%d",
		parentActorKey.TGID, forkedPID, idecChild.Snapshot.AppID, idecChild.Conflicts)

	// 5. Exec twice under one PID while enrichment is paused: gen1 rejected as context_changed, gen2 validated.
	gen1Bin := filepath.Join(tmpDir, "exec-gen1-app")
	gen2Bin := filepath.Join(tmpDir, "exec-gen2-app")
	if err := copyFileExecutable(selfExe, gen1Bin); err != nil {
		t.Fatal(err)
	}
	if err := copyFileExecutable(selfExe, gen2Bin); err != nil {
		t.Fatal(err)
	}
	cmdExec2 := exec.Command(gen1Bin, "-test.run=^TestIdentityChild$")
	cmdExec2.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=exec_twice_gen1",
		"NS_IDENTITY_PORT=41005",
		"NS_IDENTITY_PORT2=41006",
		"NS_IDENTITY_PAYLOAD=i1-exec-gen1",
		"NS_IDENTITY_PAYLOAD2=i1-exec-gen2",
		"NS_IDENTITY_GEN2_EXE="+gen2Bin,
	)
	execIn, err := cmdExec2.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	execOut, err := cmdExec2.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdExec2.Stderr = os.Stderr
	if err := cmdExec2.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(execOut), "GEN2_SENT")
	f.syncLedger(t, ledger, processed)
	rdecGen1 := f.readUDPByPayload(t, "i1-exec-gen1", 41005)
	idecGen1 := ledger.ResolvePacket(rdecGen1)
	if idecGen1.Status != IdentityUnknown || idecGen1.Reason != ReasonContextChanged {
		t.Fatalf("superseded exec gen1 must be rejected as context_changed, got %+v", idecGen1)
	}
	rdecGen2 := f.readUDPByPayload(t, "i1-exec-gen2", 41006)
	idecGen2 := ledger.ResolvePacket(rdecGen2)
	wantGen2 := strings.ToLower(gen2Bin)
	if idecGen2.Status != IdentityKnown || idecGen2.Snapshot == nil ||
		idecGen2.Snapshot.Path != wantGen2 || idecGen2.Snapshot.AppID != wantGen2 {
		t.Fatalf("current exec gen2 decision = %+v, want %q", idecGen2, wantGen2)
	}
	ledger.ReleasePacket(idecGen2.Snapshot)
	_ = execIn.Close()
	_ = cmdExec2.Wait()
	t.Logf("I1_EXEC_TWICE pid=%d gen1_reason=%s gen2_app=%s", cmdExec2.Process.Pid, idecGen1.Reason, idecGen2.Snapshot.AppID)

	// 6. Unlink and replace executable at same path (inode reuse / replacement does not alias).
	unlinkBin := filepath.Join(tmpDir, "unlink-target-app")
	if err := copyFileExecutable(selfExe, unlinkBin); err != nil {
		t.Fatal(err)
	}
	var origSt unix.Stat_t
	if err := unix.Stat(unlinkBin, &origSt); err != nil {
		t.Fatal(err)
	}
	cmdUnlink := exec.Command(unlinkBin, "-test.run=^TestIdentityChild$")
	cmdUnlink.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=unlink_and_replace",
		"NS_IDENTITY_PORT=41007",
		"NS_IDENTITY_PAYLOAD=i1-unlinked-exe",
		"NS_IDENTITY_SELF_PATH="+unlinkBin,
	)
	unlinkIn, err := cmdUnlink.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	unlinkOut, err := cmdUnlink.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdUnlink.Stderr = os.Stderr
	if err := cmdUnlink.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(unlinkOut), "UNLINK_SENT")
	var replacedSt unix.Stat_t
	if err := unix.Stat(unlinkBin, &replacedSt); err != nil || replacedSt.Ino == origSt.Ino {
		t.Fatalf("expected replacement file with distinct inode: err=%v orig=%d new=%d", err, origSt.Ino, replacedSt.Ino)
	}
	f.syncLedger(t, ledger, processed)
	rdecUnlink := f.readUDPByPayload(t, "i1-unlinked-exe", 41007)
	idecUnlink := ledger.ResolvePacket(rdecUnlink)
	if idecUnlink.Status != IdentityKnown || idecUnlink.Snapshot == nil ||
		!idecUnlink.Snapshot.ExeDeleted || idecUnlink.Snapshot.Context.ExeIno != origSt.Ino {
		t.Fatalf("unlink/replace decision = %+v, snap=%+v, want origIno=%d", idecUnlink, idecUnlink.Snapshot, origSt.Ino)
	}
	ledger.ReleasePacket(idecUnlink.Snapshot)
	_ = unlinkIn.Close()
	_ = cmdUnlink.Wait()
	t.Logf("I1_UNLINK_REPLACE pid=%d exe_deleted=%t orig_ino=%d replacement_ino=%d",
		cmdUnlink.Process.Pid, idecUnlink.Snapshot.ExeDeleted, origSt.Ino, replacedSt.Ino)

	// 7. Namespace change (unshare CLONE_NEWNS) between before and after context samples rejected.
	nsBin := filepath.Join(tmpDir, "ns-change-app")
	if err := copyFileExecutable(selfExe, nsBin); err != nil {
		t.Fatal(err)
	}
	cmdNS := exec.Command(nsBin, "-test.run=^TestIdentityChild$")
	cmdNS.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=unshare_on_signal",
		"NS_IDENTITY_PORT=41008",
		"NS_IDENTITY_PAYLOAD=i1-ns-change",
	)
	nsIn, err := cmdNS.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	nsOut, err := cmdNS.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdNS.Stderr = os.Stderr
	if err := cmdNS.Start(); err != nil {
		t.Fatal(err)
	}
	nsReader := bufio.NewReader(nsOut)
	waitLine(t, nsReader, "BEFORE_READY")
	recNS := f.snapshotActors(t)
	var nsKey ActorKey
	var nsEv ActorEvidence
	for k, ev := range recNS {
		if k.TGID == uint32(cmdNS.Process.Pid) {
			nsKey = k
			nsEv = ev
			processed[k] = true
			break
		}
	}
	if nsKey.TGID == 0 {
		t.Fatalf("missing actor key for ns-change child pid=%d", cmdNS.Process.Pid)
	}
	beforeNSCtx, nsMounts, err := SampleExecutionContext(nsKey.TGID, nsKey.Start, nsKey.Exec)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = nsIn.Write([]byte("U"))
	waitLine(t, nsReader, "AFTER_UNSHARE")
	afterNSCtx, _, err := SampleExecutionContext(nsKey.TGID, nsKey.Start, nsKey.Exec)
	if err != nil {
		t.Fatal(err)
	}
	if beforeNSCtx.MntNSInum == afterNSCtx.MntNSInum {
		t.Fatalf("expected MntNSInum to change across unshare(CLONE_NEWNS): %d", beforeNSCtx.MntNSInum)
	}
	ledger.EnrichActor(nsKey, nsEv, RawProcessMaterial{
		Before:  beforeNSCtx,
		After:   afterNSCtx,
		ExePath: nsBin,
		Mounts:  nsMounts,
	})
	rdecNS := f.readUDPByPayload(t, "i1-ns-change", 41008)
	idecNS := ledger.ResolvePacket(rdecNS)
	if idecNS.Status != IdentityUnknown || idecNS.Reason != ReasonContextChanged {
		t.Fatalf("namespace change between samples must be rejected: %+v", idecNS)
	}
	_ = nsIn.Close()
	_ = cmdNS.Wait()
	t.Logf("I1_CONTEXT_CHANGE pid=%d mnt_before=%d mnt_after=%d reason=%s",
		cmdNS.Process.Pid, beforeNSCtx.MntNSInum, afterNSCtx.MntNSInum, idecNS.Reason)

	// 8. Cross-UID SCM_RIGHTS: creator (UID 1001) passes socket to sender (UID 1002), then conflicting app (UID 1003) sends on same socket.
	creatorBin := filepath.Join(tmpDir, "scm-creator-uid1001")
	senderBin := filepath.Join(tmpDir, "scm-sender-uid1002")
	conflictBin := filepath.Join(tmpDir, "scm-sender-uid1003")
	for _, dst := range []string{creatorBin, senderBin, conflictBin} {
		if err := copyFileExecutable(selfExe, dst); err != nil {
			t.Fatal(err)
		}
	}
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(sp[0])
		_ = unix.Close(sp[1])
	})
	passFile := os.NewFile(uintptr(sp[1]), "scm-pass")
	cmdCreator := exec.Command(creatorBin, "-test.run=^TestIdentityChild$")
	cmdCreator.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=scm_creator",
		"NS_IDENTITY_PORT=41009",
	)
	cmdCreator.ExtraFiles = []*os.File{passFile}
	cmdCreator.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 1001, Gid: 1001},
	}
	cmdCreator.Stderr = os.Stderr
	if err := cmdCreator.Run(); err != nil {
		t.Fatalf("scm creator (uid 1001): %v", err)
	}
	_ = passFile.Close()
	sp[1] = -1

	sharedSockFD := receiveFDFromSocket(t, sp[0])
	sharedSockFile := os.NewFile(uintptr(sharedSockFD), "shared-udp")
	t.Cleanup(func() { _ = sharedSockFile.Close() })

	// UID 1002 sends first packet on the socket created by UID 1001.
	cmdSender1 := exec.Command(senderBin, "-test.run=^TestIdentityChild$")
	cmdSender1.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=scm_sender",
		"NS_IDENTITY_PAYLOAD=i1-scm-uid1002",
	)
	cmdSender1.ExtraFiles = []*os.File{sharedSockFile}
	cmdSender1.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 1002, Gid: 1002},
	}
	s1In, err := cmdSender1.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	s1Out, err := cmdSender1.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdSender1.Stderr = os.Stderr
	if err := cmdSender1.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(s1Out), "SCM_SENT")
	f.syncLedger(t, ledger, processed)
	rdecSCM1 := f.readUDPByPayload(t, "i1-scm-uid1002", 41009)
	idecSCM1 := ledger.ResolvePacket(rdecSCM1)
	wantSenderPath := strings.ToLower(senderBin)
	if idecSCM1.Status != IdentityKnown || idecSCM1.Snapshot == nil ||
		idecSCM1.Snapshot.Context.UID != 1002 ||
		idecSCM1.Snapshot.Path != wantSenderPath || idecSCM1.Snapshot.AppID != wantSenderPath {
		t.Fatalf("cross-UID SCM_RIGHTS first sender decision = %+v, snap=%+v", idecSCM1, idecSCM1.Snapshot)
	}
	ledger.ReleasePacket(idecSCM1.Snapshot)
	_ = s1In.Close()
	_ = cmdSender1.Wait()

	// UID 1003 (distinct app binary) sends second packet on the same socket cookie -> sticky conflicting_identity.
	cmdSender2 := exec.Command(conflictBin, "-test.run=^TestIdentityChild$")
	cmdSender2.Env = append(os.Environ(),
		"NS_IDENTITY_CHILD=scm_sender",
		"NS_IDENTITY_PAYLOAD=i1-scm-uid1003",
	)
	cmdSender2.ExtraFiles = []*os.File{sharedSockFile}
	cmdSender2.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 1003, Gid: 1003},
	}
	s2In, err := cmdSender2.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	s2Out, err := cmdSender2.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmdSender2.Stderr = os.Stderr
	if err := cmdSender2.Start(); err != nil {
		t.Fatal(err)
	}
	waitLine(t, bufio.NewReader(s2Out), "SCM_SENT")
	f.syncLedger(t, ledger, processed)
	rdecSCM2 := f.readUDPByPayload(t, "i1-scm-uid1003", 41009)
	idecSCM2 := ledger.ResolvePacket(rdecSCM2)
	if idecSCM2.Status != IdentityConflicting || idecSCM2.Reason != ReasonConflictingApp || idecSCM2.Conflicts == 0 {
		t.Fatalf("cross-UID second app on shared socket must be conflicting: %+v", idecSCM2)
	}
	_ = s2In.Close()
	_ = cmdSender2.Wait()
	t.Logf("I1_SCM_RIGHTS creator_uid=1001 sender1_uid=%d sender1_app=%s sender2_status=%s conflicts=%d",
		idecSCM1.Snapshot.Context.UID, idecSCM1.Snapshot.AppID, idecSCM2.Status, idecSCM2.Conflicts)
}

func TestIdentityI2(t *testing.T) {
	f := newIdentityFixture(t)
	ledger := NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	processed := make(map[ActorKey]bool)
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	_ = os.Chmod(filepath.Dir(tmpDir), 0o755)
	_ = os.Chmod(tmpDir, 0o755)
	appABin := filepath.Join(tmpDir, "i2-app-a")
	appBBin := filepath.Join(tmpDir, "i2-app-b")
	if err := copyFileExecutable(selfExe, appABin); err != nil {
		t.Fatal(err)
	}
	if err := copyFileExecutable(selfExe, appBBin); err != nil {
		t.Fatal(err)
	}

	runSharedRingCase := func(sqpoll bool, preSendto bool, port int, prePayload, payloadA, payloadB string) {
		t.Helper()
		shmPath := filepath.Join(tmpDir, fmt.Sprintf("i2-shm-%d", port))
		if err := os.WriteFile(shmPath, make([]byte, 4096), 0o600); err != nil {
			t.Fatal(err)
		}

		sqpollVal := "0"
		if sqpoll {
			sqpollVal = "1"
		}
		preVal := "0"
		if preSendto {
			preVal = "1"
		}

		cmdA := exec.Command(appABin, "-test.run=^TestIdentityChild$")
		cmdA.Env = append(os.Environ(),
			"NS_IDENTITY_CHILD=i2_ring_owner",
			"NS_IDENTITY_PEER_BIN="+appBBin,
			"NS_IDENTITY_PORT="+strconv.Itoa(port),
			"NS_IDENTITY_SHM="+shmPath,
			"NS_IDENTITY_SQPOLL="+sqpollVal,
			"NS_IDENTITY_PRE_SENDTO="+preVal,
			"NS_IDENTITY_PRE_PAYLOAD="+prePayload,
			"NS_IDENTITY_PAYLOAD="+payloadA,
			"NS_IDENTITY_PAYLOAD2="+payloadB,
		)
		inA, err := cmdA.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		outA, err := cmdA.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmdA.Stderr = os.Stderr
		if err := cmdA.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = inA.Close()
			if cmdA.Process != nil {
				_ = cmdA.Process.Kill()
				_ = cmdA.Wait()
			}
		}()
		readerA := bufio.NewReader(outA)

		if preSendto {
			waitLine(t, readerA, "PRE_SENDTO_DONE")
			// Enrich while i2-app-a has NOT yet created an io_uring fd, establishing a prior known owner.
			f.syncLedger(t, ledger, processed)
			rdecPre := f.readUDPByPayload(t, prePayload, port)
			idecPre := ledger.ResolvePacket(rdecPre)
			if idecPre.Status != IdentityKnown || idecPre.Snapshot == nil || idecPre.Snapshot.AppID != strings.ToLower(appABin) {
				t.Fatalf("expected prior clean sendto owner %q, got %+v", strings.ToLower(appABin), idecPre)
			}
			ledger.ReleasePacket(idecPre.Snapshot)
			_, _ = io.WriteString(inA, "C")
		}

		waitLine(t, readerA, "RING_READY")

		rdecs := f.readUDPSet(t, port, payloadA, payloadB)
		rdecA := rdecs[payloadA]
		rdecB := rdecs[payloadB]
		if rdecA.Packet.Cookie == 0 || rdecA.Packet.Cookie != rdecB.Packet.Cookie {
			t.Fatalf("expected identical non-zero socket cookie on shared ring sends: a=%d b=%d", rdecA.Packet.Cookie, rdecB.Packet.Cookie)
		}

		// Synchronize actor records; if the kernel worker thread was outside the leaf cgroup
		// or the ring creator now holds an active io_uring submitter, record the unobservable submitter.
		f.syncLedger(t, ledger, processed)
		if HasAsyncSubmitter(uint32(cmdA.Process.Pid)) {
			ledger.ObserveUnobservableSubmitter(rdecA.Packet.Cookie)
		}

		idecA := ledger.ResolvePacket(rdecA)
		idecB := ledger.ResolvePacket(rdecB)
		if idecA.Status != IdentityUnknown || idecA.Reason != ReasonSubmitterUnobservable {
			t.Fatalf("shared io_uring packet A must be unknown/submitter_unobservable (never credited to %s): %+v", appABin, idecA)
		}
		if idecB.Status != IdentityUnknown || idecB.Reason != ReasonSubmitterUnobservable {
			t.Fatalf("shared io_uring packet B must be unknown/submitter_unobservable (never credited to %s): %+v", appABin, idecB)
		}
		t.Logf("I2_SHARED_RING sqpoll=%t pre_sendto=%t cookie=%d pktA_reason=%s pktB_reason=%s",
			sqpoll, preSendto, rdecA.Packet.Cookie, idecA.Reason, idecB.Reason)
	}

	// 1. Shared IORING_SETUP_SQPOLL ring between i2-app-a and i2-app-b.
	runSharedRingCase(true, false, 42001, "", "i2-sqpoll-app-a", "i2-sqpoll-app-b")

	// 2. Shared non-SQPOLL ring with IOSQE_ASYNC (io-wq worker execution) between i2-app-a and i2-app-b.
	runSharedRingCase(false, false, 42002, "", "i2-iowq-app-a", "i2-iowq-app-b")

	// 3. Prior known UDP owner invalidated when shared SQPOLL submitter contributes to the same socket generation.
	runSharedRingCase(true, true, 42003, "i2-prior-clean", "i2-Invalidate-A", "i2-Invalidate-B")
}
