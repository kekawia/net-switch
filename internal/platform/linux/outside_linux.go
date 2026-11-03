//go:build linux

package linuxplatform

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"github.com/AyoubAchour/net-switch/internal/platform/outside"
	"golang.org/x/sys/unix"
)

const (
	diagCallTimeout          = 3 * time.Second
	maxOutsideDumpBytes      = 8 << 20
	maxDescriptorsPerProcess = 65536
)

var (
	diagSeq            atomic.Uint32
	errDiagInterrupted = errors.New("sock_diag dump interrupted")
)

// NewWatcher builds a Linux outside-connections watcher backed by sock_diag
// (with INET_DIAG_INFO tcp_info byte counters) and /proc descriptor scans.
func NewWatcher(enginePath string) *outside.Watcher[diagSocket] {
	return newLinuxWatcher(enginePath, linuxSource{
		now:     time.Now,
		dump:    func() ([]diagSocket, error) { return dumpEstablishedTCP(netip.AddrPort{}, netip.AddrPort{}, true) },
		owners:  scanSocketOwners,
		readOne: diagReadOne,
	})
}

// ParseOutsideArgs parses flags for `netswitch-engine worker outside`.
func ParseOutsideArgs(args []string) (enginePath string, once bool, err error) {
	flags := flag.NewFlagSet("outside", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	parent := flags.Uint64("parent", 0, "")
	flags.StringVar(&enginePath, "engine", "", "")
	flags.BoolVar(&once, "once", false, "")
	if err := flags.Parse(args); err != nil {
		return "", false, err
	}
	if flags.NArg() > 0 {
		return "", false, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *parent > math.MaxUint32 {
		return "", false, fmt.Errorf("--parent %d is not a process id", *parent)
	}
	return enginePath, once, nil
}

// WatchStdinEOF exits cleanly when Control closes the worker's standard input pipe.
func WatchStdinEOF() {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		return
	}
	os.Exit(0)
}

// RunOutside runs the `outside` worker stream (or one reading with `--once`).
func RunOutside(args []string) int {
	enginePath, once, err := ParseOutsideArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !once {
		go WatchStdinEOF()
	}
	watcher := NewWatcher(enginePath)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		b, err := json.Marshal(watcher.Sample())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := os.Stdout.Write(append(b, '\n')); err != nil {
			return 0
		}
		if once {
			return 0
		}
		<-ticker.C
	}
}

// CloseTCP revalidates each outside TCP connection's 4-tuple, owning PID,
// process start time, live descriptor and socket cookie before ending it with
// SOCK_DESTROY.
func CloseTCP(ctx context.Context, args map[string]any) (map[string]any, error) {
	tuples, err := decodeSelectors(args)
	if err != nil {
		return nil, err
	}
	return closeConnections(tuples, closeOps{
		processStart: readProcStatStart,
		findSocket: func(local, remote netip.AddrPort, cookie uint64) (diagSocket, bool, error) {
			return findEstablishedSocket(ctx, local, remote, cookie)
		},
		pidHoldsInode: pidHoldsSocketInode,
		destroy: func(s diagSocket) error {
			return diagDestroy(ctx, s)
		},
		isGone: func(err error) bool {
			return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
		},
		isUnsupported: func(err error) bool {
			return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS)
		},
	})
}

func findEstablishedSocket(ctx context.Context, local, remote netip.AddrPort, cookie uint64) (diagSocket, bool, error) {
	if err := ctx.Err(); err != nil {
		return diagSocket{}, false, err
	}
	rows, err := dumpEstablishedTCP(local, remote, false)
	if err != nil {
		return diagSocket{}, false, err
	}
	for _, r := range rows {
		if r.state != linuxTCPEstablished || r.local != local || r.remote != remote {
			continue
		}
		if cookie != 0 && r.cookie != cookie {
			continue
		}
		return r, true, nil
	}
	return diagSocket{}, false, nil
}

func dumpEstablishedTCP(local, remote netip.AddrPort, withInfo bool) ([]diagSocket, error) {
	var all []diagSocket
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rows, err := dumpFamilyWithRetry(family, local, remote, withInfo)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.ENOENT)) {
				continue
			}
			return nil, err
		}
		all = append(all, rows...)
	}
	return all, nil
}

func dumpFamilyWithRetry(family int, local, remote netip.AddrPort, withInfo bool) ([]diagSocket, error) {
	for attempt := 0; attempt < 3; attempt++ {
		rows, err := dumpFamilyOnce(family, local, remote, withInfo)
		if !errors.Is(err, errDiagInterrupted) {
			return rows, err
		}
	}
	return nil, errDiagInterrupted
}

func openDiagSocket(deadline time.Time) (*os.File, int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, -1, err
	}
	f := os.NewFile(uintptr(fd), "sock_diag")
	if err := f.SetReadDeadline(deadline); err != nil {
		f.Close()
		return nil, -1, err
	}
	return f, fd, nil
}

func receiveDiagPacket(f *os.File, buf []byte) (int, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n, flags int
	var from unix.Sockaddr
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		n, _, flags, from, readErr = unix.Recvmsg(int(fd), buf, nil, unix.MSG_DONTWAIT)
		return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, readErr
	}
	if flags&unix.MSG_TRUNC != 0 {
		return 0, unix.ENOBUFS
	}
	peer, ok := from.(*unix.SockaddrNetlink)
	if !ok || peer.Pid != 0 {
		return 0, errors.New("netlink response is not from the kernel")
	}
	return n, nil
}

func dumpFamilyOnce(family int, local, remote netip.AddrPort, withInfo bool) ([]diagSocket, error) {
	f, fd, err := openDiagSocket(time.Now().Add(diagCallTimeout))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	req := make([]byte, 72)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	seq := diagSeq.Add(1)
	binary.NativeEndian.PutUint32(req[8:12], seq)
	req[16] = byte(family)
	req[17] = unix.IPPROTO_TCP
	if withInfo {
		req[18] = linuxInetDiagInfoExt
	}
	binary.NativeEndian.PutUint32(req[20:24], linuxTCPEstablishedBit)
	if local.Port() != 0 {
		binary.BigEndian.PutUint16(req[24:26], local.Port())
	}
	if remote.Port() != 0 {
		binary.BigEndian.PutUint16(req[26:28], remote.Port())
	}
	for i := 64; i < 72; i++ {
		req[i] = 0xff // INET_DIAG_NOCOOKIE
	}
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	buf := make([]byte, 64<<10)
	total := 0
	var out []diagSocket
	for {
		n, err := receiveDiagPacket(f, buf)
		if err != nil {
			return nil, err
		}
		total += n
		if total > maxOutsideDumpBytes {
			return nil, errors.New("sock_diag dump exceeds byte bound")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errDiagInterrupted
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
						return nil, syscall.Errno(-code)
					}
				}
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("short sock_diag error")
				}
				if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
					return nil, syscall.Errno(-code)
				}
				return out, nil
			case unix.SOCK_DIAG_BY_FAMILY:
				r, err := parseInetDiagMsg(m.Data)
				if err != nil {
					return nil, err
				}
				out = append(out, r)
			case unix.NLMSG_OVERRUN:
				return nil, unix.ENOBUFS
			}
		}
	}
}

func putDiagEndpoint(b []byte, family, portAt, addrAt int, ap netip.AddrPort) {
	addr := ap.Addr()
	if family == unix.AF_INET6 && addr.Is4() {
		addr = netip.AddrFrom16(addr.As16())
	}
	binary.BigEndian.PutUint16(b[portAt:], ap.Port())
	copy(b[addrAt:addrAt+16], addr.AsSlice())
}

func diagReadOne(s diagSocket) (down, up uint64, ok bool) {
	f, fd, err := openDiagSocket(time.Now().Add(diagCallTimeout))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	req := make([]byte, 72)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST)
	seq := diagSeq.Add(1)
	binary.NativeEndian.PutUint32(req[8:12], seq)
	req[16] = byte(s.family)
	req[17] = unix.IPPROTO_TCP
	req[18] = linuxInetDiagInfoExt
	binary.NativeEndian.PutUint32(req[20:24], linuxTCPEstablishedBit)
	putDiagEndpoint(req, s.family, 24, 28, s.local)
	putDiagEndpoint(req, s.family, 26, 44, s.remote)
	binary.NativeEndian.PutUint32(req[60:64], s.ifindex)
	binary.NativeEndian.PutUint32(req[64:68], uint32(s.cookie))
	binary.NativeEndian.PutUint32(req[68:72], uint32(s.cookie>>32))

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, 0, false
	}
	buf := make([]byte, 8<<10)
	for {
		n, err := receiveDiagPacket(f, buf)
		if err != nil {
			return 0, 0, false
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return 0, 0, false
		}
		for _, m := range messages {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.SOCK_DIAG_BY_FAMILY:
				r, err := parseInetDiagMsg(m.Data)
				if err != nil || r.state != linuxTCPEstablished || r.cookie != s.cookie || !r.measured {
					return 0, 0, false
				}
				return r.down, r.up, true
			case unix.NLMSG_ERROR, unix.NLMSG_DONE, unix.NLMSG_OVERRUN:
				return 0, 0, false
			}
		}
	}
}

func diagDestroy(ctx context.Context, s diagSocket) error {
	deadline := time.Now().Add(diagCallTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	f, fd, err := openDiagSocket(deadline)
	if err != nil {
		return err
	}
	defer f.Close()

	req := make([]byte, 72)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], unix.SOCK_DESTROY)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	seq := diagSeq.Add(1)
	binary.NativeEndian.PutUint32(req[8:12], seq)
	req[16] = byte(s.family)
	req[17] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(req[20:24], ^uint32(0))
	putDiagEndpoint(req, s.family, 24, 28, s.local)
	putDiagEndpoint(req, s.family, 26, 44, s.remote)
	binary.NativeEndian.PutUint32(req[60:64], s.ifindex)
	binary.NativeEndian.PutUint32(req[64:68], uint32(s.cookie))
	binary.NativeEndian.PutUint32(req[68:72], uint32(s.cookie>>32))

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := receiveDiagPacket(f, buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range messages {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return errors.New("short sock_destroy acknowledgement")
				}
				if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
					return syscall.Errno(-code)
				}
				return nil
			case unix.NLMSG_DONE:
				return nil
			}
		}
	}
}

func readProcStatStart(pid uint32) (uint64, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/stat", pid), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, errors.New("proc stat is not a regular file")
	}
	var buf [4096]byte
	n := 0
	for n < len(buf) {
		got, err := unix.Read(fd, buf[n:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if got == 0 {
			return parseProcessStatStart(buf[:n])
		}
		n += got
	}
	return 0, errors.New("proc stat exceeds read bound")
}

func readProcExe(pid uint32) string {
	var buf [4096]byte
	n, err := unix.Readlink(fmt.Sprintf("/proc/%d/exe", pid), buf[:])
	if err != nil || n <= 0 || n >= len(buf) {
		return ""
	}
	return strings.TrimSuffix(string(buf[:n]), " (deleted)")
}

func numericName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func visitDirents(dirFD int, buf []byte, limit int, fn func(name []byte) bool) error {
	visited := 0
	for visited < limit {
		n, err := unix.ReadDirent(dirFD, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		pos := 0
		for pos < n && visited < limit {
			rec := buf[pos:n]
			if len(rec) < 20 {
				return unix.EIO
			}
			recLen := int(binary.NativeEndian.Uint16(rec[16:18]))
			if recLen < 20 || recLen > len(rec) {
				return unix.EIO
			}
			name := rec[19:recLen]
			nul := bytes.IndexByte(name, 0)
			if nul < 0 {
				return unix.EIO
			}
			name = name[:nul]
			pos += recLen
			if bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
				continue
			}
			visited++
			if !fn(name) {
				return nil
			}
		}
	}
	return nil
}

func scanSocketOwners(inodes map[uint32]struct{}) map[uint32]procOwner {
	out := make(map[uint32]procOwner, len(inodes))
	if len(inodes) == 0 {
		return out
	}
	procFD, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return out
	}
	defer unix.Close(procFD)

	procBuf := make([]byte, 16<<10)
	fdBuf := make([]byte, 16<<10)
	var linkBuf [64]byte

	_ = visitDirents(procFD, procBuf, math.MaxInt, func(entry []byte) bool {
		if !numericName(entry) {
			return true
		}
		pidName := string(entry)
		pidVal, err := strconv.ParseUint(pidName, 10, 32)
		if err != nil || pidVal == 0 {
			return true
		}
		pidDir, err := unix.Openat(procFD, pidName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return true
		}
		fdDir, err := unix.Openat(pidDir, "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(pidDir)
		if err != nil {
			return true
		}

		var matched []uint32
		_ = visitDirents(fdDir, fdBuf, maxDescriptorsPerProcess, func(fdEntry []byte) bool {
			if !numericName(fdEntry) {
				return true
			}
			n, err := unix.Readlinkat(fdDir, string(fdEntry), linkBuf[:])
			if err != nil || n <= 0 || n >= len(linkBuf) {
				return true
			}
			inode, ok := parseSocketLink(linkBuf[:n])
			if !ok {
				return true
			}
			if _, want := inodes[inode]; !want {
				return true
			}
			if _, exists := out[inode]; exists {
				return true
			}
			matched = append(matched, inode)
			return true
		})
		unix.Close(fdDir)

		if len(matched) == 0 {
			return true
		}
		pid := uint32(pidVal)
		startBefore, err := readProcStatStart(pid)
		if err != nil {
			return true
		}
		exe := readProcExe(pid)
		appID := ownerbpf.InspectLiveProcessAppID(pid, startBefore, exe)
		startAfter, err := readProcStatStart(pid)
		if err != nil || startAfter != startBefore {
			return true
		}
		owner := procOwner{pid: pid, start: startBefore, path: exe, appID: appID}
		for _, inode := range matched {
			if _, exists := out[inode]; !exists {
				out[inode] = owner
			}
		}
		return len(out) < len(inodes)
	})
	return out
}

func pidHoldsSocketInode(pid uint32, inode uint32) (bool, error) {
	if pid == 0 || inode == 0 {
		return false, nil
	}
	fdDir, err := unix.Open(fmt.Sprintf("/proc/%d/fd", pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(fdDir)

	buf := make([]byte, 16<<10)
	var linkBuf [64]byte
	found := false
	err = visitDirents(fdDir, buf, maxDescriptorsPerProcess, func(entry []byte) bool {
		if !numericName(entry) {
			return true
		}
		n, err := unix.Readlinkat(fdDir, string(entry), linkBuf[:])
		if err != nil || n <= 0 || n >= len(linkBuf) {
			return true
		}
		if got, ok := parseSocketLink(linkBuf[:n]); ok && got == inode {
			found = true
			return false
		}
		return true
	})
	if found {
		return true, nil
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	return false, err
}
