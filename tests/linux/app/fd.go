//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// The modes below hand sockets between processes. Each one that holds a
// socket before connecting it prints a line
//
//	ready socket:<inode> pid:<pid>
//
// once the hand-off is complete, then waits for --wait-file. The harness
// checks which processes hold the socket (and their cgroups) in between, so
// the connection happens exactly in the state the case describes.

// FDResult is the answer of the modes that connect a socket made elsewhere.
type FDResult struct {
	InitialSeen string  `json:"initialSeen,omitempty"`
	Seen        string  `json:"seen,omitempty"`
	Err         string  `json:"err,omitempty"`
	ConnectMS   float64 `json:"connectMs"`
	Pid         int     `json:"pid"`
	Uid         int     `json:"uid"`
	Inode       uint64  `json:"inode"`
}

func tcpSocket(v6 bool) (int, error) {
	family := syscall.AF_INET
	if v6 {
		family = syscall.AF_INET6
	}
	return syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
}

func inode(fd int) uint64 {
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil {
		return 0
	}
	return st.Ino
}

// ready announces a held socket, then waits for the go-ahead.
func ready(fd int, wait string) error {
	fmt.Printf("ready socket:%d pid:%d\n", inode(fd), os.Getpid())
	return waitFile(wait, 60*time.Second)
}

func sockaddr(ap netip.AddrPort) syscall.Sockaddr {
	if ap.Addr().Is4() {
		return &syscall.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}
	}
	return &syscall.SockaddrInet6{Addr: ap.Addr().As16(), Port: int(ap.Port())}
}

// connectFD connects a blocking TCP socket and reads the whoami answer. It
// takes ownership of fd.
func connectFD(fd int, to netip.AddrPort, timeout time.Duration) FDResult {
	r := FDResult{Pid: os.Getpid(), Uid: os.Getuid(), Inode: inode(fd)}
	// No SO_SNDTIMEO: with one, a signal (Go's runtime sends them) ends a
	// blocking connect with EINTR instead of restarting it (signal(7)). The
	// deadline shuts the socket down instead, which aborts the connect.
	var timedOut atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		timedOut.Store(true)
		_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
	})
	start := time.Now()
	err := syscall.Connect(fd, sockaddr(to))
	stopped := timer.Stop()
	r.ConnectMS = msSince(start)
	if err != nil || (!stopped && timedOut.Load()) {
		syscall.Close(fd)
		if timedOut.Load() {
			r.Err = "TIMEOUT"
		} else {
			r.Err = Code(err)
		}
		return r
	}
	f := os.NewFile(uintptr(fd), "socket")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(timeout))
	data, err := io.ReadAll(io.LimitReader(conn, 256))
	r.Seen = strings.TrimSpace(string(data))
	if err != nil {
		r.Err = Code(err)
	} else if r.Seen == "" {
		r.Err = "EMPTY"
	}
	return r
}

// presocketConnect creates the socket, announces it, waits, then connects
// it: the socket's cgroup is where the process was when it was created.
func presocketConnect(to netip.AddrPort, wait string, timeout time.Duration) (any, error) {
	if wait == "" {
		return nil, usageError{errors.New("--presocket needs --wait-file")}
	}
	fd, err := tcpSocket(to.Addr().Is6())
	if err != nil {
		return nil, err
	}
	if err := ready(fd, wait); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return connectFD(fd, to, timeout), nil
}

func runConnectFD(args []string) (any, error) {
	fs := flag.NewFlagSet("connect-fd", flag.ContinueOnError)
	fd := fs.Int("fd", 3, "inherited socket")
	to := fs.String("to", "", "whoami server ip:port")
	wait := fs.String("wait-file", "", "connect once this file exists")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if err := waitFile(*wait, 60*time.Second); err != nil {
		return nil, err
	}
	return connectFD(*fd, list[0], time.Duration(*timeout)*time.Millisecond), nil
}

func runFDPassSend(args []string) (any, error) {
	fs := flag.NewFlagSet("fdpass-send", flag.ContinueOnError)
	path := fs.String("unix", "", "the receiver's socket")
	v6 := fs.Bool("v6", false, "an IPv6 socket")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	fd, err := tcpSocket(*v6)
	if err != nil {
		return nil, err
	}
	ino := inode(fd)
	var conn *net.UnixConn
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: *path, Net: "unix"})
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			syscall.Close(fd)
			return nil, fmt.Errorf("receiver never listened: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()
	if _, _, err := conn.WriteMsgUnix([]byte("fd"), syscall.UnixRights(fd), nil); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	// Only once our copy is closed may the receiver use it.
	if err := syscall.Close(fd); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte("closed\n")); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	reply, _ := io.ReadAll(conn)
	return map[string]any{"sent": true, "inode": ino, "reply": strings.TrimSpace(string(reply)), "pid": os.Getpid(), "uid": os.Getuid()}, nil
}

func runFDPassRecv(args []string) (any, error) {
	fs := flag.NewFlagSet("fdpass-recv", flag.ContinueOnError)
	path := fs.String("unix", "", "socket to listen on")
	to := fs.String("to", "", "whoami server ip:port")
	wait := fs.String("wait-file", "", "connect once this file exists")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(*path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	if err := os.Chmod(*path, 0o777); err != nil {
		return nil, err
	}
	_ = ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.AcceptUnix()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf, oob := make([]byte, 16), make([]byte, syscall.CmsgSpace(4*4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, fmt.Errorf("no socket arrived: %v", err)
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("no socket arrived: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := readLine(conn)
	if err != nil || line != "closed" {
		return nil, fmt.Errorf("the sender never said it closed its copy (%q, %v)", line, err)
	}
	if err := ready(fds[0], *wait); err != nil {
		return nil, err
	}
	r := connectFD(fds[0], list[0], time.Duration(*timeout)*time.Millisecond)
	_, _ = conn.Write([]byte("done"))
	return r, nil
}

func readLine(conn net.Conn) (string, error) {
	var b [1]byte
	var line []byte
	for {
		if _, err := conn.Read(b[:]); err != nil {
			return string(line), err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
}

func runShareExec(args []string) (any, error) {
	fs := flag.NewFlagSet("share-exec", flag.ContinueOnError)
	to := fs.String("to", "", "whoami server ip:port")
	child := fs.String("child", "", "program to start; it's run as <child> app connect-fd --fd 3 --to <to> --wait-file <wait>")
	keep := fs.Bool("keep", true, "keep our copy of the socket open while the child connects")
	wait := fs.String("wait-file", "", "the child connects once this file exists")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if *child == "" || *wait == "" {
		return nil, usageError{errors.New("--child and --wait-file are required")}
	}
	fd, err := tcpSocket(list[0].Addr().Is6())
	if err != nil {
		return nil, err
	}
	ino := inode(fd)
	f := os.NewFile(uintptr(fd), "socket")
	cmd := exec.Command(*child, "app", "connect-fd", "--fd", "3", "--to", list[0].String(), "--wait-file", *wait)
	cmd.ExtraFiles = []*os.File{f}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	// The child holds the socket from its start; drop ours first if asked.
	if !*keep {
		f.Close()
	}
	fmt.Printf("ready socket:%d pid:%d child:%d keep:%v\n", ino, os.Getpid(), cmd.Process.Pid, *keep)
	err = cmd.Wait()
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("child: %w", err)
	}
	return json.RawMessage(lastLine(out.Bytes())), nil
}

func lastLine(b []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	return bytes.TrimSpace(lines[len(lines)-1])
}

func udpRawSocket(v6 bool) (int, error) {
	family := syscall.AF_INET
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}
	if v6 {
		family = syscall.AF_INET6
		sa = &syscall.SockaddrInet6{}
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func sendUDPProbeOnce(conn *net.UDPConn, target netip.AddrPort, timeout time.Duration) (string, string) {
	tok := token()
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for attempt := 0; attempt < 12 && time.Now().Before(deadline); attempt++ {
		msg := payload(tok, 0, attempt, 0)
		if _, err := conn.WriteToUDPAddrPort(msg, target); err != nil {
			return "", Code(err)
		}
		stepEnd := time.Now().Add(80 * time.Millisecond)
		if stepEnd.After(deadline) {
			stepEnd = deadline
		}
		_ = conn.SetReadDeadline(stepEnd)
		for time.Now().Before(stepEnd) {
			n, _, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			seen, body, pErr := wire.ParseEchoReply(buf[:n])
			if pErr == nil && strings.HasPrefix(string(body), "T:"+tok+":") {
				return seen.String(), ""
			}
		}
	}
	return "", "TIMEOUT"
}

func runShareUDP(args []string) (any, error) {
	fs := flag.NewFlagSet("share-udp", flag.ContinueOnError)
	to := fs.String("to", "", "echo server ip:port")
	child := fs.String("child", "", "program to start; run as <child> app send-udp-fd")
	wait := fs.String("wait-file", "", "send once this file exists")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if *child == "" || *wait == "" {
		return nil, usageError{errors.New("--child and --wait-file are required")}
	}
	fd, err := udpRawSocket(list[0].Addr().Is6())
	if err != nil {
		return nil, err
	}
	ino := inode(fd)
	sockFile := os.NewFile(uintptr(fd), "udp-socket")
	pconn, err := net.FilePacketConn(sockFile)
	if err != nil {
		sockFile.Close()
		return nil, err
	}
	udpConn := pconn.(*net.UDPConn)

	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		udpConn.Close()
		sockFile.Close()
		return nil, err
	}
	cmd := exec.Command(*child, "app", "send-udp-fd", "--fd", "3", "--sync-fd", "4", "--to", list[0].String(), "--timeout", strconv.Itoa(*timeout))
	cmd.ExtraFiles = []*os.File{sockFile, pipeRead}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		pipeRead.Close()
		pipeWrite.Close()
		udpConn.Close()
		sockFile.Close()
		return nil, err
	}
	pipeRead.Close()
	fmt.Printf("ready socket:%d pid:%d child:%d keep:true\n", ino, os.Getpid(), cmd.Process.Pid)
	if err := waitFile(*wait, 60*time.Second); err != nil {
		pipeWrite.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		udpConn.Close()
		sockFile.Close()
		return nil, err
	}
	dur := time.Duration(*timeout) * time.Millisecond
	initialSeen, sendErr := sendUDPProbeOnce(udpConn, list[0], dur)
	udpConn.Close()
	_, _ = pipeWrite.Write([]byte("go\n"))
	pipeWrite.Close()
	waitErr := cmd.Wait()
	sockFile.Close()
	if waitErr != nil {
		return nil, fmt.Errorf("child: %w", waitErr)
	}
	var res FDResult
	if err := json.Unmarshal(lastLine(out.Bytes()), &res); err != nil {
		return nil, err
	}
	res.InitialSeen = initialSeen
	if res.Err == "" && sendErr != "" {
		res.Err = sendErr
	}
	return res, nil
}

func runSendUDPFD(args []string) (any, error) {
	fs := flag.NewFlagSet("send-udp-fd", flag.ContinueOnError)
	fd := fs.Int("fd", 3, "inherited UDP socket")
	syncFD := fs.Int("sync-fd", 4, "sync pipe read end")
	to := fs.String("to", "", "echo server ip:port")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	syncFile := os.NewFile(uintptr(*syncFD), "sync")
	_, _ = io.ReadAll(syncFile)
	syncFile.Close()

	r := FDResult{Pid: os.Getpid(), Uid: os.Getuid(), Inode: inode(*fd)}
	sockFile := os.NewFile(uintptr(*fd), "shared-udp")
	pconn, err := net.FilePacketConn(sockFile)
	sockFile.Close()
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	defer pconn.Close()
	start := time.Now()
	seen, errCode := sendUDPProbeOnce(pconn.(*net.UDPConn), list[0], time.Duration(*timeout)*time.Millisecond)
	r.ConnectMS = msSince(start)
	r.Seen = seen
	r.Err = errCode
	return r, nil
}

func runSpawn(args []string) (any, error) {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return nil, usageError{errors.New("usage: spawn -- <program> [args...]")}
	}
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("child: %w", err)
	}
	return json.RawMessage(lastLine(out)), nil
}
