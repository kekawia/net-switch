package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func refusalRawConn(c net.Conn) (syscall.RawConn, error) {
	conn, ok := c.(syscall.Conn)
	if !ok {
		return nil, errors.New("UDP fixture has no raw socket")
	}
	return conn.SyscallConn()
}

func enableRefusalTimestamps(c net.Conn) error {
	raw, err := refusalRawConn(c)
	if err != nil {
		return err
	}
	remote, ok := c.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return errors.New("UDP fixture has no UDP destination")
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMPNS_NEW, 1)
		if optionErr != nil {
			return
		}
		level, option := unix.IPPROTO_IP, unix.IP_RECVERR
		if remote.IP.To4() == nil {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
		}
		optionErr = unix.SetsockoptInt(int(fd), level, option, 1)
	})
	return errors.Join(err, optionErr)
}

// IP_RECVERR retains the incoming ICMP skb, including its kernel receive time.
// Read the queue only after the ordinary UDP read reports ECONNREFUSED; never
// substitute the time this goroutine happened to obtain CPU or the result lock.
func refusalKernelTime(c net.Conn) (int64, error) {
	raw, err := refusalRawConn(c)
	if err != nil {
		return 0, err
	}
	var data [2048]byte
	var control [512]byte
	var count, flags int
	var receiveErr error
	err = raw.Control(func(fd uintptr) {
		_, count, flags, _, receiveErr = unix.Recvmsg(int(fd), data[:], control[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	})
	if err = errors.Join(err, receiveErr); err != nil {
		return 0, err
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return 0, errors.New("truncated refusal timestamp metadata")
	}
	messages, err := unix.ParseSocketControlMessage(control[:count])
	if err != nil {
		return 0, err
	}
	return parseRefusalKernelTime(messages)
}

func parseRefusalKernelTime(messages []unix.SocketControlMessage) (int64, error) {
	var timestamp int64
	var found, refused bool
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SO_TIMESTAMPNS_NEW {
			if found || len(message.Data) != 16 {
				return 0, errors.New("ambiguous refusal timestamp")
			}
			seconds := int64(binary.NativeEndian.Uint64(message.Data[:8]))
			nanos := int64(binary.NativeEndian.Uint64(message.Data[8:]))
			if seconds <= 0 || seconds > 1<<40 || nanos < 0 || nanos >= int64(time.Second) {
				return 0, errors.New("invalid kernel refusal time")
			}
			timestamp = time.Unix(seconds, nanos).UnixMilli()
			found = true
		}
		if ((message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_RECVERR) || (message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_RECVERR)) && len(message.Data) >= 16 {
			errno := unix.Errno(binary.NativeEndian.Uint32(message.Data))
			origin := message.Data[4]
			refused = errno == unix.ECONNREFUSED && (origin == unix.SO_EE_ORIGIN_ICMP || origin == unix.SO_EE_ORIGIN_ICMP6)
		}
	}
	if !found || !refused {
		return 0, fmt.Errorf("missing kernel refusal evidence: timestamp=%t ICMP=%t", found, refused)
	}
	return timestamp, nil
}
