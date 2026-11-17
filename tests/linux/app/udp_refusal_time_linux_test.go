package app

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelRefusalTimestampSurvivesDelayedUserspace(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := "127.0.0.1"
			if network == "udp6" {
				ip = "::1"
			}
			listener, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialUDP(network, nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := enableRefusalTimestamps(conn); err != nil {
				t.Fatal(err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			sent := time.Now().UnixMilli()
			if _, err := conn.Write([]byte("refusal-clock-proof")); err != nil {
				t.Fatal(err)
			}
			var data [128]byte
			if _, err := conn.Read(data[:]); Code(err) != "ECONNREFUSED" {
				t.Fatal("closed port did not refuse the datagram", err)
			}
			readAt := time.Now().UnixMilli()
			// Reproduce the old observer's delay between the read and recording
			// its result, without changing the kernel's packet arrival time.
			time.Sleep(100 * time.Millisecond)
			stamp, err := refusalKernelTime(conn)
			if err != nil {
				t.Fatal(err)
			}
			if stamp < sent || stamp > readAt {
				t.Fatalf("kernel timestamp %d outside send/read interval %d..%d", stamp, sent, readAt)
			}
			if time.Now().UnixMilli()-stamp < 90 {
				t.Fatal("timestamp followed delayed userspace instead of packet arrival")
			}
		})
	}
}

func TestRefusalTimestampRequiresBothKernelTimeAndICMP(t *testing.T) {
	stamp := make([]byte, 16)
	binary.NativeEndian.PutUint64(stamp, 20)
	binary.NativeEndian.PutUint64(stamp[8:], 123000000)
	report := make([]byte, 16)
	binary.NativeEndian.PutUint32(report, uint32(unix.ECONNREFUSED))
	report[4] = unix.SO_EE_ORIGIN_ICMP
	timeMessage := unix.SocketControlMessage{Header: unix.Cmsghdr{Level: unix.SOL_SOCKET, Type: unix.SO_TIMESTAMPNS_NEW}, Data: stamp}
	errorMessage := unix.SocketControlMessage{Header: unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_RECVERR}, Data: report}
	if got, err := parseRefusalKernelTime([]unix.SocketControlMessage{timeMessage, errorMessage}); err != nil || got != 20123 {
		t.Fatal(got, err)
	}
	for _, messages := range [][]unix.SocketControlMessage{nil, {timeMessage}, {errorMessage}, {timeMessage, timeMessage, errorMessage}} {
		if _, err := parseRefusalKernelTime(messages); err == nil {
			t.Fatal("incomplete or ambiguous clock evidence accepted")
		}
	}
	report[4] = unix.SO_EE_ORIGIN_LOCAL
	if _, err := parseRefusalKernelTime([]unix.SocketControlMessage{timeMessage, errorMessage}); err == nil {
		t.Fatal("local error counted as received ICMP")
	}
}
