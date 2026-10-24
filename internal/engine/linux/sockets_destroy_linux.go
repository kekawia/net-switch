//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Spec §2, "failing open also ends connections the engine was carrying": when
// the engine stops, lapses or dies, the connections apps had through its TUN
// terminate inside the engine's own network stack, so nothing resets them;
// without this an app sits on a dead connection until TCP gives up, minutes
// later, instead of reconnecting directly. Windows aborts a removed adapter's
// sockets by itself; Linux does not, so cleanup does it the way `ss -K` does.
//
// The rule: a socket is ended when it is connected, its local address is one
// of the journaled TUN addresses, and its peer is not local to this host.
// Listeners, unconnected UDP sockets and local-only connections are spared.
// It works from the ownership record, so it runs whether or not the TUN still
// exists (the engine's own stop closes the non-persistent TUN before journal
// cleanup, and a death removes it), and it is best effort inside its own small
// share of the cleanup budget: the dump is bounded, the first unsupported or
// refused answer ends it, and the mandatory cleanup that follows always keeps
// its time. A kernel built without CONFIG_INET_DIAG_DESTROY answers EOPNOTSUPP.

// socketRetirementShare is the most of the cleanup budget socket retirement
// may take: a quarter of what remains, and never more than this.
const socketRetirementShare = 500 * time.Millisecond

// Bounds on one namespace-wide dump; variables so tests can shrink them.
var (
	socketDumpMaxBytes   = 4 << 20
	socketDumpMaxMatches = 2048
)

var errSocketDumpBounded = errors.New("socket table larger than the retirement bound; remaining connections end on their own")

// sockDestroyRequest sends one SOCK_DESTROY; tests substitute a refusal.
var sockDestroyRequest = sockDestroy

type retirement struct {
	ended, spared int
	err           error
}

// retireRoutedSockets ends the connections carried on the journal's live TUN
// addresses and logs the outcome. It never fails the cleanup it precedes.
func retireRoutedSockets(ctx context.Context, session *journal.Session) retirement {
	records, err := session.Live()
	if err != nil {
		log.Printf("engine cleanup: cannot read the ownership record to end routed connections: %v", err)
		return retirement{err: err}
	}
	var prefixes []netip.Prefix
	for _, r := range records {
		if r.Kind != "address" {
			continue
		}
		var v addressObject
		if json.Unmarshal([]byte(r.Fingerprint["object"]), &v) != nil {
			continue
		}
		if p, err := netip.ParsePrefix(v.CIDR); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	if len(prefixes) == 0 {
		return retirement{}
	}
	share := socketRetirementShare
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline) / 4; remaining < share {
			share = remaining
		}
	}
	if share <= 0 {
		return retirement{err: context.DeadlineExceeded}
	}
	bounded, cancel := context.WithTimeout(ctx, share)
	defer cancel()
	out := retireRoutedSocketsWithin(bounded, prefixes, hostLocal())
	switch {
	case out.err != nil:
		log.Printf("engine cleanup: ended %d routed connections on %v (%d spared) before stopping: %v", out.ended, prefixes, out.spared, out.err)
	case out.ended > 0:
		log.Printf("engine cleanup: ended %d routed connections on %v (%d sockets spared)", out.ended, prefixes, out.spared)
	}
	return out
}

// hostLocal reports whether an address belongs to this host: loopback, or
// assigned to any interface of this network namespace.
func hostLocal() func(netip.Addr) bool {
	own := map[netip.Addr]bool{}
	if addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL); err == nil {
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				own[ip.Unmap()] = true
			}
		}
	}
	return func(a netip.Addr) bool { return a.IsLoopback() || own[a.Unmap()] }
}

// retireRoutedSocketsWithin applies the rule to every socket of this network
// namespace, within ctx's deadline and the dump bounds.
func retireRoutedSocketsWithin(ctx context.Context, prefixes []netip.Prefix, local func(netip.Addr) bool) retirement {
	var out retirement
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		out.err = err
		return out
	}
	destroyer := os.NewFile(uintptr(fd), "sock_destroy")
	defer destroyer.Close()
	carried := func(r socketRow) bool {
		inPrefix := false
		for _, p := range prefixes {
			inPrefix = inPrefix || p.Contains(r.local.Addr())
		}
		if !inPrefix {
			return false
		}
		connected := r.remote.Port() != 0 && r.remote.Addr().IsValid() && !r.remote.Addr().IsUnspecified()
		if r.protocol == unix.IPPROTO_TCP {
			connected = connected && r.state != unix.BPF_TCP_LISTEN && r.state != unix.BPF_TCP_TIME_WAIT && r.state != unix.BPF_TCP_NEW_SYN_RECV
		}
		if !connected || local(r.remote.Addr()) {
			out.spared++
			return false
		}
		return true
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			matches, err := scanSockets(ctx, family, protocol, carried)
			for _, r := range matches {
				if ctx.Err() != nil {
					out.err = ctx.Err()
					return out
				}
				switch destroyErr := sockDestroyRequest(ctx, destroyer, fd, r); {
				case destroyErr == nil:
					out.ended++
				case errors.Is(destroyErr, unix.ENOENT), errors.Is(destroyErr, unix.ESRCH):
					// Gone on its own between the dump and the destroy.
				case errors.Is(destroyErr, unix.EOPNOTSUPP), errors.Is(destroyErr, unix.EINVAL), errors.Is(destroyErr, unix.EPERM), errors.Is(destroyErr, unix.EACCES):
					out.err = fmt.Errorf("socket destruction unavailable (kernel without CONFIG_INET_DIAG_DESTROY, or refused): %w", destroyErr)
					return out
				default:
					out.err = fmt.Errorf("destroy %s->%s: %w", r.local, r.remote, destroyErr)
					return out
				}
			}
			if err != nil {
				out.err = err
				return out
			}
		}
	}
	return out
}

// scanSockets streams one sock_diag dump, keeping only the rows carried
// returns true for, and stops at the byte or match bound.
func scanSockets(ctx context.Context, family, protocol int, carried func(socketRow) bool) ([]socketRow, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "sock_diag dump")
	defer f.Close() // closing mid-dump discards the kernel's remaining pages
	if deadline, ok := ctx.Deadline(); ok {
		if err := f.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}
	b := make([]byte, 72)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	sequence := diagSequence.Add(1)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	b[16] = byte(family)
	b[17] = byte(protocol)
	binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
	for i := 64; i < 72; i++ {
		b[i] = 255 // INET_DIAG_NOCOOKIE
	}
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var matches []socketRow
	buf := make([]byte, 64<<10)
	read := 0
	for {
		n, err := readNetlink(f, buf)
		if err != nil {
			if ctx.Err() != nil {
				return matches, ctx.Err()
			}
			return matches, err
		}
		read += n
		if read > socketDumpMaxBytes {
			return matches, errSocketDumpBounded
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return matches, err
		}
		for _, m := range messages {
			if m.Header.Seq != sequence {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return matches, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
						return matches, syscall.Errno(-code)
					}
				}
				return matches, nil
			case unix.SOCK_DIAG_BY_FAMILY:
				r, err := parseDiag(m.Data)
				if err != nil {
					return matches, err
				}
				r.protocol = protocol
				if carried(r) {
					matches = append(matches, r)
					if len(matches) > socketDumpMaxMatches {
						return matches[:socketDumpMaxMatches], errSocketDumpBounded
					}
				}
			case unix.NLMSG_OVERRUN:
				return matches, unix.ENOBUFS
			}
		}
	}
}

// sockDestroy sends one SOCK_DESTROY for the socket a dump reported, naming it
// exactly as the dump did (local as source, remote as destination, bound
// device and cookie); the kernel applies its own inbound lookup order for UDP
// (net/ipv4/udp_diag.c, __udp_diag_destroy), so nothing is swapped here.
func sockDestroy(ctx context.Context, f *os.File, fd int, r socketRow) error {
	b := make([]byte, 72)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.SOCK_DESTROY)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	sequence := diagSequence.Add(1)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	b[16] = byte(r.family)
	b[17] = byte(r.protocol)
	binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
	// inet_diag_sockid: sport 24, dport 26, src 28, dst 44, if 60, cookie 64.
	put := func(portAt, addrAt int, a netip.AddrPort) {
		addr := a.Addr()
		if r.family == unix.AF_INET6 && addr.Is4() {
			addr = netip.AddrFrom16(addr.As16())
		}
		binary.BigEndian.PutUint16(b[portAt:], a.Port())
		copy(b[addrAt:addrAt+16], addr.AsSlice())
	}
	put(24, 28, r.local)
	put(26, 44, r.remote)
	binary.NativeEndian.PutUint32(b[60:], r.ifindex)
	binary.NativeEndian.PutUint32(b[64:], uint32(r.cookie))
	binary.NativeEndian.PutUint32(b[68:], uint32(r.cookie>>32))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Second)
	}
	if err := f.SetReadDeadline(deadline); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := readNetlink(f, buf)
		if err != nil {
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range messages {
			if m.Header.Seq != sequence {
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
