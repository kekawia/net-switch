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
// The rules this file follows, in order:
//
//   - Exact matches only: a socket is a candidate when its local address equals
//     a journaled TUN address, compared normalised; never a prefix.
//   - The same ownership checks as the rest of cleanup: only address records of
//     this boot and this network namespace are read, with the same fingerprint
//     validation the object driver applies, before any socket is selected.
//   - Unknown means do nothing: an error or uncertainty in ownership, locality
//     or the dump aborts the whole retirement; it never widens it. Listeners,
//     unconnected UDP sockets, local-only connections and link-local peers
//     (whose scope the dump does not settle) are spared.
//   - Everything inside its own bounded share of the cleanup budget: the host
//     address listing, the streamed and bounded dumps and the destroys; the
//     first unsupported or refused destroy ends the pass. The mandatory journal
//     cleanup that follows always keeps its own time.
//
// It works from the ownership record, so it runs whether or not the TUN still
// exists: the engine's own stop closes the non-persistent TUN before journal
// cleanup, and a death removes it.

// socketRetirementShare is the most of the cleanup budget socket retirement
// may take: a quarter of what remains, and never more than this.
const socketRetirementShare = 500 * time.Millisecond

// Bounds on one namespace-wide dump; variables so tests can shrink them.
var (
	socketDumpMaxBytes   = 4 << 20
	socketDumpMaxMatches = 2048
)

var errSocketDumpBounded = errors.New("socket table larger than the retirement bound; remaining connections end on their own")

// Test seams: the destroy request and the host address listing.
var (
	sockDestroyRequest = sockDestroy
	listHostAddresses  = func() ([]netlink.Addr, error) { return netlink.AddrList(nil, netlink.FAMILY_ALL) }
)

type retirement struct {
	ended, spared int
	err           error
}

// retireRoutedSockets ends the connections carried on the journal's live TUN
// addresses of this boot and namespace, and logs the outcome. It never fails
// the cleanup it precedes.
func retireRoutedSockets(ctx context.Context, session *journal.Session, boot, netns string) retirement {
	records, err := session.Live()
	if err != nil {
		log.Printf("engine cleanup: cannot read the ownership record to end routed connections: %v", err)
		return retirement{err: err}
	}
	tun := routedAddresses(records, boot, netns)
	if len(tun) == 0 {
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
	out := retireRoutedSocketsWithin(bounded, tun)
	switch {
	case out.err != nil:
		log.Printf("engine cleanup: ended %d routed connections on %v (%d spared) before stopping: %v", out.ended, keys(tun), out.spared, out.err)
	case out.ended > 0:
		log.Printf("engine cleanup: ended %d routed connections on %v (%d sockets spared)", out.ended, keys(tun), out.spared)
	}
	return out
}

func keys(set map[netip.Addr]bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	return out
}

// routedAddresses reads the exact TUN addresses from the live address records
// that pass the same ownership checks cleanup applies: a valid fingerprint of
// this boot and this network namespace. Anything else is not ours to act on.
func routedAddresses(records []journal.Record, boot, netns string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, r := range records {
		f := r.Fingerprint
		if r.Kind != "address" || len(f) != 3 || f["boot"] == "" || f["netns"] == "" || f["boot"] != boot || f["netns"] != netns {
			continue
		}
		var v addressObject
		if json.Unmarshal([]byte(f["object"]), &v) != nil {
			continue
		}
		p, err := netip.ParsePrefix(v.CIDR)
		if err != nil {
			continue
		}
		out[p.Addr().Unmap()] = true
	}
	return out
}

// retirementScope is what one retirement pass knows about this host: the
// journaled TUN addresses (exact candidates for the local side, and local
// peers even after teardown removed them) and every address this namespace's
// interfaces hold.
type retirementScope struct {
	tun  map[netip.Addr]bool
	host map[netip.Addr]bool
}

func newRetirementScope(tun map[netip.Addr]bool, addrs []netlink.Addr) retirementScope {
	s := retirementScope{tun: tun, host: map[netip.Addr]bool{}}
	for a := range tun {
		s.host[a] = true
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			s.host[ip.Unmap()] = true
		}
	}
	return s
}

// carried decides one dumped socket: true means it is a connection the engine
// carried and must end; false with spared means it matched the TUN address
// but is kept by the rule; false otherwise.
func (s retirementScope) carried(r socketRow) (carried, spared bool) {
	if !s.tun[r.local.Addr().Unmap()] {
		return false, false
	}
	peer := r.remote.Addr().Unmap()
	connected := r.remote.Port() != 0 && peer.IsValid() && !peer.IsUnspecified()
	if r.protocol == unix.IPPROTO_TCP {
		connected = connected && r.state != unix.BPF_TCP_LISTEN && r.state != unix.BPF_TCP_TIME_WAIT && r.state != unix.BPF_TCP_NEW_SYN_RECV
	}
	// A link-local peer's scope is not in the dump, so an equal address on
	// another interface cannot be told apart: unknown, so spared.
	if !connected || peer.IsLoopback() || peer.IsLinkLocalUnicast() || peer.IsLinkLocalMulticast() || s.host[peer] {
		return false, true
	}
	return true, false
}

// retireRoutedSocketsWithin runs one pass within ctx's deadline: host
// addresses, then every dump, then the destroys. Any failure before the
// destroys ends the pass with nothing destroyed.
func retireRoutedSocketsWithin(ctx context.Context, tun map[netip.Addr]bool) retirement {
	var out retirement
	addrs, err := hostAddressesWithin(ctx)
	if err != nil {
		out.err = fmt.Errorf("host addresses unknown; no routed connection ended: %w", err)
		return out
	}
	scope := newRetirementScope(tun, addrs)
	var matches []socketRow
	bounded := false
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			rows, err := scanSockets(ctx, family, protocol, func(r socketRow) bool {
				c, spared := scope.carried(r)
				if spared {
					out.spared++
				}
				return c
			})
			matches = append(matches, rows...)
			if errors.Is(err, errSocketDumpBounded) {
				bounded = true
				continue
			}
			if err != nil {
				out.err = fmt.Errorf("socket listing failed; no routed connection ended: %w", err)
				return out
			}
		}
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		out.err = err
		return out
	}
	destroyer := os.NewFile(uintptr(fd), "sock_destroy")
	defer destroyer.Close()
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
	if bounded {
		out.err = errSocketDumpBounded
	}
	return out
}

// hostAddressesWithin lists this namespace's addresses inside ctx's deadline.
// The netlink library has its own socket timeout, but the share is shorter;
// a listing that does not finish in time leaves locality unknown.
func hostAddressesWithin(ctx context.Context) ([]netlink.Addr, error) {
	type result struct {
		addrs []netlink.Addr
		err   error
	}
	done := make(chan result, 1)
	go func() {
		addrs, err := listHostAddresses()
		done <- result{addrs, err}
	}()
	select {
	case r := <-done:
		return r.addrs, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
				return nil, ctx.Err()
			}
			return nil, err
		}
		read += n
		if read > socketDumpMaxBytes {
			return matches, errSocketDumpBounded
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
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
						return nil, syscall.Errno(-code)
					}
				}
				return matches, nil
			case unix.SOCK_DIAG_BY_FAMILY:
				r, err := parseDiag(m.Data)
				if err != nil {
					return nil, err
				}
				r.protocol = protocol
				if carried(r) {
					matches = append(matches, r)
					if len(matches) > socketDumpMaxMatches {
						return matches[:socketDumpMaxMatches], errSocketDumpBounded
					}
				}
			case unix.NLMSG_OVERRUN:
				return nil, unix.ENOBUFS
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
