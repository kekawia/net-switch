//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// destroyBoundSockets ends every TCP and UDP socket of this network namespace
// whose local address lies in prefix: the apps' own sockets, which bound to
// the engine's TUN address because the default route led there. Their
// connections terminate inside the engine's network stack, so once the engine
// stops or dies nothing answers them any more; without this an app sits on a
// dead connection until TCP gives up, minutes later, instead of failing open
// and reconnecting directly (spec §2: when the engine dies, "normal internet
// works in between"). Windows aborts the sockets of a removed adapter by
// itself; Linux does not, so cleanup does it the way `ss -K` does: a sock_diag
// dump finds each socket, and SOCK_DESTROY (CONFIG_INET_DIAG_DESTROY) ends it
// by its exact identity and cookie, which resets the peer and fails the app's
// calls with ECONNABORTED. A kernel without that option answers EOPNOTSUPP,
// which is reported but is not a cleanup failure: the routing objects still go.
func destroyBoundSockets(ctx context.Context, prefix netip.Prefix) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), "sock_destroy")
	defer f.Close()
	destroyed := 0
	var unsupported error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			rows, err := diag(ctx, family, protocol, netip.AddrPort{}, netip.AddrPort{}, true)
			if err != nil {
				return destroyed, fmt.Errorf("list sockets bound to %s: %w", prefix, err)
			}
			for _, r := range rows {
				if !prefix.Contains(r.local.Addr()) {
					continue
				}
				err := sockDestroy(ctx, f, fd, family, protocol, r)
				switch {
				case err == nil:
					destroyed++
				case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ESRCH):
					// Gone on its own between the dump and the destroy.
				case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EINVAL):
					unsupported = fmt.Errorf("this kernel cannot destroy sockets (CONFIG_INET_DIAG_DESTROY): %w", err)
				default:
					return destroyed, fmt.Errorf("destroy socket %s->%s: %w", r.local, r.remote, err)
				}
			}
		}
	}
	return destroyed, unsupported
}

// sockDestroy sends one SOCK_DESTROY for the socket a dump reported. The
// request names the socket the way the kernel's own lookup wants it: TCP by
// (local, remote), UDP by the inbound convention (remote, local), both with
// the socket's cookie so a reused port can never hit a newer socket.
func sockDestroy(ctx context.Context, f *os.File, fd, family, protocol int, r socketRow) error {
	local, remote := r.local, r.remote
	if protocol == unix.IPPROTO_UDP {
		local, remote = remote, local
	}
	b := make([]byte, 72)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.SOCK_DESTROY)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	sequence := diagSequence.Add(1)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	b[16] = byte(family)
	b[17] = byte(protocol)
	binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
	// inet_diag_sockid: sport at 24, dport at 26, src at 28, dst at 44,
	// interface at 60, cookie at 64.
	put := func(portAt, addrAt int, a netip.AddrPort) {
		if !a.IsValid() {
			return
		}
		addr := a.Addr()
		if family == unix.AF_INET6 && addr.Is4() {
			addr = netip.AddrFrom16(addr.As16())
		}
		binary.BigEndian.PutUint16(b[portAt:], a.Port())
		copy(b[addrAt:addrAt+16], addr.AsSlice())
	}
	put(24, 28, local)
	put(26, 44, remote)
	binary.NativeEndian.PutUint32(b[64:], uint32(r.cookie))
	binary.NativeEndian.PutUint32(b[68:], uint32(r.cookie>>32))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
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
