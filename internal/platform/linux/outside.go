// Package linuxplatform implements Linux worker streams and one-shot queries
// for Control's platform boundary.
package linuxplatform

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/platform/outside"
)

const (
	linuxAFInet            = 2
	linuxAFInet6           = 10
	linuxIPProtoTCP        = 6
	linuxTCPEstablished    = 1
	linuxTCPEstablishedBit = 1 << linuxTCPEstablished

	linuxInetDiagInfo    = 2
	linuxInetDiagInfoExt = 1 << (linuxInetDiagInfo - 1)

	// Verified offsets in Linux UAPI struct tcp_info (v5.8+ on 64-bit little-endian;
	// checked against golang.org/x/sys/unix.TCPInfo in outside_linux_test.go).
	tcpInfoBytesAckedOffset    = 120
	tcpInfoBytesReceivedOffset = 128
	tcpInfoBytesSentOffset     = 200
)

type diagSocket struct {
	family   int
	state    uint8
	local    netip.AddrPort
	remote   netip.AddrPort
	ifindex  uint32
	cookie   uint64
	uid      uint32
	inode    uint32
	down, up uint64
	measured bool
	fresh    bool
}

func parseInetDiagMsg(b []byte) (diagSocket, error) {
	var r diagSocket
	if len(b) < 72 {
		return r, errors.New("short inet_diag message")
	}
	var src, dst netip.Addr
	switch b[0] {
	case linuxAFInet:
		src = netip.AddrFrom4([4]byte(b[8:12]))
		dst = netip.AddrFrom4([4]byte(b[24:28]))
	case linuxAFInet6:
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
	default:
		return r, errors.New("unknown inet_diag family")
	}
	r.family = int(b[0])
	r.state = b[1]
	r.local = netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(b[4:6]))
	r.remote = netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(b[6:8]))
	r.ifindex = binary.LittleEndian.Uint32(b[40:44])
	r.cookie = uint64(binary.LittleEndian.Uint32(b[44:48])) | uint64(binary.LittleEndian.Uint32(b[48:52]))<<32
	r.uid = binary.LittleEndian.Uint32(b[64:68])
	r.inode = binary.LittleEndian.Uint32(b[68:72])
	for off := 72; off+4 <= len(b); {
		n := int(binary.LittleEndian.Uint16(b[off:]))
		kind := binary.LittleEndian.Uint16(b[off+2:]) & 0x3fff
		if n < 4 || off+n > len(b) {
			return r, errors.New("invalid inet_diag attribute")
		}
		if kind == linuxInetDiagInfo {
			if down, up, ok := parseTCPInfo(b[off+4 : off+n]); ok {
				r.down, r.up, r.measured = down, up, true
			}
		}
		off += (n + 3) &^ 3
	}
	return r, nil
}

func parseTCPInfo(info []byte) (down, up uint64, ok bool) {
	if len(info) >= tcpInfoBytesSentOffset+8 {
		return binary.LittleEndian.Uint64(info[tcpInfoBytesReceivedOffset:]),
			binary.LittleEndian.Uint64(info[tcpInfoBytesSentOffset:]),
			true
	}
	if len(info) >= tcpInfoBytesReceivedOffset+8 {
		return binary.LittleEndian.Uint64(info[tcpInfoBytesReceivedOffset:]),
			binary.LittleEndian.Uint64(info[tcpInfoBytesAckedOffset:]),
			true
	}
	return 0, 0, false
}

func parseSocketLink(b []byte) (uint32, bool) {
	if len(b) < 10 || !bytes.HasPrefix(b, []byte("socket:[")) || b[len(b)-1] != ']' {
		return 0, false
	}
	var v uint64
	digits := b[8 : len(b)-1]
	for _, ch := range digits {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		v = v*10 + uint64(ch-'0')
		if v > math.MaxUint32 {
			return 0, false
		}
	}
	return uint32(v), v != 0
}

func parseProcessStatStart(b []byte) (uint64, error) {
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return 0, errors.New("bad process stat")
	}
	// Field 22 (starttime) is the 20th whitespace-separated token after ')'.
	pos := end + 1
	for field := 0; field < 20; field++ {
		for pos < len(b) && (b[pos] == ' ' || b[pos] == '\t' || b[pos] == '\n') {
			pos++
		}
		start := pos
		for pos < len(b) && b[pos] != ' ' && b[pos] != '\t' && b[pos] != '\n' {
			pos++
		}
		if start == pos {
			return 0, errors.New("short process stat")
		}
		if field == 19 {
			return strconv.ParseUint(string(b[start:pos]), 10, 64)
		}
	}
	return 0, errors.New("short process stat")
}

func formatProcessStarted(startTicks uint64, cookie uint64) string {
	return strconv.FormatUint(startTicks, 10) + ":" + strconv.FormatUint(cookie, 16)
}

func parseProcessStarted(s string) (startTicks uint64, cookie uint64, hasCookie bool, ok bool) {
	startPart, cookiePart, found := strings.Cut(s, ":")
	if startPart == "" {
		return 0, 0, false, false
	}
	start, err := strconv.ParseUint(startPart, 10, 64)
	if err != nil || start == 0 {
		return 0, 0, false, false
	}
	if !found {
		return start, 0, false, true
	}
	if cookiePart == "" {
		return 0, 0, false, false
	}
	c, err := strconv.ParseUint(cookiePart, 16, 64)
	if err != nil || c == 0 {
		return 0, 0, false, false
	}
	return start, c, true, true
}

func formatOutsideCreated(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.0000000") + "Z"
}

type procOwner struct {
	pid   uint32
	start uint64
	path  string
}

type linuxSource struct {
	now     func() time.Time
	dump    func() ([]diagSocket, error)
	owners  func(inodes map[uint32]struct{}) map[uint32]procOwner
	readOne func(s diagSocket) (down, up uint64, ok bool)
}

func newLinuxWatcher(engine string, src linuxSource) *outside.Watcher[diagSocket] {
	nowFn := src.now
	if nowFn == nil {
		nowFn = time.Now
	}
	createdByCookie := map[uint64]string{}
	ownersByPID := map[uint32]procOwner{}

	return outside.NewWatcher(engine, outside.System[diagSocket]{
		Estats:     true,
		RefreshRow: true,
		Connections: func() ([]outside.Connection[diagSocket], error) {
			rows, err := src.dump()
			if err != nil {
				return nil, err
			}
			candidates := make([]diagSocket, 0, len(rows))
			needInodes := map[uint32]struct{}{}
			for _, r := range rows {
				if r.state != linuxTCPEstablished || r.cookie == 0 || !r.local.Addr().Is4() || !r.remote.Addr().Is4() {
					continue
				}
				if outside.Ignored(r.local.Addr().String(), r.remote.Addr().String()) {
					continue
				}
				candidates = append(candidates, r)
				if r.inode != 0 {
					needInodes[r.inode] = struct{}{}
				}
			}
			var byInode map[uint32]procOwner
			if len(needInodes) > 0 && src.owners != nil {
				byInode = src.owners(needInodes)
			}
			activeCookies := make(map[uint64]bool, len(candidates))
			ownersByPID = map[uint32]procOwner{}
			out := make([]outside.Connection[diagSocket], 0, len(candidates))
			stamp := ""
			for _, r := range candidates {
				owner := byInode[r.inode]
				if owner.pid == 0 {
					continue
				}
				activeCookies[r.cookie] = true
				ownersByPID[owner.pid] = owner
				created := createdByCookie[r.cookie]
				if created == "" {
					if stamp == "" {
						stamp = formatOutsideCreated(nowFn())
					}
					created = stamp
					createdByCookie[r.cookie] = created
				}
				r.fresh = true
				out = append(out, outside.Connection[diagSocket]{
					Established: true,
					Local:       r.local.Addr().As4(),
					LocalPort:   r.local.Port(),
					Remote:      r.remote.Addr().As4(),
					RemotePort:  r.remote.Port(),
					PID:         owner.pid,
					Created:     created,
					Row:         r,
				})
			}
			for cookie := range createdByCookie {
				if !activeCookies[cookie] {
					delete(createdByCookie, cookie)
				}
			}
			return out, nil
		},
		ProcessPath: func(pid uint32) string {
			return ownersByPID[pid].path
		},
		ProcessStart: func(pid uint32, row *diagSocket) string {
			o := ownersByPID[pid]
			if o.start == 0 || row.cookie == 0 {
				return ""
			}
			return formatProcessStarted(o.start, row.cookie)
		},
		Read: func(row *diagSocket) (uint64, uint64, bool) {
			if row.fresh {
				row.fresh = false
				return row.down, row.up, row.measured
			}
			if src.readOne == nil {
				return 0, 0, false
			}
			return src.readOne(*row)
		},
	})
}

type closeOps struct {
	processStart  func(pid uint32) (uint64, error)
	findSocket    func(local, remote netip.AddrPort, cookie uint64) (diagSocket, bool, error)
	pidHoldsInode func(pid uint32, inode uint32) (bool, error)
	destroy       func(s diagSocket) error
	isGone        func(err error) bool
	isUnsupported func(err error) bool
}

func decodeSelectors(args map[string]any) ([]platform.TCPSelector, error) {
	if args == nil || args["connections"] == nil {
		return nil, nil
	}
	if direct, ok := args["connections"].([]platform.TCPSelector); ok {
		return direct, nil
	}
	b, err := json.Marshal(args["connections"])
	if err != nil {
		return nil, err
	}
	var out []platform.TCPSelector
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func validPort(v float64) (uint16, bool) {
	if v < 1 || v > math.MaxUint16 || math.Trunc(v) != v {
		return 0, false
	}
	return uint16(v), true
}

func validPID(v float64) (uint32, bool) {
	if v < 1 || v > math.MaxUint32 || math.Trunc(v) != v {
		return 0, false
	}
	return uint32(v), true
}

func closeConnections(tuples []platform.TCPSelector, ops closeOps) (map[string]any, error) {
	closed, failed, gone := 0, 0, 0
	codes := []string{}
	if len(tuples) == 0 {
		return map[string]any{"closed": 0, "failed": 0, "gone": 0, "codes": codes}, nil
	}
	for i, t := range tuples {
		pid, okPID := validPID(t.PID)
		lport, okLP := validPort(t.LPort)
		rport, okRP := validPort(t.RPort)
		localIP, errL := netip.ParseAddr(t.Local)
		remoteIP, errR := netip.ParseAddr(t.Remote)
		if !okPID || !okLP || !okRP || errL != nil || errR != nil || !localIP.Is4() || !remoteIP.Is4() {
			gone++
			continue
		}
		var wantStart, wantCookie uint64
		if t.ProcessStarted != "" {
			var ok bool
			wantStart, wantCookie, _, ok = parseProcessStarted(t.ProcessStarted)
			if !ok {
				gone++
				continue
			}
		}
		startBefore, err := ops.processStart(pid)
		if err != nil || (wantStart != 0 && startBefore != wantStart) {
			gone++
			continue
		}
		sock, found, err := ops.findSocket(netip.AddrPortFrom(localIP, lport), netip.AddrPortFrom(remoteIP, rport), wantCookie)
		if err != nil {
			return nil, err
		}
		if !found || sock.inode == 0 {
			gone++
			continue
		}
		held, err := ops.pidHoldsInode(pid, sock.inode)
		if err != nil || !held {
			gone++
			continue
		}
		startAfter, err := ops.processStart(pid)
		if err != nil || startAfter != startBefore {
			gone++
			continue
		}
		err = ops.destroy(sock)
		switch {
		case err == nil:
			closed++
		case ops.isGone != nil && ops.isGone(err):
			gone++
		case ops.isUnsupported != nil && ops.isUnsupported(err):
			failed += len(tuples) - i
			codes = append(codes, "not supported here")
			return map[string]any{
				"closed": closed,
				"failed": failed,
				"gone":   gone,
				"codes":  codes,
				"reason": "not supported here",
			}, nil
		default:
			failed++
			codes = append(codes, fmt.Sprint(err))
		}
	}
	return map[string]any{"closed": closed, "failed": failed, "gone": gone, "codes": codes}, nil
}
