//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// RejectionEvidence is immutable, private evidence captured before releasing
// the rejected slot. Hex is capped separately from the comparison: both copies
// include at most MaxPacketSize bytes, and neither can ever be delivered.
type RejectionEvidence struct {
	Kind                                             string `json:"kind"`
	Head, Tail, TailAgain, Size, SizeAgain, Capacity uint32
	CopyOffset, CopyLength                           int
	FirstHex, SecondHex                              string
	Changed                                          bool
	Primary, Independent                             packetDiagnosis
}

type packetDiagnosis struct {
	Predicate string
	// Folded sums include the received checksum; a valid sum is 65535.
	// -1 means not evaluated (length/fragment/protocol/optional checksum).
	IPv4Sum, TransportSum int
}

type rejectionError struct {
	reason   string
	evidence RejectionEvidence
}

func (e *rejectionError) Unwrap() error { return ErrCorrupt }
func (e *rejectionError) Error() string {
	b, _ := json.Marshal(e.evidence)
	return fmt.Sprintf("%v: Send %s rejection=%s", ErrCorrupt, e.reason, b)
}

// All callers are rejection branches. The successful entry/read/validIP path
// performs no extra loads, copies, checksums, allocations or logging for this
// diagnostic. Bounds use the ORIGINAL acquired Tail, never the second load.
func captureRejection(r ring, reason string, head, tail, size uint32, first []byte, rejectedReread ...uint32) error {
	e := RejectionEvidence{Kind: "ring_framing_rejection", Head: head, Tail: tail, Size: size, Capacity: r.capacity,
		Primary: packetDiagnosis{"not_evaluated", -1, -1}, Independent: packetDiagnosis{"not_evaluated", -1, -1}}
	data := r.data()
	// entry has already validated these bounds. Keep this helper safe in tests
	// and if a future call site supplies invalid cursors.
	if validCapacity(r.capacity) && head < r.capacity && tail < r.capacity && (head|tail)&3 == 0 && len(data) >= int(r.capacity)+ringSlack {
		e.SizeAgain = binary.LittleEndian.Uint32(data[head : head+4])
		if len(rejectedReread) != 0 {
			e.SizeAgain = rejectedReread[0]
		}
		e.TailAgain = r.load(4)
		offset := 0
		if first != nil {
			offset = 4
		}
		n := min(int((tail-head)&(r.capacity-1))-offset, MaxPacketSize)
		if first != nil {
			n = min(n, len(first))
		}
		if n > 0 {
			if first == nil {
				first = bytes.Clone(data[int(head) : int(head)+n])
			} else {
				first = first[:n]
			}
			// Take the second bounded copy BEFORE parsing or formatting. Head is
			// still held; formatting time cannot create a false comparison window.
			second := bytes.Clone(data[int(head)+offset : int(head)+offset+n])
			e.CopyOffset, e.CopyLength = offset, n
			e.Changed = !bytes.Equal(first, second)
			e.FirstHex = hex.EncodeToString(first[:min(n, 256)])
			e.SecondHex = hex.EncodeToString(second[:min(n, 256)])
			if reason == "packet failed validation" {
				e.Kind = "packet_content_rejection"
				e.Primary = diagnoseIP(first)
				e.Independent = independentlyDiagnoseIP(first)
			}
		}
	}
	return &rejectionError{reason, e}
}

// Failure-only explanation of validIP using its production checksum helpers.
// Keep predicate order identical; parity tests cover valid and damaged inputs.
func diagnoseIP(p []byte) (d packetDiagnosis) {
	d = packetDiagnosis{"version", -1, -1}
	if len(p) == 0 {
		return
	}
	var src, dst netip.Addr
	var protocol byte
	var payload []byte
	switch p[0] >> 4 {
	case 4:
		d.Predicate = "ihl"
		if len(p) < 20 {
			return
		}
		n := int(p[0]&15) * 4
		if n < 20 || n > len(p) {
			return
		}
		d.Predicate = "total_length"
		if int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			return
		}
		d.Predicate = "ipv4_checksum"
		d.IPv4Sum = int(checksum.Checksum(p[:n], 0))
		if d.IPv4Sum != 65535 {
			return
		}
		d.Predicate = ""
		if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return
		}
		src, dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		protocol, payload = p[9], p[n:]
	case 6:
		d.Predicate = "total_length"
		if len(p) < 40 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
			return
		}
		src, dst = netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
		protocol, payload = p[6], p[40:]
		d.Predicate = "extension_length"
		for protocol == 0 || protocol == 43 || protocol == 60 {
			if len(payload) < 8 {
				return
			}
			n := (int(payload[1]) + 1) * 8
			if n > len(payload) {
				return
			}
			protocol, payload = payload[0], payload[n:]
		}
		if protocol == 44 {
			if len(payload) >= 8 {
				d.Predicate = ""
			}
			return
		}
	default:
		return
	}
	d.Predicate = "transport_length"
	switch protocol {
	case 6:
		if len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload) {
			return
		}
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return
		}
		if src.Is4() && binary.BigEndian.Uint16(payload[6:8]) == 0 {
			d.Predicate = ""
			return
		}
	default:
		d.Predicate = ""
		return
	}
	d.TransportSum = int(checksum.Checksum(payload, packet.Sum(nil, packet.Pseudo(src, dst, protocol, len(payload)))))
	d.Predicate = ""
	if d.TransportSum != 65535 {
		if protocol == 6 {
			d.Predicate = "tcp_checksum"
		} else {
			d.Predicate = "udp_checksum"
		}
	}
	return
}

// Independent offset-based parser. No production packet, pseudo-header or
// checksum helpers are used here. This is evidence, never an acceptance gate.
func independentlyDiagnoseIP(p []byte) (d packetDiagnosis) {
	d = packetDiagnosis{"version", -1, -1}
	if len(p) == 0 {
		return
	}
	word := func(i int) int { return int(p[i])*256 + int(p[i+1]) }
	version, offset, proto := int(p[0]/16), 0, 0
	var pseudo []byte
	if version == 4 {
		d.Predicate = "ihl"
		if len(p) < 20 {
			return
		}
		offset = int(p[0]%16) * 4
		if offset < 20 || offset > len(p) {
			return
		}
		d.Predicate = "total_length"
		if word(2) != len(p) {
			return
		}
		d.Predicate = "ipv4_checksum"
		d.IPv4Sum = independentSum(p[:offset])
		if d.IPv4Sum != 65535 {
			return
		}
		d.Predicate = ""
		if word(6)&16383 != 0 {
			return
		}
		proto = int(p[9])
		pseudo = append(pseudo, p[12:20]...)
	} else if version == 6 {
		d.Predicate = "total_length"
		if len(p) < 40 || word(4) != len(p)-40 {
			return
		}
		offset, proto = 40, int(p[6])
		pseudo = append(pseudo, p[8:40]...)
		d.Predicate = "extension_length"
		for proto == 0 || proto == 43 || proto == 60 {
			if len(p)-offset < 8 {
				return
			}
			next := offset + 8*(int(p[offset+1])+1)
			if next > len(p) {
				return
			}
			proto, offset = int(p[offset]), next
		}
		if proto == 44 {
			if len(p)-offset >= 8 {
				d.Predicate = ""
			}
			return
		}
	} else {
		return
	}
	d.Predicate = "transport_length"
	n := len(p) - offset
	if proto == 6 {
		if n < 20 {
			return
		}
		header := int(p[offset+12]/16) * 4
		if header < 20 || header > n {
			return
		}
	} else if proto == 17 {
		if n < 8 || word(offset+4) != n {
			return
		}
		if version == 4 && word(offset+6) == 0 {
			d.Predicate = ""
			return
		}
	} else {
		d.Predicate = ""
		return
	}
	if version == 4 {
		pseudo = append(pseudo, 0, byte(proto), byte(n>>8), byte(n))
	} else {
		pseudo = append(pseudo, 0, 0, byte(n>>8), byte(n), 0, 0, 0, byte(proto))
	}
	pseudo = append(pseudo, p[offset:]...)
	d.TransportSum = independentSum(pseudo)
	d.Predicate = ""
	if d.TransportSum != 65535 {
		if proto == 6 {
			d.Predicate = "tcp_checksum"
		} else {
			d.Predicate = "udp_checksum"
		}
	}
	return
}

func independentSum(p []byte) int {
	sum := uint32(0)
	for i, b := range p {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return int(sum)
}
