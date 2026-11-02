package ownerbpf

import (
	"encoding/binary"
	"errors"
)

const MaxGSOSegmentsPerFrame = 128

var (
	ErrVirtioShortFrame      = errors.New("virtio TUN frame shorter than header")
	ErrVirtioInvalidHeader   = errors.New("invalid virtio or IP/L4 header")
	ErrVirtioUnsupportedGSO  = errors.New("unsupported virtio GSO type")
	ErrVirtioSegmentOverflow = errors.New("GSO segment count exceeds per-frame limit")
	ErrVirtioArenaFull       = errors.New("virtio segment arena full")
)

type VirtioSegmentSpan struct {
	Offset int
	Length int
}

// AppendNormalizedVirtioFrame normalizes a single raw IFF_VNET_HDR TUN frame
// (10-byte native little-endian virtio_net_hdr followed by L3 packet bytes) into
// one or more wire-valid L3/L4 packets appended into arena[arenaUsed:], returning
// the new arenaUsed and appending each segment's [Offset, Length] to spans.
//
// On malformed headers or arena exhaustion, arenaUsed and spans are returned
// unchanged so any previously normalized frames in the same burst remain intact.
// When a single GSO super-packet exceeds MaxGSOSegmentsPerFrame (such as
// pathological TCP_MAXSEG=88), the first MaxGSOSegmentsPerFrame wire-valid
// segments (with FIN/PSH cleared) are emitted alongside ErrVirtioSegmentOverflow
// so TCP sequence numbers continue to advance while counting the overflow drop.
func AppendNormalizedVirtioFrame(
	raw []byte,
	arena []byte,
	arenaUsed int,
	spans []VirtioSegmentSpan,
) (int, []VirtioSegmentSpan, error) {
	if len(raw) <= VirtioNetHdrLen {
		return arenaUsed, spans, ErrVirtioShortFrame
	}
	flags := raw[0]
	gsoType := raw[1] &^ VirtioNetHdrGSOECN
	gsoSize := int(binary.LittleEndian.Uint16(raw[4:6]))
	csumStart := int(binary.LittleEndian.Uint16(raw[6:8]))
	csumOffset := int(binary.LittleEndian.Uint16(raw[8:10]))
	pkt := raw[VirtioNetHdrLen:]

	ipVer := pkt[0] >> 4
	if (ipVer != 4 || len(pkt) < 20) && (ipVer != 6 || len(pkt) < 40) {
		return arenaUsed, spans, ErrVirtioInvalidHeader
	}

	if gsoType == VirtioNetHdrGSONone {
		if arenaUsed+len(pkt) > len(arena) {
			return arenaUsed, spans, ErrVirtioArenaFull
		}
		seg := arena[arenaUsed : arenaUsed+len(pkt)]
		copy(seg, pkt)
		if (flags & VirtioNetHdrFNeedsCsum) != 0 {
			cSumAt := csumStart + csumOffset
			if csumStart < 0 || csumOffset < 0 || cSumAt+2 > len(seg) {
				return arenaUsed, spans, ErrVirtioInvalidHeader
			}
			initial := binary.BigEndian.Uint16(seg[cSumAt : cSumAt+2])
			seg[cSumAt] = 0
			seg[cSumAt+1] = 0
			sum := checksumBytes(uint32(initial), seg[csumStart:])
			folded := ^foldOnesComplement(sum)
			if folded == 0 && ((ipVer == 4 && seg[9] == 17) || (ipVer == 6 && csumOffset == 6)) {
				folded = 0xffff
			}
			binary.BigEndian.PutUint16(seg[cSumAt:cSumAt+2], folded)
		}
		spans = append(spans, VirtioSegmentSpan{Offset: arenaUsed, Length: len(pkt)})
		return arenaUsed + len(pkt), spans, nil
	}

	if gsoSize <= 0 {
		return arenaUsed, spans, ErrVirtioInvalidHeader
	}

	var (
		ipHdrLen int
		l4Off    int
		l4HdrLen int
		isTCP    bool
		proto    uint8
	)

	switch gsoType {
	case VirtioNetHdrGSOTCPv4:
		if ipVer != 4 {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		ipHdrLen = int(pkt[0]&0x0f) * 4
		if ipHdrLen < 20 || len(pkt) < ipHdrLen+20 || pkt[9] != 6 || (binary.BigEndian.Uint16(pkt[6:8])&0x3fff) != 0 {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		l4Off = ipHdrLen
		l4HdrLen = int(pkt[l4Off+12]>>4) * 4
		if l4HdrLen < 20 || len(pkt) < l4Off+l4HdrLen {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		isTCP = true
		proto = 6

	case VirtioNetHdrGSOTCPv6:
		if ipVer != 6 {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		ipHdrLen = 40
		l4Off = 40
		if (flags&VirtioNetHdrFNeedsCsum) != 0 && csumStart >= 40 {
			l4Off = csumStart
		}
		if len(pkt) < l4Off+20 {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		l4HdrLen = int(pkt[l4Off+12]>>4) * 4
		if l4HdrLen < 20 || len(pkt) < l4Off+l4HdrLen {
			return arenaUsed, spans, ErrVirtioInvalidHeader
		}
		isTCP = true
		proto = 6

	case VirtioNetHdrGSOUDPL4:
		if ipVer == 4 {
			ipHdrLen = int(pkt[0]&0x0f) * 4
			if ipHdrLen < 20 || len(pkt) < ipHdrLen+8 || pkt[9] != 17 || (binary.BigEndian.Uint16(pkt[6:8])&0x3fff) != 0 {
				return arenaUsed, spans, ErrVirtioInvalidHeader
			}
			l4Off = ipHdrLen
		} else {
			ipHdrLen = 40
			l4Off = 40
			if (flags&VirtioNetHdrFNeedsCsum) != 0 && csumStart >= 40 {
				l4Off = csumStart
			}
			if len(pkt) < l4Off+8 {
				return arenaUsed, spans, ErrVirtioInvalidHeader
			}
		}
		l4HdrLen = 8
		isTCP = false
		proto = 17

	default:
		return arenaUsed, spans, ErrVirtioUnsupportedGSO
	}

	totalHdrLen := l4Off + l4HdrLen
	payload := pkt[totalHdrLen:]
	numSegs := 1
	if len(payload) > gsoSize {
		numSegs = (len(payload) + gsoSize - 1) / gsoSize
	}
	emitSegs := min(numSegs, MaxGSOSegmentsPerFrame)
	emitPayloadBytes := len(payload)
	if emitSegs < numSegs {
		emitPayloadBytes = emitSegs * gsoSize
	}
	neededBytes := emitSegs*totalHdrLen + emitPayloadBytes
	if arenaUsed+neededBytes > len(arena) {
		return arenaUsed, spans, ErrVirtioArenaFull
	}

	var baseIPID uint16
	if ipVer == 4 {
		baseIPID = binary.BigEndian.Uint16(pkt[4:6])
	}
	var baseSeq uint32
	var origTCPFlags uint8
	if isTCP {
		baseSeq = binary.BigEndian.Uint32(pkt[l4Off+4 : l4Off+8])
		origTCPFlags = pkt[l4Off+13]
	}

	curArena := arenaUsed
	baseSpanLen := len(spans)
	for segIdx, payloadOff := 0, 0; segIdx < emitSegs; segIdx++ {
		chunkLen := min(gsoSize, len(payload)-payloadOff)
		isLast := segIdx == numSegs-1
		segLen := totalHdrLen + chunkLen
		if segLen > 0xffff || (ipVer == 6 && segLen-40 > 0xffff) {
			return arenaUsed, spans[:baseSpanLen], ErrVirtioInvalidHeader
		}
		seg := arena[curArena : curArena+segLen]
		copy(seg[:totalHdrLen], pkt[:totalHdrLen])
		copy(seg[totalHdrLen:], payload[payloadOff:payloadOff+chunkLen])

		if ipVer == 4 {
			binary.BigEndian.PutUint16(seg[2:4], uint16(segLen))
			binary.BigEndian.PutUint16(seg[4:6], baseIPID+uint16(segIdx))
			seg[10] = 0
			seg[11] = 0
			ipSum := ^foldOnesComplement(checksumBytes(0, seg[:ipHdrLen]))
			binary.BigEndian.PutUint16(seg[10:12], ipSum)
		} else {
			binary.BigEndian.PutUint16(seg[4:6], uint16(segLen-40))
		}

		if isTCP {
			binary.BigEndian.PutUint32(seg[l4Off+4:l4Off+8], baseSeq+uint32(payloadOff))
			f := origTCPFlags
			if !isLast {
				f &^= (0x01 | 0x08) // clear FIN and PSH on non-final segments
			}
			if segIdx > 0 {
				f &^= 0x80 // clear CWR on non-first segments
			}
			seg[l4Off+13] = f
			seg[l4Off+16] = 0
			seg[l4Off+17] = 0
			csum := transportChecksum(ipVer, seg, l4Off, proto, false)
			binary.BigEndian.PutUint16(seg[l4Off+16:l4Off+18], csum)
		} else {
			binary.BigEndian.PutUint16(seg[l4Off+4:l4Off+6], uint16(8+chunkLen))
			seg[l4Off+6] = 0
			seg[l4Off+7] = 0
			csum := transportChecksum(ipVer, seg, l4Off, proto, true)
			binary.BigEndian.PutUint16(seg[l4Off+6:l4Off+8], csum)
		}

		spans = append(spans, VirtioSegmentSpan{Offset: curArena, Length: segLen})
		curArena += segLen
		payloadOff += chunkLen
	}
	if emitSegs < numSegs {
		return curArena, spans, ErrVirtioSegmentOverflow
	}
	return curArena, spans, nil
}

func checksumBytes(sum uint32, b []byte) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	return sum
}

func foldOnesComplement(sum uint32) uint16 {
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func transportChecksum(ipVer uint8, pkt []byte, l4Off int, proto uint8, zeroIsFFFF bool) uint16 {
	l4Len := uint32(len(pkt) - l4Off)
	var sum uint32
	if ipVer == 4 {
		sum = checksumBytes(0, pkt[12:20])
		sum += uint32(proto)
		sum += l4Len
	} else {
		sum = checksumBytes(0, pkt[8:40])
		sum += (l4Len >> 16) + (l4Len & 0xffff)
		sum += uint32(proto)
	}
	sum = checksumBytes(sum, pkt[l4Off:])
	folded := ^foldOnesComplement(sum)
	if zeroIsFFFF && folded == 0 {
		return 0xffff
	}
	return folded
}
