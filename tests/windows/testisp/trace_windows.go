//go:build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type tcpObservation struct {
	At        int64  `json:"at"`
	Direction string `json:"direction"`
	packetFields
	Header traceHeader `json:"header"`
}

type packetFields struct {
	Source        uint16 `json:"source"`
	Target        uint16 `json:"target"`
	Flags         byte   `json:"flags"`
	Sequence      uint32 `json:"sequence"`
	Ack           uint32 `json:"ack"`
	Payload       int    `json:"payloadBytes"`
	Window        uint16 `json:"window"`
	IPChecksumOK  bool   `json:"ipChecksumOK"`
	TCPChecksumOK bool   `json:"tcpChecksumOK"`
}

type traceHeader struct {
	data [60]byte
	n    uint8
}

func (h traceHeader) MarshalJSON() ([]byte, error) {
	out := make([]byte, 2+2*int(h.n))
	out[0], out[len(out)-1] = '"', '"'
	hex.Encode(out[1:], h.data[:h.n])
	return out, nil
}

// Keep writes constant-cost. Readers receive the same chronological tail.
type tcpTraceTail struct {
	rows [256]tcpObservation
	next uint64
}

func (t *tcpTraceTail) add(item tcpObservation) {
	t.rows[t.next%uint64(len(t.rows))] = item
	t.next++
}

func (t *tcpTraceTail) MarshalJSON() ([]byte, error) {
	if t.next == 0 {
		return []byte("null"), nil
	}
	if t.next <= uint64(len(t.rows)) {
		return json.Marshal(t.rows[:t.next])
	}
	oldest := int(t.next % uint64(len(t.rows)))
	rows := make([]tcpObservation, len(t.rows))
	n := copy(rows, t.rows[oldest:])
	copy(rows[n:], t.rows[:oldest])
	return json.Marshal(rows)
}

// A short header-only tail makes passive-close failures diagnosable without a
// large packet capture or collecting application payloads.
func (g *gateway) trace(packet []byte, labels *traceLabels) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return
	}
	target := [4]byte{198, 19, 128, 2}
	if [4]byte(packet[12:16]) != target && [4]byte(packet[16:20]) != target {
		return
	}
	offset := int(packet[0]&15) * 4
	if offset < 20 || offset+20 > len(packet) {
		return
	}
	tcp := packet[offset:]
	item := tcpObservation{At: time.Now().UnixMicro(), Direction: labels.direction, packetFields: packetFields{Source: binary.BigEndian.Uint16(tcp), Target: binary.BigEndian.Uint16(tcp[2:]), Flags: tcp[13], Sequence: binary.BigEndian.Uint32(tcp[4:]), Ack: binary.BigEndian.Uint32(tcp[8:])}}
	item.Payload = len(tcp) - int(tcp[12]>>4)*4
	item.Window = binary.BigEndian.Uint16(tcp[14:])
	item.IPChecksumOK = checksum.Checksum(packet[:offset], 0) == 0xffff
	pseudo := header.PseudoHeaderChecksum(6, tcpip.AddrFromSlice(packet[12:16]), tcpip.AddrFromSlice(packet[16:20]), uint16(len(tcp)))
	item.TCPChecksumOK = checksum.Checksum(tcp, pseudo) == 0xffff
	if h := int(tcp[12]>>4) * 4; h >= 20 && h <= len(tcp) {
		item.Header.n = uint8(copy(item.Header.data[:], tcp[:h]))
	}
	if labels != traceDelivered {
		g.diag.Lock()
		if g.diag.wire == nil {
			g.diag.wire = make(map[string]uint64)
		}
		g.diag.wire[labels.segments]++
		if item.Flags&2 != 0 {
			if item.Flags&16 != 0 {
				g.diag.wire[labels.synack]++
			} else {
				g.diag.wire[labels.syn]++
			}
		}
		if item.Flags&1 != 0 {
			g.diag.wire[labels.fin]++
		}
		g.diag.Unlock()
	}
	g.states()
	g.captureEvent(diagnosticEvent{Kind: labels.event, packet: true, fields: item.packetFields})
	g.stats.Lock()
	defer g.stats.Unlock()
	g.stats.TCPTrace.add(item)
}

type traceLabels struct {
	direction, event, segments, synack, syn, fin string
}

func newTraceLabels(direction string) *traceLabels {
	return &traceLabels{direction, "packet-" + direction, direction + "-segments", direction + "-synack", direction + "-syn", direction + "-fin"}
}

var traceRequest = newTraceLabels("request")
var traceReply = newTraceLabels("reply")
var traceDelivered = newTraceLabels("delivered")
