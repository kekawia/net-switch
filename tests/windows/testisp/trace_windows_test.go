//go:build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type traceEndpoint struct{ tcpip.Endpoint }

func (traceEndpoint) State() uint32 { return uint32(tcp.StateEstablished) }

func traceFixture(t testing.TB) (*gateway, []byte) {
	t.Helper()
	g := &gateway{stack: stack.New(stack.Options{}), device: &observedDevice{}}
	t.Cleanup(func() { g.stack.Close(); g.stack.Wait() })
	for range 64 {
		g.diag.endpoints = append(g.diag.endpoints, watchedEndpoint{endpoint: traceEndpoint{}, state: uint32(tcp.StateEstablished)})
	}
	p := make([]byte, 1460)
	p[0], p[8], p[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{198, 19, 128, 2})
	binary.BigEndian.PutUint16(p[10:12], ^checksum.Checksum(p[:20], 0))
	binary.BigEndian.PutUint16(p[20:22], 12001)
	binary.BigEndian.PutUint16(p[22:24], 443)
	p[32], p[33] = 0x50, 0x10
	binary.BigEndian.PutUint16(p[34:36], 32000)
	return g, p
}

func setTraceSequence(p []byte, seq uint32) {
	binary.BigEndian.PutUint32(p[24:28], seq)
	binary.BigEndian.PutUint16(p[36:38], 0)
	pseudo := header.PseudoHeaderChecksum(6, tcpip.AddrFromSlice(p[12:16]), tcpip.AddrFromSlice(p[16:20]), uint16(len(p)-20))
	binary.BigEndian.PutUint16(p[36:38], ^checksum.Checksum(p[20:], pseudo))
}

func TestTraceTailPreservesEvidence(t *testing.T) {
	g, p := traceFixture(t)
	stats := g.stack.Stats()
	stats.TCP.Retransmits.IncrementBy(1)
	stats.TCP.Timeouts.IncrementBy(2)
	stats.DroppedPackets.IncrementBy(3)
	stats.TCP.InvalidSegmentsReceived.IncrementBy(4)
	stats.TCP.SegmentSendErrors.IncrementBy(5)
	g.device.writeDrops.Store(6)
	for i := range 300 {
		setTraceSequence(p, uint32(i))
		g.trace(p, traceRequest)
	}
	var response struct {
		Trace []struct {
			Sequence                    uint32
			Header, Direction           string
			IPChecksumOK, TCPChecksumOK bool
		} `json:"tcpTrace"`
	}
	raw, err := json.Marshal(&g.stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Trace) != 256 {
		t.Fatal(len(response.Trace))
	}
	for i, row := range response.Trace {
		seq := uint32(i + 44)
		setTraceSequence(p, seq)
		if row.Sequence != seq || row.Direction != "request" || row.Header != hex.EncodeToString(p[20:40]) || !row.IPChecksumOK || !row.TCPChecksumOK {
			t.Fatalf("trace entry %d lost evidence: %+v", i, row)
		}
	}
	last := g.diag.events[(g.diag.next-1)%uint64(len(g.diag.events))]
	raw, err = json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Kind, Tuple, Detail string
		Counters            map[string]uint64
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	expected := map[string]uint64{"retransmits": 1, "timeouts": 2, "dropped": 3, "invalid": 4, "sendErrors": 5, "sessionWriteDrops": 6}
	if event.Kind != "packet-request" || event.Tuple != "12001 -> 443" || event.Detail != "flags=10 seq=299 ack=0 bytes=1420 ipOK=true tcpOK=true window=32000" || !reflect.DeepEqual(event.Counters, expected) {
		t.Fatalf("packet event changed: %s", raw)
	}
	// Delivered observations still validate the actual bytes independently.
	p[len(p)-1] ^= 1
	g.trace(p, traceDelivered)
	raw, err = json.Marshal(&g.stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	tail := response.Trace[len(response.Trace)-1]
	if tail.Direction != "delivered" || !tail.IPChecksumOK || tail.TCPChecksumOK || g.diag.wire["request-segments"] != 300 {
		t.Fatal("checksum failure or original wire count was lost")
	}
}

func BenchmarkGatewayPacketTrace(b *testing.B) {
	g, p := traceFixture(b)
	setTraceSequence(p, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.trace(p, traceRequest)
	}
}
