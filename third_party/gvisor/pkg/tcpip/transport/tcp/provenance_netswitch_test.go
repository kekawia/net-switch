// Net Switch addition, not upstream.
// Licensed under the MIT license; see the repository LICENSE.

package tcp

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type testProvenanceEnv struct {
	owner   string
	cookie  uint64
	serial  uint64
	unknown bool
}

func (e *testProvenanceEnv) NetSwitchMissingProvenance() any {
	return &testProvenanceEnv{unknown: true}
}

func (e *testProvenanceEnv) MergeNetSwitchProvenance(other any) any {
	o, ok := other.(*testProvenanceEnv)
	if !ok || o == nil || e.unknown || o.unknown || e.cookie == 0 || e.cookie != o.cookie || e.owner == "" || e.owner != o.owner {
		return &testProvenanceEnv{unknown: true}
	}
	return &testProvenanceEnv{owner: e.owner, cookie: e.cookie}
}

func buildTestIPv4TCPSYN(src, dst netip.Addr, sport, dport uint16, options, payload []byte) []byte {
	tcpLen := header.TCPMinimumSize + len(options)
	totalLen := header.IPv4MinimumSize + tcpLen + len(payload)
	raw := make([]byte, totalLen)
	ip := header.IPv4(raw[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	th := header.TCP(raw[header.IPv4MinimumSize : header.IPv4MinimumSize+tcpLen])
	th.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     1000,
		DataOffset: uint8(tcpLen),
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	copy(raw[header.IPv4MinimumSize+header.TCPMinimumSize:], options)
	copy(raw[header.IPv4MinimumSize+tcpLen:], payload)

	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFrom4(src.As4()),
		tcpip.AddrFrom4(dst.As4()),
		uint16(tcpLen+len(payload)),
	)
	xsum = checksum.Checksum(payload, xsum)
	th.SetChecksum(^th.CalculateChecksum(xsum))
	return raw
}

func fragmentIPv4Packet(full []byte, ipID uint16, firstPayloadBytes int) ([]byte, []byte) {
	origIP := header.IPv4(full[:header.IPv4MinimumSize])
	body := full[header.IPv4MinimumSize:]

	frag0 := make([]byte, header.IPv4MinimumSize+firstPayloadBytes)
	copy(frag0[:header.IPv4MinimumSize], origIP)
	copy(frag0[header.IPv4MinimumSize:], body[:firstPayloadBytes])
	ip0 := header.IPv4(frag0)
	ip0.SetID(ipID)
	ip0.SetTotalLength(uint16(len(frag0)))
	ip0.SetFlagsFragmentOffset(header.IPv4FlagMoreFragments, 0)
	ip0.SetChecksum(0)
	ip0.SetChecksum(^ip0.CalculateChecksum())

	rest := body[firstPayloadBytes:]
	frag1 := make([]byte, header.IPv4MinimumSize+len(rest))
	copy(frag1[:header.IPv4MinimumSize], origIP)
	copy(frag1[header.IPv4MinimumSize:], rest)
	ip1 := header.IPv4(frag1)
	ip1.SetID(ipID)
	ip1.SetTotalLength(uint16(len(frag1)))
	ip1.SetFlagsFragmentOffset(0, uint16(firstPayloadBytes))
	ip1.SetChecksum(0)
	ip1.SetChecksum(^ip1.CalculateChecksum())
	return frag0, frag1
}

func TestPacketBufferProvenanceCloneDeepCopyAndReset(t *testing.T) {
	raw := buildTestIPv4TCPSYN(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("93.184.216.34"),
		42000,
		443,
		nil,
		nil,
	)
	env := &testProvenanceEnv{owner: "app-a", cookie: 0x101, serial: 1}
	pk := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	pk.NetSwitchProvenance = env
	if _, ok := pk.NetworkHeader().Consume(header.IPv4MinimumSize); !ok {
		t.Fatal("consume network header")
	}
	pk.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if _, ok := pk.TransportHeader().Consume(header.TCPMinimumSize); !ok {
		t.Fatal("consume transport header")
	}
	pk.TransportProtocolNumber = header.TCPProtocolNumber

	cloned := pk.Clone()
	if cloned.NetSwitchProvenance != env {
		t.Fatalf("Clone provenance = %#v, want %p", cloned.NetSwitchProvenance, env)
	}
	inbound := pk.CloneToInbound()
	if inbound.NetSwitchProvenance != env {
		t.Fatalf("CloneToInbound provenance = %#v, want %p", inbound.NetSwitchProvenance, env)
	}
	deep := pk.DeepCopyForForwarding(header.IPv4MinimumSize + header.TCPMinimumSize)
	if deep.NetSwitchProvenance != env {
		t.Fatalf("DeepCopyForForwarding provenance = %#v, want %p", deep.NetSwitchProvenance, env)
	}

	deep.DecRef()
	inbound.DecRef()
	cloned.DecRef()
	pk.DecRef()

	for i := 0; i < 16; i++ {
		reused := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		if reused.NetSwitchProvenance != nil {
			reused.DecRef()
			t.Fatalf("reused PacketBuffer retained stale NetSwitchProvenance: %#v", reused.NetSwitchProvenance)
		}
		reused.DecRef()
	}
}

func TestForwarderAndReassemblyNetSwitchProvenance(t *testing.T) {
	const nicID tcpip.NICID = 1
	ep := channel.New(16, 1500, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	defer s.Wait()
	defer s.Close()
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		t.Fatalf("SetPromiscuousMode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		t.Fatalf("SetSpoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	type observed struct {
		before any
		after  any
	}
	gotCh := make(chan observed, 8)
	fwd := NewForwarder(s, 65535, 64, func(r *ForwarderRequest) {
		before := r.NetSwitchProvenance()
		r.Complete(false)
		after := r.NetSwitchProvenance()
		gotCh <- observed{before: before, after: after}
	})
	s.SetTransportProtocolHandler(ProtocolNumber, fwd.HandlePacket)

	await := func(t *testing.T) observed {
		t.Helper()
		select {
		case obs := <-gotCh:
			if obs.after != nil {
				t.Fatalf("NetSwitchProvenance after Complete = %#v, want nil", obs.after)
			}
			return obs
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for ForwarderRequest")
			return observed{}
		}
	}
	inject := func(raw []byte, prov any) {
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
		pk.NetSwitchProvenance = prov
		ep.InjectInbound(header.IPv4ProtocolNumber, pk)
		pk.DecRef()
	}

	// 1. Bare SYN and Fast Open SYN+payload preserve exact provenance pointer across newIncomingSegment clone.
	synEnv := &testProvenanceEnv{owner: "app-syn", cookie: 0x201, serial: 10}
	inject(buildTestIPv4TCPSYN(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"), 50001, 443, nil, nil), synEnv)
	if obs := await(t); obs.before != synEnv {
		t.Fatalf("bare SYN provenance = %#v, want %p", obs.before, synEnv)
	}

	tfoOpts := []byte{34, 6, 1, 2, 3, 4, header.TCPOptionNOP, header.TCPOptionNOP}
	tfoEnv := &testProvenanceEnv{owner: "app-tfo", cookie: 0x202, serial: 11}
	inject(buildTestIPv4TCPSYN(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"), 50002, 443, tfoOpts, []byte("hello")), tfoEnv)
	if obs := await(t); obs.before != tfoEnv {
		t.Fatalf("Fast Open SYN provenance = %#v, want %p", obs.before, tfoEnv)
	}

	// 2. Fragment reassembly: agreeing fragments with distinct skb serials preserve owner.
	f0, f1 := fragmentIPv4Packet(buildTestIPv4TCPSYN(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"), 50003, 443, nil, []byte("reassembled")), 0x3101, 16)
	inject(f0, &testProvenanceEnv{owner: "app-frag", cookie: 0x301, serial: 21})
	inject(f1, &testProvenanceEnv{owner: "app-frag", cookie: 0x301, serial: 22})
	if env, ok := await(t).before.(*testProvenanceEnv); !ok || env.unknown || env.owner != "app-frag" || env.cookie != 0x301 {
		t.Fatalf("agreeing fragments provenance = %#v, want known app-frag", env)
	}

	// 3. Mixed fragments, missing provenance, and duplicate-hole conflicts reject to unknown.
	for idx, tc := range []struct {
		name  string
		first []any
		last  any
	}{
		{name: "mixed-owner", first: []any{&testProvenanceEnv{owner: "app-a", cookie: 0x401, serial: 31}}, last: &testProvenanceEnv{owner: "app-b", cookie: 0x402, serial: 32}},
		{name: "missing-fragment", first: []any{&testProvenanceEnv{owner: "app-a", cookie: 0x403, serial: 33}}, last: nil},
		{name: "duplicate-hole-conflict", first: []any{&testProvenanceEnv{owner: "app-a", cookie: 0x404, serial: 34}, &testProvenanceEnv{owner: "app-b", cookie: 0x405, serial: 35}}, last: &testProvenanceEnv{owner: "app-a", cookie: 0x404, serial: 36}},
	} {
		p0, p1 := fragmentIPv4Packet(buildTestIPv4TCPSYN(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"), uint16(50010+idx), 443, nil, []byte("reassembled")), uint16(0x3200+idx), 16)
		for _, prov := range tc.first {
			inject(p0, prov)
		}
		inject(p1, tc.last)
		if env, ok := await(t).before.(*testProvenanceEnv); !ok || !env.unknown || env.owner != "" {
			t.Fatalf("%s: reassembled provenance = %#v, want unknown", tc.name, env)
		}
	}
}
