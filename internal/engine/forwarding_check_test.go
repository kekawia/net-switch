package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type healthRoutes struct{ testfake.Routes }

func (*healthRoutes) ForwardingIndex() int { return 9 }

func TestPrivateForwardingChallengeUsesNetstackAndBothPumps(t *testing.T) {
	tun := testfake.NewTun()
	key := bytes.Repeat([]byte{42}, 32)
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: &healthRoutes{}, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}, HealthKey: key}, flows.Defaults(), nil)
	defer e.Stop(context.Background())
	config := policy.Config{Lines: []platform.Line{{ID: "down"}}}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	index, port := e.ForwardingCheck()
	if index != 9 || port == 0 {
		t.Fatal(index, port)
	}
	source := netip.MustParseAddrPort("198.18.0.1:32768")
	target := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.2"), port)
	// A reachable endpoint without the private key must not qualify as health.
	tun.In <- packet.UDP(source, target, make([]byte, 40))
	want := append(append([]byte(nil), key...), []byte("nonce123")...)
	tun.In <- packet.UDP(source, target, want)
	select {
	case got := <-tun.Out:
		if len(got) != 68 || !bytes.Equal(got[28:], want) {
			t.Fatalf("wrong private echo: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("private packet did not traverse read pump, netstack and write pump")
	}

	// Host TCP probes to 198.18.0.2:port must terminate locally inside netstack
	// without entering the promiscuous WAN TCP forwarder or admitting a flow.
	synSeg := make([]byte, 20)
	binary.BigEndian.PutUint16(synSeg[0:2], source.Port())
	binary.BigEndian.PutUint16(synSeg[2:4], target.Port())
	binary.BigEndian.PutUint32(synSeg[4:8], 100)
	synSeg[12], synSeg[13] = 5<<4, 0x02 // data offset 5, SYN
	binary.BigEndian.PutUint16(synSeg[14:16], 65535)
	binary.BigEndian.PutUint16(synSeg[16:18], ^packet.Sum(synSeg, packet.Pseudo(source.Addr(), target.Addr(), 6, len(synSeg))))
	tun.In <- packet.IP(source.Addr(), target.Addr(), 6, synSeg)
	select {
	case got := <-tun.Out:
		if len(got) < 40 || got[9] != 6 || got[33]&0x12 != 0x12 {
			t.Fatalf("expected local TCP SYN-ACK from private endpoint, got: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("private TCP endpoint did not answer SYN locally")
	}
	if snap := e.Table.Stats(); snap.Flows != 0 || snap.Admitted != 0 {
		t.Fatalf("private TCP probe leaked into flow table: %+v", snap)
	}
}
