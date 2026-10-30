package testfake

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestOwnersCountsTCPAndUDPCalls(t *testing.T) {
	o := &Owners{}
	if o.Calls.Load() != 0 {
		t.Fatal("nonzero starting count")
	}
	if _, err := o.TCP(context.Background(), platform.Tuple{}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.UDP(context.Background(), netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	if o.Calls.Load() != 2 {
		t.Fatal("lookup calls not counted", o.Calls.Load())
	}
	o.Err = errors.New("lookup refused")
	if _, err := o.TCP(context.Background(), platform.Tuple{}); err == nil {
		t.Fatal("lookup failure lost")
	}
	if o.Calls.Load() != 3 {
		t.Fatal("failed lookup was not counted")
	}
}
