//go:build linux && !amd64 && !arm64

package linux

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func ebpfBackendSupported() bool { return false }

type ebpfOwnerStats struct{}

type ebpfOwnerState struct{}

func (o *Owners) ebpfStats() *ebpfOwnerStats { return nil }

func (o *Owners) AttachProvenance(_ context.Context, _ platform.TunDevice) (bool, error) {
	if o.isEBPFBackend() {
		return false, errors.New("eBPF owner backend is unsupported on this architecture")
	}
	return false, nil
}

func (o *Owners) EnableProvenance() error { return nil }
func (o *Owners) StopProvenance() error   { return nil }
func (o *Owners) CloseProvenance() error  { return nil }

func (o *Owners) scheduleProvenanceCookieRetire(_ uint64) {}
func (o *Owners) requestProvenanceReconcile()             {}

func (o *Owners) TCPWithProvenance(ctx context.Context, t platform.Tuple, _ any) (platform.Owner, error) {
	return o.TCP(ctx, t)
}

func (o *Owners) UDPWithProvenance(ctx context.Context, tuple platform.Tuple, _ any) (platform.Owner, error) {
	return o.UDPFor(ctx, tuple)
}

func (o *Owners) ValidateUDPDatagram(_ platform.Owner, _ any) platform.DatagramValidation {
	return platform.DatagramValid
}

func (o *Owners) snapshotEBPFAt(ctx context.Context, keys []netip.AddrPort, started time.Time) (map[netip.AddrPort]platform.Owner, error) {
	return o.SnapshotAt(ctx, keys, started)
}
