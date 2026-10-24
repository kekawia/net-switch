package lifecycle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func replaceNativeState(from, to string) error { return durableRename(from, to) }

func serveNative(ctx context.Context, data string, options host.Options) error {
	return linux.ServeHosted(ctx, localipc.DefaultPath("engine"), data, options, nil)
}

// cleanupNative is the recovery after a death: the host's, or systemd's
// ExecStopPost when the host itself was killed. The socket retirement it runs
// (spec §2) is recorded in the engine's log as a timestamped event, like the
// host's own NATIVE_TERMINATED and NATIVE_CLEANED, so a stream's end can be
// ordered against it even when the host left no record at all.
func cleanupNative(ctx context.Context, data string) error {
	log := Log(data, service.Engine)
	instance := ""
	if record, err := host.ReadRecord(filepath.Join(data, "engine-state.json")); err == nil {
		instance = record.Instance
	}
	retired := func(r linux.Retirement) {
		log(fmt.Sprintf("NATIVE_SOCKETS_RETIRED instance=%s ended=%d spared=%d at=%s recovery_pid=%d error=%q", instance, r.Ended, r.Spared, r.At.UTC().Format(time.RFC3339Nano), os.Getpid(), r.Error))
	}
	return linux.RecoverReported(ctx, data, func() (func(error) error, error) { return recoveryOutcome(data) }, retired)
}
