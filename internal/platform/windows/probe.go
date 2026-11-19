package winplatform

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/platform/windows/observer"
)

type probeOptions struct {
	index   uint
	targets string
	timeout int
}

type probeResult struct {
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms,omitempty"`
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
}

func parseProbeArgs(args []string) (probeOptions, error) {
	opts := probeOptions{}
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.UintVar(&opts.index, "interface-index", 0, "")
	flags.StringVar(&opts.targets, "targets", "", "")
	flags.IntVar(&opts.timeout, "timeout-ms", 2000, "")
	if err := flags.Parse(args); err != nil {
		return probeOptions{}, err
	}
	if flags.NArg() > 0 {
		return probeOptions{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if opts.index == 0 || opts.index > math.MaxUint32 || opts.timeout <= 0 || opts.timeout > 60_000 {
		return probeOptions{}, errors.New("probe needs a valid interface index and timeout (1..60000 ms)")
	}
	if _, err := probeTargets(opts.targets); err != nil {
		return probeOptions{}, err
	}
	return opts, nil
}

func runProbe(args []string) int {
	opts, err := parseProbeArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	return runProbeOptions(opts)
}

func probeTargets(value string) ([]string, error) {
	targets := strings.Split(value, ",")
	if len(targets) > 16 {
		return nil, fmt.Errorf("at most 16 probe targets are allowed")
	}
	for _, target := range targets {
		address, err := netip.ParseAddrPort(target)
		if err != nil || !address.Addr().Is4() || address.Port() == 0 {
			return nil, fmt.Errorf("invalid IPv4 probe target %q", target)
		}
	}
	return targets, nil
}

func raceProbes(ctx context.Context, targets []string, dial func(context.Context, string) error) probeResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan probeResult, len(targets))
	for _, target := range targets {
		go func() {
			start := time.Now()
			if err := dial(ctx, target); err != nil {
				results <- probeResult{Error: target + ": " + err.Error()}
			} else {
				results <- probeResult{OK: true, MS: max(1, time.Since(start).Milliseconds()), Target: target}
			}
		}()
	}
	failures := []string{}
	for range targets {
		select {
		case result := <-results:
			if result.OK {
				return result
			}
			failures = append(failures, result.Error)
		case <-ctx.Done():
			return probeResult{Error: ctx.Err().Error()}
		}
	}
	return probeResult{Error: strings.Join(failures, "; ")}
}

var _ = observer.WriteLine
