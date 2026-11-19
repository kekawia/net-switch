package winplatform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProbeArguments(t *testing.T) {
	if _, err := parseProbeArgs([]string{"--interface-index", "3", "--targets", "1.1.1.1:443,8.8.8.8:443"}); err != nil {
		t.Fatalf("valid probe args rejected: %v", err)
	}
	for _, args := range [][]string{
		{"--interface-index", "0", "--targets", "1.1.1.1:443"},
		{"--interface-index", "1", "--targets", "example.com:443"},
		{"--interface-index", "1", "--targets", "[::1]:443"},
		{"--interface-index", "1", "--targets", "1.1.1.1:0"},
		{"--interface-index", "1", "--targets", "1.1.1.1:443", "--timeout-ms", "0"},
	} {
		if _, err := parseProbeArgs(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestFirstSuccessfulProbeCancelsTheOther(t *testing.T) {
	cancelled := make(chan struct{})
	result := raceProbes(context.Background(), []string{"slow", "fast"}, func(ctx context.Context, target string) error {
		if target == "fast" {
			return nil
		}
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	if !result.OK || result.Target != "fast" || result.MS < 1 {
		t.Fatalf("%+v", result)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("the losing probe wasn't cancelled")
	}
	result = raceProbes(context.Background(), []string{"a", "b"}, func(context.Context, string) error { return errors.New("refused") })
	if result.OK || !strings.Contains(result.Error, "a: refused") || !strings.Contains(result.Error, "b: refused") {
		t.Fatalf("%+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = raceProbes(ctx, []string{"a"}, func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() })
	if result.OK || result.Error == "" {
		t.Fatalf("%+v", result)
	}
}
