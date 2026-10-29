//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A valid IPv4 ICMP echo arriving through the fixture TUN. icmp_rcv's success
// path consumes the incoming skb in receive context; it is not a TUN read.
func perfEcho() []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[2] = 0
	p[3] = 28
	p[8] = 64
	p[9] = 1
	copy(p[12:16], []byte{198, 18, 0, 2})
	copy(p[16:20], []byte{198, 18, 0, 1})
	p[20] = 8
	checksum := func(b []byte) uint16 {
		var sum uint32
		for i := 0; i < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[22:24], checksum(p[20:]))
	return p
}

func TestBridgePerfSkippedConsumes(t *testing.T) {
	f := newBridgeFixture(t, false, unix.IFF_NAPI)
	if runtime.NumCPU() < 2 {
		t.Fatal("RPS positive control needs two CPUs")
	}
	// sysfs mounts retain their network namespace. The inherited /sys mount
	// need not expose our unshared namespace; mount an owned temporary view.
	sysfs := t.TempDir()
	if err := unix.Mount("sysfs", sysfs, "sysfs", 0, ""); err != nil {
		t.Fatal("private sysfs view prerequisite", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(sysfs, 0); err != nil {
			t.Error(err)
		}
	})
	rpsPath := filepath.Join(sysfs, "class/net/nsbridge0/queues/rx-0/rps_cpus")
	mask := fmt.Sprintf("%x", uint64(1)<<f.cpu)
	if err := os.WriteFile(rpsPath, []byte(mask), 0600); err != nil {
		t.Fatal("RPS setup prerequisite", err)
	}
	got, err := os.ReadFile(rpsPath)
	if err != nil || strings.TrimLeft(strings.ReplaceAll(strings.TrimSpace(string(got)), ",", ""), "0") != mask {
		t.Fatal("RPS readback differs", string(got), err)
	}
	counts := func() (uint64, uint64, error) {
		var states []CPUState
		if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
			return 0, 0, err
		}
		var raw, perf uint64
		for _, s := range states {
			raw += s.Consumes
			perf += s.PerfConsumes
		}
		return raw, perf, nil
	}
	write := func(count int) <-chan error {
		done := make(chan error, 1)
		joined := make(chan struct{})
		t.Cleanup(func() { <-joined })
		go func() {
			defer close(joined)
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var cpu unix.CPUSet
			cpu.Set((f.cpu + 1) % 2)
			if err := unix.SchedSetaffinity(0, &cpu); err != nil {
				done <- err
				return
			}
			p := perfEcho()
			for i := 0; i < count; i++ {
				if n, err := unix.Write(f.fd, p); err != nil || n != len(p) {
					done <- fmt.Errorf("TUN receive injection %d: %d/%d %v", i, n, len(p), err)
					return
				}
				// Fixed pacing bounds backlog; it does not retry lost input.
				if i%16 == 15 {
					time.Sleep(100 * time.Microsecond)
				}
			}
			done <- nil
		}()
		return done
	}
	beforeRaw, beforePerf, err := counts()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-write(32); err != nil {
		t.Fatal(err)
	}
	// Quiescent baseline: wait without map-syscall stress before sampling.
	time.Sleep(20 * time.Millisecond)
	baseRaw, basePerf, err := counts()
	if err != nil {
		t.Fatal(err)
	}
	if baseRaw-beforeRaw != 32 || basePerf-beforePerf != 32 {
		t.Fatalf("unstressed receive baseline raw=%d perf=%d want=32/32", baseRaw-beforeRaw, basePerf-beforePerf)
	}
	const sent = 10000
	done := write(sent)
	deadline := time.Now().Add(5 * time.Second)
	lookups := 0
	finished := false
	for !finished && time.Now().Before(deadline) {
		var cfg BridgeConfig
		if err := f.b.Collection.Maps["config"].Lookup(uint32(0), &cfg); err != nil {
			t.Fatal(err)
		}
		lookups++
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			finished = true
		default:
		}
	}
	if !finished { // Join writer before allowing cleanup to close its TUN fd.
		if err := <-done; err != nil {
			t.Error(err)
		}
		t.Fatal("fixed receive workload exceeded its bound")
	}
	time.Sleep(20 * time.Millisecond)
	afterRaw, afterPerf, err := counts()
	if err != nil {
		t.Fatal(err)
	}
	raw, perf := afterRaw-baseRaw, afterPerf-basePerf
	if raw != sent {
		t.Fatalf("input/consume precondition sent=%d raw=%d perf=%d", sent, raw, perf)
	}
	if perf >= raw || lookups == 0 {
		t.Fatalf("perf skip positive control not exercised: raw=%d perf=%d lookups=%d", raw, perf, lookups)
	}
	t.Logf("P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=%d raw=%d perf=%d missing=%d stress_lookups=%d injected_skips=0", sent, raw, perf, raw-perf, lookups)
}
