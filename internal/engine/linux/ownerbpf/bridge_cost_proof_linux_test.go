//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Bounded concurrent UDP burst load, with checked per-datagram cookies. This
// measures the query/hold cost, not the sixteen release acceptance workloads.
func TestBridgeBurstCost(t *testing.T) {
	for _, limit := range []int{1, 8, 32} {
		t.Run(fmt.Sprintf("N%d", limit), func(t *testing.T) {
			f := newBridgeFixture(t, false)
			f.r.Measure = true
			var sockets [2]int
			var cookies [2]uint64
			for i := range sockets {
				sockets[i], _ = bridgeSocket(t, 0)
				c, err := unix.GetsockoptUint64(sockets[i], unix.SOL_SOCKET, unix.SO_COOKIE)
				if err != nil {
					t.Fatal(err)
				}
				cookies[i] = c
			}
			const waves = 64
			sumCaptures := func() uint64 {
				var states []CPUState
				if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
					t.Fatal(err)
				}
				var total uint64
				for _, s := range states {
					total += s.Captures
				}
				return total
			}
			capturesBase := sumCaptures()
			start := time.Now()
			var usageBefore, usageAfter unix.Rusage
			if err := unix.Getrusage(unix.RUSAGE_SELF, &usageBefore); err != nil {
				t.Fatal(err)
			}
			var samples, holds []int64
			packets := 0
			for wave := range waves {
				finished := make(chan error, 2)
				quiesceCPU1 := make(chan struct{})
				quiescedCPU1 := make(chan error, 1)
				for sender := range 2 {
					sender := sender
					go func() {
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()
						var cpu unix.CPUSet
						cpu.Set(sender)
						if err := unix.SchedSetaffinity(0, &cpu); err != nil {
							finished <- err
							if sender == 1 {
								quiescedCPU1 <- err
							}
							return
						}
						for packet := range 32 {
							var payload [12]byte
							binary.BigEndian.PutUint32(payload[:4], uint32(sender))
							binary.BigEndian.PutUint32(payload[4:8], uint32(wave))
							binary.BigEndian.PutUint32(payload[8:], uint32(packet))
							if err := unix.Sendto(sockets[sender], payload[:], 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
								finished <- err
								if sender == 1 {
									quiescedCPU1 <- err
								}
								return
							}
						}
						finished <- nil
						if sender == 1 {
							<-quiesceCPU1
							quiescedCPU1 <- nil
						}
					}()
				}
				var producerErr error
				for range 2 {
					producerErr = errors.Join(producerErr, <-finished)
				}
				if producerErr != nil {
					close(quiesceCPU1)
					<-quiescedCPU1
					t.Fatal(producerErr)
				}
				// Ensure any deferred NET_TX_SOFTIRQ drain has entered net_dev_start_xmit
				// for all 64 datagrams and both CPUs have exited softirq BH context
				// (meaning tun_net_xmit completed ptr_ring_produce) before timing the
				// non-blocking N-packet ReadBurst calls.
				wantCaptures := capturesBase + uint64((wave+1)*64)
				capDeadline := time.Now().Add(time.Second)
				for sumCaptures() < wantCaptures {
					if time.Now().After(capDeadline) {
						close(quiesceCPU1)
						<-quiescedCPU1
						t.Fatalf("cost precondition: wave=%d captures=%d want=%d", wave, sumCaptures()-capturesBase, (wave+1)*64)
					}
					runtime.Gosched()
				}
				close(quiesceCPU1)
				if err := <-quiescedCPU1; err != nil {
					t.Fatal(err)
				}
				var seen [2][32]bool
				for read := 0; read < 64; read += limit {
					frames, err := f.r.ReadBurst(f.fd, limit)
					if err != nil || len(frames) != limit {
						t.Fatalf("cost precondition: burst=%d err=%v", len(frames), err)
					}
					samples = append(samples, int64(f.r.LastSample))
					holds = append(holds, int64(f.r.LastHold))
					for _, fr := range frames {
						if len(fr.Data) != 40 {
							t.Fatal("cost payload size", len(fr.Data))
						}
						i := binary.BigEndian.Uint32(fr.Data[28:32])
						w := binary.BigEndian.Uint32(fr.Data[32:36])
						seq := binary.BigEndian.Uint32(fr.Data[36:40])
						if i >= 2 || w != uint32(wave) || seq >= 32 || seen[i][seq] {
							t.Fatal("cost payload oracle mismatch")
						}
						seen[i][seq] = true
						if fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != cookies[i] {
							t.Fatal("cost traffic attributed incorrectly", fr.Decision)
						}
						packets++
					}
				}
			}
			elapsed := time.Since(start)
			if err := unix.Getrusage(unix.RUSAGE_SELF, &usageAfter); err != nil {
				t.Fatal(err)
			}
			cpuUS := (usageAfter.Utime.Sec-usageBefore.Utime.Sec+usageAfter.Stime.Sec-usageBefore.Stime.Sec)*1e6 + usageAfter.Utime.Usec - usageBefore.Utime.Usec + usageAfter.Stime.Usec - usageBefore.Stime.Usec
			slices.Sort(samples)
			slices.Sort(holds)
			possible, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			if packets != 4096 {
				t.Fatal("cost workload incomplete", packets)
			}
			t.Logf("BURST_COST arch=%s N=%d packets=%d bursts=%d query_calls=%d possible_cpus=%d sample3_p50_ns=%d sample3_p95_ns=%d hold_upper_p95_ns=%d wall_ns=%d cpu_us=%d maxrss_kib=%d workload=concurrent_udp_bursts release_storm_qualified=false", runtime.GOARCH, limit, packets, len(samples), len(samples)*3, possible, samples[len(samples)/2], samples[(len(samples)*95-1)/100], holds[(len(holds)*95-1)/100], elapsed.Nanoseconds(), cpuUS, usageAfter.Maxrss)
		})
	}
}
