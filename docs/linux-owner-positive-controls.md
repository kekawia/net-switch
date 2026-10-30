# Modern positive-control checkpoint

## Build-only preflight before dispatch

After every change to the opt-in fixtures, cross-compile the complete
`ownerbpfproof` test binary for **both** linux/amd64 and linux/arm64 with the
pinned Go toolchain, `CGO_ENABLED=0`, `GOMAXPROCS=2` and `-p 2`, at Idle priority.
Use `go test -c -tags=ownerbpfproof -o <architecture-specific-output>` on
`./internal/engine/linux/ownerbpf`; never execute these binaries on the PC.
Both compiler exit codes must be zero before dispatching the small hosted run.
This does not replace BPF object generation, verifier checks or kernel tests.

Run 40884669811 failed before kernel execution because the test used
`unix.SCHED_OTHER`, which our vendored x/sys does not export. It exports
`SCHED_NORMAL=0`, matching
[Linux's UAPI scheduler header](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sched.h?h=v7.0).
The fixture now uses that exported name. Plain unit/contract tests could not
catch this because they excluded the `ownerbpfproof` build tag.

The first passing bridge run is
[40878506707](https://github.com/kekawia/net-switch/actions/runs/40878506707),
head c375f0c7bdb3b67d829fdc8c2f7ecdb934cf4192. The earlier load failure remains
recorded separately. This run did not complete P1/P2 or the release storm gates.

## Starting conditions checked against logs and code

Both [amd64](https://github.com/kekawia/net-switch/actions/runs/40878506707/job/123463747268)
and [arm64](https://github.com/kekawia/net-switch/actions/runs/40878506707/job/123463747094)
reported kernel 7.0.0-1017-azure, ABI 3, raw_tracepoint mode and queue length 500.

- `P1_PAIR distinct_payload=false known_cookies=2/2 complete_identities=0/2`
  and the distinct-payload=true variant passed on both. A was closed before B
  rebound its port; the first variant compared every packet byte.
- `P1_DROP sent=1200 read=500 dropped=700 post_drop_cookie=correct` appeared
  on both. The test required captures=1200 and drops>0 before reading, then
  reconciled actual reads plus drops with sends and checked payload/cookie pairs.
- Actual address reuse occurred after two ping-pong iterations on both, with
  generations 1/2. The amd64 address was ffff8d9388641700 (cookie 9); ARM64 was
  ffff000107106400 (cookie 8193). These were measured addresses, not assumptions
  from the iteration count. Both logged `recurrence_suppressed=1 unknown=1`.
- Both logged `P2_PERF_BASELINE raw=32 perf=32 stressed_skip_control=not_yet_proved`.
  Equality was asserted; this was not evidence that skips had been triggered.

New assertions additionally require sender execution intervals to overlap,
unique sender/sequence payloads, agreement with the kernel interface drop
counter, a matching packet-map entry before the deletion under test, and an
independent diagnostic observation of the suppressed pointer recurrence.

## Verified controls in hosted run 40934322738 (`e5fc011c`)

All modern positive-control fixtures executed and passed on kernel `7.0.0-1017-azure`
in [run 40934322738](https://github.com/kekawia/net-switch/actions/runs/40934322738)
([amd64 job 123667040419](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040419),
[arm64 job 123667040491](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040491)):

- **Preempted reader (`TestBridgePreemptedReader`):**
  - `amd64`: `P2_PREEMPT_SKIP hold_tid=4968 reader2_tid=4969 consume_recursion_delta=1 retained_before_reload=true r1=attribution_unknown_recursion r2=missing`
  - `arm64`: `P2_PREEMPT_SKIP hold_tid=4934 reader2_tid=4935 consume_recursion_delta=1 retained_before_reload=true r1=attribution_unknown_recursion r2=missing`
- **Nested free (`TestBridgeNestedFreeSkip`) and EFAULT copy fault:**
  - `amd64`: `P2_EFAULT fault_read=EFAULT free_terminal_count=1 packet_map_empty=true`, `P2_NESTED_FREE_SKIP hold_tid=4966 observer_nested_free=8 free_recursion_delta=8 retained_entries=8 kernel_drops_delta=8 decision=attribution_unknown_recursion`
  - `arm64`: `P2_EFAULT fault_read=EFAULT free_terminal_count=1 packet_map_empty=true`, `P2_NESTED_FREE_SKIP hold_tid=4932 observer_nested_free=8 free_recursion_delta=8 retained_entries=8 kernel_drops_delta=8 decision=attribution_unknown_recursion`
- **Perf skips (`TestBridgePerfTracepointSkips`):**
  - `amd64`: `P2_PERF_BASELINE raw=32 perf=32 stressed_skip_control=proved`, `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9360 missing=640 stress_lookups=746672 injected_skips=0`
  - `arm64`: `P2_PERF_BASELINE raw=32 perf=32 stressed_skip_control=proved`, `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9872 missing=128 stress_lookups=786209 injected_skips=0`
- **Stale-record mutation (`TestBridgeStaleRecordMutation`):**
  - `amd64`: `skip_post_check=false` refused (`free_recursion_delta=8`, `decision=attribution_unknown_recursion`); `skip_post_check=true` accepted stale cookie `16` over live sender cookie `17` (`result=stale_accepted`).
  - `arm64`: `skip_post_check=false` refused (`free_recursion_delta=8`, `decision=attribution_unknown_recursion`); `skip_post_check=true` accepted stale cookie `16` over live sender cookie `17` (`result=stale_accepted`).
- **Pre-loader socket (`TestBridgePreLoaderSocket`) and read lifetimes (`TestBridgeReadLifetimes`) in [run 40975971592](https://github.com/kekawia/net-switch/actions/runs/40975971592) (`87d57477`, [amd64 job 123804282892](https://github.com/kekawia/net-switch/actions/runs/40975971592/job/123804282892), [arm64 job 123804282804](https://github.com/kekawia/net-switch/actions/runs/40975971592/job/123804282804)):**
  - `amd64`: `P1_PRE_LOADER cookie=29 init_calls_delta=1 init_zero=0`, `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=35 purge_deleted=510 packet_map_empty=true`
  - `arm64`: `P1_PRE_LOADER cookie=28 init_calls_delta=1 init_zero=0`, `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=34 purge_deleted=510 packet_map_empty=true`

## Source basis and remaining limits

Inspected upstream v7.0
[raw/perf dispatch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v7.0),
[map-syscall instrumentation exclusion](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/syscall.c?h=v7.0),
[ICMP consume path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?h=v7.0),
[TUN NAPI path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/tun.c?h=v7.0)
and [sysfs namespace binding](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/sysfs/mount.c?h=v7.0).
The hold has an 80,000-clock-call work ceiling (2,500 quanta of 32 straight-line
calls) and checks its 20 ms deadline between quanta (see
[linux-owner-verifier-complexity.md](linux-owner-verifier-complexity.md));
insufficient overlap fails.

Still outstanding for PR 1: both pinned 5.8 floor guests (`owner-proof / floor-5.8-amd64`
and `floor-5.8-arm64-tcg-correctness`). This document does not clear any release blocker.

