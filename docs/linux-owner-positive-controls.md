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

## Added controls, awaiting hosted execution

**Preempted reader:** a fault-only consume callback opens a bounded hold window.
An independent CPU observes it and wakes a higher-priority registered reader on
the same CPU. Its read must finish while the first callback is still active,
the kernel consume recursion counter must rise, its completion must be missing,
and both affected bursts must be unknown. A retained entry must exist before
reload. Failed scheduling/hold preconditions are fatal, never retried to green.

**Nested free:** a real EFAULT read holds the free callback while netem releases
traffic into a previously verified full TUN ring. An independent fault-only raw
free observer must see the interrupted task's TID during the hold; kernel drops
and the primary free program's recursion counter must both increase. The observer
only counts events, never supplies packet evidence or changes oracle answers.
The normal object contains neither hold nor observer. The fault object has one
additional raw program, with the same 64-byte fault map and 128-byte CPU state.

**Perf skips:** a separate normal-object fixture enables TUN receive NAPI and RPS
to the syscall-stress CPU. Valid incoming ICMP echo requests exercise
`icmp_rcv`'s consume path. The identical device-filter counters must first agree
at 32/32 without stress. A fixed 10,000-packet workload then overlaps map syscalls;
all 10,000 raw consumes must occur, and raw-minus-perf must be strictly positive.
No injected skips or modifications to the attribution oracle are used. A private
temporary sysfs mount exposes the fixture network namespace; it is unmounted
during cleanup, and the writer is joined before its fd can close.

**Reload:** stop publication, join active bursts, disable capture, close the
fixture TUN, unregister readers and close all collection FDs. A fresh TUN and
collection must have a different epoch and packet-map ID, an initially empty
packet map, and correct attribution of fresh traffic. The deletion-fault case
first proves the exact stale entry remained. No live-map reset stands in for
reload. The old epoch's publication callback must not execute.

**Cost:** N=1/8/32, 4,096 datagrams each in concurrent 64-packet waves, with
independent payload and cookie checks. Report three-query-plus-barrier p50/p95,
an upper hold bound including the read work, process CPU, wall time, possible CPU
count and peak RSS. These are bounded concurrent-UDP measurements, not the
sixteen acceptance storms, and no result is claimed until the jobs execute.

## Source basis and remaining limits

Inspected upstream v7.0
[raw/perf dispatch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v7.0),
[map-syscall instrumentation exclusion](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/syscall.c?h=v7.0),
[ICMP consume path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?h=v7.0),
[TUN NAPI path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/tun.c?h=v7.0)
and [sysfs namespace binding](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/sysfs/mount.c?h=v7.0).
The distro kernel version alone does not prove the control; actual counters and
hold state do. The hold is bounded by 20,000 iterations and 20 ms; insufficient
overlap fails. No arbitrary extension/retry is a passing result.

Still outstanding: successful execution of these new controls, the real stale-
record mutation with the post-burst check removed, all remaining lifetime paths,
complete manifests/audit, actual release-storm comparisons and both pinned 5.8
guests. This document does not clear any release blocker.
