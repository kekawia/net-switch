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

## Verified controls in hosted run 40934322738 (`e5fc011c`) and run 41007619728 (`a2dd47da`)

All modern positive-control fixtures executed and passed on kernel `7.0.0-1017-azure`
in [run 40934322738](https://github.com/kekawia/net-switch/actions/runs/40934322738)
([amd64 job 123667040419](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040419),
[arm64 job 123667040491](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040491))
and [run 41007619728](https://github.com/kekawia/net-switch/actions/runs/41007619728)
([amd64 job 123907266238](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123907266238),
[arm64 job 123907266073](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123907266073)):

- **Preempted reader (`TestBridgePreemptedReader`) — plain statement on hosted kernels:**
  - **Preempted-reader `consume` recursion-counter growth is UNPROVEN on hosted kernels:**
    - On the hosted Ubuntu 24.04 kernel `7.0.0-1017-azure` (`CONFIG_PREEMPT_LAZY=y`, `CONFIG_TREE_RCU=y`, without `CONFIG_PREEMPT_RCU`), `__bpf_trace_run` wraps execution in `rcu_read_lock()`, which disables preemption on non-`PREEMPT_RCU` kernels (`bridge_epoch_proof_linux_test.go:554-561`). `TestBridgePreemptedReader` therefore takes the serialized `!preemptRCU` branch (`consume_recursion_delta=0 task_serialized=true`).
    - On the upstream Linux `v5.8` (`5.8.0`) floor guest (`CONFIG_PREEMPT=y`, `CONFIG_PREEMPT_RCU=y`), `__bpf_trace_run` has no per-program recursion guard (`raw_recursion_guard=false`), so `TestBridgePreemptedReader` takes the `floor58` branch (`both_readers_attributed=true`).
    - Only the pure unit/model test (`TestBurstRejectsRecursionAndStaysPoisoned` in `burst_test.go`) covers `consume` recursion-counter growth (`Misses` increment on `consume`).
  - Verbatim lines from run `40934322738`:
    - `amd64` (job `123667040419`):
      `P2_READER ready=true tid=4650 cpu=0 policy=FIFO priority=20`
      `P2_CONTROLLER ready=true tid=4648 cpu=1 policy=FIFO priority=30`
      `P2_HOLDER ready=true tid=4651 cpu=0 policy=FIFO priority=10`
      `P2_PREEMPT preempt_rcu=false rcu_read_lock=preempt_disable hold_ns=3624508 consume_recursion_delta=0 task_serialized=true`
    - `arm64` (job `123667040491`):
      `P2_READER ready=true tid=4568 cpu=0 policy=FIFO priority=20`
      `P2_CONTROLLER ready=true tid=4569 cpu=1 policy=FIFO priority=30`
      `P2_HOLDER ready=true tid=4563 cpu=0 policy=FIFO priority=10`
      `P2_PREEMPT preempt_rcu=false rcu_read_lock=preempt_disable hold_ns=2313946 consume_recursion_delta=0 task_serialized=true`
- **Nested free (`TestBridgeNestedFreeDrop`) and delete fault (`TestBridgeDeleteFault`):**
  -Note: `EFAULT` during `read()` with `TerminalFree` (`count=1`) is covered by the pure `CheckRead` model test `TestProvenanceTerminalAndHealth/copy_fault`, not a kernel `P2_EFAULT` log tag.
  - Verbatim lines from run `40934322738`:
    - `amd64` (job `123667040419`):
      `P2_DELETE retained_before_reload=true cookie=7 health=1`
      `P2_NESTED_FREE full_ring_before=500 nested_same_task=8 kernel_drops=8 free_recursion_delta=8 reload_required=true`
    - `arm64` (job `123667040491`):
      `P2_DELETE retained_before_reload=true cookie=7 health=1`
      `P2_NESTED_FREE full_ring_before=500 nested_same_task=8 kernel_drops=8 free_recursion_delta=8 reload_required=true`
- **Perf skips (`TestBridgePerfCounterBaseline` and `TestBridgePerfSkippedConsumes`):**
  - Verbatim lines from run `40934322738`:
    - `amd64` (job `123667040419`):
      `P2_PERF_BASELINE raw=32 perf=32 scope=unstressed stress_control=TestBridgePerfSkippedConsumes`
      `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9744 missing=256 stress_lookups=503988 injected_skips=0`
    - `arm64` (job `123667040491`):
      `P2_PERF_BASELINE raw=32 perf=32 scope=unstressed stress_control=TestBridgePerfSkippedConsumes`
      `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9840 missing=160 stress_lookups=792066 injected_skips=0`
- **Stale-record mutation (`TestBridgeStaleRecordMutation`):**
  - Verbatim lines from run `40934322738`:
    - `amd64` (job `123667040419`):
      `P2_STALE_MUTATION skip_post_check=false address=ffff89f7480e6d00 stale_cookie=13 sender_cookie=14 free_recursion_delta=8 decision=attribution_unknown_recursion result=refused`
      `P2_STALE_MUTATION skip_post_check=true address=ffff89f743df0600 stale_cookie=16 sender_cookie=17 accepted_cookie=16 free_recursion_delta=8 result=stale_accepted`
    - `arm64` (job `123667040491`):
      `P2_STALE_MUTATION skip_post_check=false address=ffff0001069c1900 stale_cookie=13 sender_cookie=14 free_recursion_delta=8 decision=attribution_unknown_recursion result=refused`
      `P2_STALE_MUTATION skip_post_check=true address=ffff000101057300 stale_cookie=16 sender_cookie=17 accepted_cookie=16 free_recursion_delta=8 result=stale_accepted`
- **Pre-loader socket (`TestBridgePreLoaderSocket`) and read lifetimes (`TestBridgeReadLifetimes`) in [run 40975971592](https://github.com/kekawia/net-switch/actions/runs/40975971592) (`87d57477`, [amd64 job 123804282892](https://github.com/kekawia/net-switch/actions/runs/40975971592/job/123804282892), [arm64 job 123804282804](https://github.com/kekawia/net-switch/actions/runs/40975971592/job/123804282804)) and [run 41007619728](https://github.com/kekawia/net-switch/actions/runs/41007619728) (`a2dd47da`, [amd64 job 123907266238](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123907266238), [arm64 job 123907266073](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123907266073)):**
  - `amd64` (job `123907266238`): `P1_PRE_LOADER cookie=27 init_calls_delta=1 init_zero=0`, `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=33 purge_deleted=510 packet_map_empty=true`
  - `arm64` (job `123907266073`): `P1_PRE_LOADER cookie=28 init_calls_delta=1 init_zero=0`, `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=34 purge_deleted=510 packet_map_empty=true`

## Verified upstream Linux `v5.8` (`5.8.0`) floor guests in [run 41007619728](https://github.com/kekawia/net-switch/actions/runs/41007619728) (`a2dd47da`)

Both floor guests (`owner-proof / floor-5.8-amd64` [job 123907265984](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123907265984) and `floor-5.8-arm64-tcg-correctness` [job 123913028598](https://github.com/kekawia/net-switch/actions/runs/41007619728/job/123913028598)) built and booted upstream Linux `v5.8` (`bcf876870b95592b52519ed4aafcf9d95999bc9c`, tarball SHA-256 `e7f75186aa0642114af8f19d99559937300ca27acaf7451b36d4f9b0f85cf1f5`) inside the digest-pinned Debian Bookworm compiler container (`docker.io/library/buildpack-deps:bookworm@sha256:ccb050a415a94a3a78acbe35084ec8f06ae46fa158e3650c96f9b4fb514de6d3`) with the two build-script `sed` adjustments recorded in `tests/linux/ownerproof/guest.lock.json` (`sed -i "s/-Werror//g" tools/lib/subcmd/Makefile tools/objtool/Makefile` for GCC 12.2.0 and `sed -i "s/-J /--skip_encoding_btf_enum64 -J /g" scripts/link-vmlinux.sh` plus `KCFLAGS="-gdwarf-4 -Wno-error -fcommon" HOSTCFLAGS="-Wno-error -fcommon"` so `pahole 1.24` emits DWARF-4 / BTF without 64-bit BTF enum `kind_flag=1`). Host QEMU runs on the Ubuntu 24.04 runner outside the Bookworm compiler container and is recorded in `guest.lock.json` under `unverifiedRunnerInputs.qemu`:

- **`owner-proof / floor-5.8-amd64` (job `123907265984`):**
  - `FLOOR_GUEST_BOOT release=5.8.0 machine=x86_64 goarch=amd64 cpus=2 version="#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970"`
  - `FLOOR_GUEST_BTF path=/sys/kernel/btf/vmlinux bytes=4959637`
  - `FLOOR_GUEST_RUNNING_CONFIG release=5.8.0 bytes=127284 sha256=42309a5b01aef7aec5a856561eef8c049dd247501b3edaad746382413aff9252`
  - `P2_PREEMPT floor58=true raw_recursion_guard=false ended=1 hold_ns=2625554 both_readers_attributed=true`
  - `P2_NESTED_FREE floor58=true raw_recursion_guard=false full_ring_before=500 nested_same_task=8 kernel_drops=8 reload_required=true`
  - `P2_STALE_MUTATION floor58=true raw_recursion_guard=false skip_post_check=false nested_frees_retired_all=true retained_records=0`
  - `P2_STALE_MUTATION floor58=true raw_recursion_guard=false skip_post_check=true nested_frees_retired_all=true retained_records=0`
  - `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9492 missing=508 stress_lookups=1122622 injected_skips=0`
  - `BRIDGE_COUNTERS programs=3 field_present=false floor58=true`
  - `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=45 purge_deleted=510 packet_map_empty=true`
  - `FLOOR_GUEST_VERIFIED arch=amd64 accel=kvm qemu_exit=0 status=pass`
- **`floor-5.8-arm64-tcg-correctness` (job `123913028598`):**
  - `FLOOR_GUEST_BOOT release=5.8.0 machine=aarch64 goarch=arm64 cpus=2 version="#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970"`
  - `FLOOR_GUEST_BTF path=/sys/kernel/btf/vmlinux bytes=5996442`
  - `FLOOR_GUEST_RUNNING_CONFIG release=5.8.0 bytes=226169 sha256=8f2fd8ae8b40b3875083d636f8308d5b16e4b43c3e8abf1170780e6ea27e2a0b`
  - `P2_PREEMPT floor58=true raw_recursion_guard=false ended=1 hold_ns=15362528 both_readers_attributed=true`
  - `P2_NESTED_FREE floor58=true raw_recursion_guard=false full_ring_before=500 nested_same_task=8 kernel_drops=8 reload_required=true`
  - `P2_STALE_MUTATION floor58=true raw_recursion_guard=false skip_post_check=false nested_frees_retired_all=true retained_records=0`
  - `P2_STALE_MUTATION floor58=true raw_recursion_guard=false skip_post_check=true nested_frees_retired_all=true retained_records=0`
  - `P2_PERF_SKIP baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9884 missing=116 stress_lookups=16605 injected_skips=0`
  - `BRIDGE_COUNTERS programs=3 field_present=false floor58=true`
  - `P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=60 cross_cpu=1 cross_cpu_health_bound=1_read shared_skb_rejected=1 multi_burst_refused=4 nested_terminal=8 ambiguous_reads=1 pub_fault_cookie=45 purge_deleted=510 packet_map_empty=true`
  - `FLOOR_GUEST_VERIFIED arch=arm64 accel=tcg qemu_exit=0 status=pass`

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
insufficient overlap fails. This document does not clear any release blocker.

