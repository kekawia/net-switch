# Linux 1.0 release blockers

**Status: closed (0 open release blockers, 0 pending gates).**

All 16 Linux 1.0 attribution release blockers recorded under SYSTEM-DESIGN §5.6
are closed following production eBPF packet/read-bound initiator and
first-accepted-sender attribution integration (PRs
[#109](https://github.com/kekawia/net-switch/pull/109),
[#115](https://github.com/kekawia/net-switch/pull/115),
[#116](https://github.com/kekawia/net-switch/pull/116), and
[#117](https://github.com/kekawia/net-switch/pull/117)) and full four-runner
qualification on commit `7c767ea5b9d9ab6c6fa584215a8e851fd479e030` in Acceptance
run [41586785606](https://github.com/kekawia/net-switch/actions/runs/41586785606).
Every formerly deferred attribution, held-capacity, pagination, and burst-owner
assertion is now a mandatory `Check` on 1.0, and `nsaccept release-gate` runs on
every Acceptance CI job in addition to its standalone `workflow_dispatch` gate.
See the [source-backed study](linux-owner-ebpf-study.md),
[hook manifest](linux-owner-provenance-hooks.json), and
[lifetime audit](linux-owner-provenance-lifetime.md).

## Four-runner eBPF qualification (`7c767ea5`, run 41586785606)

Acceptance run [41586785606](https://github.com/kekawia/net-switch/actions/runs/41586785606)
qualified the default `ebpf` owner backend across all four hosted Linux runners
(Go 1.27.3, kernel `7.0.0-1017-azure`) while the 16 declarations were still
present (`jobFailed=false`, `releaseFailed=0` across all 34 `ReleaseCheck`
assertions: 28 in `release` and 6 in `faults`):

- **Ubuntu 24.04 x64:** job `125754513553`, artifact `13208304958`, `AMD EPYC 7763 64-Core Processor`
- **Ubuntu 26.04 x64:** job `125754513514`, artifact `13209182896`, `AMD EPYC 9V74 80-Core Processor`
- **Ubuntu 24.04 ARM64:** job `125754513538`, artifact `13209017042`, ARM64 `0xd49`
- **Ubuntu 26.04 ARM64:** job `125754513459`, artifact `13208878330`, ARM64 `0xd49`

Each overload cell below reports natural misses / non-injected lookups in the
case's own window (99.5% required; deliberately injected fault misses are
reported separately: `132 / 132` in `overload.udp-pending-bytes`, `3,000 / 3,000`
in `overload.unknown-owner-limits`, and `131 / 131` in `overload.memory-at-limit`).

| Case | Ubuntu 24 x64 | Ubuntu 26 x64 | Ubuntu 24 ARM64 | Ubuntu 26 ARM64 |
| --- | ---: | ---: | ---: | ---: |
| `overload.udp-sessions-per-app` | 0 / 10,004 | 0 / 10,004 | 0 / 10,004 | 0 / 10,004 |
| `overload.udp-sessions-total` | 0 / 16,388 | 0 / 16,388 | 0 / 16,388 | 0 / 16,388 |
| `overload.tcp-connection-storm` | 0 / 12,904 | 0 / 12,904 | 0 / 12,904 | 0 / 12,904 |
| `overload.tcp-handshakes-in-flight` | 0 / 10,786 | 0 / 13,180 | 0 / 11,626 | 0 / 12,881 |
| `overload.tcp-flows-total` (burst) | 0 / 65,536 | 15 / 65,536 (99.98%) | 0 / 65,536 | 0 / 65,536 |
| `overload.tcp-flows-total` (held-load tail) | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `overload.tcp-buffer-budget` | 0 / 64 | 0 / 64 | 0 / 64 | 0 / 64 |
| `overload.rejection-notices-per-app` | 0 / 12,000 | 0 / 12,000 | 0 / 12,000 | 0 / 12,000 |
| `overload.rejection-notices-total` | 0 / 25,600 | 0 / 25,600 | 0 / 25,600 | 0 / 25,600 |
| `overload.timewait-cap` | 0 / 5,060 | 0 / 5,060 | 0 / 5,060 | 0 / 5,060 |
| `overload.udp-pending-bytes` | 0 / 4 | 0 / 4 | 0 / 4 | 0 / 4 |
| `overload.unknown-owner-limits` | 0 / 3 | 0 / 3 | 0 / 3 | 0 / 3 |
| `overload.tun-write-queue` | 0 / 4 | 0 / 4 | 0 / 4 | 0 / 4 |
| `overload.memory-at-limit` | 0 / 86 | 0 / 86 | 0 / 86 | 0 / 86 |
| `protocol.flows-pagination` (identified of 300) | 300 | 300 | 300 | 300 |
| `capacity.mixed-caps` (burst misses) | 0 / 70,898 | 99 / 70,591 (99.86%) | 28 / 72,114 (99.96%) | 0 / 70,769 |
| `capacity.mixed-caps` (held-load tail) | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `capacity.mixed-caps` (held UDP / total) | 16,384 / 65,536 | 16,384 / 65,536 | 16,384 / 65,536 | 16,384 / 65,536 |
| `udp.fifty-destinations-one-session` | charlie on c | charlie on c | charlie on c | charlie on c |
| `lookup.p95-measured` (all 4 phases p95 / mean) | <=100 µs / 26.1 µs | <=100 µs / 22.1 µs | <=100 µs / 24.2 µs | <=100 µs / 26.8 µs |

Exact held capacities and memory budgets across all four runners on `7c767ea5`:

- **Exact held caps:** `65,536` TCP flows in `overload.tcp-flows-total`, `16,384`
  UDP sessions plus `49,152` TCP flows (`65,536` total) alongside `4,096`
  retained `TIME_WAIT` endpoints in `capacity.mixed-caps`, `16,384` UDP sessions
  in `overload.udp-sessions-total`, `8,192` identified UDP sessions per app in
  `overload.udp-sessions-per-app`, and `8,192` identified TCP flows in
  `overload.tcp-connection-storm` were reached exactly on all four runners.
- **Forced-GC live heap (`<= 483,183,820 B` / `460.8 MiB` limit):**
  `overload.tcp-flows-total` measured `436,499,736 B` (Ubuntu 24 x64),
  `437,594,544 B` (Ubuntu 26 x64), `436,597,368 B` (Ubuntu 24 ARM64), and
  `439,473,448 B` (Ubuntu 26 ARM64). `capacity.mixed-caps` measured
  `399,655,752 B` (Ubuntu 24 x64), `397,844,136 B` (Ubuntu 26 x64),
  `411,952,696 B` (Ubuntu 24 ARM64), and `397,189,496 B` (Ubuntu 26 ARM64).
- **BPF map memory:** `111,454,832 B` (`106.29 MiB`) across `12` preallocated
  maps (`bpfMapMeasured=1`), explicitly reported alongside `forcedGCHeapBytes`,
  `runtimeBytes`, `rssBytes`, and `kernelSocketBytes`.
- **Steady and recovery gates:** `lookup.gate-terminal`, `lookup.gate-app-scope`,
  post-fault recovery probes, `TIME_WAIT` post-burst probes (`50` alpha + `10`
  bravo), and held-session continuity sweeps passed with zero misses on every
  runner.

## Same-host three-way backend overhead (`7c767ea5`, run 41586785606)

Run [41586785606](https://github.com/kekawia/net-switch/actions/runs/41586785606)
executed back-to-back comparisons on the same `ubuntu-24.04` (`AMD EPYC 7763`,
job `125754513553`) and `ubuntu-26.04` (`AMD EPYC 9V74`, job `125754513514`)
hosts across three modes on commit `7c767ea5`:

1. `proc_disabled`: `--owner-backend proc-fallback` with no eBPF programs loaded.
2. `proc_instrumented`: `--owner-backend proc-fallback` with the production eBPF
   bridge and sender probe loaded and enabled in the kernel while userspace kept
   the non-provenance TUN pump and `/proc` scanner.
3. `ebpf_full`: `--owner-backend ebpf` (default production path).

`lookup.p95-measured` (`0 / 700` misses in every run; p95 bucket upper bounds for
unscoped 1x / 10x and scoped 1x / 10x, plus mean lookup latency):

| Host | Mode | Unscoped 1x / 10x p95 | Scoped 1x / 10x p95 | Mean lookup |
| --- | --- | ---: | ---: | ---: |
| Ubuntu 24 x64 (`EPYC 7763`) | `proc_disabled` | 3.9 ms / 2.0 ms | 300 µs / 600 µs | 212.959 µs |
| Ubuntu 24 x64 (`EPYC 7763`) | `proc_instrumented` | 4.0 ms / 2.2 ms | 400 µs / 700 µs | 222.769 µs |
| Ubuntu 24 x64 (`EPYC 7763`) | `ebpf_full` | 100 µs / 100 µs | 100 µs / 100 µs | 34.153 µs |
| Ubuntu 26 x64 (`EPYC 9V74`) | `proc_disabled` | 3.1 ms / 1.9 ms | 200 µs / 600 µs | 165.368 µs |
| Ubuntu 26 x64 (`EPYC 9V74`) | `proc_instrumented` | 3.2 ms / 1.5 ms | 200 µs / 900 µs | 180.106 µs |
| Ubuntu 26 x64 (`EPYC 9V74`) | `ebpf_full` | 100 µs / 100 µs | 100 µs / 100 µs | 29.754 µs |

`performance.two-cpu-and-dns` (engine pinned to 2 CPUs, `0 / 60` DNS probe drops
in every run):

| Host | Mode | 1-stream Mbit/s (ratio, CPU, managed) | 8-stream Mbit/s (ratio, CPU, managed) |
| --- | --- | ---: | ---: |
| Ubuntu 24 x64 (`EPYC 7763`) | `proc_disabled` | 5,024.57 (0.7622, 7.405 s, 54.4 MB) | 4,659.37 (0.4691, 9.163 s, 66.2 MB) |
| Ubuntu 24 x64 (`EPYC 7763`) | `proc_instrumented` | 5,044.91 (0.6781, 9.785 s, 62.8 MB) | 4,684.09 (0.4692, 9.831 s, 65.1 MB) |
| Ubuntu 24 x64 (`EPYC 7763`) | `ebpf_full` | 4,882.01 (0.6751, 8.398 s, 85.7 MB) | 4,475.39 (0.4513, 8.140 s, 96.6 MB) |
| Ubuntu 26 x64 (`EPYC 9V74`) | `proc_disabled` | 6,543.53 (0.7968, 9.549 s, 67.3 MB) | 6,727.42 (0.5284, 12.147 s, 71.2 MB) |
| Ubuntu 26 x64 (`EPYC 9V74`) | `proc_instrumented` | 6,396.10 (0.8063, 9.551 s, 63.8 MB) | 6,473.69 (0.4966, 11.073 s, 82.8 MB) |
| Ubuntu 26 x64 (`EPYC 9V74`) | `ebpf_full` | 6,232.11 (0.6618, 10.381 s, 94.8 MB) | 6,183.52 (0.4761, 8.676 s, 108.7 MB) |

## Fallback-scanner A/B settlement (`7c6692a` vs current `proc-fallback`)

Run [41586785606](https://github.com/kekawia/net-switch/actions/runs/41586785606)
also ran the required same-host back-to-back A/B on `overload.tcp-flows-total`
comparing the round-3 build (`7c6692aa2b3526b9e3d176d0b41c6fa699eb665f`) against
current `--owner-backend proc-fallback` (`7c767ea5`) and primary `ebpf`:

| Host | Build / Mode | Burst misses | Tail misses | Held flows (after tail) | Mean lookup |
| --- | --- | ---: | ---: | ---: | ---: |
| Ubuntu 24 x64 (`EPYC 7763`, job `125754513553`) | `7c6692a` | 13,548 / 77,035 (17.59%) | 8 / 9 | 65,536 (`65,535` pre-tail) | 2.948 ms |
| Ubuntu 24 x64 (`EPYC 7763`, job `125754513553`) | `7c767ea5` `proc-fallback` | 23,279 / 80,002 (29.10%) | 100 / 100 | 58,771 (`6,765` shortfall = unknown overflow) | 4.094 ms |
| Ubuntu 24 x64 (`EPYC 7763`, job `125754513553`) | `7c767ea5` `ebpf` | 0 / 65,536 (0.00%) | 0 / 0 | 65,536 | 15.406 µs |
| Ubuntu 26 x64 (`EPYC 9V74`, job `125754513514`) | `7c6692a` | 7,482 / 70,970 (10.54%) | 0 / 0 | 65,536 | 1.966 ms |
| Ubuntu 26 x64 (`EPYC 9V74`, job `125754513514`) | `7c767ea5` `proc-fallback` | 12,768 / 76,256 (16.74%) | 0 / 0 | 65,536 | 2.721 ms |
| Ubuntu 26 x64 (`EPYC 9V74`, job `125754513514`) | `7c767ea5` `ebpf` | 15 / 65,536 (0.023%) | 0 / 0 | 65,536 | 12.017 µs |

Inspection of `git diff 7c6692a..7c767ea5 -- internal/engine/linux/` accounts for
the slow-cluster difference between `7c6692a` and current `proc-fallback`:

- Between `7c6692a` (PR #36) and `7c767ea5`, PRs #83, #96, and #98 added bounded
  production scan diagnostics (`owner_trace_linux.go` atomic in-flight read
  tracking and slow-batch ring, plus `diag_trace_linux.go` per-query stage
  timestamps), strict wall-clock `lookupContextError` checks (`!time.Now().Before(deadline)`)
  before entering `holders()` (`ExpiredBeforeHolderScan=59`,
  `ExactRepliesAfterDeadline=55` on `EPYC 7763`; `23` and `22` on `EPYC 9V74`),
  and native socket-destroy / line-slot lifecycle tracking (`sockets_destroy_linux.go`,
  `line_slots_linux.go`).
- Even `7c6692a` missed `17.59%` of burst lookups on `EPYC 7763` and `10.54%` on
  `EPYC 9V74` (21–35x above the `<= 0.5%` 1.0 requirement), confirming `/proc`
  scanning cannot meet 1.0 storm attribution on either build.
- Current `proc-fallback` retains its bounded degraded-mode guarantees (`0` wrong
  identities, `0` leaked or phantom flows, `100%` of the `EPYC 7763` occupancy
  shortfall accounted for by `21,331` distinct unknown-overflow refusals, `65,536`
  held on `EPYC 9V74`, and `<= 4.0 ms` p95 across all `lookup.p95-measured`
  phases), while primary `ebpf` settles storm attribution on the same hosts at
  `0.00%` and `0.023%` misses.

## Historical pre-eBPF baseline (`fb74394`, run 39565641409)

Prior to eBPF integration, PR #36 delivered the Linux platform and `/proc`
fallback scanner (measured on `fb74394` in Acceptance run
[39565641409](https://github.com/kekawia/net-switch/actions/runs/39565641409);
heap profile evidence in run
[39552484899](https://github.com/kekawia/net-switch/actions/runs/39552484899),
earlier capacity sizing runs
[39441805445](https://github.com/kekawia/net-switch/actions/runs/39441805445)
and
[39461404148](https://github.com/kekawia/net-switch/actions/runs/39461404148)),
deferring the 16 load-attribution, pagination, mixed-cap, and 50-destination
UDP burst assertions until eBPF landed. All hard capacity accounting, flow-table
snapshot correlation, probe identity/route corroboration, refusal classification,
and held-load tail checks introduced for that catalogue remain active as
mandatory `Check` assertions on 1.0.

## Release gate enforcement

`nsaccept release-gate` inspects the complete source catalogue in
`tests/linux/suite`, accepts no case filter, and fails if any `ReleaseBlocker` or
`Pending` gate exists:

```text
go run ./tests/linux/cmd/nsaccept release-gate
```

It runs automatically during `Build the harness` on every Linux Acceptance CI
job as well as via `.github/workflows/linux-acceptance.yml`'s `release_gate=true`
manual dispatch mode.
