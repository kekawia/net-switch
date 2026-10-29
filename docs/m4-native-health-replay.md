# Health replay checkpoint

All four traces are now registered: 2,063 additional entries, with a passing
local aggregate of `covered 3985 / 7,894; uncovered 3909; pending map[]` and
producer/lifecycle/report exits 0/0/0. The historical checkpoints below retain
their original scope; the remaining slice work is the four reverted mutations.

lostDefaultRoute adds 395 entries. Its successful directory cleanup, startup
votes and response snapshot markers use the existing replacements. The route
input is staged without a health vote. Explicit per-poll assertions require
route-miss counts of 0 before 5 s, 1 from 5–9 s, 2 from 10–14 s, and 0 after
the restored route is sampled at 15 s. Only the 11 s poll fails over; only the
16 s poll recovers. Each line's routeReadAt remains on five-second boundaries.

All health traces also assert inside each probe-result hook that no vote has
been published yet: the complete operator round must join before health changes.

## Resumed work

The CI race in job 123709836811 was in the generated-ID recording hook:
two full-probe goroutines wrote the same map. The hook now uses the same mutex
as the request/result recording hooks; production probe concurrency is unchanged.
The other new hooks were audited: probe answers are read-only during a joined
round; request/result writes are locked; connection, event and projection work
runs on the calling test goroutine after the round joins. The local race command
first rejected disabled cgo. With CGO_ENABLED=1 it failed because gcc is absent,
so race verification remains a hosted check. No compiler was installed.

busyFailedChecks is now implemented: all 687 entries are registered. The supplied
flow retains one instance-scoped identity across 35 accumulating snapshots;
incoming bytes keep the line busy when the 15 s and 30 s rounds fail. Each
failed native round contains one quick and two distinct full checks, but adds
no failed health vote. The independent cadence check requires exactly those
rounds, and the complete API comparison preserves the busy line's null ping.
No routed byte count is substituted for physical adapter usage.
The pure aggregate reports `covered 2841 / 7,894; uncovered 5053; pending map[]`,
producer/lifecycle/report exits 0/0/0.

probeFailover's 749 entries are implemented. Independent deadlines require a1
rounds at 15, 20, 25, 30, 35 and 40 s, with b2 still on its 15-second cadence.
The first failed quick check gets two full confirmations; subsequent doubtful
rounds are full-only. Three failed rounds cause the 26 s poll to publish failover.
The input changes to 25 ms at 31 s; full rounds at 35 and 40 s each count once,
and the 41 s poll publishes failback. Both complete HTTP states, all diagnostic
conditions and generated event identities are checked. No trace output chooses
Control's health, probe result or lane target.
The pure aggregate reports `covered 3590 / 7,894; uncovered 4304; pending map[]`,
producer/lifecycle/report exits 0/0/0.

2026-10-29. Paused at the user's request after implementing failoverFailback.
The requested slice contains 2,063 entries: failoverFailback 232,
busyFailedChecks 687, probeFailover 749 and lostDefaultRoute 395.

## Implemented

failoverFailback reuses the startup driver, native revision compiler boundary,
ordered counterpart and file cursors, and ledger v2. Its suffix feeds physical
interface inputs through RefreshAdapters and runs real Poll/Supervise at each
one-second deadline. It never assigns a lane's health or target from expected
output. Complete literal policies and native flow decisions check both changes.

The starting state requires both lines up, one completed startup pass each,
no failed votes, no pending probe, no physical counters and no prior events.
Removing Ethernet's address at 1 s leaves it up after the 2 s sample; the second
miss changes its lane to Wi-Fi at 3 s. Restoring the address before 4 s starts
two full checks against distinct rotated operators. Their complete round adds
one passing vote, and the 5 s poll restores Ethernet's lane. Recovery checks
validate generated unique operation IDs, physical line, kind, instance, targets
and 18 ms results. Full HTTP responses retain event order through an explicit
one-to-one event identity mapping.

Every original suffix observation is compared in order with a projection of
completed native operations. Completion IDs advance consecutively and must name
an already checked adjacent operation. The file cursor consumes native journal
work. Existing session and stale-policy replacement contracts own the 19 retired
startup entries; Control owns the other 213. No other health trace is registered;
the suffix rejects attempts to run them until their implementation is completed.

## Timing authority and scope

SYSTEM-DESIGN §4.5 says "quick check 3 s, full check 10 s" and "The health
state machine and its timings are today's (`line-health.mjs`)." The frozen
source declares `ADDRESS_MISSES_TO_FAIL = 2`, `ROUTE_MISSES_TO_FAIL = 2`,
`ROUTE_STALE_MS = 30_000`, `MIN_POLL_GAP_MS = 400`,
`PROBE_FAILS_TO_FAIL = 3`, `PROBE_PASSES_TO_RECOVER = 2`, and
`PASS_WAIT_MS = 30_000`. internal/linehealth/health.go matches those constants
and declares `RouteReadEveryMS = 5000`. internal/control/poll.go chooses
`wait := int64(15000)`, changing to `5000` in doubt; its busy threshold is
`rate.Down >= 16*1024 || rate.Up >= 16*1024`.

This checkpoint exercises address confirmation at one-second polls, immediate
full-check scheduling on address recovery, the following poll's publication,
five-second adapter discovery, both GET /api/state responses, default probes,
two equally weighted lines, no pins/caps/combining/IPv6, down/up events and the
associated health and lane-change diagnostics. Startup contracts are reused.

Not yet exercised by this checkpoint: failed checks, busy suppression, the
15/5-second repeated probe cadence, route-loss grace, full-check deadlines,
custom targets, stale or unavailable results, traffic-evidence shortcuts,
failed settings/journal operations, real sockets, services, TUN or OS routes.
The next three traces must establish their own complete-round and scheduling
projections; existing helper branches alone are not evidence for those traces.

No product behavior change or new permitted divergence was needed. Native
operator selection follows the existing design decision in §§4.4–4.5: the
address-recovery round checks Google and Quad9, with two full results and one
vote, rather than the old two-operator wire representation.

## Validation and remaining work

The focused failoverFailback test passed. The first aggregate failed because
new annotations were inserted before the existing API fixture used by ledger
regression tests; appending the annotations restores that fixture's identity.
This was a test-registration error, not a product change.

After restoration, the full pure Control, control/engine and ledger suites plus
`-run ^TestNativeStartupSessionReplacement$ ./internal/lifecycle` passed. The
`go test -json -count=1` streams went directly to replay-report without saved
logs: `covered 2154 / 7,894; uncovered 5740; pending map[]`, with
producer/lifecycle/report exit codes 0/0/0. All Go runs used the pinned toolchain,
Idle priority, GOMAXPROCS=2 and -p 2. No native engine process was started.

The paused checkpoint still needs the four requested reverted gate mutations
(missing receipt, failing subtest, dropped check and reordering), independent
review, and the other 1,831 trace entries. No CI was manually dispatched or
watched. Frozen reference files and tests/oracle bytes remain unchanged.

Research used the existing repository contracts and Go's official discussion
of deterministic asynchronous testing: https://go.dev/blog/synctest.
The existing injected clock and synchronous probe boundary are retained.
