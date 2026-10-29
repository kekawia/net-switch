# Health replay checkpoint

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
