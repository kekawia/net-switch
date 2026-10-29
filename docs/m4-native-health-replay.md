# Health, probes and route votes replay

2026-10-30. All four traces are registered: failoverFailback (232),
busyFailedChecks (687), probeFailover (749), lostDefaultRoute (395).
The slice adds 2,063 entries. The restored local aggregate reports
`covered 3985 / 7,894; uncovered 3909; pending map[]`, with
producer/lifecycle/report exit codes 0/0/0. Hosted race checks and independent
review remain separate requirements.

## Native behavioral evidence

The shared per-trace startup driver runs each complete trace through real
Control, the production native revision compiler and literal policy checks.
It reuses the ordered counterpart, exact file cursor, poll handling and ledger
v2. Physical interfaces/routes/probe answers/connection snapshots supply inputs;
expected outputs never set health, votes or lane targets. Every suffix entry
has an ordered native observation or a completion of an already checked one.
Completion IDs advance consecutively. Existing native session and stale-policy
replacement contracts retain ownership of retired startup representations.

Each trace starts with both lines up, one completed startup pass each, no failed
votes, no pending probe, no physical counters, no traffic evidence and no events.
The same Core keeps accumulated state throughout the suffix.

- **failoverFailback:** removing Ethernet's address at 1 s leaves it up at 2 s;
  the second miss moves its lane to Wi-Fi at 3 s. Restoring the address before
  4 s starts two full checks. Their complete round adds one pass; the 5 s poll
  restores Ethernet's lane. Both complete API responses and policy decisions
  are checked, including the down/up events and lane diagnostics.
- **busyFailedChecks:** one instance-scoped flow retains its identity across
  35 increasing byte snapshots. Failed rounds at 15 s and 30 s each contain
  one quick and two distinct full checks. Real tracker rates establish the
  busy starting condition; neither round adds a failed health vote. The exact
  diagnostic and complete final API state retain the busy line's null ping.
  Routed bytes never replace physical adapter usage.
- **probeFailover:** independent deadlines require a1 rounds at 15, 20, 25,
  30, 35 and 40 s; b2 retains the 15-second cadence. The first failed quick
  check gets two full confirmations; doubtful rounds are full-only. Three
  failed rounds cause failover at the 26 s poll. The input changes to 25 ms
  at 31 s; full rounds at 35 and 40 s count once each, with failback at 41 s.
- **lostDefaultRoute:** a staged route input creates no immediate health vote.
  Explicit per-poll assertions require route-miss counts 0 before 5 s, 1 at
  5–9 s, 2 at 10–14 s, and 0 after the restored route is sampled at 15 s.
  Both lines' routeReadAt stays on five-second boundaries. Failover occurs
  at 11 s and recovery at 16 s. Successful directory cleanup, startup votes
  and all response snapshot markers retain their existing native replacements.

Each probe request/result checks a generated unique operation ID, physical
line, interface index, kind, instance, rotated operator and input-derived
outcome/delay. Full operators must be distinct. A check inside every result
hook proves that no partial-round vote has been published. After the round
joins, exactly one pass/failure or no busy vote is required. Event IDs have a
one-to-one mapping; all other event fields and ordering remain exact.

Named replacement assertions are `physical probe deadline`, `rotating full
operators`, `partial operator round published a vote`, and the once-per-round
vote guards in replayNativeHealthSuffix. These implement the existing design
decision in SYSTEM-DESIGN §§4.4–4.5: three native operators and full HTTPS
confirmation replace the old two-operator wire representation. No new product
behavior change or permitted divergence was needed.

## Timing authority and scope

SYSTEM-DESIGN §4.5 says "quick check 3 s, full check 10 s" and "The health
state machine and its timings are today's (`line-health.mjs`)." The frozen
source declares `ADDRESS_MISSES_TO_FAIL = 2`, `ROUTE_MISSES_TO_FAIL = 2`,
`ROUTE_STALE_MS = 30_000`, `MIN_POLL_GAP_MS = 400`,
`PROBE_FAILS_TO_FAIL = 3`, `PROBE_PASSES_TO_RECOVER = 2`, and
`PASS_WAIT_MS = 30_000`. internal/linehealth/health.go matches those constants
and adds `RouteReadEveryMS = 5000`. internal/control/poll.go chooses
`wait := int64(15000)`, changing to `5000` in doubt; busy suppression uses
`rate.Down >= 16*1024 || rate.Up >= 16*1024`. internal/engine/probe/probe.go
uses `bound := 10 * time.Second` and `bound = 3 * time.Second` for quick checks.

Exercised routes are GET /api/state and the historical engine version, lane PUT,
connection GET and physical-line delay GET representations. Settings are two
equally weighted lines, default targets, no pins, caps, combining or IPv6.
Logs cover startup, failed internet test, busy suppression, no-address,
no-internet and no-default-route transitions, recovery and lane movement.
Timing checks cover one-second confirmation polls, 15/5-second probe cadence,
five-second route reads, complete rounds, and snapshot-side response timing.

Nearby gaps: custom probes; engineUnavailable/stale instance/kind results;
the two-destination real-traffic shortcut; actual 3/10-second socket deadlines;
30-second stale-route/pass-wait expiry; sub-400-ms duplicate polls; upstream-only
or exactly-threshold busy traffic; failed network/settings/journal operations;
concurrent HTTP; other API routes; real sockets, services, TUN or OS routes.
Existing adversarial protocol and installed tests remain necessary.

## Race correction and validation

CI job 123709836811 identified simultaneous writes to the generated-ID map
from the two production full-probe goroutines. The hook now uses the same
mutex as request/result recording. Production probing remains concurrent.
Other new hooks were audited: physical answers/baselines are immutable during
each joined round; request/result/ID writes are locked; connection, event and
projection work runs on the calling test goroutine after joining.

The local race command first rejected disabled cgo. With CGO_ENABLED=1 it
failed because gcc is absent. Race verification therefore remains hosted;
no compiler was installed. The mutex follows Go's official
[race-detector guidance](https://go.dev/doc/articles/race_detector).

The full pure Control, control/engine and ledger suites plus
`-run ^TestNativeStartupSessionReplacement$ ./internal/lifecycle` passed after
all mutations were reverted. `go test -json -count=1` streamed directly into
replay-report with no saved logs. Runs used the pinned toolchain, Idle priority,
GOMAXPROCS=2 and -p 2. Intermediate totals were 2,841 after busyFailedChecks
and 3,590 after probeFailover, before the final 3,985.

Four actual temporary mutations were executed through that aggregate and
reverted, without changing frozen bytes:

- Missing lostDefaultRoute receipt: tests passed, report failed with 374
  required receipts missing; producer/lifecycle/report 0/0/1.
- Failing the subtest after Consume: Receipt refused the failed test and the
  aggregate rejected the run; exits 1/0/1.
- Dropping the actual HTTP response comparison: the next request failed with
  `got 271/http want 205/api`; exits 1/0/1.
- Swapping the first two physical sample entries in memory: the exact value
  comparison failed at 136, Ethernet versus Wi-Fi; exits 1/0/1.

The earlier checkpoint's registration-order error (new annotations preceding
the ledger regression's API fixture) was corrected by appending annotations;
the complete ledger suite passes. Frozen lib/, server.mjs and tests/oracle
bytes remain unchanged. No engine, service, TUN or route operation ran locally.
CI was not manually dispatched or watched.
