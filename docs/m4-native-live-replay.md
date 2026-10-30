# Live line and IPv6 replay

2026-10-30. Work in progress. lineOrder (274), lineRemove (234), lineAdd (201)
and adapterRename (281) add 990 checked entries to the previous 3,985.
The aggregate passes at **4,975 / 7,894**, with producer/lifecycle/report exits
0/0/0. ipv6 (1,153) remains unregistered.

The shared startup driver, native compiler boundary, HTTP transaction executor,
ordered counterpart and exactly-once file cursor are reused. Startup rule files
also pass the complete ordered revision-file cursor for this slice. Each old
rule refresh and restart compilation belongs to the same checked live apply.
No frozen file is changed and no compatibility adapter drives native decisions.

## lineOrder evidence

POST /api/lines/order receives the original ordered ids b2,a1. Real Control
persists settings/backup and journal before Apply. The complete native policy
is compared with independent literals. All 400 new unpinned decisions use b2.
Both full API responses, including the subsequent GET /api/state, match.
The engine instance stays on with exactly one Apply and no Start/Stop, probes,
clock advance, events or outside closures. The line-order diagnostic is exact.

`checkLiveOrderHeldFlows` compiles the actual before/after Control policies into
the pure production flow table. It first proves a held a1 flow exists, applies
the new policy, proves the entire record survives unchanged, then admits a new
b2 flow at the new revision. This is not installed networking evidence.

The named `live instance and held-flow preservation` replacement accounts for
the ordered stop/PID/remove/listener/config/spawn/handshake/lane/probe sequence
at 169–266. It implements the design decision recorded in SYSTEM-DESIGN §§4.4
and 5.7: live changes replace restarts and lane changes close no flows.
An independent operation plan checks all retired diagnostics, requests, replies,
routes, probes and cleanup names; the file cursor requires both complete rule
sets in order and one distinct native acknowledgement. Settings publications
consume their actual native write/rename results. Completion IDs advance once
and inherit only an already-proved operation. No prefix-only suffix acceptance.

The existing response-only ledger groups reject recorded state-snapshot markers.
This trace has snapshots at 267 and 271, so it uses the existing translated
ordered-file-cursor alternative rather than pretending its snapshot is an ack
or weakening the v2 boundary validator.

## Scope and limits

lineRemove reuses the same executor and retired-operation plan. It removes b2
through POST /api/lines/remove, checks the complete single-line policy and both
API responses, and proves that new and held main flows stay on a1. It also
checks the removed b2 rule files and retained settings publication. The surviving
line's completed 18 ms ping stays visible: the old restart reset it to null.
This is an explicit health-bookkeeping replacement under §5.7, checked from
the healthy starting condition and absence of any extra probe or restart.
The trace has no supplied held b2 flow; installed traffic evidence is separate.

Exercised settings: two equally weighted lines, empty pins, combining and IPv6
off, reordered main and unchanged physical lane targets. Both lines start up
with completed 18 ms quick probes. Timing is the original unchanged instant;
response snapshots follow the acknowledged live revision. Diagnostics include
startup and line order; retired restart diagnostics are explicit replacements.

Nearby gaps: IPv6 transitions, failed durable writes or Apply,
concurrent requests, active probe races, installed services and actual traffic.
No new hook runs on probe goroutines in this checkpoint. Existing synchronized
startup callbacks are reused. Hosted race checks and independent review remain.

## Mutation evidence

Four temporary mutations ran through the full pure Control, control/engine,
ledger and selected native lifecycle aggregate and were reverted:

- Missing lineOrder receipt: 253 required receipts missing; exits 0/0/1.
- Failed subtest after checks: receipt refused; exits 1/0/1.
- Dropped HTTP response comparison: got 270/http, wanted 269/api; exits 1/0/1.
- Swapped in-memory log/async-result at 166/167: ordered replacement rejected
  async-result where the first log was required; exits 1/0/1.

Tests use pinned Go 1.27.3, Idle priority, GOMAXPROCS=2 and -p 2. JSON streams
go directly into replay-report, including TestNativeStartupSessionReplacement;
no logs are saved. No engine process, service, TUN or host route is run.

## Live add defect and evidence

lineAdd starts with only a1, no probes and no b2 lane. The shared startup
counterpart now accepts this existing one-line startup shape. The generated
060606 identity maps bijectively to the fixture LineID provider's 000001;
the resulting complete settings, compiled policy and responses are checked.

The first replay reproduced a product defect: the live-add path skipped the
new lane's initial health sample, which used to run during Start. Its real
compiled target was a1 instead of 000001. Source inspection of changeLines,
Start and sampleLinesLocked established the cause; GitHub issue search found
no matching report. Service-mode add now samples only the new line before
Apply and schedules physical checks after acknowledgement. It does not
resample unrelated lines or restart. This restores §4.1 parity, not a new
permitted divergence. A reverted mutation disabling both new steps failed
the literal policy assertion with 000001:a1 instead of 000001:000001.

Both physical quick checks have unique nonempty operations, the current
instance, index 0, target 1.1.1.1:443, outcome OK and delay 18 ms. Their hooks
write maps under a mutex; reads occur only after the joined synchronous
ProbeBackground returns. Each lane publishes exactly one passed round.
The complete ordered native effects include both lane logs, the added-line
diagnostic and both probe groups. The same full aggregate passes after the fix.

## Adapter rename

The original adapters/interfaces inputs go through RefreshAdapters. The GUID
adapter-0 retains logical a1 and changes only its alias to LAN. Both settings
copies and journals are checked before the live revision. The one-second Poll
applies the new binding before Supervise, so the latter needs no second update
or restart diagnostic. Both native logs are checked, including the rename.
The renamed lane's physical probe retains its operator rotation (8.8.8.8:443),
18 ms result and current instance. Counter readings stay unknown.

The shared retired restart plan covers 181–275, and the ordered rule cursor
requires the entire new compilation. The full GET/state response matches;
the original repeated same-time ticks create no second poll. The before/after
Control policies preserve the held a1 record in the pure flow table and admit
new traffic on a1 through the LAN binding. The trace uses exact GUID spelling;
the existing TestServiceLiveRenameReconcilesIdentityBeforeApply in the same
passing sweep separately covers brace/case normalization ({ABC} versus abc).
