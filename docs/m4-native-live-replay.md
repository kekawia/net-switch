# Live line and IPv6 replay

2026-10-30. Work in progress. lineOrder (274) and lineRemove (234) add 508
checked entries to the previous 3,985. The aggregate passes at **4,493 / 7,894**,
with producer/lifecycle/report exits 0/0/0. adapterRename (281), ipv6 (1,153)
and lineAdd (201) remain unregistered.

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

Nearby gaps: add/rename, IPv6 transitions, failed durable writes or Apply,
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
