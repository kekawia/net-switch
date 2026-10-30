# Live line and IPv6 replay

2026-10-30. All five traces are registered: lineOrder (274), lineRemove (234),
lineAdd (201), adapterRename (281) and ipv6 (1,153). They add **2,143** checked
entries to the previous 3,985. The aggregate passes at **6,128 / 7,894**, with
producer/lifecycle/report exits 0/0/0. The remaining 1,766 entries belong to
other slices. Hosted race checks and independent logic review remain.

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

Nearby gaps: failed durable writes or Apply,
concurrent requests, active probe races, installed services and actual traffic.
New probe-observation maps/slices are mutex-protected; the health driver's
generated-ID map retains its existing lock. Reads occur after joined rounds.
Hosted race checks and independent review remain.

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

## IPv6 settling and selective closure

The unchanged interfaces inputs drive real network snapshots, Poll and
Supervise for 62 one-second intervals. The frozen factory declares
`const IPV6_SETTLE_MS = 30_000;`; native effectiveIPv6Locked uses
`if now-*c.ipv6Since < 30000`. SYSTEM-DESIGN §5.7 requires the existing
"30-second stable-change interval" through every writer. First observation
at 1 s enables IPv6 at exactly 31 s; first observed loss at 32 s disables it
at exactly 62 s. Each preceding tick retains the loaded policy and the
original pending timestamp. Complete policies, IPv4/IPv6 admission decisions,
unchanged instance and both API responses are checked. There are exactly
three acknowledged revisions including startup and 62 connection reads.
The existing Poll/Supervise-order tests also check 29,999 and 30,000 ms.

The native probe cadence remains 15 seconds (10 requests including startup),
and route reads remain on five-second boundaries. Old restarts at 31/62 s
reset those schedules. The named retained-cadence replacement maps the old
46/61-second checks to the independently checked native 45/60-second rounds;
likewise each old post-restart route read consumes its prior native read once.
The shared counterpart cursor requires an already-consumed native source
position. Pending results cannot be overwritten or left over. Restart-only
extra probes are explicit preservation replacements, not invented new votes.

The two retired restart intervals (545–633 and 1061–1149) use the same
ordered operation plan and complete rule-file cursor as the line cases.
Their failed directory-list callbacks stay failed (ERR_INVALID_ARG_TYPE).
The minute usage publication at 60 s consumes its own real write/rename;
the policy observation and duplicate timer callbacks retain their order.
No flow input is supplied by this trace: all 62 snapshots are empty.

`checkNativeIPv6Closure` is a stronger companion selector witness. It compiles
the actual enabled/disabled Control policies, establishes four synthetic held
records (both address families on both physical lines), then applies the final
policy and invokes the production IPv6 selector at its apply point. Exactly
two IPv6 records close; both original IPv4 records retain ID, line and revision.
Only companion admission pins are synthetic. Engine.Apply's automatic wiring
of that selector is covered separately by the existing
TestLiveApplyPreservesFlowsAndDisablesOnlyIPv6; this local replay does not run
an engine or claim installed IPv6 address-loss evidence.

Additional reverted mutations: changing native settlement from 30,000 to zero
failed the literal policy check on the first interval; replacing the IPv6
selector with line a1 still closed two records, but failed the exact IPv4
survivor check. Both selected replay runs exited 1. The four aggregate gate
mutations above cover the new shared live-replay registration path.

Remaining scope outside these traces: physical IPv6 address validity and
deprecation, real sockets and route reconciliation, custom/failed probes during
the live change, lost acknowledgements, concurrent HTTP, and installed service
life cycles. Existing failure, platform and hosted engine tests remain required.
