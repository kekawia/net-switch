# Policy transactions, caps and physical usage replay

Implementation contract, 2026-10-29. Target: combining (197),
combiningNoOpenLine (298), capBlockedAndMainException (275), capMoved (222),
capReset (256), midnightGap (188): 1,436 entries. Registration is earned only
after executing checks; this document alone claims no coverage.

## Clock and physical inputs

Read `scenario.now` (milliseconds since epoch) and `scenario.timezone` from the
hash-verified fixture. Missing values mean the oracle's 2026-10-19T12:00:00Z and
UTC. Set the clock and Options.Location before constructing Core/usage.
capReset starts at 2026-10-19T23:59:57Z; midnightGap starts at
2026-09-06T03:59:59Z in America/Santiago. Never substitute local machine time.

Research: pinned Go src/time/zoneinfo.go's LoadLocation reads ZONEINFO, system
zone data, GOROOT/lib/time/zoneinfo.zip, then embedded time/tzdata. Errors must
fail the replay. The [tzdb Chile rules](https://github.com/eggert/tz/blob/main/southamerica)
say Sep Sun>=2 at 04:00 UTC from 2023 onward. On September 6, 2026 this changes
Santiago from September 5 23:59:59 -04 to September 6 01:00:00 -03.
Check those two instants with the pinned runtime, not a constructed nonexistent
midnight (Go Date does not promise which side of a skipped time it selects).

The helper-line JSON supplies physical adapter RX/TX counters to the native
worker input. It is not routed application traffic. A clock-tick at the next
one-second polling deadline drives Poll then Supervise; repeated ticks at the
same time are ordered callback/barrier observations, not additional samples.
Check each alias/value against that poll's meter observation. Null counters
remain unknown. The initial zero sample establishes a baseline; the subsequent
200-byte sample contributes 200 bytes, not an application flow's 10+2 bytes.

SaveUsage writes usage.json at startup and the minute deadline; Poll updates
in-memory physical usage. Native routed accounting can also commit before
ackTotals. usage.recovery.json is written only when recovery state exists;
an unreadable primary uses a durable recovery record, and a complete recovered
record is written to the primary before recovery-file removal. These traces
have no primary read failure, so assert recovery-file absence. The exact file
cursor must consume each real write/rename once, including native journal work.

## Exhaustion and native closure

SYSTEM-DESIGN §§3.3, 4.6 and 5.7 replace partial lane changes and a second
connection enumeration with a complete acknowledged revision and a persisted
closeFlows intent: physical line, selected engine instance and admitted-before
apply point. Assert the starting live flows, unrelated/main/newer survivors,
durable intent before apply, matching ack before closure and selected result.
The event and reached-cap log precede policy publication; the out-of-data
closure log follows successful closure. Preserve blocked-line and main-line
exception diagnostics. Do not invent a second native enumeration to imitate
legacy GET /connections; bind that legacy selection to the fenced closure.

Event IDs require a one-to-one mapping, not blanket string removal. The legacy
sequences are capMoved 0f0f0f0f0f0f; both all-exhausted traces 151515151515 and
161616161616; capReset 090909090909, 0a0a0a0a0a0a, 0f0f0f0f0f0f,
101010101010; midnightGap 090909090909 and 0a0a0a0a0a0a. Associate each with
the corresponding native ID generator result in event order and assert unique
keys and values, kind, line, time and text before translating API event IDs.

## HTTP transaction groups

Ledger v2 retains v1 timer-backed groups and adds an explicit `boundary` of
`response` with `ack: -1`. This means the original trace has no independent
ack marker. The original HTTP input and API response delimit every member;
the executing owner must prove a native ack before the real handler returns.
It does not manufacture an original engine reply, snapshot or timer.
All rule writes in the interval remain mandatory members, ordered and owned
by one assertion. Nested HTTP boundaries, extra/omitted members, an ack index
on response groups and an unknown boundary must fail validation.

## Exercised scope and nearby gaps

Routes: POST /api/combine, POST /api/lines/update (strict and daily cap),
GET /api/state. Settings: manual 1:3 combining, automatic combining, strict
secondary, 100-byte daily caps, exhausted main exception and secondary block,
lane movement, daily reset and Santiago's missing midnight. Existing startup
session, probe, file and diagnostic contracts are reused per trace.
Combining's source-port slices become per-flow decisions under §4.4/§5.4;
settings precede engine mutation under §3.3. Timings are one-second polls,
duplicate same-time callbacks and the removed 300 ms combine reload barrier.

Not covered: custom/failed probes, stale replies, failed settings/journal writes,
usage recovery failure, weekly/monthly resets, clock rollback, concurrent API
requests, live interfaces, actual traffic, installed services or TUN/routes.
Existing adversarial protocol and durability tests remain necessary.

## Combining checkpoint

The complete combining trace is registered: 178 Control entries, 17 native
session replacements and two complete-revision cleanup replacements. The
aggregate reports **683 / 7,894**, with both producers and report exit 0.
The native 1:3 policy produces 100/300 decisions in 400 flows. Making b2 strict
disables combining and clears shares (sharesLocked returns no shares with fewer
than two eligible lines); every unpinned flow then uses main.

Executed mutations, reverted: missing combining receipt leaves producers
passing but report exit 1 (178 missing entries); failing the subtest refuses
the receipt and fails both producer/report; dropping the response observation
fails at the next HTTP input; swapping startup async observations 112/114 fails
the ordered counterpart cursor. The latter three had producer/report exit 1.
Response-group regressions additionally reject a fabricated ack, v1 use,
unknown boundary, reordered/omitted member and crossing the next HTTP request.

## Santiago checkpoint

midnightGap's 188 entries are registered. The aggregate reports **871 / 7,894**,
producer and report exit 0. The pinned runtime's timezone regression verifies
both sides of the gap. Two one-second polls ingest the physical baseline and
200-byte delta; duplicate clock ticks consume completed-poll barriers without
additional reads. Full events, diagnostics and API output match, with explicit
event bijection 090909090909 → 000000000009 and
0a0a0a0a0a0a → 00000000000a. Both native IDs must have come from the generator.
The blocked revision persists its fenced b2 closure intent before Apply;
closure is deferred to the next poll, beyond this trace's end. Main remains
usable. No suffix usage or recovery file is written.

The remaining four traces are not yet registered.
