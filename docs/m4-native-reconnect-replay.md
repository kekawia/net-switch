# Native reconnect replay

2026-10-30. reconnectPinned (154) and reconnectShared (151) are registered
through the existing startup driver, ordered file cursor and ledger v2.
The local aggregate passes at **6,433 / 7,894**, with 1,461 entries uncovered
and producer/lifecycle/report exits 0/0/0. Hosted race checks and independent
review remain pending. No product behavior changes or frozen edits.

Both traces start with a running acknowledged instance, healthy physical lines,
empty routed/outside observations and no pending closure. The original two
routed records enter through Poll with a bijection to instance-scoped IDs.
The helper observation establishes the exact outside socket on a1. The original
POST body goes through HTTP and real Control; the entire response, including
the nested state, is compared. The existing default-probe replacement applies
to that nested state too.

Pinned reconnect requires only the original off-target ID, the same instance,
the original selection time and a nonempty operation ID. Both journal copies
must contain that exact intent before CloseFlows. A production pure flow table
establishes both held records, adds a newer off-target record, executes the ID
selector and checks the exact on-target record and newer record survive.
Both journal copies must record completion before outside closure. Shared
reconnect must issue no routed close and no closure-journal writes.

The outside selector compares every tuple field and the optional process-start
field. Its native result, the combined closed/failed/gone counts, diagnostic,
complete response and their effect order are checked. Every historical suffix
entry is compared to an independent ordered operation plan. Completions inherit
only a checked preceding operation and retain their contiguous IDs. No extra
poll, probe, revision, restart, event, timer or physical counter is accepted.
Hooks reachable through the engine and platform use a mutex; platform hook
installation holds the platform mutex.

The first aggregate failed because the new annotations were inserted ahead of
the existing appLine annotations, whose positions several ledger mutation
tests use. Appending the annotations preserves those tests; the restored full
aggregate passes. Local compilation also caught two incorrect import paths in
the new test before any replay ran.

Remaining trace work: hungEngine, quitFailure, routingAndReads,
settingsSetupUpdate and migration. The additional obligations listed in
m4-semantic-ledger.md remain outside this denominator and are not claimed here.
No engine process, service, TUN or host route was run locally.
