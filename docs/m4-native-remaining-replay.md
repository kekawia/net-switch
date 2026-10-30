# Remaining native trace slices

## Gate mutations and current checkpoint

Four new mutations ran through the full pure aggregate and were reverted:
missing migration receipt rejected 172 required rows (exits 0/0/1); a failed
migration subtest refused its receipt (1/0/1); dropping the shared HTTP response
check rejected missing API observations (1/0/1); swapping migration's Undo/backup
publications rejected a publication without its preceding write (1/0/1).
Restored aggregate: **7,553 / 7,894**, exits **0/0/0**. Frozen files are unchanged.
Hosted race checks and independent review remain.

## Follow-ups outside the denominator

- `TestNativeNodeNegativeHTTPContracts` runs all 12 negative node.json routes
  against a running, compiled native boundary and real service-mode Control.
  It compares complete status, headers and body, then checks no settings writes,
  engine mutations or removals occurred. This includes host/origin/token checks,
  malformed/oversized input, missing endpoints and invalid actions. The oversized
  request is 65,537 spaces; record.mjs hashes its JSON encoding. Initial Poll
  precedes Start, matching the recorded initialized lane state.
- `TestNativeUndoFailureOracle` runs all seven unchanged undo.json cases in
  service mode: damaged-policy, damaged-metrics, policy-failure, save-failure,
  partial-ordered, empty-record and legacy-ordered. Comparisons check status/error,
  remaining ordered Undo data, policy, every platform call and failure diagnostic.
  The original non-service tests remain too.
- Native failed Apply maps to `TestServiceLiveUpdateFailureRetriesWithoutStopping`.
  It injects preparation refusal through Poll and Supervise, checks the unchanged
  snapshot and exact apply-only calls, then requires the original revision/hash
  and durable desired policy on recovery. It runs in the aggregate.
- Journal/settings failure distinction maps to `TestServiceJournalFailureDoesNotReachEngine`
  and `TestServiceSettingsMirrorFailureKeepsCommittedSettings`. The former checks
  no engine call or revision advance after journal refusal; the latter retains
  the committed value in memory/journal and repairs its mirror on the next save.
- Exact totals recovery maps to `TestTotalsConsumerSurvivesCrashesAroundTheAck`
  and `TestTotalsAreNotAcknowledgedWhenTheCommitFails`. They use production flow
  accounting, reconstruct Control across interrupted commits/acks, and check
  independently supplied byte totals without double counting. Both execute here.
- Reconnect retry and instance fencing are mapped in m4-native-reconnect-replay.md.
  Native lease exits, failure identity and reattachment execute in the selected
  lifecycle aggregate. These remain pure protocol evidence.

Still open: settingsSetupUpdate (341 entries), lost/mismatched native Apply
acknowledgements, and the remaining native invalid-start/pagination/concurrency
replacement audit. Installed parity and removal gates are separate. The settings
trace's protectMachineDir callback needs an explicit native protected-store
replacement; no protection result is credited merely because a memory store was
constructed. No partial settings trace was registered in this checkpoint.

## migration

All 191 entries execute through the same native startup driver. Real Core.New
migrates setupUndo into both Undo copies before removing that legacy setting,
then converts legacy lines and pins. Both settings publications and backups
are compared in order, including the unknown keep:1.25 field. The final journal
and settings mirror match the literal complete native policy at startup.

Generated old IDs 050505/060606 map bijectively to native 000007/000008. The
native sequence follows the two Undo publications and first journal/settings
transaction. Labels, saved pin spelling, order and unknown settings retain their
original values. The startup rule cursor consumes all four files and one ack.
GET/state and successful Quit compare complete responses and cleanup.

The shared file cursor now distinguishes windows-undo.json.bak from the primary
file. Migration's final mirror repair follows its second settings publication;
the older single-stage migration still repairs after the first. Each repair
must equal its corresponding checked publication, without another receipt.

Aggregate **7,553 / 7,894**, 341 uncovered, exits **0/0/0**. No product changes.

## routingAndReads

All 268 entries are registered. Ping, installed apps, missing icon, routing off,
two off-state ticks, state reads and routing on all execute through real Control
and HTTP. Full responses include the installed-app array and icon query string.
The installed-app and app-info calls are ordered and counted. Off intent is
durable before Stop; two ticks neither restart nor query the stopped engine.
Control remains uncancelled and keeps the original session bytes throughout.

The second Start stages and acknowledges a complete native revision. Its rule
files consume a distinct acknowledgement in the existing cursor. Both physical
checks retain operator rotation and instance/kind fencing. The historical first
on-response captured b2's ping before its probe completed. The test dispatcher
defers that probe until response bytes have been constructed, then completes it
before delivery. It asserts the pending starting condition and exact snapshot
time; the following state read sees both completed results. No expected response
field is changed to mask this timing boundary.

Aggregate **7,362 / 7,894**, 532 uncovered, exits **0/0/0**. No product changes.

## hungEngine

All 486 entries are registered. The existing health driver feeds 20 failed
native connection reads, then one successful read, at the original times.
Every poll checks the identical running instance, policy and revision, unchanged
failure budget, and no restart or extra apply. The third failed observation
disables measuring and emits its exact diagnostic once; successful recovery
clears the failure counter and restores measuring. Physical probes retain
their 15-second cadence and complete native operation/instance checks.

The old restart at 20 seconds is explicitly obsolete under SYSTEM-DESIGN 2-3
and NATIVE-REPLAY-RETIREMENT. Its complete ordered stream is checked against
the existing restart plan. Repeated rule publications compare every field to
the already checked startup compilation, changing only the four enumerated
temporary identities. They earn no invented new native acknowledgement.
The first response now correctly has measuring:false until observations recover.
This implements an existing design decision, not a product change in this PR.

True-death evidence remains separate: TestNativeRecoveryReplaySevenLeaseExits,
TestNativeRecoveryReplayFailureIdentity and the startup replacement's reattach
case execute in the local aggregate. Restored aggregate: **7,094 / 7,894**,
800 uncovered, exits **0/0/0**. Hosted race checks and review remain pending.

A reverted mutation restoring the actual poll-count restart failed at the
second Start. Merely removing the two poll-count guards initially still passed:
the service-mode branch continued to do an idempotent live Apply, so it had not
restored a restart. The effective mutation also bypassed that live branch.

## quitFailure

The 175 entries use the shared startup driver and ledger v2. Both original
POST requests execute through HTTP and real Control. The first injected stop
failure returns the exact 400 response, resets quitting, retains the complete
session bytes and leaves Control uncancelled. It neither saves usage nor removes
anything. Both journal copies contain wanted:false before either stop attempt.

The retry starts from the retained error/PID observation, stops successfully,
saves usage through the existing file cursor, removes only server.json, cancels
Control and returns the exact successful response. All six diagnostics and
their effect order are checked. The simulated PID is a status observation;
no process is launched. Historical PID cleanup is an explicit replacement by
the acknowledged native stop, supported by TestNativeStartupSessionReplacement.

Pure Control, control/engine and ledger suites, plus the selected native
lifecycle startup and closure-fencing tests, pass through replay-report:
**6,608 / 7,894**, 1,286 uncovered, producer/lifecycle/report exits **0/0/0**.
No product behavior or frozen fixture was changed. Hosted race checks and
independent review remain pending.
