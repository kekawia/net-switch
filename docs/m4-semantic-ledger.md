# Native replay semantic ledger v2

Updated 2026-10-30. Implements NATIVE-REPLAY-RETIREMENT and the locked design
§§2–3, 4.1, 4.4–4.6 and 5.7. The 25 frozen traces now have complete native
assertion bindings. This document does not authorize installed-harness retirement
or deletion of frozen references.

## Final measured result

The restored local Windows aggregate reports **7,894 / 7,894**, zero uncovered
and no pending entries. All four producers and replay-report exit **0**.
Static inventory alone still credits zero: only receipts from passing tests count.

| Measure | Entries |
| --- | ---: |
| Hash-verified original entries | 7,894 |
| Covered in the passing Windows aggregate | 7,894 |
| Uncovered / pending | 0 / 0 |
| Unchanged external observation | 1,284 |
| Translated native operation/result | 5,215 |
| Named atomic revision member | 36 |
| Obsolete representation with replacement assertion | 1,359 |

Exactly two entries, settingsSetupUpdate 7–8, describe Windows machine-store
protection. They are scoped to the existing native Windows ACL-policy test
`TestTrustedMachineSecurity`. Linux requires and credits 7,892 entries; the
other two remain outside that job's scope, never falsely credited. The Windows
test checks owner/DACL/write-grant policy, not installed ACL application.

The final trace uses the existing driver, ordered counterpart/file cursors and
ledger v2. See [final slice evidence](m4-native-remaining-replay.md),
[reconnect](m4-native-reconnect-replay.md), [live revisions](m4-native-live-replay.md),
[health](m4-native-health-replay.md), [policy](m4-native-policy-replay.md) and
[startup](m4-native-startup-replay.md).

## Implementation and use

`internal/replayledger/mapping.json` is the versioned, machine-readable source.
It has 25 original SHA-256 keys, eight generic rules with 25 whole-trace
bindings each, 90 sequence annotations, nine atomic groups, and references to
existing supporting tests. V2 adds response-bounded HTTP groups with an explicit
`boundary: response` and `ack: -1`: no fake original acknowledgement is invented.
Their executing owner proves native acknowledgement before the HTTP return.
All members must share one owner and scope. V1 timer-backed groups still work.
Response-only intervals reject recorded timer-completion and state-snapshot
markers. Poll and HTTP rule-file representations also pass the shared ordered
revision-file cursor: exact file sets, distinct write/publication/rename pairs,
and a distinct consumed native acknowledgement are required before receipts.
It contains no copied fixture payloads. The fixtures and provenance are read
from their existing `tests/oracle` paths, never regenerated or rewritten.

`DefaultMapping`, `Load`, and `Build` validate the mapping and expand it into one
row per original entry. Trace names sort only the independent trace runs;
sequence order inside each trace is untouched. Every row carries its original
hash, sequence, kind/direction, disposition, assertion obligation, status and
optional revision group. Generic unchanged kinds share one checked rule;
explicit annotations replace that rule only at their named sequences. Duplicate
annotations and overlapping generic rules fail, rather than silently winning.

The ordinary test emits totals as JSON. For all 7,894 per-entry rows, including
every uncovered entry, run with the pinned toolchain and the usual Idle/two-core
wrapper:

```text
go test -mod=vendor -p 2 -count=1 -v ./internal/replayledger
go test -mod=vendor -p 2 -count=1 -v ./internal/replayledger -run ^TestNativeSemanticLedger$ -args -ledger-report
```

The JSON inventory is one test-log line. Nothing writes a log or modifies a
fixture. Inventory alone earns no coverage.

Native replay assertions use `NewCursor` with their selected rows and call
`Consume(t, hash, seq, disposition)` **after** their behavioral checks pass.
The cursor compares the mapping's test name with `t.Name()`, including subtests;
it does not accept a caller-supplied test name. `Finish` rejects omissions and
cross-kind reordering. `Receipt(t)` requires the same test, an exhausted cursor and
`!t.Failed()`. It writes one `REPLAY_RECEIPT {json}` line through `t.Log` per
assertion/hash/group. Row selections are generated from the mapping, not copied
by hand into the test. Behavioral checks still need review and mutation proofs;
knowing which test ran does not prove that its assertions are adequate.

**Cursor is a convenience, not a security boundary.** The owning test can print
a receipt line itself. Review must read its Consume sites and the behavioral
assertions before them; mutation proofs must show those checks matter. Round 2
removes `callerIdentity`, `runtime.Caller` and the `-trimpath` special case:
they cannot prevent the owning test from printing a line and add no protection
to the aggregate pass/ownership gate. The module-name constant stays solely in
that gate: it turns the mapping's relative source path into an exact package
identity, rejecting a same-named test in a foreign package. This is simpler than
adding a module-discovery mechanism, while retaining the same package check.

The AST check covers every annotation, per-trace rule binding and supporting
reference. A target must be a top-level Test function taking `*testing.T`, with
no results or type parameters. An absent source file is allowed only if **all**
references to that function are `pending #N`; those rows can never produce a
receipt. A present file with a deleted or malformed test fails, even if pending.
Mixed pending and non-pending references to an absent function fail. Pending
counts are reported by PR number, not hardcoded to #107.

### Cross-package aggregation in CI

The existing internal-package test step in `ci.yml` now builds the small report
command and pipes the same test sweep straight into it (Windows and Linux):

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$PSNativeCommandUseErrorActionPreference = $false
go build -o ./bin/replay-report.exe ./internal/replayledger/cmd/replay-report
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$script:replayTestExit = $null
& {
  go test -json -count=1 -timeout=10m ./internal/... ./cmd/... ./tests/...
  $script:replayTestExit = $LASTEXITCODE
} | & ./bin/replay-report.exe
$replayReportExit = $LASTEXITCODE
if ($null -eq $script:replayTestExit) { throw "Test process did not finish" }
if ($script:replayTestExit -ne 0) { exit $script:replayTestExit }
if ($replayReportExit -ne 0) { exit $replayReportExit }
exit 0
```

The command loads the hash-verified mapping, validates its source targets, and
joins receipts across packages. It waits for the receipt's exact test, all parent
tests and the package to PASS. Failures after logging, including cleanup failures,
invalidate the run. Unknown entries, repeated receipts, mismatched package/test
identities, pending entries, incomplete groups and truncated streams fail.
Every non-pending row with a valid test binding **must** receive a receipt on
each applicable job. A missing Consume, missing Receipt, t.Skip, excluded test,
build tag, or package left out of the command cannot quietly reduce coverage.
The gate reports the missing entry count and the first missing trace/sequence
and test. Unbound generic obligations remain explicitly uncovered.
Split test-output events are reassembled before reading receipt JSON. Test
diagnostics remain visible on stdout. `build-output` events print their Output;
`build-fail` marks its ImportPath failed, even when no Package field is present.
A recorded compile-failure stream proves the original compiler text survives.
There is no saved log; both native process exit codes are checked explicitly.
PowerShell preserves the native Windows environment that Git Bash changed;
see [the CI investigation and separate product follow-up](m4-ledger-ci-environment.md).
The final line is `covered N / 7,894`, with
uncovered and per-PR pending counts. The standalone inventory always reports zero
covered; only aggregated executing tests earn credit. No static `covered` flag exists.

Bindings may set `"os": "windows"` or `"os": "linux"` for genuinely
OS-specific tests. Omit it for pure cross-platform replay. The joiner uses its
own GOOS, with no command-line override: a Windows-scoped row is required on
**every Windows matrix job**, including ARM64, and not credited on Linux. A
Linux-scoped row is required on every Linux job. A receipt from the wrong OS
fails, so a scoped test must skip or be excluded by its platform build tag on
the other OS. Both OS jobs remain required CI jobs; a success on the other OS cannot
satisfy the scoped obligation. Rows outside this job's scope remain uncovered
in its report, not falsely covered. An atomic group's members must share one
OS scope; unknown OS strings fail mapping validation.

### Compact bindings and the startup slice

The shared startup replay belongs in package `control`, in
`internal/control/native_startup_replay_test.go`, to reuse its pure Control
fixtures without importing Control from lifecycle. It is one
`TestNativeStartupReplay` with 25 named per-trace subtests, sharing setup code
but replaying each trace's own startup inputs and ordered assertions.

Concrete fixtures to reuse from `internal/control/core_test.go`: `testCore`
creates the initial settings-backed Core and returns `*fakeEngine`,
`*fakeClock` and `*memoryFiles`; `testCoreWithFiles` supports accumulated state
and restart. Reuse `fakeClock.advance`, `memoryFiles.beforeWrite`, `failPrefix`,
`syncs`, `writes`, `events`, `logs` and `recordOrder`, plus `fakePlatform`'s
recorded outside-close hook. Set `c.op.ServiceMode = true`. Replace the engine
boundary with a new pure `nativeStartupEngine` in the startup test file: reuse
`fakeEngine` only for observation plumbing, override Start/Apply to call the
production `engine.NativeRevision` compiler, compare independent literal
`policy.Config` expectations with `apppath.Windows` for these Windows fixtures,
and supply checked native acknowledgements. Extend the file observer to include
journal writes: the existing `recordWriteOrder` filter alone is not sufficient.
Do not call `installReplayAdapter` or delegate mutations to the old adapter.

Build a `nativeTraceComparator` in that same test file. Its
`Observe(seq, kind, actual)` method compares the next original-sequence value
and native transaction boundary; reuse `orderedTraceJSON`,
`rewriteTraceStrings`, `normalizeResourceString`, `operatorStateExpectation`
and `firstDifference` from `replay_test.go` for their narrow existing purposes.
Use explicit native group/ack observations, not `revisionOutputOrder`'s old
adapter reordering. Record all effects in one stream through `recordOrder`;
do not compare separately sorted kind lists. The comparator reports success
to the test, which then calls Cursor.Consume. Its `Finish` checks no effects,
replies or groups remain. The [startup foundation](m4-native-startup-replay.md)
now supplies `nativeStartupEngine`, ordered selected-value/effect comparisons,
and reply/group exhaustion. All three startup/saved-identity traces are
registered with explicit lifecycle and stale-state replacement contracts.
Ordered native counterpart and exactly-once file cursors reject reordered or
reused observations; all 25 traces now consume their own startup entries.

Each subtest calls `DefaultMapping`, `Load("../..", mapping)`, and `Build`, then
selects the original-order rows whose hash matches its fixture and whose
assertion equals its registered `file#TestNativeStartupReplay/traceName` binding.
It passes those rows to `NewCursor`. Consume each row only when the native
boundary assertion succeeds; call Receipt once at the end of that subtest.
Startup rows from a trace must have one owner: a later feature replay must reuse
the setup without emitting another startup receipt.

Rules accept `"bindings": {"<fixture hash>": {"test": "internal/control/native_startup_replay_test.go#TestNativeStartupReplay/appLine"}}`.
This binds every matching kind in that trace unless a sequence annotation
overrides it. Each rule needs **one binding per fixture hash it is claiming**;
there is no wildcard or global test binding. Eight rules across all 25 traces
need at most 200 compact bindings, not 7,894 sequence integers. Split the
existing I/O rule into a completion-only rule if the
assertion owners differ. Thus the 3,003 completion markers require per-trace
bindings, not 3,003 hand-authored sequence numbers. An annotation also accepts
inclusive `"ranges": [[0,134]]` alongside `seqs`; overlaps, negative/reversed
ranges and out-of-bounds ranges fail. Use a range only where the whole span has
one disposition/owner; mixed dispositions retain their kind rules. Ranges and
rule bindings do not themselves imply coverage.

Worked appLine mapping diff (historical API-only starting point). The completed
registration also includes the named replacement annotations described above.
Here `H` is `80a0365dc4be2eb7617807696f8ecd6948d01511288b1074b0311d31d9133c11`
and `T` is `internal/control/native_startup_replay_test.go#TestNativeStartupReplay/appLine`.
Each line adds the shown member to the existing rule object; expand H and T
to those exact strings. Preserve each rule's kinds, disposition and obligation:

```diff
 rules[0] ordered-external-observations
+  "bindings": { H: { "test": T } }
 rules[1] native-requests-results-and-instance-flow-bijection
+  "bindings": { H: { "test": T } }
 rules[2] native-probe-rounds-and-busy-suppression
+  "bindings": { H: { "test": T } }
 rules[3] control-io-and-revision-boundaries
+  "bindings": { H: { "test": T } }
 rules[4] native-session-and-verified-cleanup
+  "bindings": { H: { "test": T } }
 rules[5] diagnostic-conditions-and-session-announcement
+  "bindings": { H: { "test": T } }
 rules[6] no-stale-compiled-lines-or-pins
+  "bindings": { H: { "test": T } }
 rules[7] acknowledgement-replaces-reload-wait
+  "bindings": { H: { "test": T } }
 annotations and groups: unchanged (#107's 23 rows retain their owners/status)
```

The effective result adds 188 registered appLine rows alongside #107's 23 bound rows;
all other traces remain untouched. This is **not only the 135-entry startup
prefix**: the appLine subtest must also drive the recorded pin/unpin suffix and
check its other 53 bookkeeping/completion entries, without emitting #107's 23
receipts. A prefix-only implementation cannot register all eight whole-trace
bindings. The reload-wait rule has no remaining unannotated appLine row, so its
binding adds no required receipt by itself. To scope a real OS-only binding,
use `{ "test": T, "os": "windows" }`; annotation overrides likewise accept
`"os"` and replace the entire binding/scope for their rows.

## Obligations and existing evidence

| Mapping assertion | Required native assertion before receipt |
| --- | --- |
| `ordered-external-observations` | Exact ordered inputs, API field presence/nulls/arrays, settings precedence, snapshot timing, events and outside-close selectors. Physical counters retain their meaning. Explicit default-probe and resource-ID mappings only. |
| `native-requests-results-and-instance-flow-bijection` | Version → hello/capabilities, paged flows with one-to-one instance-scoped IDs, failed observations without invented death, DELETE selectors and fenced results. Lane operations need explicit complete revision groups. |
| `native-probe-rounds-and-busy-suppression` | Physical line, operation ID, instance/kind fencing, full-round votes, busy suppression and exact snapshot-side timing. |
| `control-io-and-revision-boundaries` | Actual I/O errors, undefined versus null, ordered durable settings/backup, intent/journal boundaries, full literal policy, matching ack and post-ack publication/closure. Adapter file bookkeeping needs explicit revision/cleanup annotations. |
| `native-session-and-verified-cleanup` | Endpoint acquisition/release, authenticated service instance, start/stop outcomes, verified cleanup, failure budget and failed Quit/retry. No fake native listeners or directory scans. |
| `diagnostic-conditions-and-session-announcement` | Each log condition and its order, severity, resource identity and failure details; native session announcement. No blanket omission. |
| `no-stale-compiled-lines-or-pins` | Successful directory-list purpose replaced by complete-revision cleanup; old callback failures remain separately accounted for through async results. |
| `acknowledgement-replaces-reload-wait` | Native acknowledgement barrier, without an artificial 300 ms sleep, at each of the three original waits. |

These obligations are now backed by registered native tests. Mixed kinds such
as file completions, writes and engine requests keep value-specific mappings
and complete transaction assertions.
No claim is made that every such entry has the same native representation.

For `file-completion`, **translated** means a native Control I/O operation's
completion replaces the original callback: assert the corresponding operation,
success or actual error, and its position relative to settings, backup and
revision publication. A removed adapter-file write instead needs an explicit
native revision or cleanup assertion; merely finding its completion marker is
not enough. For `completion`, the original boundary ID/kind and adjacency remain
checked, and the replay must assert the corresponding native operation completed
on that side of the next observable effect. Go need not reproduce a JavaScript
callback ID, but it must prove the operation, result, null/undefined semantics
where relevant and order before consuming the marker. The per-trace bindings now supply those behavioral assertions; every applicable
row must receive its executing owner's receipt.

PR #105 proves the twelve config families, six pin/share families and empty-app
policy from `test/fixtures/windows-golden.json` inputs, through literal native
configuration/decision checks. It does not consume any of these trace entries.
Its eight test functions are named in `supportingEvidence` and described in
`m4-native-goldens.md`.

PR #106 proves seven lifecycle recovery semantics: reattach, held reconnect,
stale query fencing, one failure identity, no-IPC ForgetLane, bounded acknowledged
stop, and seven accumulated lease-exit cycles. Reattach/held reconnect share a
test, so the mapping names six primary test functions. It likewise consumes zero
trace entries. `m4-native-lifecycle-replay.md` describes its additional regression
tests and limits. The ledger verifies these named test declarations still exist;
it does not substitute that source check for executing their suites.

PR #107 binds these 23 selected entries to the executing cross-platform subtests:

| Assertion | Original appLine sequences | Disposition |
| --- | --- | --- |
| `TestNativeAPIPinReplay/pin` | 135, 158, 163, 168, 170 | Unchanged |
| Same, `appLine-pin` revision | 138, 143, 148, 153 | Atomic revision |
| Same, acknowledgement replacing reload | 166 | Obsolete |
| `TestNativeAPIPinReplay/unpin` | 171, 194, 199, 204, 206 | Unchanged |
| Same, `appLine-unpin` revision | 174, 179, 184, 189 | Atomic revision |
| Same, acknowledgement replacing reload | 202 | Obsolete |
| `TestNativeAPIPinReplay/read` | 207, 208, 210 | Unchanged |

The v1 group shape is deliberately **appLine-specific**: HTTP trigger,
timer-completion acknowledgement replacement, API publication, and output write
members with `apps-`, `share-` or `cut-` file prefixes. Settings writes are not
revision members. Other transaction shapes need a reviewed mapping/schema
extension; do not force them into these appLine assumptions.

The group intervals are 135–170 and 171–206, with acknowledgement replacements
at 166 and 202. Every intervening entry still has its own row; grouping never
moves or hides those entries. All rule writes in each interval must be members,
even if somebody removes both an annotation and its group-member declaration.
Missing triggers, barriers, publication boundaries, members or groups fail.
These checks validate the plan's grouping, not the actual native ack semantics.
#107 rebases onto #108's merged main cf10c6db. Its registration
changes its seven annotations from `pending #107` to `uncovered`, keeps
the exact 23 sequences and test/subtest references, and adds Consume/Receipt
calls to those passing native assertions. The AST check then requires the file
and function to exist. Only a passing aggregated run flips those 23 report rows
to covered; merely merging the file or changing the status does not. Its other 188 entries were subsequently registered by the startup replay;
no API receipt was duplicated.

## Follow-ups outside the 7,894-entry count

“New” means added by this PR; “mapped” means an existing named native test.
All named tests below passed locally, in the pure aggregate or the focused
protocol suite. Startup replacements also execute their named subtests. Control tests are in
`internal/control`, lifecycle tests in `internal/lifecycle`, and the invalid
start test in `internal/engine`.

| Follow-up | Disposition and evidence |
| --- | --- |
| node.json authentication, malformed and invalid actions | **New:** `TestNativeNodeNegativeHTTPContracts` checks all 12 negative routes' full status/headers/body and absence of native mutation. |
| Seven Undo cases | **New:** `TestNativeUndoFailureOracle` executes damaged-policy, damaged-metrics, policy-failure, save-failure, partial-ordered, empty-record and legacy-ordered in service mode; compares remaining records, calls and diagnostics. |
| Failed native Apply | **Mapped:** `TestServiceLiveUpdateFailureRetriesWithoutStopping` injects preparation refusal through Poll and Supervise, retains the snapshot and retries the same durable number/hash. |
| Lost Apply acknowledgement | **New:** `TestNativeApplyAcknowledgementRecovery/lost` commits through the real protocol/flow table, holds the reply, cancels its caller, then delivers it late. The client does not publish it; retry returns the same apply point and keeps the held flow. |
| Mismatched Apply acknowledgement | **New:** `TestNativeApplyAcknowledgementRecovery/number` and `/hash` corrupt the actual protocol reply after commit. Both are rejected without snapshot publication; retry is idempotent. |
| Closure retry identity | **Mapped:** `TestReconnectPersistsItsOriginalSelectionBeforeClose` retains the exact durable request across a lost answer and newly opened flow. This is Control boundary evidence. |
| Closure instance fencing | **Mapped:** `TestClosureIsFencedToItsOriginalInstance` rejects stale instance IDs and replacement between capture/send through native IPC while preserving the unrelated flow. |
| Journal versus settings-mirror failure | **Mapped:** `TestServiceJournalFailureDoesNotReachEngine` and `TestServiceSettingsMirrorFailureKeepsCommittedSettings` distinguish refusal before commit from repair after authoritative commit. |
| Exact totals recovery | **Mapped:** `TestTotalsConsumerSurvivesCrashesAroundTheAck` and `TestTotalsAreNotAcknowledgedWhenTheCommitFails` reconstruct Control across write/ack boundaries using production flow accounting and independent exact byte totals. |
| Version rejected before attach | **New:** `TestNativeHelloRejectionBeforeAttach/version` changes only native hello; the first subsequent valid attach must still receive epoch 1. |
| Adapter-only and missing-native capabilities | **New:** `TestNativeHelloRejectionBeforeAttach/adapter` and `/missing`; **mapped:** `TestRemoteRefusesEnginesMissingRequiredCapabilities`. No attachment or runtime start is permitted. |
| Invalid native start | **New:** `TestNativeInvalidStartHasNoPlatformEffects` checks six invalid revisions. None calls the fake TUN opener, touches routes, creates a stack or publishes policy. |
| Native pagination beyond one frame | **New:** `TestNativeFlowPaginationReplacement` establishes 4,096 records, proves the unpaged encoding exceeds 1 MiB, then checks all ordered IDs, owners and counters through Remote.Connections. Measured sample: 2,541,823 bytes. |
| Four clients × fifteen Run actions | **New:** `TestNativeRunFourClientsFifteenActions` runs actual Core.Run with the native protocol and flow table; all 60 actions complete, app discovery, streams/probes and at least ten reads occur, shutdown unloads policy, workers join, and fatal logs are absent. |
| Unknown methods, epoch fencing and protocol concurrency | **Mapped:** `TestUnknownMethodRejected`, `TestEngineAssignsEpochs`, `TestRevisionProtocol`, `TestDecodeLimitsAndUnknownFields`, `TestSlowApplyAllowsRenewalButSerializesAttach` and `TestConcurrentProbeIdempotencyDoesNotBlockRenew` in `internal/engine/protocol`; the focused pure suite passes. |

The eight historical fakeRemote consumers are explicitly accounted for:

| Historical consumer | Native replacement |
| --- | --- |
| TestTransportFailureReattachesWithoutEngineFailure | **Mapped:** TestNativeRecoveryReplayReattach, with exact epoch advance and no false failure identity. |
| TestTransportInterruptionIsStartingUntilReattached | **Mapped:** TestNativeRecoveryReplayReattach, with the dial held before publication. |
| TestOldStoppedQueryCannotFailReplacement | **Mapped:** TestNativeRecoveryReplayStaleServiceQuery. |
| TestOneFailureIdentityPerEngineInstance | **Mapped:** TestNativeRecoveryReplayFailureIdentity. |
| TestVersionMismatchRefusedBeforeAttach | **New:** TestNativeHelloRejectionBeforeAttach/version. |
| TestForgetLaneDoesNotPerformIPC | **Mapped:** TestNativeRecoveryReplayForgetLane. |
| TestAcknowledgedStopHasDeadlineAndForcesFailOpen | **Mapped:** TestNativeRecoveryReplayAcknowledgedStop. |
| TestLeaseExitAfterRepeatedStandbyNeverBecomesCrash | **Mapped:** TestNativeRecoveryReplaySevenLeaseExits, retaining accumulated state through seven exits. |

The two adapter_test replacements are the new invalid-start and pagination tests.
The old four-client adapter Run test is retained beside its new native replacement.
Additional mapped regression coverage includes TestNativeRecoveryReplayOverlappingStops
and TestNativeRecoveryReplayTransportLostDuringStop.

## Product change and evidence limits

The hello test reproduced a real gap: production Remote accepted an adapter-only
engine and consumed attach epoch 1. Native Control now rejects that hello before
attach, as required by the retirement handoff. Historical adapter fixtures use an
explicit unexported test hook; production never sets it. This is the only product
change in this PR. The sole production NewRemote caller is ControlService.

The native runtime fixture uses the production protocol and flow table over
memory pipes. Platform outcomes are staged inputs. No engine process, real
service, TUN, capture or host route was run locally. Invalid-start testing uses
an opener that can only record an erroneous call and return an error.

**Still separate:** installed parity, actual protected-store installation,
Linux attribution/integrity release gates, and adapter/binary removal. These
are not silently marked complete by replay coverage. Hosted race checks and
independent review remain required before merging; this PR remains a draft.

## Validation and gate evidence

Pinned Go 1.27.3, Idle priority, GOMAXPROCS=2 and -p 2. The complete pure Control,
control/engine and ledger suites plus selected lifecycle, native invalid-start
and Windows ACL-policy tests stream go test -json -count=1 directly into
replay-report. No saved logs. Final coverage is 7,894 with all five exits zero.

The final settings gate mutations are run and reverted: missing receipt,
failing subtest, dropped full-response check and reordered observations. Earlier
slice mutation evidence remains in their linked documents. Restoring adapter
acceptance makes the hello test fail; dropping native acknowledgement validation
makes both mismatch cases fail. The restored suites pass.

The missing settings receipt rejected 318 required rows (0/0/0/0/1). A failed
settings subtest refused its receipt; dropping the response check failed at
160/http expecting 159/api; swapping autostart results failed at 142. Each of
those three aggregates exited 1/0/0/0/1. No mutated source or fixture remains.

The requested CI dependency tests,
`node --test .github/ci/ledger.test.mjs .github/ci/drift.test.mjs`, pass all
17 tests. The new Windows binding is declared in drift.mjs and classified as
shared because Linux also parses that test declaration.
The final staged-tree run also includes changes.test.mjs: 41 pass, zero failures
or skips. All eight historical fakeRemote consumers pass with explicit test-only
adapter selection; the production capability check remains strict.

The ledger continues to reject changed hashes, duplicate/missing dispositions,
unpaired replies, incomplete groups, unearned receipts, failed/skipped parents
and incomplete streams. Original replies are only per-route FIFO: the frozen
format has no request IDs, so same-route outstanding replies cannot be uniquely
distinguished. Native operation IDs and instance fencing are tested separately.
