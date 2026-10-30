# Native replay semantic ledger v2

2026-10-27, based on main `3c7b26d0`. Implements the accounting boundary in
NATIVE-REPLAY-RETIREMENT.md, with locked design §§3.3, 4.1, 4.4–4.6 and 5.7.
This is an inventory and assertion-receipt mechanism, not the missing replay.
It authorizes no retirement or deletion.

## Measured result

Completed hungEngine, 2026-10-30: 486 more entries, passing local aggregate
**7,094 / 7,894** (800 uncovered), exits 0/0/0. Failed observations preserve
the native instance and recover without the retired poll-count restart.

Completed quitFailure, 2026-10-30: 175 more entries, passing local aggregate
**6,608 / 7,894** (1,286 uncovered), exits 0/0/0. See
[remaining slice evidence](m4-native-remaining-replay.md).

Completed reconnect slice, 2026-10-30: reconnectPinned and reconnectShared add
305 entries, bringing the passing local aggregate to **6,433 / 7,894**
(1,461 uncovered), exits 0/0/0. Hosted race checks and independent review remain.
See [reconnect evidence](m4-native-reconnect-replay.md).

Completed live line/IPv6 slice, 2026-10-30: adapterRename, ipv6, lineAdd,
lineOrder and lineRemove add 2,143 entries, bringing the passing local
aggregate to **6,128 / 7,894** (1,766 uncovered). Gate mutations fail and were
reverted. Hosted race checks and independent review remain. See
[live replay evidence](m4-native-live-replay.md). Earlier checkpoints follow.

Completed health slice, 2026-10-30: failoverFailback, busyFailedChecks,
probeFailover and lostDefaultRoute add 2,063 entries, bringing the passing local
aggregate to **3,985 / 7,894** (3,909 uncovered). All four requested gate mutations
failed and were reverted. Hosted race checks and independent review remain.
See [health replay evidence](m4-native-health-replay.md). The policy slice totals
below describe the preceding checkpoint.

Updated 2026-10-29 by the six-trace policy/physical-usage slice in PR #112.
The pure Control, control/engine and ledger suites plus the selected native
lifecycle contract report `covered 1922 / 7,894; uncovered 5972; pending map[]`
(all exit codes 0). This adds 1,436 entries to the existing 486 startup/API
entries without an OS restriction. Static inventory still credits zero.
Missing receipts, failing subtests, dropped HTTP checks and reordered cross-kind
observations failed the gate in reverted mutations.
See [policy replay evidence](m4-native-policy-replay.md) and the earlier
[startup evidence](m4-native-startup-replay.md).

| Measure | Entries |
| --- | ---: |
| Hash-verified original entries consumed once by accounting | 7,894 |
| Proven by native trace assertions in a passing aggregate run | 1,922 |
| Uncovered after that run | 5,972 |
| Pending #107 | 0 |

| Checked disposition (coverage is separate) | Entries |
| --- | ---: |
| Unchanged external observation | 1,284 |
| Translated native operation/result | 6,309 |
| Member of a named atomic revision | 36 |
| Obsolete representation with a replacement assertion | 265 |
| Total | 7,894 |

The distinction matters: assigning an assertion obligation to a completion or
log is not proof that native Control produced that completion or log. No feature
test is credited for entries it never read. The current generic obligations
remain uncovered outside the registered traces. No assertion name
alone, or a manually edited `covered` status, earns coverage.

## Implementation and use

`internal/replayledger/mapping.json` is the versioned, machine-readable source.
It has 25 original SHA-256 keys, eight generic rules with nine whole-trace
bindings each, 41 sequence annotations, nine atomic groups, and references to
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
fixtures without importing Control from lifecycle. It will be one
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
reused observations; the other 22 traces still need their own startup receipts.

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

These are named **uncovered obligations**, not invented passing tests. Mixed
kinds such as file completions, writes and engine requests remain translated
until their value-specific mapping and complete transaction assertions exist.
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
where relevant and order before consuming the marker. Current generic bindings
do not yet supply those behavioral assertions and remain uncovered.

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

## Exact uncovered inventory

All sequences below are inclusive and remain uncovered after the API and
all three startup traces' passing aggregate.
The full JSON report supplies each individual row without maintaining a second
hand-written trace. Each trace starts at sequence zero.

| Trace | Uncovered sequences | Count |
| --- | --- | ---: |
| adapterRename | 0–280 | 281 |
| appLine | None (0–210 registered across its owners) | 0 |
| busyFailedChecks | 0–686 | 687 |
| capBlockedAndMainException | 0–274 | 275 |
| capMoved | 0–221 | 222 |
| capReset | 0–255 | 256 |
| combining | 0–196 | 197 |
| combiningNoOpenLine | 0–297 | 298 |
| failoverFailback | 0–231 | 232 |
| hungEngine | 0–485 | 486 |
| ipv6 | 0–1152 | 1,153 |
| legacyCaseOrder | None (0–143 registered) | 0 |
| lineAdd | 0–200 | 201 |
| lineOrder | 0–273 | 274 |
| lineRemove | 0–233 | 234 |
| lostDefaultRoute | 0–394 | 395 |
| midnightGap | 0–187 | 188 |
| migration | 0–190 | 191 |
| probeFailover | 0–748 | 749 |
| quitFailure | 0–174 | 175 |
| reconnectPinned | 0–153 | 154 |
| reconnectShared | 0–150 | 151 |
| routingAndReads | 0–267 | 268 |
| savedVersionOrder | None (0–130 registered) | 0 |
| settingsSetupUpdate | 0–340 | 341 |
| **Total** | | **7,408** |

| Input kind | Uncovered | Output kind | Uncovered |
| --- | ---: | --- | ---: |
| adapter-snapshot | 82 | api | 59 |
| adapters | 1 | console | 22 |
| async-result | 867 | engine | 393 |
| clock-tick | 506 | event | 17 |
| completion | 2,807 | log | 257 |
| connections | 40 | outside-close | 2 |
| connectionsStatus | 2 | remove | 27 |
| counter-sample | 447 | spawn | 30 |
| directory-list | 16 | write | 330 |
| engine-reply | 302 |  |  |
| file-completion | 819 |  |  |
| helper-line | 12 |  |  |
| http | 59 |  |  |
| initial-files | 22 |  |  |
| interfaces | 5 |  |  |
| probe-result | 91 |  |  |
| probe-vote | 33 |  |  |
| probes | 3 |  |  |
| process-exit | 10 |  |  |
| quitFailure | 2 |  |  |
| refresh-adapters | 1 |  |  |
| release | 1 |  |  |
| routes | 2 |  |  |
| socket-completion | 104 |  |  |
| state-snapshot | 31 |  |  |
| timer-completion | 1 |  |  |
| update-reply | 4 |  |  |
| updateStatus | 1 |  |  |

## Remaining slices

These disjoint counts partition the remaining 7,408 entries outside the API
and completed startup receipts. Shared
startup machinery should be implemented once; each trace must still supply and
consume its own startup entries. Slices include completions and all external
observations, not just their headline feature.

| Slice | Traces / entries | Total |
| --- | --- | ---: |
| Startup and saved app identities | Complete: appLine remainder 188, legacyCaseOrder 144, savedVersionOrder 131 | 0 |
| Policy transactions, caps and physical usage | combining 197, combiningNoOpenLine 298, capBlockedAndMainException 275, capMoved 222, capReset 256, midnightGap 188 | 1,436 |
| Health, probes and route votes | failoverFailback 232, busyFailedChecks 687, probeFailover 749, lostDefaultRoute 395 | 2,063 |
| Live line/IPv6 revisions | adapterRename 281, ipv6 1,153, lineAdd 201, lineOrder 274, lineRemove 234 | 2,143 |
| Reconnect and flow identity | reconnectPinned 154, reconnectShared 151 | 305 |
| Lifecycle and read APIs | hungEngine 486, quitFailure 175, routingAndReads 268 | 929 |
| Settings, setup, updates and migration | settingsSetupUpdate 341, migration 191 | 532 |
| **Total still uncovered** | | **7,408** |

Build the shared native boundary and ordered comparator with the startup slice,
then reuse it. Required follow-ups outside this 7,894-entry denominator remain:
node.json authentication/malformed/invalid actions, all seven Undo cases, native
failed applies and lost/mismatched acks, closure retry/fencing, journal/settings
failure distinction, exact totals recovery, lifecycle capability/invalid-start/
pagination/concurrency replacements, installed parity and removal gates.

## Validation and review boundary

The ledger itself is pure accounting. The startup replay also fixes Control's
already-applied lane publication; see its evidence doc. No engine, service, TUN
or route is started locally. The normal internal-package CI sweep includes this package.
The test checks the original request/reply stream, including all 97 `/delay`
requests omitted by the old cross-kind comparison, and rejects leftover replies,
missing responses, unsupported kinds (including future exit), detached/missing
completion markers, invalid mappings and incomplete revision groups.
Reply pairing is **per-route FIFO only**: these traces carry a route but no
request ID. It rejects leftovers and missing results, but cannot distinguish
two outstanding requests to the same route whose results are swapped. This is
a trace-format limit, not a claim of native operation-ID verification.

Mutation cases operate on freshly decoded in-memory copies, never frozen bytes.
The five required mutations are unknown kind, duplicate disposition, removed
disposition rule, reply with no matching request, and missing revision member.
Additional cases reject coordinated member/annotation removal, unknown rules,
unearned coverage, changed fixture hashes, missing fixture sets, stale assertions
and out-of-order consumption. A temporary positive expectation is used to show
the five required mutations make a real test run fail, then reverted.

The initial five mutated positive cases failed with their specific diagnostics;
the initial restored suite passed 25 leaf cases. All Go commands use
Go 1.27.3, Idle priority, GOMAXPROCS=2 and `-p 2`. The first full dependency-check
attempt exposed an unresolved computed test-source path. Explicit read-site
declarations now cover the fixtures, provenance and three supporting test files.
After that correction, the actual dependency graph reports no problems, both
here and on the main baseline. The entire classifier mutation suite was not
rerun in that round; hosted checks and independent logic review remain pending.
The declaration list remains unchanged in round 1. A dedicated dependency test
fails if `supportingEvidence` adds a source file outside its declared reads.

Round 1 validation: 61 passing leaf cases, with one subprocess-only fixture
skipped in the outer run (its passing, failed and late-cleanup-failure modes all
ran in bounded child processes). The real test binary's receipt passed through
the pinned `test2json` converter and aggregator; prior failure refused emission,
and a cleanup failure after emission invalidated coverage. The streaming command
ended with `covered 0 / 7,894; uncovered 7894; pending map[#107:23]`. Static checks,
the dependency graph and 14 dependency/gate tests passed. No log file was saved.

Requested source mutations were run and reverted:

- Rename `TestConsumeIdentity`: Consume failed with the old expected binding and
  the actual `TestConsumeIdentityRenamed` identity.
- Delete that function: `TestBindingTargets` failed with the missing
  `*testing.T` test declaration.
- Change the absent #107 target's status to uncovered: `TestNativeSemanticLedger`
  failed opening its missing source file. Pending references alone still pass.

The settings-write mutation also fails at appLine sequence 158: it is not an
apps/share/cut rule-write member. Counterexamples for unknown and repeated
receipts, failed/skipped tests, failed parents/packages, incomplete streams,
range overlaps, and partial groups remain in the ordinary suite. The hosted
full internal sweep and independent re-review are still pending.

Round 2 adds a hard completeness gate for all applicable registered rows.
Two temporary mutations each made `TestReceiptRuntimeProof/pass` fail at the
joiner with `missing required receipts for 1 registered entries on windows`:
excluding the registered child test with a non-matching test filter, and
removing its Receipt call while leaving the test itself passing. Both mutations
are reverted. Ordinary regressions retain those cases plus skips, excluded
packages, and required/mismatched Windows and Linux bindings. A real 1.27.3
compile failure was recorded into `testdata/build-failure.json`; its
`build-output` diagnostics and `build-fail` ImportPath are both asserted.
The subprocess converter now comes from `exec.LookPath("go")`; local runs put
the pinned toolchain on PATH just as CI does.

The restored PowerShell pipeline passed the pure suite (77 leaf cases plus the
outer subprocess-fixture skip), static checks and the streaming report. Separate
native-process probes returned 7 for producer=7/consumer=0, 9 for
producer=0/consumer=9, and 0 only for both=0. No output file was used. The next
hosted Windows test counts remain a separate pending check.

Review this document with the ledger package and the two existing evidence docs:
can a fresh reader connect the next slice without guessing what counts as proof;
does any machinery duplicate the existing replay unnecessarily; and do these
counts, pending sequences and evidence limits match the code? This change only
adds shared accounting, not a second replay implementation. Full native replay
and M4 retirement remain incomplete.
