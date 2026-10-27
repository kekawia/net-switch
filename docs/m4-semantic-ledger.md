# Native replay semantic ledger v1

2026-10-27, based on main `3c7b26d0`. Implements the accounting boundary in
NATIVE-REPLAY-RETIREMENT.md, with locked design §§3.3, 4.1, 4.4–4.6 and 5.7.
This is an inventory and assertion-receipt mechanism, not the missing replay.
It authorizes no retirement or deletion.

## Measured result

| Measure | Entries |
| --- | ---: |
| Hash-verified original entries consumed once by accounting | 7,894 |
| Proven by native trace assertions on this branch | 0 |
| Uncovered | 7,894 |
| Of the uncovered entries, pending #107 | 23 |
| Remaining after #107's 23 assertions land and are connected | 7,871 |

| Checked disposition (coverage is separate) | Entries |
| --- | ---: |
| Unchanged external observation | 1,284 |
| Translated native operation/result | 6,582 |
| Member of a named atomic revision | 8 |
| Obsolete representation with a replacement assertion | 20 |
| Total | 7,894 |

The distinction matters: assigning an assertion obligation to a completion or
log is not proof that native Control produced that completion or log. No feature
test is credited for entries it never read. The current generic obligations
remain uncovered, including all 3,003 completion markers. No assertion name
alone, or a manually edited `covered` status, earns coverage.

## Implementation and use

`internal/replayledger/mapping.json` is the versioned, machine-readable source.
It has 25 original SHA-256 keys, eight generic rules, seven sequence annotations
for #107, two atomic groups, and references to the existing supporting tests.
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

The JSON is one test-log line. `go test -json` can wrap it in structured test
events for a machine consumer. Nothing writes a report or modifies a fixture.

Future native replay assertions use `NewCursor` with their explicitly selected
rows and call `Consume(hash, seq, disposition, assertion)` **after** their checks
pass. `Finish` rejects omissions, repeats, changed assertions and cross-kind
reordering. `Receipt` requires a finished cursor. `Report.Cover` accepts only
matching, uncovered rows with native test references (`_test.go#Test...`), rejects
pending/generic/stale/duplicate receipts, and updates the covered/uncovered
counts and breakdowns atomically. Replay must emit that report in the same test
run; the standalone inventory run deliberately cannot infer another test's pass.

Receipts trust their caller's assertions, as other test helpers do: they are not
proof that an arbitrary function name performed the behavior. Review and
behavioral mutations remain required before connecting a new slice. The
accounting test's own exhaustive cursor walk earns **no** native coverage.

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

PR #107 is read-only input to this work. Its 23 selected entries are pending:

| Assertion | Original appLine sequences | Disposition |
| --- | --- | --- |
| `TestNativeAPIPinReplay/pin` | 135, 158, 163, 168, 170 | Unchanged |
| Same, `appLine-pin` revision | 138, 143, 148, 153 | Atomic revision |
| Same, acknowledgement replacing reload | 166 | Obsolete |
| `TestNativeAPIPinReplay/unpin` | 171, 194, 199, 204, 206 | Unchanged |
| Same, `appLine-unpin` revision | 174, 179, 184, 189 | Atomic revision |
| Same, acknowledgement replacing reload | 202 | Obsolete |
| `TestNativeAPIPinReplay/read` | 207, 208, 210 | Unchanged |

The group intervals are 135–170 and 171–206, with acknowledgement replacements
at 166 and 202. Every intervening entry still has its own row; grouping never
moves or hides those entries. All rule writes in each interval must be members,
even if somebody removes both an annotation and its group-member declaration.
Missing triggers, barriers, publication boundaries, members or groups fail.
These checks validate the plan's grouping, not the actual native ack semantics.
After #107 lands, connect its assertions to receipts and then remove the pending
status. Do not relabel its other 188 entries as covered.

## Exact uncovered inventory

All sequences below are inclusive and uncovered, including pending #107.
The full JSON report supplies each individual row without maintaining a second
hand-written trace. Each trace starts at sequence zero.

| Trace | Uncovered sequences | Count |
| --- | --- | ---: |
| adapterRename | 0–280 | 281 |
| appLine | 0–210 | 211 |
| busyFailedChecks | 0–686 | 687 |
| capBlockedAndMainException | 0–274 | 275 |
| capMoved | 0–221 | 222 |
| capReset | 0–255 | 256 |
| combining | 0–196 | 197 |
| combiningNoOpenLine | 0–297 | 298 |
| failoverFailback | 0–231 | 232 |
| hungEngine | 0–485 | 486 |
| ipv6 | 0–1152 | 1,153 |
| legacyCaseOrder | 0–143 | 144 |
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
| savedVersionOrder | 0–130 | 131 |
| settingsSetupUpdate | 0–340 | 341 |
| **Total** | | **7,894** |

| Input kind | Uncovered | Output kind | Uncovered |
| --- | ---: | --- | ---: |
| adapter-snapshot | 88 | api | 64 |
| adapters | 1 | console | 25 |
| async-result | 922 | engine | 408 |
| clock-tick | 506 | event | 17 |
| completion | 3,003 | log | 279 |
| connections | 40 | outside-close | 2 |
| connectionsStatus | 2 | remove | 27 |
| counter-sample | 453 | spawn | 33 |
| directory-list | 17 | write | 368 |
| engine-reply | 311 | | |
| file-completion | 913 | | |
| helper-line | 12 | | |
| http | 64 | | |
| initial-files | 25 | | |
| interfaces | 5 | | |
| probe-result | 97 | | |
| probe-vote | 35 | | |
| probes | 3 | | |
| process-exit | 10 | | |
| quitFailure | 2 | | |
| refresh-adapters | 1 | | |
| release | 1 | | |
| routes | 2 | | |
| socket-completion | 116 | | |
| state-snapshot | 34 | | |
| timer-completion | 3 | | |
| update-reply | 4 | | |
| updateStatus | 1 | | |

## Remaining slices

These disjoint counts partition the entire 7,871 entries outside #107. Shared
startup machinery should be implemented once; each trace must still supply and
consume its own startup entries. Slices include completions and all external
observations, not just their headline feature.

| Slice | Traces / entries | Total |
| --- | --- | ---: |
| Startup and saved app identities | appLine remainder 188, legacyCaseOrder 144, savedVersionOrder 131 | 463 |
| Policy transactions, caps and physical usage | combining 197, combiningNoOpenLine 298, capBlockedAndMainException 275, capMoved 222, capReset 256, midnightGap 188 | 1,436 |
| Health, probes and route votes | failoverFailback 232, busyFailedChecks 687, probeFailover 749, lostDefaultRoute 395 | 2,063 |
| Live line/IPv6 revisions | adapterRename 281, ipv6 1,153, lineAdd 201, lineOrder 274, lineRemove 234 | 2,143 |
| Reconnect and flow identity | reconnectPinned 154, reconnectShared 151 | 305 |
| Lifecycle and read APIs | hungEngine 486, quitFailure 175, routingAndReads 268 | 929 |
| Settings, setup, updates and migration | settingsSetupUpdate 341, migration 191 | 532 |
| **Total outside pending #107** | | **7,871** |

Build the shared native boundary and ordered comparator with the startup slice,
then reuse it. Required follow-ups outside this 7,894-entry denominator remain:
node.json authentication/malformed/invalid actions, all seven Undo cases, native
failed applies and lost/mismatched acks, closure retry/fencing, journal/settings
failure distinction, exact totals recovery, lifecycle capability/invalid-start/
pagination/concurrency replacements, installed parity and removal gates.

## Validation and review boundary

Pure package only; no runtime code is changed and no engine, service, TUN or
route is started. The normal internal-package CI sweep includes this package.
The test checks the original request/reply stream, including all 97 `/delay`
requests omitted by the old cross-kind comparison, and rejects leftover replies,
missing responses, unsupported kinds (including future exit), detached/missing
completion markers, invalid mappings and incomplete revision groups.

Mutation cases operate on freshly decoded in-memory copies, never frozen bytes.
The five required mutations are unknown kind, duplicate disposition, removed
disposition rule, reply with no matching request, and missing revision member.
Additional cases reject coordinated member/annotation removal, unknown rules,
unearned coverage, changed fixture hashes, missing fixture sets, stale assertions
and out-of-order consumption. A temporary positive expectation is used to show
the five required mutations make a real test run fail, then reverted.

The five mutated positive cases failed with their specific diagnostics; the
restored suite passed 25 leaf cases. `go vet` also passed. All Go commands used
Go 1.27.3, Idle priority, GOMAXPROCS=2 and `-p 2`. The first full dependency-check
attempt exposed an unresolved computed test-source path. Explicit read-site
declarations now cover the fixtures, provenance and three supporting test files.
After that correction, the actual dependency graph reports no problems, both
here and on the main baseline. The entire classifier mutation suite was not
rerun; hosted checks and independent logic review remain pending.

Review this document with the ledger package and the two existing evidence docs:
can a fresh reader connect the next slice without guessing what counts as proof;
does any machinery duplicate the existing replay unnecessarily; and do these
counts, pending sequences and evidence limits match the code? This change only
adds shared accounting, not a second replay implementation. Full native replay
and M4 retirement remain incomplete.
