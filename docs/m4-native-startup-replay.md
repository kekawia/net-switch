# Startup and saved identities replay work

Inventory recorded before implementation, against main 22e044d7 (2026-10-29).
The initial requested slice had 463 unregistered entries: appLine's remaining 188,
legacyCaseOrder's 144, and savedVersionOrder's 131. No frozen bytes may change.

Current result: all three traces are registered. The restored aggregate reports
**covered 486 / 7,894; uncovered 7408; pending map[]**, both producers and report
exit 0. The 154/298 figures below are the earlier saved-identity checkpoints.

## Inputs, conditions and gaps

- Routes: POST /api/app-line (pin then unpin) and GET /api/state. The historical
  engine requests are GET /version, PUT /proxies/lane-{id}, and GET
  /proxies/line-{id}/delay. No DELETE, connection pagination or failed engine
  observation occurs in this slice.
- Settings: two connected, equally weighted physical lines, IPv6 and combining
  off, no caps, default probes. appLine begins without pins. legacyCaseOrder
  migrates empty lines plus mainAlias/secondAlias and differently cased duplicate
  cableApps/secondApps paths. savedVersionOrder has two ordered Discord version
  paths: 1.0.9 on a1 followed by 1.0.10 on b2. The later saved identity must win.
  Preserve the input object's order; decoding appLines into an unordered Go map
  before loading settings would destroy the evidence.
- Startup files: settings exist; Undo, usage and old engine.pid do not. Observe
  actual native reads and absence results, atomic writes and backups. Package
  metadata, directory creation, temporary-file completions and removed rule/PID
  writes require separately named native replacements, not successful no-ops.
- Diagnostics: worker-source announcements, session startup, routing starting/on,
  both lane-target announcements, and the legacy-settings migration announcement.
  No routing failure, cap, failover or reconnect diagnostic occurs.
- Directory cleanup: appLine has a successful directory list. The saved identity
  fixtures instead record readdir ERR_INVALID_ARG_TYPE; their absence of a
  directory-list event must not be treated as successful cleanup. Native complete
  revision replacement needs independent stale-pin/lane assertions.
- Timing: the origin is 2026-10-19T12:00:00Z; startup has no clock advances.
  Physical counter readings are null and successful probe delays are 18 ms.
  appLine includes probe votes, snapshot boundaries and two 300 ms reload waits;
  those waits become acknowledged revision barriers under design §§3.3/4.4.
  The saved identity traces end with GET/state without a state-snapshot marker.
- Session boundaries: legacy control listeners 47820/47821, temporary engine
  listener 49000 acquisition/release, session file and console announcement,
  child spawn/PID and version handshake. A fakeEngine instance string alone
  does not prove native authentication, capability validation or endpoint release.

Nearby gaps remain: custom probes, failed/delayed probes, busy suppression,
non-null counters, clock changes, stale replies, concurrent requests, failed
settings/journal writes, restart/reattach, failed startup/quit, unknown settings,
invalid/authenticated API cases, installed service lifecycle and real traffic.
No engine, service, TUN or routes may run on this PC.

## Required evidence boundaries

Reuse the Control fixtures and one native compiler boundary. Start and Apply must
both compile the production policy against independent literal expectations;
the historical adapter must not participate. Use one ordered effect stream,
including journal writes. Check starting state, durable intent and settings,
matching acknowledgement and publication in each transaction.

Receipt registration must wait for every owned row's behavioural check. In
particular, the full-trace rule bindings illustrated in m4-semantic-ledger.md
cannot be installed for a startup-only or identity-only test. Existing appLine
API receipts retain their existing owner.

The shared comparator checks original sequence/kind and ordered JSON values;
it must reject missing/repeated observations and leftover native effects. A
comparison is evidence only for the supplied actual observation, not for any
unobserved asynchronous operation. No blanket completion handler earns receipts.

Research: Go's [testing contract](https://pkg.go.dev/testing) requires FailNow on
the test goroutine and does not stop other goroutines. Boundary callbacks return
errors to their caller; the executing test reports them. The aggregate report
must continue to require the subtest, parents and package to pass.

## Registered savedVersionOrder checkpoint

All 131 entries now have executing owners. The aggregate adds them to the
existing 23 appLine entries: **covered 154 / 7,894**, with 7,740 uncovered.
All bindings are cross-platform; these tests use Windows identity rules
explicitly without starting an engine process, service, listener, TUN or routes.

- 112 entries: `TestNativeStartupReplay/savedVersionOrder` in Control.
- 17 obsolete listener/PID/spawn/version entries (7–8, 21–22, 57–58, 62–65,
  93–99): `TestNativeStartupSessionReplacement` in lifecycle.
- Two obsolete failed-cleanup entries (86–87):
  `TestLegacyEmptyAppsReplacesPinsWithoutASentinel` in control/engine.

Each owner selects its original-order rows from the hash-verified shared
mapping, performs the behavioural checks, then emits its receipt. Existing
appLine ownership is unchanged. There is no copied 131-entry expectation list.

### Native replacements and guards

| Original kind / operation | Native evidence and named guard |
| --- | --- |
| initial-files | Real Store load retains the saved raw JSON and ordered app identities; `ordered settings read` and `saved setting`. |
| file-completion: settings, Undo, usage reads | Observe actual read bytes/errors during construction, including fs.ErrNotExist; `actual store read result`. |
| package read / mkdir | Obsolete representation: host-supplied Core version and constructed settings/journal stores replace package metadata and adapter-directory setup. The API proves the supplied version is exposed. This is not a disk-permissions test. |
| adapter-snapshot / platform.detectAdapters | Recorded inputs go through RefreshAdapters/ApplyNetwork, not direct final-state assignment; `platform operations` and `production adapter observation`. |
| counter-sample | Null physical counters remain unknown, with no invented routed bytes; initial Poll and exact usage-file contents. |
| platform.readDefaultRoutes / readMinimizeConnectionsPolicy / isElevated | One native worker network snapshot consolidates same-time adapter/routes/policy reads; every original result is compared against the resulting state. Elevation runs through CheckElevation. |
| socket-completion / spawn / PID read-write / version request-reply | Obsolete stand-in mechanisms bound to the named native session contract below, not fake listeners or PID files. |
| server/usage write and file-completion | Actual atomic write/rename results, persisted JSON, destination and order; `actual atomic native publication`. |
| apps/share/cut/config writes and completions / lane request-reply | Complete literal native policy, matching acknowledgement, exact lane selectors/results and pin decisions; `complete acknowledged revision`. No adapter file is written. |
| failed readdir and its completion | Explicit ERR_INVALID_ARG_TYPE remains classified as failure, not a successful list. The existing native flow-table replacement test first proves a pin exists, replaces the complete revision, then proves it disappeared without a sentinel. |
| probe request / probe-result / delay JSON result | Physical line, unique operation ID, interface index, operator, kind, instance, outcome and 18 ms latency; completed round state before API. The healthy startup takes one successful quick check per line, not an invented full round. |
| log / log.append result | Ordered native diagnostics and exact callback arguments/null/undefined semantics; pending diagnostic callbacks must drain. Worker-source wording changes under §4.3; conditions and order remain. |
| log.rotate | Obsolete private child-log representation. The named startup test proves native diagnostic delivery and absence of child log/config/PID artifacts; no fake rotation is introduced. |
| console | Production PublishSession return, alongside the atomic session write and announcement order. |
| http / api | Real HTTP handler and complete ordered request/response comparison, including status, headers, nulls and array order. Only §4.5's third default probe is translated. No read-side effects or clock advance. |
| completion | Original ID/kind/adjacency checked; receipt inherits the already checked completed native operation. Unsupported or unproved operations cannot earn markers. |

The native session replacement invokes the existing real in-memory protocol
tests for hello/instance mapping, required capabilities, Start/Apply points,
release/reacquisition through reattach, and acknowledged cleanup. It validates
that its bound original entries are only the explicitly retired kinds.
Transport trust is supplied by the fixture; net.Pipe is **not** proof of OS peer
authentication, installed endpoint ACLs or real service cleanup. Those remain
the existing installed/identity gates. This is the named-contract substitution
permitted by the handoff; it does not manufacture socket activity inside Control.

The ordered native stream includes construction reads, logs, journal writes,
session/usage publication, staged desired policy, Start, Apply/ack and probe
round boundaries. `Finish` rejects unconsumed effects, outstanding replies,
open groups and unobserved API entries. Tests deliberately leave each kind of
remainder behind and require failure. Original callback order is checked
without independently sorting effect kinds.

### Startup publication defect found and fixed

The previous fake published an Apply while off, then reset its revision during
Start. Real Remote.Apply only stages desired state while off; native Start
returns with that revision already loaded. The shared boundary now models
that contract, also checked by the existing real protocol Start/Apply test.

This exposed a product bug in Control's already-applied fast path: it returned
without publishing lane targets/diagnostics after native Start. Startup lacked
both lane logs; they appeared later during an unrelated pin request. The fix
publishes matching lane state on that fast path, after any required journal
update, with a generation check. Repeating ApplyPolicy produces neither a new
apply nor repeated logs. This is parity restoration under §§4.1/4.4, not a new
allowed divergence. Repository issue search found no existing report.

### Validation and sensitivity

The pure Control, control/engine and ledger suites, followed by the selected
native lifecycle contract, stream go test JSON directly into replay-report.
All commands use pinned Go 1.27.3, Idle priority, GOMAXPROCS=2 and -p 2; both
producer exit codes and the report exit code are checked. No logs are saved.

The restored final stream reported 154 covered / 7,894, with both producers
and the report exiting 0. The dependency graph reported no problems, and all
13 workflow gate tests passed (28,932 evaluated gate cases). Frozen reference
and oracle bytes remain unchanged.

Mutations executed and reverted on the newly registered trace:

- Remove the startup receipt: producers 0/0, report 1, missing 112 entries
  starting at savedVersionOrder:0.
- Fail its subtest after checks: producers 1/0, report 1; Receipt refuses emission.
- Remove the actual HTTP replay/comparison call: producers 1/0, report 1;
  Finish reports missing behavioural observation at 129/http.
- Remove the product fast-path publication fix: producers 1/0, report 1;
  startup lacks lane logs and the existing pin replay detects delayed logs.

Earlier foundation mutations also showed saved-version key reversal changes
the compiled pin from b2 to a1 and fails the literal policy guard.

Validation corrections: an initial PowerShell consumer script did not forward
stdin and the report rejected its empty stream; the corrected pipeline connects
the native commands directly. New annotations exposed a ledger unit test that
assumed every annotation belonged to the original 23 API rows; its pending-PR
fixture now explicitly selects those API annotations. No coverage gate was
weakened.

### Registered legacyCaseOrder checkpoint

All 144 legacyCaseOrder entries are now registered, using the same driver:
125 Control rows, 17 session replacements, and 2 cleanup replacements.
The passing aggregate reports **298 / 7,894**, both producers and report exit 0.
The generation bijection is 010101 → 000001 and 020202 → 000002. It is applied
only to resource identities in decoded trace copies, including embedded JSON;
saved executable paths and object order remain unchanged. The generated IDs
and their distinctness are independently asserted against Core's migrated lines.

Migration checks the original read, the changed full ordered settings document,
both durable settings copies and the migration diagnostic. Native service
construction also journals the migrated desired state and repairs its settings
mirror on recovery; the extra journal/mirror writes are included in the ordered
native stream. The original two differently cased keys remain in order and the
second pin wins for both Windows case variants. No new product code changes.

Sensitivity mutation: swapping cableApps and secondApps in the in-memory input
failed `ordered migrated settings guard`, showing the reversed saved keys and
their line IDs. It was reverted; frozen fixture bytes were unchanged.

### Registered appLine and completed slice

appLine's remaining 188 entries are now registered: 167 to its startup replay,
17 to the native session contract, and 4 successful-directory-list/callback
entries to the existing complete-revision cleanup contract. The original 23
API entries keep their original owners and groups without duplicate receipts.

The pin/unpin executor is shared with TestNativeAPIPinReplay. The startup owner
uses it on its continuously running Core, with receipts disabled for those 23
entries, then checks every remaining file/completion/snapshot obligation. Both
native revisions, durable settings/backup and journal ordering, pin removal,
acknowledgement barriers, snapshot timing and absence of extra probes/logs are
checked by the same executor. Two real settings writes cannot share one result.
Probe votes are tied to completed native rounds and their publication time.

The redundant TestNativeStartupIdentityEvidence was removed. Changed-version,
case-variant and near-neighbour/unpinned decisions now run in the full driver.
The fixture table keeps independent literal policies; generated migration IDs
are mapped bijectively and the session token comes from each trace's own input.

### Review fixes: ordered observations and exactly-once file calls

The previous value-only checks could accept reordered async observations or
reuse a previous successful file operation. The driver now has two consuming
cursors in addition to the aggregate receipt cursor:

- The counterpart cursor projects the native startup transaction into ordered
  legacy observations. Every engine/probe/log/async-result/vote has a named
  source position in the actual native effect stream, which must already have
  passed its boundary comparison. The projection explicitly expands one atomic
  revision into its ordered lane members and one worker snapshot into its
  same-time legacy reads. Its operation order is independent of the trace loop;
  it never sorts the observed kinds or constructs expectations from the entry
  currently being checked.
- The file cursor advances over actual read/write/rename results once. A
  publication compares the bytes of that particular preceding write, and the
  rename must follow its checked publication. Only named native journal/recovery
  operations and the migration mirror repair are grouped separately; repair
  bytes must equal the first publication. Finish rejects unused calls and
  pending writes. Assertion-only file inspection uses peekFile and cannot
  create fake product read evidence.

Real replay mutations, all reverted, failed the aggregate with producers 1/0
and report 1:

1. Swap savedVersionOrder's log.append and delay.json values (112/114): the
   counterpart cursor rejects delay.json where log.append is required.
2. Put its probe-result before the GET request (108/109): the cursor rejects
   probe-result where engine GET /proxies/line-a1/delay is required.
3. Remove appLine's second settings write observation after asserting it exists:
   sequence 192 rejects rename where a distinct writeFile is required. Both HTTP
   mutations themselves succeeded, proving the gate detects missing evidence
   rather than merely relying on the product request failing.

Permanent regressions cover reordered async/probe observations and a missing
second file write. The restored complete pure suites and selected native
lifecycle contract report 486 covered; the dependency graph reports no problems.
Synthetic ledger binding tests retain their original 85-completion/135-range/
188-plus-23 checks by explicitly starting with the original API-only fixture,
rather than accidentally including the new overriding startup annotations.

No work remains in this 463-entry slice. The other slices still contain 7,408
uncovered entries. Hosted checks and independent re-review remain pending.
