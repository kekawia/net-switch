# Startup and saved identities replay work

Inventory recorded before implementation, against main 22e044d7 (2026-10-29).
The requested slice has 463 unregistered entries: appLine's remaining 188,
legacyCaseOrder's 144, and savedVersionOrder's 131. No frozen bytes may change.

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

## Delivered foundation, not a completed replay slice

The shared `nativeStartupEngine` replaces the pin-only boundary. Both Start and
Apply now compile and compare full literal native policies; Apply checks a
monotonically advancing acknowledgement point, revision, hash and instance.
The existing API replay uses it and retains its 23 receipts. No production
source or mapping bindings change.

`TestNativeStartupIdentityEvidence` checks empty pins and saved Discord version
precedence through real Control and native policy compilation/decisions. It
also compares the saved-version state API, including explicit nulls, array
order, headers and absence of read-side effects. Raw saved JSON retains pin
insertion order. The comparator rejects out-of-order/duplicate/missing entries,
changed values, absent versus null and changed saved-key order. A failed
comparison remains failed even if a later call retries it correctly.

This is **not** a completed trace, including the one-trace fallback requested in
the brief. All 463 requested entries remain unregistered. The comparator checks
ordered selected JSON observations; native transaction-group/effect/reply
exhaustion still needs implementation before it can serve the full ledger
contract. The fake still supplies lifecycle/probe plumbing. There is no proof
of authenticated native session acquisition, capability negotiation or release.
No generic callback completion is claimed as checked.

Continue in this order without adding whole-trace bindings prematurely:

1. Finish savedVersionOrder's 131 entries: observable file results from Store
   construction (including missing files), native session/endpoint replacement,
   explicit readdir failure replacement, ordered journal/start/apply/ack,
   physical probe requests/results and diagnostic completions. Extend Finish
   to reject leftover native effects, replies and groups. Register that trace
   only when all rows have behavioural evidence.
2. Reuse that startup driver for legacyCaseOrder (144), preserving ordered
   migration, generated resource identities and settings/backup/log boundaries.
3. Replay appLine startup plus its remaining suffix bookkeeping (188), preserving
   the existing 23 API owners. Then the aggregate target is 486.

## Local validation and mutations

Pure Control and ledger tests run at Idle priority, GOMAXPROCS=2, -p 2 with the
pinned Go 1.27.3. JSON streams go directly into replay-report, with both native
exit codes checked and no saved logs. Initial helper failures were fixture
mistakes: service-mode Control prepares an Apply while off before Start, and
engine owner IDs need the same Windows normalization as the real attribution
boundary. Correcting these test assumptions required no product change.

Four temporary mutations were run through the aggregate gate and reverted:

- Remove the existing API read receipt: producer 0, report 1, three missing
  required receipts beginning at appLine:207.
- Fail that read subtest before Receipt: producer 1, report 1; emission refused
  for the failed test.
- Drop the saved-version API Observe call: producer 1, report 1; Finish reports
  `missing behavioural observation at 130/api`.
- Reverse the two saved Discord keys in the in-memory input: producer 1,
  report 1; literal policy guard reports a1 instead of b2 for the normalized
  Discord identity. Frozen fixture bytes were never edited.

The first two proofs apply to existing registered rows; the last two prove the
new supporting checks affect the gate, not that new rows have earned receipts.

Restored final aggregate: `covered 23 / 7,894; uncovered 7871; pending map[]`,
producer 0 and report 0. Control passed in 3.109 s and replayledger in 4.029 s.
The repository dependency graph reported no problems; formatting and diff
whitespace checks passed. Hosted checks and independent review remain pending.
