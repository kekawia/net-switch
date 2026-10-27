# Native lifecycle replay: recovery slice

Plan recorded before implementation, 2026-10-27, against main 6ed22230.
This is a bounded part of retirement PR 3, separate from native policy goldens.
It adds native counterparts and deletes no historical evidence.

## Semantic mapping and assertions

The handoff inventories six `fakeRemote` consumers in round2 and two in
round3. This slice covers seven of them through production Remote, the real
native protocol server and the real in-memory flow table:

- Transport failure: disconnect a loaded instance; reattach must advance its
  epoch exactly once, retain its revision, and never publish a failure identity.
- Held reconnect: gate the next dial; status must be starting with the same
  instance and no error until native hello/attach/status complete.
- Stale stopped query: hold the old service query across a successful attach;
  its eventual stopped answer cannot fail the replacement attachment.
- One failure identity: classify the same failed instance twice; retain one ID.
- ForgetLane: it is a native no-op with no IPC; the complete revision owns lanes.
- Acknowledged stop: the real stop unloads policy; a blocked service wait has a
  deadline, invokes bounded forced cleanup and publishes off only after success.
- Seven lease exits: each starts with a loaded native revision, then consumes a
  matching native cleanup outcome and reaches off without a failure identity.

These are lifecycle semantics called out by the trace retirement handoff,
not dispositions of individual frozen trace entries. No claim of consuming
any of the 7,894 entries is made. The historical tests remain unchanged.

## Coverage boundaries

Exercises native hello, attach, status, start, renew and stop transport paths,
revision restoration, epoch changes, service queries and exit classification.
The fixture has no OS engine, capture, routes, sockets or service manager;
service outcomes are typed inputs. Pipe endpoints are memory-only and server
goroutines are joined. Real protocol handling rejects unsupported methods.

No HTTP routes, settings/backup/usage/Undo writes, probe votes, outside closes,
or exact console/event/log ordering are covered. The error/failure fields and
transport-recovery/forced-stop log conditions are checked, not frozen log text.
No claim is made about real lease-clock expiry or installed cleanup.

Still required: the eighth consumer (version rejection before attach), the
adapter-only/missing-capability boundary, both adapter test replacements
(invalid start and multi-frame pagination), four-client × fifteen-action Run
concurrency, and the full hash-keyed exact-once native semantic ledger. Keep
the original traces, node.json and seven Undo cases. Native goldens are being
handled separately. Installed harness replacement and physical deletion come
later; this slice does not complete M4.

## Validation and review handoff

The final focused run passed 20 leaf tests: 12 new native cases and the eight
original lifecycle test functions (the old lease test loops internally).
The new suite also passed ten repetitions before the final added assertion
that acknowledged stop unloads the flow table's policy. The final run includes
that assertion. All runs used Go 1.27.3, Idle priority, GOMAXPROCS=2 and -p=2.
Formatting and whitespace checks passed. Only this report and the new test
file changed; production code and frozen reference bytes are unchanged.

The seven lease cases use independent instances, matching the original test's
structure. They prove Remote's classification, not accumulated Control crash
budget state or actual sleep/lease-clock behavior. Stop cancellation is injected
after acknowledgement; the test checks the production 20-second graceful and
10-second forced-cleanup deadlines without sleeping through those budgets.

Existing lifecycle CI includes the new file in its offline contracts. Existing
main CI includes it under the race detector on Linux x64/ARM64 and Windows x64.
Hosted results and independent logic review remain pending. No CI was watched.
For review, compare the seven mappings above with the new tests and the original
round2/round3 consumers. Check fixture cleanup, reconnect publication barriers,
and the stated distinction between typed service outcomes and installed proof.
