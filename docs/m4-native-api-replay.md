# Native API replay: app pin/unpin slice

Plan recorded before implementation, 2026-10-27, on main 3c7b26d0.
This is the first bounded API slice of retirement PR 3, not the complete
7,894-entry ledger. Nothing frozen is edited or retired.

## Trace mapping

`appLine.trace.json` has 211 entries and SHA-256
`80a0365dc4be2eb7617807696f8ecd6948d01511288b1074b0311d31d9133c11`.
The mapping is versioned and bound to that hash. It covers these 23 entries:

- HTTP inputs 135, 171, 207 and API outputs 170, 206, 210: replay pin, unpin,
  then state read on one continuously running native Control boundary. Compare
  complete response objects, status, headers, array order and explicit nulls.
- Settings/backup writes 158, 163, 194, 199: compare whole persisted documents
  with the trace, before each native mutation, and check their publication order.
  Before both mutating requests, settings.json must differ from the requested
  document. The final GET expects no settings change or write.
- Rule writes 138, 143, 148, 153 form atomic revision `pin`; writes 174, 179,
  184, 189 form `unpin`. Replace their representation with independent literal
  full native configs and decisions. No dummy executable, compiled rule files,
  or Clash commands. Unpin must remove the previous pin without resetting Core.
- Waits 166, 202: replace each 300 ms reload delay with an acknowledged native
  revision barrier. Assert ack before response returned, without clock advance
  or any Clock.After call during any of the three requests. The counting fake
  completes waits immediately in this replay so an unexpected wait fails an
  assertion rather than hanging.
- State snapshots 168, 204, 208: compare the recorded clock and full response.
  Probe and platform call counts must stay unchanged across each request.
  This does not instrument the instant State() constructs the response.

One ordered observed ledger spans settings, backup, journal, native apply/ack,
and response return: desired journal and backup, settings and backup, refreshed journal
and backup, apply, acknowledgement, response returned. The api marker is recorded
after ServeHTTP returns. Both journal copies must contain
the complete submitted revision and settings before Apply. Settings move before mutation under locked design §§3.3/4.4;
the old rule-write-before-settings sequence is deliberately not reproduced.
Native compilation uses production NativeRevision with Windows identity rules.
Whole-policy literals and owner decisions are independent of that compiler.
The only response translation is the explicit addition of Quad9 to the two
legacy default probes (§4.5). The saved settings bytes retain the legacy list;
the test checks that distinction rather than changing the trace inputs.

## Boundaries and remaining work

The other 188 entries are **uncovered**, not silently marked consumed: startup
0–134 (135 entries), and 53 file/completion bookkeeping entries in the suffix.
Initial files and adapter inputs are used as setup, not claimed as replayed
startup. The Windows policy value 1 and successful 18 ms probe replies are
hand-set startup preconditions, not derived or replayed from startup entries.
The selected trace has no logs or events during the three requests;
assert that silence, and no flow closure or restart. No log condition is retired.

Only POST /api/app-line and GET /api/state are exercised. No other route,
invalid/auth/malformed request, update, setup/Undo, line edit, combining change,
IPv6 transition, cap, usage counter, reconnect, probe vote, failed I/O, delayed
reply, real IPC or installed traffic is covered. Settings retain the trace's
defaults and two lines; this is not an unknown-key or multi-pin-order proof.
Adjacent uncovered cases are node.json routes[14] (pin with custom probeTargets
containing only 9.9.9.9:443) and routes[15] (empty-path pin rejected with 400).
All other 24 traces remain uncovered by this slice. The full exact-once ledger,
completion/error driving, version/capability rejection, invalid start,
pagination and concurrency still need separate slices.

## Validation

The final focused run passed 42 leaf cases: three new API replay steps,
14 native Control golden cases, and all 25 retained historical traces
(7,894 entries). Go 1.27.3 ran at Idle priority, GOMAXPROCS=2, -p=2,
-mod=vendor and -count=1. After review round 1, the package reported 6.703 seconds.
No service, engine process, capture, route or app ran locally.

Sensitivity mutation (reverted): making POST /api/app-line return immediately
after saving settings, without ApplyPolicy, failed the pin step. Its ordered
ledger ended in `settings backup -> api`, missing native apply/ack. Restoring
the call passed the complete run above. No product defect or runtime change
is claimed. The earlier setup failures were missing initial usage sampling,
the explicitly mapped third default probe, and the historical file observer
omitting journal writes; these were fixture gaps, not product fixes.

Round 1 added two mutation proofs, both reverted before the final run:
- A 300 ms Clock.After wait in the product app-line path failed with
  `request called Clock.After 1 times`; the fake clock did not advance.
- Dropping pin compilation failed with `native apply guard: native revision
  differs from literal`, naming the missing AppLines value rather than only 500.

Apply now delegates acknowledgement bookkeeping to fakeEngine with ackPoint,
then publishes StartedWith as the live-update fixture does. Compilation and
literal comparisons remain native. No helper resets accumulated state.

Hosted checks at the revised head and independent re-review remain pending. The existing main
CI runs this package; no new privileged job or workflow is added. Frozen
reference/oracle bytes and production source remain unchanged.

## Shared ledger registration

Rebased onto cf10c6db after PR #108 merged. All seven annotations are now bound
(`status: uncovered`, with their actual test/subtest references) in
internal/replayledger/mapping.json. No OS scope is set: these are pure tests.
Each subtest selects its rows from Build in original sequence order and checks
that each selected row has a behavioral assertion in that subtest. Only after
all response, durability, native-policy, ordering and I/O checks pass does it
Consume those rows and call Receipt. The cursor emits one receipt per owned
group: two for pin, two for unpin, one for read (23 entries total).
The parent emits no duplicate receipt. The aggregate gate requires each owner,
its parent and its package to pass. Static inventory alone still credits zero.
Cross-slice ownership stays in the shared ledger; no second registry is added.

2026-10-29 validation: the complete `go test -json -count=1` sweep of
`./internal/control ./internal/replayledger` streamed directly into replay-report,
without a log file. Both processes exited 0; the report printed
`covered 23 / 7,894; uncovered 7871; pending map[]`. Package times were
21.770 s and 29.923 s. The pinned toolchain ran at Idle priority with
GOMAXPROCS=2 and -p=2. Fifteen CI dependency/workflow gate tests also passed.

Three temporary mutations were tested and reverted:
- Omitting read's Receipt left the tests passing but replay-report failed with
  three missing required receipts, first appLine:207 (producer 0, report 1).
- Failing read after Consume made Receipt refuse emission. No read receipt was
  logged and the aggregate rejected the failed package (producer 1, report 1).
- Renaming TestNativeAPIPinReplay made TestNativeSemanticLedger fail its source
  binding check with the missing Test function and original bound name.

The report now lists all failed build import paths in sorted order, with a
two-order regression. The shared CI replay step explicitly selects UTF-8.
Hosted checks at this rebased head remain pending; CI was not watched.

The later [startup replay](m4-native-startup-replay.md) now shares this slice's
native boundary and registers savedVersionOrder separately. The current
aggregate is 154 entries; this API test still owns exactly its original 23.
The startup work also restores initial lane publication when native Start has
already acknowledged its revision; the failure and reverted mutation are
documented there. Earlier validation results above describe the API slice at
the time it first registered.
