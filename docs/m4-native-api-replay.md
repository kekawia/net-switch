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
- Rule writes 138, 143, 148, 153 form atomic revision `pin`; writes 174, 179,
  184, 189 form `unpin`. Replace their representation with independent literal
  full native configs and decisions. No dummy executable, compiled rule files,
  or Clash commands. Unpin must remove the previous pin without resetting Core.
- Waits 166, 202: replace each 300 ms reload delay with an acknowledged native
  revision barrier. The response follows acknowledgement, without clock advance.
- State snapshots 168, 204, 208: preserve the recorded clock and construct the
  response after the transaction; no asynchronous probe completes in this suffix.

One ordered observed ledger spans settings, backup, journal, native apply/ack,
and response: desired journal and backup, settings and backup, refreshed journal
and backup, apply, acknowledgement, response. Both journal copies must contain
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
startup. The selected trace has no logs or events during the three requests;
assert that silence, and no flow closure or restart. No log condition is retired.

Only POST /api/app-line and GET /api/state are exercised. No other route,
invalid/auth/malformed request, update, setup/Undo, line edit, combining change,
IPv6 transition, cap, usage counter, reconnect, probe vote, failed I/O, delayed
reply, real IPC or installed traffic is covered. Settings retain the trace's
defaults and two lines; this is not an unknown-key or multi-pin-order proof.
All other 24 traces remain uncovered by this slice. The full exact-once ledger,
completion/error driving, version/capability rejection, invalid start,
pagination and concurrency still need separate slices.

## Validation

The final focused run passed 42 leaf cases: three new API replay steps,
14 native Control golden cases, and all 25 retained historical traces
(7,894 entries). Go 1.27.3 ran at Idle priority, GOMAXPROCS=2, -p=2,
-mod=vendor and -count=1. The package reported 8.020 seconds.
No service, engine process, capture, route or app ran locally.

Sensitivity mutation (reverted): making POST /api/app-line return immediately
after saving settings, without ApplyPolicy, failed the pin step. Its ordered
ledger ended in `settings backup -> api`, missing native apply/ack. Restoring
the call passed the complete run above. No product defect or runtime change
is claimed. The earlier setup failures were missing initial usage sampling,
the explicitly mapped third default probe, and the historical file observer
omitting journal writes; these were fixture gaps, not product fixes.

Hosted race checks and independent review remain pending. The existing main
CI runs this package; no new privileged job or workflow is added. Frozen
reference/oracle bytes and production source remain unchanged.

Review from this document and the touched code alone: is any mapping ambiguous?
Does the small native Apply boundary duplicate something that should be shared?
Report any differences between these coverage claims and the actual assertions.
