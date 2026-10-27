# Native lifecycle replay: recovery slice

Plan recorded before implementation, 2026-10-27, against main 6ed22230.
This is a bounded part of retirement PR 3, separate from native policy goldens.
It adds native counterparts and deletes no historical evidence. The native
tests sit beside the old adapter tests until PR 4 deletes the adapter.

## Semantic mapping and assertions

The handoff inventories six `fakeRemote` consumers in round2 and two in
round3. This slice covers seven of them through production Remote, the real
native protocol server and the real in-memory flow table:

- Transport failure: close a loaded instance's byte transport and let Remote's
  renew loop detect the loss; reattach must advance its
  epoch exactly once, retain its revision, and never publish a failure identity.
- Held reconnect: gate the next dial; status must be starting with the same
  instance and no error until native hello/attach/status complete.
- Stale stopped query: hold the old service query across a successful attach;
  its eventual stopped answer cannot fail the replacement attachment.
- One failure identity: classify the same failed instance twice; retain one ID
  while replacing the error with the actual exit classification and interruption
  cause. A no-op second classification must fail this assertion.
- ForgetLane: it is a native no-op with no IPC; the complete revision owns lanes.
- Acknowledged stop: the real stop unloads policy; a blocked service wait has a
  deadline, invokes bounded forced cleanup and publishes off only after success.
  Failed forced cleanup returns both errors and releases recovery suppression.
  The acknowledged instance stays Stopping through transport loss until its
  verified clean service outcome publishes Off. A new Start clears that intent.
  Concurrent Stops share one in-flight operation and its result; they do not
  repeat the graceful and forced budgets. A waiting caller can cancel its wait;
  a live joiner may retry once only after the owner's own context is canceled
  or expires; an internal stop deadline does not grant another budget. Deferred flight
  completion releases waiters even on panic, then rethrows to the crash handler.
  No-session SCM errors do not manufacture failure identities. A service that
  was actually observed running is watched even when attach and force both fail;
  its unauthenticated identity is never charged to the crash budget.
  Successful stop publication cannot discard a replacement session.
  `TestNativeRecoveryReplayFailedForcedStop` covers loss after the failed Stop
  returns. `TestNativeRecoveryReplayTransportLostDuringStop` covers loss during
  the graceful service wait, before failed forced cleanup releases suppression.
  Stale recovery classifications pause before another dial/query/outcome read.
- Seven lease exits: one Remote retains state across all seven cycles. Each starts
  a loaded replacement instance, consumes its matching native cleanup outcome,
  and reaches off without a failure identity. Its start-attempt count accumulates.

These are lifecycle semantics called out by the trace retirement handoff,
not dispositions of individual frozen trace entries. No claim of consuming
any of the 7,894 entries is made. The historical tests remain unchanged.

## Coverage boundaries

Exercises native hello, attach, status, start, renew and stop transport paths,
revision restoration, epoch changes, service queries and exit classification.
The fixture has no OS engine, capture, routes, sockets or service manager;
service outcomes are typed inputs. Pipe endpoints are memory-only and server
goroutines are joined by the shared `newNativeFixture`. Unsupported-method
rejection is a protocol property tested separately by
`protocol.TestUnknownMethodRejected`, added in this review round because no
explicit existing case was found. Old-epoch renewal rejection remains covered
by `protocol.TestEngineAssignsEpochs`; the duplicate replay assertion is removed.

The replay slice covers no HTTP routes, settings/backup/Undo writes, probe votes,
outside closes, or exact console/event/log ordering. The later usage-read fixes
below add separate startup preservation and harness polling evidence. The error/failure fields and
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

Review round 3's final focused run passed 36 leaf tests: 17 replay cases and
19 shared-fixture regression tests. Round 1 also checked the two separate
protocol cases. All runs used
Go 1.27.3, Idle priority, GOMAXPROCS=2 and -p=2. Frozen reference bytes remain
unchanged. Hosted race results remain pending.

Mutation proof: replacing recovery's default `failLocked` call with a no-op
made `TestNativeRecoveryReplayFailureIdentity` fail with "second exit
classification did not publish the interruption cause". Restoring the call
made it pass in the final run. The mutation is not committed.

The new failed-forceStop test first failed because stopping remained true after
an acknowledged stop followed by failed service wait and forced cleanup. Remote
now clears that flag and hands the current session to disconnect/recovery before
returning the joined error. The late-loss test checks
both failures and cleared recovery suppression, then closes the real transport.
It observes the recovery service query, checks Stopping with no failure identity,
and supplies a clean stopped outcome. Remote converges to Off without a failure
identity. This supersedes the earlier test's direct Stop retry.

Review round 2 adds an instance-scoped acknowledged-stop marker, separate from
the in-progress stop flag. It preserves Stopping in both disconnect publication
and the snapshot's closed-transport window. Round 3 replaces queued full Stop
attempts with a shared in-flight result. A stale query takes the cancellable one-second
pause as other recovery retries instead of immediately issuing more work.

Both requested regression mutations failed, then passed after restoration:
- Removing Stop serialization let B enter forced cleanup while A was held there;
  `TestNativeRecoveryReplayOverlappingStops` failed on that overlap.
- Removing the stale-result pause made two service queries occur in 0 seconds;
  `TestNativeRecoveryReplayStaleQueryIsPaced` failed. The test advances the start
  attempt during each service query to exercise accumulated stale results.

Neither mutation remains in the patch. The final run includes both fixes.

Round 3's early-loss test closes the transport inside waitStopped, waits for
rpc.Done and the diagnostic from renew's deferred disconnect, then returns the
wait error. This proves the loss was swallowed before forced cleanup fails.
Recovery must consult the service query and reach Off for a clean outcome or
publish the instance's failure identity for a crash outcome.

Mutation proof: omitting the failed-force recovery handoff made both early-loss
subtests fail with "swallowed transport loss never resumed recovery". Restoring
the handoff made both pass. The mutation is reverted. The overlapping-Stop test
now checks exactly one forced-cleanup call and identical returned errors for
both callers, instead of allowing a second serialized cleanup attempt.

Crash-budget non-consumption is proven where classification lives, in Remote.
Control core's counting is already covered by its refused-start tests; this
slice does not duplicate those. The chained lease cases exercise accumulated
Remote state, not actual sleep/lease-clock expiry.

Stop cancellation is injected after acknowledgement. The 20-second graceful
and 10-second forced-cleanup bounds asserted here are implementation constants
in `Remote.stopOnce`, not bounds derived by
these tests from the spec. Tests check deadlines without sleeping through them.

Existing lifecycle CI includes the new file in its offline contracts. Existing
main CI includes it under the race detector on Linux x64/ARM64 and Windows x64.
Review rounds 1–5 are addressed; hosted results and re-review remain pending. No CI
was watched.
For review, compare the seven mappings above with the new tests and the original
round2/round3 consumers. Check fixture cleanup, reconnect publication barriers,
and the stated distinction between typed service outcomes and installed proof.

## Hosted usage-read harness follow-up

The reported ARM64 failure on 8291482 was a sharing violation while reading
usage.json during publication. All harness usage reads now preserve the error and
skip only Windows sharing/lock violations (32 and 33), including wrapped PathError.
It does not accept an unreadable record as zero usage. All other read errors
are fatal. Settle and identity polling retain 25 seconds and 200 ms; quiescence
retains 60 seconds and one second. Standalone own()/routedApps reads use the
existing enclosing proof context's deadline. No deadline is widened. Timeout
remains fatal and reports the last good snapshot and last error, without a
final unguarded read. One shared polling helper enforces this everywhere.

The earlier product inspection was too narrow: lack of an overlapping product
writer does not make startup read errors safe. Round 4 proved that any read
failure could allow the next save to erase history. The corrected findings are:
- `Core.New` reads usage.json through durableFiles/os.ReadFile before Core.Run
  starts the usage writers. Concurrent ordinary readers allow read sharing;
  they do not block that startup read. It now retries Windows errors 32 and 33
  for ten 20-ms intervals, eleven attempts total. The round-4 startup refusal was
  wrong and is superseded by the round-5 decision below: accounting history must
  never prevent Control or routing from starting. Missing files retain their
  fresh-start behavior. I/O errors preserve the original and start in recovery
  accounting mode. Corrupt JSON is moved aside before any replacement save.
- `Core.SaveUsage` holds usageWrite across snapshot and atomic publication.
  AtomicWrite writes and syncs a temporary file, then durableRename uses
  MoveFileEx replacement. The pinned Windows os.Open implementation shares
  READ and WRITE, not DELETE, so a concurrent ordinary reader can obstruct
  publication. AtomicWrite already retries errors 5, 32 and 33 ten times at
  50-ms intervals (eleven attempts total).
- A reader held beyond that budget can still fail a product write. The error
  propagates; readTotals does not acknowledge counters or advance routedSaved.
  Its next read retries the dirty commit even if the counters are unchanged.
  Existing tests prove recovery without loss or double counting. This is a
  bounded, surfaced write failure on the ordinary primary path. Recovery mode
  instead commits to the separate recovery file before acknowledging.

## Round 4 regression proof

All seven new test functions were shown to fail without their corrections:
- Restoring remote.go from 19489ce5 failed all four Stop tests: recovery started
  with no session; panic left a pending flight; a live joiner inherited the
  canceled result; and old stop publication orphaned the replacement.
- Restoring Core.New from 19489ce5 failed both startup tests. Permission and
  persistent 32/33 errors allowed a SaveUsage that replaced the fixture's
  12,345-byte history with empty lines. Transient 32/33 reads were not retried.
- Restoring fatal-on-sharing behavior in the shared harness reader failed its
  retry test. Separately restoring last-read-on-error behavior failed its
  timeout assertion by replacing the last good 42-byte snapshot with an empty map.

All mutations were reverted. The corrected focused run passed 37 leaf cases:
21 Stop/recovery cases, five startup cases, two existing usage persistence
cases, eight error classifications and the new polling test. All 25 retained
historical trace cases also passed (7,894 entries). Tests used Idle
priority, GOMAXPROCS=2 and -p=2. The installed ARM64 scenario was not run locally;
hosted results and re-review remain pending.

## Round 5: routing-independent, durable usage recovery

Design decision recorded in the spec: Control always starts despite accounting
history errors. It exposes `usageError` in /api/state and logs the underlying
error. The main usage file stays untouched while unreadable. A five-second
background retry and accounting saves retry the read; the old startup-lockout
test is replaced. Corrupt content is renamed to `usage.json.corrupt-<UTC time>`;
failed rename keeps the main file paused and visible as an error.

Pausing the main file must not fill the engine's retained set. Each accounting
receipt is committed atomically, with the existing sync hooks and trusted folder
permissions, to `usage.recovery.json` before ackTotals. That file contains a
versioned saved-usage snapshot and the first complete engine snapshot's marks.
The marks remove overlap with the unreadable original's last receipt, even if
acknowledgements have since retired several generations. Physical usage adds
only matching periods; peaks take the larger value. Routed values retain exact
uint64 arithmetic and saturate overflow, matching the existing consumer.

Only identities in that first complete snapshot can overlap the original.
They stay un-compacted until merge; later absent identities compact normally.
This adds at most one initial snapshot's identities/marks to normal Control
retention. Engine acknowledgements and its own retained-set limit are unchanged.

Recovery publication order:
1. While history is unreadable, save the incremental recovery record, then ack.
2. Once readable, merge the old history and accumulated usage under the usage
   state lock; atomically commit the recovery record marked **full**.
3. Replace usage.json with that full snapshot. Remove the recovery file only
   after the replacement succeeds, then sync its parent where supported.

A leftover full record is authoritative on startup, never added to usage.json.
Thus crashes before main replacement, after main replacement, and before removal
cannot double count. Failed primary publication or removal still permits acks
because the full recovery commit is already durable. Failed recovery writes
refuse acks and retry, preserving the existing engine capacity behavior. An
unreadable recovery file is likewise preserved, buffered observations remain
unacknowledged, and background reads retry it rather than latching until restart.

Tests cover uninterrupted routing startup, durable acks through multiple retired
generations, a restart while the original is still unreadable, removal after
merge, failed main publication, repeated restarts with a leftover full record,
corrupt quarantine, failed quarantine, failed recovery writes, and recovery-file
read errors that later clear. The original 100-byte unacked receipt plus 32 new
bytes becomes 132, not 232, after recovery and restart.

Mutation evidence (all reverted): restoring the previous startup path failed
the unreadable, quarantine, failed-rename and recovery-write cases. Restoring
the previous Remote failed the internal-deadline join and unattached-running
service tests. Re-merging a full recovery changed 120 bytes to 240 and failed
the restart assertion. Disabling recovery-file read retries failed recovery
after permissions returned. All corrected tests pass.

Final focused validation: 68 leaf cases, including all 25 frozen traces and
7,894 entries. All local runs used Idle priority, GOMAXPROCS=2 and -p=2. Hosted
race, installed-service results and independent review remain pending. No
service, TUN, route, or engine process ran on the PC.
