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
  repeat the graceful and forced budgets. A waiting caller can cancel its wait.
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
Review rounds 1–3 are addressed; hosted results and re-review remain pending. No CI
was watched.
For review, compare the seven mappings above with the new tests and the original
round2/round3 consumers. Check fixture cleanup, reconnect publication barriers,
and the stated distinction between typed service outcomes and installed proof.
