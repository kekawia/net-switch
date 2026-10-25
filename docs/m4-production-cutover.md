# M4 PR 2: the production cutover

For the subsequent policy evidence and the exact still-pending adapter removal
boundary, see [M4 PR3: native policy evidence](m4-policy-evidence.md).

2026-10-24. Two PRs. PR 2a teaches Control the native engine's contract (spec
§5.10) and the restart, probe and accounting rules the earlier native PRs left
"for the cutover". PR 2b makes every product build run the native engine and
ports the lifecycle suite to it. The sing-box downloads, the adapter dialect in
Control's client and the legacy CI are PR 4.

## PR 2b: the native engine in product builds

- **No tag, no selector.** `internal/lifecycle/engine_selection.go` is one
  untagged file: the Engine service program is the supervisor host, and
  `netswitchctl install` refuses `--adapter` and any mode but `tun`. The
  native-service-contracts workflow builds without `m4_native`. The stand-in's
  code stays compiled only until PR 4 deletes it; no product path reaches it.
  The 0.3.x compatibility launcher in `cmd/netswitch` (an elevated desktop
  Control that starts sing-box) now builds only with `-tags control_compat`,
  which the control workflow's parity and TUN steps pass; a product `netswitch`
  started as neither `service` nor `worker` prints its usage and starts nothing
  (`TestProductBuildHasNoDesktopLauncher`).
- **Stand-in folders are refused, not migrated.** A data folder whose
  `service-config.json` (or its backup) names an adapter or proxy mode, whose
  `engine-state.json` (or, when that is all that is left, its backup) lacks the
  native schema, or whose journal holds `adapter-service-scope` /
  `adapter-linux-rule` records, is refused by the installer and by the host
  with "this data folder belonged to a pre-release stand-in build (sing-box
  adapter); run that build's uninstall or remove the folder, then install
  again". The inspection only reads: the journal's own reader opens the file
  for writing and truncates a torn tail, which only the lifetime-lock owner may
  do, so the refusal uses `journal.ReadOnly`, which shares the owner's bounded,
  checksummed frame decoder and leaves a torn tail in place
  (`TestStandInInspectionLeavesTheJournalUntouched`,
  `TestReadOnlyDecodesLikeTheOwnerWithoutTouchingTheFile`). Linux 1.0 never shipped
  and 0.3.x is Windows-only, so no field data exists.
- **A fresh engine instance accepts whatever revision Control sends first.**
  Found by the ported suite on Windows: the engine's durable record kept the
  previous instance's revision number as a floor, so a Control whose numbering
  had restarted (the fixture rewrites the control journal without a revision,
  exactly what the product does when it recovers a damaged journal from
  defaults) was refused on every `start` with "native revision history cannot
  go backwards or change its hash", 44 times in one instance, and routing
  never came on. Spec §3.3 says a restarted engine has no loaded revision and
  its persisted `appliedRevision` is history only, so `host.Durable` now guards
  only the history the running instance commits itself: the first revision of
  an instance is accepted whatever its number, and within the instance a lower
  number or a changed hash is still refused
  (`TestFreshInstanceAcceptsAnyFirstRevisionThenGuardsItsOwnHistory`). Within
  an instance the flow table already rejects stale and conflicting revisions
  before the durable write, and the protocol fences old instances and epochs.
  A first commit equal to the inherited history whose sync fails leaves the
  instance with no committed history, since nothing was acknowledged; its next
  revision, lower or not, is its first (a design decision recorded in the
  review of this PR; `TestUnacknowledgedFirstCommitEqualToInheritedHistoryGuardsNothing`).
- **A refused start is an ordinary failed attempt, counted once from Start's
  own result.** While the engine refused those 44 starts, Control retried
  every poll (1.3 s) with neither the 1/2/5/30 s backoff nor the five-failure
  latch: every refusal carried the instance's identity, so Control counted the
  first and took the rest for the failure it had already seen. The design
  (a decision recorded in the review of this PR): a start the engine answers
  with an error while its instance keeps running comes back to Control as
  `ce.StartRefused` (instance, attempt number, cause), and Control counts that
  result toward the backoff and the latch, synchronously, exactly once. Status
  reads never produce a countable failure: the engine keeps showing the error
  for the UI until the next start, but that status carries no `FailureID`, so a
  poll before the retry, a reattach, or the retry's own read cannot count it
  again, and a retry that succeeds leaves no failure behind. Countable
  failures from status come only from instance-ending outcomes (exit
  classification), as before. The start goes out on the very session fixed
  for it (`sendOn`), and a refused apply on an engine that was already on stays
  a plain conflict (spec §3.3). Transport errors take the other path, where
  connection recovery publishes the outcome once
  (`TestRefusedStartIsReturnedToControlNotPublishedAsAFailure`,
  `TestPollAndReattachDuringRefusedStartMintNoFailure`,
  `TestReattachBetweenCaptureAndSendIsNotMisattributed`,
  `TestPolledRefusalErrorIsShownNotCounted`, `TestRefusedStartsBackOffAndLatch`:
  1, 2, 5, 30 s, latch at the fifth, explicit routing-on clears it).
- **Linux: the connections the engine was carrying are ended when it stops,
  lapses or dies** (spec §2, "failing open also ends connections the engine
  was carrying"). An app's stream through the TUN terminates inside the
  engine's network stack, so nothing resets it when the engine goes; the
  ported suite sat on every such stream until its read deadline in six cases,
  lease lapse included. Windows aborts a removed adapter's sockets by itself;
  Linux does not. The rule: a connected TCP or UDP socket whose local address
  equals a journaled TUN address (exactly, normalised; never a prefix) and
  whose peer is not local to this host is ended with SOCK_DESTROY, the way
  `ss -K` does; listeners, unconnected UDP sockets, local-only connections
  (including to a TUN address teardown already removed) and link-local peers
  (whose scope the dump does not settle) are spared. It reads only address
  records that pass the same ownership checks as the rest of cleanup (this
  boot, this network namespace, a valid fingerprint), from the ownership
  record before journal cleanup, in both the engine's own cleanup (stop and
  lapse, after the engine has closed its non-persistent TUN) and recovery
  after a death (the host's, and `netswitchctl cleanup` from ExecStopPost), so
  it does not depend on the TUN or its addresses still existing. Unknown means
  do nothing: a failed or late host-address listing, or a failed dump, aborts
  the pass with nothing destroyed. Everything runs inside its own share of the
  cleanup budget (a quarter of what remains, at most 500 ms), the host listing
  included; the dump is streamed and bounded, the first unsupported or refused
  answer ends the pass, and the mandatory cleanup always keeps its time.
  Requests name the socket as the dump reported it, bound device and cookie
  included; the kernel applies its own inbound order for UDP. A recovery
  records its pass in the engine's log as `NATIVE_SOCKETS_RETIRED` with a
  timestamp taken before the first destroy, so when the host itself was frozen
  and left no record (systemd's watchdog killed it; ExecStopPost recovered),
  the supervisor proofs order a held stream's end against that event instead
  (`control-absent-host-and-child`: no data during the stall, the end at or
  after the retirement, a fresh flow within 28 s).
  Proofs: the rules on the pure decision code in `sockets_retire_rules_linux_test.go`
  (exact address only, foreign boot or namespace records ignored, unknown
  host addresses abort, removed TUN addresses stay local, listeners and
  link-local peers spared, slow listing bounded); `TestRoutedSocketRetirementFollowsTheSpecRule`
  (TCP handshake and connected UDP in both families ended; listener,
  local-only connection, a neighbouring address in the same subnet,
  unconnected UDP and loopback spared) and `TestRoutedSocketRetirementIsBoundedAndStopsWhenRefused`
  in CI's isolated namespace; and the lifecycle cases whose `expectClosed`
  follows a kill, a crash barrier, a lease lapse and a stop, all after the TUN
  has gone.
- **A lapsed lease never waits on a stuck command; a controller's stop is
  never cut short.** The protocol's expiry used to take the mutation lock; a
  start or apply stuck in a durable write held it, so capture stayed installed
  with Control gone. A lapse with no stop in flight now waits at most five
  seconds for that lock, then reports the stall (`ErrLeaseStalled`) on its own
  hook; the host's child ends its process there, and the host recovers the
  journal under the released lifetime lock (spec §2, "if it lapses"). A
  controller's explicit stop holds the same lock for as long as its cleanup
  takes, legitimately, so the lease loop waits for it, whether the lease is
  still valid or lapses meanwhile (`TestExplicitStopWithLongCleanupIsNotEndedByTheLease`;
  the installed proof is `TestNativeEngineService/slow-start-and-clean-stop`,
  whose 15 s cleanup the first push of this PR had ended at 5 s). The bounded
  lock wait hands the lock over with one atomic transition, so it can never be
  left held by nobody (`TestLockBeforeHandsOffAtomically`).
- **The lifecycle suite runs the native engine.** `TestRealServices` installs
  the native services in TUN mode over the real fixture (TestISP on Windows,
  the namespace topology on Linux); every traffic check goes through that
  capture and every fail-open check uses the same target directly. On Linux the
  services run inside the fixture's namespace, so the suite's HTTP requests go
  through the fixture's relay and every actor process starts inside the
  namespace (`ip netns exec`, then `setpriv` to drop to the actor), which keeps
  loopback HTTP, routed traffic and app identity in the network the engine
  captures. Each case keeps its property:
  - sing-box child kill → kill the host's verified child (`engine-child-crash-gets-a-new-service-instance`);
  - the engine's hung-adapter hangs → suspend the child; the host's own checks end it within 28 s, Control counts, five latch;
  - `engine-after-apply-commit` → the child's durable revision write (the
    barrier fires after the record is saved, before the acknowledgement), used
    by both the durable-crash case and the blocked-apply lease case;
  - `engine-after-stop-cleanup` → the child after cleanup, before exit;
    Control's forced stop ends the service inside the 18–32 s window;
  - closure replay applies the compiled native revision as a controller and
    drives the cutoff from the engine's apply point;
  - the stand-in's retired `adapter-*` directories → the retired
    `engine-outcome-*` records;
  - "stream observed inside the TUN" → the engine's own paged flow listing
    holds exactly the stream (protocol, source socket, destination) on the
    line it chose; an owner the engine reports must be the suite's process and
    executable (on Linux the namespace relay reports the process and socket it
    opened), and an owner not yet attributed, Linux's proc fallback under load,
    is accepted and logged as `CAPTURE_OWNER_UNATTRIBUTED` (a design decision
    recorded in the review of this PR);
  - the stand-in's 16 `adapter-linux-rule` intents → the native engine's
    `rule` ownership records, decoded as the engine journals them
    (`linux.ObjectJSON` of a netlink rule) and compared with the kernel's own
    `ip rule` listing on every selector and the action, protocol and mark mask
    included; a selector the comparison does not know is refused, not skipped.
    The count is one source selector per address the kernel holds on the line
    plus the fixed bypass, loopback-capture and mark selectors of each family;
  - the stand-in's TUN named "NetSwitch" → the instance's TUN (`ns` plus the
    first ten characters of the instance id, with the 198.18.0.1/30 address),
    which is what the fixture's precondition now looks for;
  - the fixture's target is a line server on Linux and a byte echo on Windows;
    the other-user app checks that platform's complete reply, and the traffic
    checks speak the same contract;
  - the blocked-apply case holds the engine to the same 42 s fail-open bound
    from Control's death as a plain lapse, measured to completed fail-open:
    service confirmed stopped, capture removed, direct traffic working.
  No case is dropped or loosened; Windows-only and Linux-only cases keep their
  existing skips. The suite's time bounds are the ones main had (job 25 min,
  test process 22 min, suite context 20 min, Windows service wait 16 min):
  main's last run finished `TestRealServices` in 523 s (Windows x64), 627 s
  (Windows ARM64) and 690 s (Linux x64) inside 9 to 12.5 min build-and-run
  steps, and the native port adds a registrar start per engine start, not
  minutes.

## PR 2a: Control's native engine client

### Dialect

Control's engine client (`internal/lifecycle/remote.go`) dials the engine's
pipe the way the installation says: the native install (recorded with the
service) gets the native dialer, which sends no M2 impersonation primer byte,
because the native host's pipe carries plain newline JSON and rejects that
byte on the first exchange. It then chooses its wire dialect from the hello
capabilities. `singbox-adapter-v1` selects the temporary
adapter payload, unchanged. Anything else must advertise `revisions`, `lease`,
`status`, `paged-totals`, `totals-ack`, `terminal-stop` and `probe-options`,
or attach is refused with the missing capability named. The adapter dialect is
deleted with sing-box in PR 4.

The native revision is compiled from Control's policy: a line binds by its
alias (the same identity the sing-box adapter used), shares become integer
weights, lanes and the blocked set are copied, and shares of blocked lines are
dropped as spec §4.6 already forbids them. A pin binds exactly the identity the
user selected (design decision recorded in the spec). The engine's identity
travels end to end: flow records carry `AppID`, Control's app tracking keeps a
sandboxed app's identity beside its display path, and the pin API stores that
identity (`flatpak:`, `snap:` or `appimage:`) instead of the shared path. A
path pin becomes the platform's own normalisation (Windows folds case, Linux
keeps it), which on Windows is the engine's identity, so 0.3.x pins and the
API behave exactly as today. On Linux a path pin inside a sandbox location, or
for an app the engine reports under a sandbox identity, is kept and shown as
needing reselection (`pinNeedsReselection` on its state row) and compiles to
nothing: it is never routed by guess, and never auto-converted, because two
sandboxes can share a path. Nothing is inferred, and the compiled hash depends
on the durable revision alone. The
engine's hash of that config is what the engine checks; the acknowledgement
Control records carries Control's own revision hash plus the engine's apply
point. An engine already loaded receives `apply`; `start` is only for a fresh
instance. A refused start keeps the connection: the engine's status, not the
transport, is what Control classifies.

Snapshots are synthesised from the fixed-size native `status`: policy fields
come from Control's durable desired revision when the engine has loaded exactly
that revision, the PID is the child's, and `StartedWith` is the loaded policy.
Flow records keep the `Chains[0] = "line-<id>"` shape every Control consumer
reads. A flow's `Host` is its destination address only once the upstream
connection is established (spec §4.5, "2 different hosts" means established
destinations); a connecting flow lists its line but is never evidence.

### Exit classification and restart budget

A stopped engine is classified through the service manager's status, which
already folds the shared outcome reader: `Cleanup`, `ExitKnown`, `ExitCode`
and the instance's outcome file. Only exit 3 with completed cleanup and the
engine's own "adapter lost" reason is adapter loss; a lease expiry or a
verified clean stop (exit 0, cleanup complete, reason "stop") is routing off;
everything else is a failure. The supervisor journals a counted failure or
loss before the restart it allows, and holds the restart back while that
write fails. While the manager reports cleanup pending,
Control polls for up to 10 s before classifying; past that it counts the exit
as a failure and says so in the log. Nothing is guessed clean. The same
classification runs at Control startup for a native engine that stopped while
Control was down, so that failure or loss counts (deduplicated by the journal's
last failure id) and is journaled before the restart it allows. Control
acknowledges the engine's service-initiated stop record, so adapter-loss
cleanup does not wait out the 2 s delivery timeout.

Core keeps a ten-minute window of clean adapter losses beside the crash budget
(both durable in the control journal, both cleared by a fresh routing intent).
The first three losses restart at once and leave `failures` alone; the fourth
and later go through the ordinary 1/2/5/30 s backoff and the five-failure
latch (spec §5.1 and §2). Closure cutoffs are apply points: the native
acknowledgement's point is recorded on each intent and sent as `startedBefore`
with the line closure; Reconnect closes by native flow ids. Every closure is
bound to the engine instance Core checked it against: the client captures its
session under one lock, refuses the request if that instance is no longer
attached, and sends the intent's instance and epoch so a replacement attached
in between is fenced by the engine itself (flow ids are reused per instance).

The engine service's only failure action is the recovery command on Windows
and `ExecStopPost` with `Restart=no` on Linux. A pure Linux test reads the unit
text and the installed proof reads the real recovery actions, so no manager
ever respawns the host: Control owns every restart.

### Probes

Every probe result carries its `kind` and the engine instance that answered.
Control accepts a result only when the kind matches what it asked for (a quick
pass never restores a line that needs the full HTTPS check) and the instance is
still the current one; anything else becomes `engineUnavailable`, which changes
no line's state. The in-process sing-box adapter and the adapter dialect stamp
the same two fields, so the rule applies to every engine.

### Exact accounting

Every five seconds while routing is on, Control reads all pages of `totals`
under one receipt within the engine's ten-second snapshot lifetime, absorbs
them into a routed-usage record keyed by identity and generation, writes
`usage.json` through the existing atomic store (temp file, fsync, rename, parent
sync), and only then sends `ackTotals {opId: "ack-" + receipt, receipt}`. The
record keeps the engine's cumulative counter as a high-water mark per
generation, so a crash between the commit and the ack re-reads counters at or
above the marks (no double count), and a crash after the ack sees retired
identities return with a new generation (no loss). A new engine instance drops
every mark. Identities the engine no longer reports fold into an `other`
bucket beyond 4,096 kept entries; present identities are never folded. The
record stays dirty until a write succeeds, so an unchanged read after a failed
commit still writes before it acknowledges. Every `usage.json` writer (the
minute timer and the accounting consumer) takes the snapshot and writes under
one lock, so an older snapshot never replaces a newer, acknowledged one. The
routed section is reloaded with exact integers, not the record's float64 path.

Caps keep counting the whole adapter, as 0.3.x does (spec §4.6, "today's rules").
The exact routed totals are stored for the desktop work in milestone 5 and have
no UI consumer yet; `/api/state` is unchanged.

### Proofs

Pure tests (fail on main's code where noted):
- `internal/lifecycle`: attaching to a real native `protocol.Server` over an
  in-memory pipe (main refuses it: "engine swap is not installed"); the
  translated revision is deterministic and compiles; start/apply carry points;
  flow records keep the chain shape and only established hosts; line closure
  by point spares newer flows; probe kind and instance on the wire; paged
  totals and an idempotent acknowledgement; exit classification; adapter loss
  reaching the snapshot after the service stops.
- `internal/control`: three free losses then the fourth counts, durable window,
  cleared by a fresh intent; `acceptProbe` rejects a mismatched kind or a
  superseded instance; a quick-only engine never restores a down line; cutoffs
  recorded and sent as points; the totals consumer over a real flow table with
  crashes between commit and ack and between ack and read, exact to the byte;
  no ack without a durable commit; the adapter-era `usage.json` keeps its shape.
- `internal/usage`: generation and instance arithmetic, compaction, file round trip.
- `internal/service` (Linux): the engine unit never restarts itself.

Installed proof (`TestNativeControlCutover`, fault build, Windows x64/ARM64 and
Ubuntu 24.04/26.04 x64/ARM64), every subtest a required PASS line in
`scripts/run-native-proof.mjs`:
- sign-in through the installed Control starts the native engine and carries
  real TUN traffic;
- the engine service has no manager restart action;
- exact usage: 65,536 echoed bytes, a Control crash at the commit barrier (the
  record already holds the bytes), reattach to the same instance, no double
  count across two further rounds, a crash at the ack barrier, then totals
  exact to the byte;
- a killed child counts exactly one failure and routing returns on a new instance;
- four injected adapter losses through the real read pump: on Windows the
  genuine Wintun removal error exits 3, three are free and the fourth counts.
  The Linux engine has no clean adapter-loss outcome at all (the exit-3 path
  exists only in `internal/engine/windows`; spec §5.1's rule is written for
  Wintun removal and the helper's death), so there a failed read pump is an
  ordinary failure: the proof requires each to count, the fifth to latch, and
  the owner's explicit retry to clear the budget;
- Control absent past the lease (recovery disabled), the engine fails open,
  then a Control start restores wanted routing within 70 s.

Local validation was limited to `go vet` and the pure tests of the changed
packages at Idle priority on two cores; all installed behaviour is hosted-only.
