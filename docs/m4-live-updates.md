# M4 live network updates

This is a bounded split from the first native-replay retirement PR in the
2026-10-25 handoff, based on main cbc1426cdd3194253e0872f6130be3356305f37a.
It fixes the reproduced service-mode restart paths. It does not retire the
adapter, replace semantic replay, or complete M4.

## Reproduction and change

Before the fix, the three supervisor cases (binding, IPv6 enabled, IPv6
disabled) recorded `stop apply start apply`. Line add and reorder recorded
`apply stop ... start apply`; remove did too. A refused live update attempted
`stop` before reaching Apply. The new tests failed on these operations before
the production changes.

Service-mode supervision now applies a durable revision through the existing
ApplyPolicy transaction. Line add/remove/reorder keep their existing apply and
skip the subsequent restart. The compatibility path is unchanged.

Review found that the first patch's supervisor-only test missed Poll: Poll
assembled a full policy from raw IPv6 availability and bypassed settlement.
On head 5db44597, all four combinations of enable/disable and Poll/Supervise
ordering failed at t=0. The corrected effective-policy boundary retains the
loaded IPv6 value across every writer for 30 seconds of observed stable change.
Tests check 29,999 ms and exactly 30,000 ms. Returning to the loaded value
resets the pending transition; unrelated revisions do not reset it.
A failed settled update keeps that deadline, so Poll or Supervise can retry
without waiting another 30 seconds. Errors propagate or log the underlying
failure. Journal failures
cannot mutate the engine; apply failures do not consume the crash budget.
Successful native changes log an update rather than falsely claiming a restart.
The failed-flow-read poll count still cannot restart a service-mode engine.

This is the deliberate live-update difference in locked design §§4.4 and 5.7,
using the transaction ordering in §3.3. The coordinator clarified parity with
the frozen factory's 30,000 ms interval (lines 291–292, 681–692): live updates
replace restarts, not damping. This is a parity clarification, not owner approval
of a new timing decision. Fresh startup uses configured availability; reattached
Control observes the loaded policy and starts its own observation interval.
Raw availability and UI loaded-policy truth remain separate. Physical line and
address loss remain immediate platform events.
The native compiler preserves the logical line ID and sends the current alias.
Windows Routes.Prepare resolves aliases and publishes bindings; Linux Prepare
resolves the requested interface while retaining existing line routing state.
The installed rename scenario exposed a second ordering gap: the Windows monitor
could observe the renamed adapter before Control, lose its old-alias match, and
close the line. A pure snapshot reproduction failed with an empty binding and
closure of line a. Unchanged selectors now retain the discovered physical ID
while it exists. Tests retain down/removal/address-loss closures, explicit
rebinds and replacement behavior; an adapter reusing the old alias cannot steal
the still-present original binding.

## Evidence and limits

- The initial five Control test functions cover ten leaf cases: three network transitions,
  four line API actions, refused-apply retry, GUID/case-normalized rename with
  durable settings and compiled alias, and failed-journal recovery. These use
  an in-memory Control engine boundary, not IPC or installed services.
- Eleven additional Control leaf cases cover both Poll/Supervise orders and
  IPv6 directions, the exact deadline, flaps, cap closure and API transactions,
  settings inputs, startup/restart/reattach and temporarily unknown loaded
  replies. Failure testing now drives Poll, Supervise, then Poll recovery and
  checks the same revision is retried. These replace the earlier unsupported
  claim that a supervisor-only test proved production timing.
- One real engine Apply/flow-table test uses an in-memory TUN and routes. It
  proves three held records exist before changing alias/lanes, preserves all
  three on that apply, and closes only IPv6 on disable while keeping IPv4 on
  both lines. It does not prove physical interface reconciliation or traffic.
- Seven new pure Windows binding cases plus two existing physical-loss cases
  pass without calling the OS adapter reader or changing any networking.
- Focused local validation: 59 passing leaf cases, including all 25 existing
  historical traces (7,894 entries) and three existing service durability and
  slow-observation tests. The historical replay is still adapter-backed; this
  does not claim exact-once native semantic disposition of those entries.
- Go 1.27.3, Idle priority, GOMAXPROCS=2, -p=2, -mod=vendor. No installed
  service, adapter, host route, VM, or network setting was touched.

The mandatory hosted subtest
`TestNativeControlCutover/live-network-update-preserves-held-traffic` uses the
existing disposable installed Control fixture with its normal Poll/Supervise
loops. Windows renames the real TestISP adapter and restores its name; Linux
adds, reorders and removes the fixture's independent second line (its reader
does not expose a stable rename identity). It checks held TCP exchanges, the
same engine instance and flow ID/source/revision, matching native acknowledgement,
and fresh TCP flow records on the new policy. Linux also checks the external
responder's egress address. A read-only observer uses hello's epoch without
attach, renew or apply. The faults proof wrapper requires this exact PASS line;
a missing or skipped case fails the wrapper.

The existing lifecycle case also expected a replacement instance after adding
or removing a line. Hosted runs exposed that stale expectation. It now keeps
one routed stream and the same instance across both actions, then exercises an
explicit routing-off/on cycle: the old service is stopped before start, its
outcome record is proven present while stopped, and the replacement must retire
that record while carrying fresh traffic. The service-exit and outcome-cleanup
guarantees remain covered by a path that actually restarts.

Windows and Linux lifecycle test binaries cross-compile locally. The installed
scenario has not run locally; its actual result, full/race checks and logic
review remain parent-owned hosted work before merge. There is no installed
physical IPv6 address-loss or 30-second IPv6 timing witness in this patch;
those claims remain limited to pure Control and in-memory engine evidence.

## Exact remaining split

The remainder of handoff PR 1 is still required before retirement:

1. Native semantic replay: compact hash-keyed mapping of all 25 traces and
   7,894 entries, exact-once dispositions, one ordered semantic ledger, named
   atomic revision groups, independent expectations, real errors, snapshot
   barriers, physical usage, probe votes, outside closures, node.json auth and
   malformed cases, and seven undo cases. Keep the failed-apply/closure,
   lost-ack/reattach/fencing and totals recovery adversarial evidence.
2. Independent native goldens replacing twelve configs, six pin/share sets
   and empty-app behavior, including original Windows paths, precedence,
   low ports, block/main exceptions and 10/50/300-flow distributions.
3. Native lifecycle replacements for all eight fakeRemote consumers, both
   adapter tests, capability/dialect rejection, invalid start, multi-frame
   pagination and four-client × fifteen-action Run concurrency, preserving
   all failure, reattach, standby, fencing and joined-shutdown assertions.

Then handoff PR 2 supplies installed native parity/routing/TUN harnesses before
physical adapter/compat deletion. PR 3 extracts the AppImage download utilities
and removes the active legacy downloads/packaging/CI with exact exceptions.
Frozen reference and oracle bytes remain untouched. The separate BPF proof
and PR101 close-fence work are outside this patch.
