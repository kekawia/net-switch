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

IPv6 still has its supervisor settlement interval. A failed settled update
keeps that deadline, so the next supervisor pass retries without waiting another
30 seconds. Errors propagate and log the underlying failure. Journal failures
cannot mutate the engine; apply failures do not consume the crash budget.
Successful native changes log an update rather than falsely claiming a restart.
The failed-flow-read poll count still cannot restart a service-mode engine.

This is the deliberate live-update difference in locked design §§4.4 and 5.7,
using the transaction ordering in §3.3. It is not a new product decision.
The native compiler preserves the logical line ID and sends the current alias.
Windows Routes.Prepare resolves aliases and publishes bindings; Linux Prepare
resolves the requested interface while retaining existing line routing state.
No platform code or platform closure policy is changed here.

## Evidence and limits

- Five new Control test functions, ten leaf cases: three network transitions,
  four line API actions, refused-apply retry, GUID/case-normalized rename with
  durable settings and compiled alias, and failed-journal recovery. These use
  an in-memory Control engine boundary, not IPC or installed services.
- One real engine Apply/flow-table test uses an in-memory TUN and routes. It
  proves three held records exist before changing alias/lanes, preserves all
  three on that apply, and closes only IPv6 on disable while keeping IPv4 on
  both lines. It does not prove physical interface reconciliation or traffic.
- Focused local validation: 39 passing leaf cases, including all 25 existing
  historical traces (7,894 entries) and three existing service durability and
  slow-observation tests. The historical replay is still adapter-backed; this
  does not claim exact-once native semantic disposition of those entries.
- Go 1.27.3, Idle priority, GOMAXPROCS=2, -p=2, -mod=vendor. No installed
  service, adapter, host route, VM, or network setting was touched.

Full/race and installed proof remain hosted work. Logic review and hosted
checks at the final head are required before merge.

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
