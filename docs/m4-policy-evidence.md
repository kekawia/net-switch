# M4 PR3: native policy evidence

2026-10-25. Based on main `87576b4d` and locked design v3.1 §§3.3,
4.1, 4.4–4.6, 5.4, 5.7, 10 and 11. This PR adds native evidence;
**adapter retirement is not complete**. No installer or UI change is included.

## What this PR proves

`TestNativePolicyDecisionEvidence` exercises Control's actual policy assembly,
the production native compiler and the native selector in one chain. Its inputs
are explicit line-health and cap-exhaustion states, not a running OS. Assertions
name lanes, physical destinations, blocked results, shares and revision numbers;
they do not depend on serialized sing-box configuration or rule-file hashes.

The compiler moves unchanged from `internal/lifecycle/remote_native.go` to
`internal/control/engine/native.go`, where the engine boundary owns the
translation. The lifecycle client calls that same function, with the same OS
identity rules. This avoids a second compiler in tests and a Control/lifecycle
import cycle. Existing compilation and identity tests remain in place.

| Evidence | Cases and limits |
| --- | --- |
| New Control decision table: 13 rows | Healthy home; main down; strict home; strict excluded from fallback; strict home down; secondary cap moved; main cap moved; all capped; no open lines while combining; all capped while combining; all down; weighted combining; exactly one open line. Each row checks three pins, unpinned and unknown owners, low source ports and disabled IPv6. |
| Existing `policy.TestDecisionTable`, `TestEvenness`, `TestImmutableAndPrediction`, `TestZeroShareOnBlockedLine` | Pins beat low-port handling; lane targets; rejection; weighted selection over 10/50/300 flows; prediction distribution; immutable snapshots; zero shares and blocked shares. Pure selector evidence. |
| Existing `TestNativeRevisionUsesTheEnginesAppIdentity` and `TestNativeRevisionIsAPureFunctionOfControlsPolicy` | Exact sandbox identities, Windows/Linux path normalization, unknown-line pins, interface aliases, integer weights and repeatable compilation. In-memory protocol evidence, not installed attribution. |
| Existing `flows.TestRejectedAndPredictDoNotAdvance` | Rejections, predictions and repeated resolution do not consume admitted-flow sequence positions; UDP admission consumes one. |
| New installed `compiled-policy-main-exception-and-blocked-pin` | Production compiler → authenticated installed service → apply acknowledgement and prediction. An empty sharing set follows the main lane, a synthetic sandbox pin reports blocked, and fresh TCP traffic is observed on the expected lane, physical line and revision. A held stream survives both applies. Runs in both product and fault builds. Prediction is not proof of OS attribution or packet-level blocked-pin rejection. |
| Existing `TestNativeControlCutover/routes-traffic-through-the-native-engine` | Installed Control starts installed native routing; real traffic traverses capture. This PR does not relabel a direct engine protocol test as installed Control behavior. |
| Existing `TestNativeEngineService` and `TestRealServices/closure-replay-keeps-newer-flows` | Real installed apply points, idempotent apply, stale/conflicting rejection, reattach fencing, closure retry and newer-flow survival. The lifecycle suite also exercises durable-commit crash barriers. |
| Existing Control service/cap/reconnect tests | Desired revision and intents persist before apply, failed apply cannot close, native apply-point cutoff, Reconnect persists selected IDs before closing and retries without widening selection. These use fake engine boundaries. |
| Retained 25-trace replay | Failover/failback, busy failed-check suppression, caps, strict lines, combining, IPv6, pinned/shared Reconnect, all HTTP routes, diagnostics and cross-kind ordering. This remains adapter-backed historical evidence. |
| Existing native Linux acceptance suite | Three-line routing, lane changes retaining flows, weighted traffic, selective closure/Reconnect, IPv6 routing/refusal and IPv6-only closure. Its attribution blockers remain separate release failures. |

For the trace coverage inventory and permitted differences, retain
`tests/oracle/TRACE-SPEC.md` verbatim. In particular, `failoverFailback`,
`probeFailover`, `busyFailedChecks`, `capMoved`, `capBlockedAndMainException`,
`combiningNoOpenLine`, `reconnectPinned`, `reconnectShared` and `ipv6` remain
checked by the complete replay. This table does not claim to replace their
timing, API, log or outside-socket assertions. Native real-traffic suppression
also retains `TestRealTrafficNeedsTwoDifferentNewHosts`,
`TestDownLineNeedsHTTPSDespiteRecentTraffic`, `TestProbeResultsRequireKindAndInstance`
and `TestQuickPassNeverRestoresADownLine`.

## Exact retirement boundary

The coordinator narrowed this PR to evidence after the deletion inventory
confirmed that the old adapter still carries comparisons that a policy table
cannot replace. **No adapter implementation, hash golden, trace comparison or
required CI leg is deleted here.** Frozen `lib/`, `server.mjs`, `lib/tray.cs` and
immutable oracle fixtures are unchanged. Product builds remain native-only.

The next removal work must supply these replacements before deleting their
consumers:

1. Preserve all 25 replay traces' API responses, settings/usage writes, events,
   logs and cross-kind ordering. Explicitly map adapter spawn/Clash operations
   and config/rule hashes to native revisions and outcomes. Do not just filter
   those ledger entries out. Keep the six one/two/three-line pinned/combined
   rule cases and empty-app case until their native mapping is explicit.
2. Replace the nine adapter-backed lifecycle round-two cases, the adapter
   dialect selection assertion, `TestRunLoopsAndRealAdapterConcurrent`, and
   `TestInvalidStartNeverReachesAdapterLifecycle` with native equivalents.
3. Remove `AdapterRuntime`, `Request.Adapter`, lifecycle adapter/child/stand-in
   service and ownership code, remote dialect branches and adapter trust checks
   only after those replacements pass. Keep stand-in folder refusal's old JSON
   field recognition and ownership-journal strings: they reject unsafe reuse.
4. Replace the `control_compat` launcher consumers before deleting the launcher.
   `control.yml` still needs its Go parity and TUN legs. Preserve their Win32
   parity and end-to-end assertions, rather than deleting the legs.
5. Then remove downloads, pins, source bundles, packaging entries and old CI.
   Linux's baseline package also supplies `Download`/`Pin` to AppImage fixtures;
   separate that utility use before removing the package. The old-product
   installer stays unchanged until M5.

This refines the older four-PR outline: native trace/transport/compatibility
replacements and physical adapter removal must precede download/legacy-CI
removal, whether they fit in one later PR or require a separately reviewed split.
The production-cutover document already deferred the remote dialect and stand-in
code to removal. Neither this PR nor its tests claim M4 is complete.

## Verification and gates

The native-service workflow runs the new pure table and the existing selector
suite. `run-native-proof.mjs` requires the new installed subtest's actual PASS
line in both variants; an empty selection or skip fails the proof wrapper.
Existing workflow time limits, matrix concurrency and hard failures are kept.

Local verification is limited to focused pure Go tests, compilation and vet,
using Go 1.27.3 at Idle priority with `GOMAXPROCS=2`, `-p=2`, `-mod=vendor`.
The cache executable is `dist/cache/go-1.27.3/go/bin/go.exe` (the extra `go`
directory matters). No engine, TUN, service or network test runs on the PC.

Before merge: native service contracts on Windows x64/ARM64 and Linux runners,
existing lifecycle CI, Control replay/parity/e2e, ordinary Go checks and CI
classifier/proof-wrapper checks must pass on the reviewed head. Installed
behavior is pending until those hosted results pass. The Linux eBPF attribution
release gate remains blocking for M4/release; this PR neither clears nor waives it.
