# Installed native harness migration

Plan recorded before implementation against main `6355be89`.
This is retirement step 2(a). Step 2(b), physical adapter and compatibility
deletion, starts from main only after this change is reviewed and merged.
Neither replay completion nor this plan constitutes installed traffic evidence.

## Inventory and replacement plan

| Current consumer | Replacement in this change | Assertions retained |
| --- | --- | --- |
| `scripts/win32-parity.mjs`, called by `control.yml` | Product worker executable for the Win32 comparison; installed lifecycle fixture for startup cases | Worker output comparisons, PowerShell warm-up, collected failures followed by hard failure; quarantine at root/staging names for junction/hardlink/children, outside ACL and sentinel preservation, single-instance exclusion, authenticated API and clean shutdown |
| `scripts/server-under-test.mjs` / `tests/windows/launch.mjs` compatibility launch used by the Control job | Disposable native installation owned by the hosted lifecycle suite | Exact executable paths, versions and SHA-256; SCM Control and host PIDs, authenticated engine peer, verified native child identity; explicit session/settings/status/cleanup handles; launcher exit never means service exit |
| `scripts/e2e-routing.mjs` in `control.yml` | Installed native routing cases using the real Control API and native paged flow records | Default 3, pinned 3, combined 12 with at least 3 on each line, pinned-main 6 and zero secondary use; verified HTTPS; SYSTEM canary remains the same process; restricted workers cannot alter Control/HKLM/TCP rows |
| `scripts/tun-control-adapter.mjs` and `scripts/e2e-tun.mjs` in `control.yml` | Installed native TUN cases and read-only engine observer | Exact socket source/owner, lane, physical line/source and acknowledged revision; 100 held connections and subsecond lane update; old flows unchanged; TestISP +3/+0/+3; 64/1800-byte UDP; port reuse; five held sockets survive DNS change and still exchange data; exact DNS restoration, fresh traffic, 20 clean cycles |
| `scripts/tun-test-https.mjs`, `control-test-https.mjs`, `tun-test-diagnostics.mjs` | External TestISP target mapping, verified TLS fixture and service/protocol diagnostics | No destination rewrite in production Control, no disabled certificate verification, no fabricated Clash-shaped records |
| `ci.yml` engine-config `e2e-tun --engine-adapter`, Windows x64/ARM64 `e2e-routing` | Explicit historical baseline consumers retained until the later legacy-CI removal step | They are never used as native evidence or a fallback for failed installed tests |
| `tests/windows/acceptance.mjs`, `launch-engine.mjs`, `engine-driver.mjs` | Existing standalone native acceptance remains separately labelled | Standalone engine evidence is not presented as installed Control evidence; baseline profile remains for the later legacy-CI removal step |
| `scripts/tun-test-udp.mjs` | Historical direct adapter probe; not the installed gate | Its native UDP obligations move to installed 64/1800-byte assertions before deletion |
| `.github/ci/drift*`, `golist*`, test launch contracts and Windows harness documentation | Update dependency readers/build variants and documented entrypoints alongside workflow migration | Native source changes must actually select the installed job; no success from a missing or skipped test |

## Fixture and ownership

Reuse the hosted lifecycle suite's SYSTEM service runner, disposable owner,
real owner-token IPC/HTTP client and native service-manager boundary. Do not add
a privileged product debug endpoint. Installation and cleanup are registered
before any subsequent step can fail. Log both candidate identity and observed
running identity. Session acquisition keeps its owner IPC connection alive.
Routing-off and Quit observe acknowledged cleanup and SCM state explicitly.

Control owns the attach epoch. Observers read hello/status/pages without attach,
renew or apply. Direct engine revision tests need an explicit ownership handoff:
quiesce Control under the existing hosted fault mechanism, retain its observed
epoch, take and log a new epoch, renew during the direct phase, then end that
instance before resuming Control. Never silently steal an active epoch or let
two controllers race to publish policy. Ordinary policy assertions use Control.

Flow assertions join actual client tuples and process identities to native
records. Expected lanes/physical lines are literal; acknowledged revision
witnesses bracket admission. Independent TestISP destination counters prove
physical transit. TLS remains verified using the fixture CA; destination
translation belongs in TestISP, never in a product binary. Every old held
connection must retain its native ID and exchange fresh nonce-bearing data.

## Delivery and validation

Only disposable GitHub-hosted runners run installed, service, route, DNS or TUN
tests. First prove workflow changes on two Windows jobs (x64 and ARM64), with
bounded matrix concurrency. Preserve the existing warm-up and final failure
aggregation. Print executed/pass counts and fail when an expected case is absent.
Local validation is limited to pure packages, pinned Go, Idle priority,
GOMAXPROCS=2 and -p=2. Frozen lib/, server.mjs, lib/tray.cs and tests/oracle stay
byte-for-byte unchanged.

## Completion ledger

All installation, routing and TUN migrations above are pending. No assertion is
waived or claimed ported by this planning commit. Any assertion found impossible
to port must be recorded here with the original assertion, concrete reason and
review requirement. Adapter runtime/protocol/child/ownership/trust and
control_compat deletion remain entirely outside this PR; Wintun adapter-loss
handling must survive the later deletion. The dedicated old-schema refusal
reader and its exact journal literals also belong to step 2(b).
