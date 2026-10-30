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

Implementation now replaces the Go Control job's compatibility launches with
the installed suite. The original planning commit precedes implementation.
Hosted x64 and ARM64 qualification and independent logic review are complete;
none of the new installed assertions is credited as passing from local compilation.

| Executing owner | Assertions |
| --- | --- |
| `TestInstalledNativeStartup/root-*` and `stage-*` | All six planted-name cases; actual installation and service API; exactly one logged quarantine; outside directory/file SDDL and sentinel unchanged; actual clean SCM Quit |
| `single-instance-preserves-live-store` | Second SCM activation preserves Control PID; direct duplicate service entry is refused; store file identity and sentinel unchanged; no quarantine; original authenticated API remains live |
| `automatic-main-and-worker-restrictions` | Auto-selected first line matches Windows' uplink; the existing worker restriction test runs against that installed Control PID and must print its actual PASS; the real unelevated owner is denied both read and write handles to the existing enrollment file |
| `TestInstalledNativeTraffic/default-pinned-combined-pinned-main` | 3 default, 3 pinned, 12 combined with at least 3 per line; API shares both 0.5; 6 pinned-main connections and no secondary transit |
| `verified-public-https` | One public TLS request, verified certificate and trace body, with native tuple/owner/lane/physical-source/revision evidence captured before HTTP |
| `held-lane-change-and-independent-path-counters` | Old pinned flows survive pin change; 100 distinct held native IDs survive a QPC-timed subsecond acknowledged lane change and exchange new nonces; new flows select the redirected lane; independently measured secondary counters +3/+0/+3 |
| `udp-64-1800-and-port-reuse` | Direct baseline then real TUN; padded DNS packets at 64/1800 bytes, response flags and exact nonce-bearing payload; native UDP tuple/owner/lane/source/revision; four same-port TCP reuses with remote FIN first and each connect under 100 ms |
| `dns-five-held-survive-and-new-traffic` | Actual uplink DNS captured before TUN startup, changed and exactly restored; all five original native IDs remain and exchange fresh HTTPS nonces; a new verified flow works after restoration |
| `twenty-clean-cycles` | Capture/routes observed before each stop; 20 service stops with completed native outcomes, no TUN/IP routes or WFP sublayer/filters left |
| Traffic fixture lifetime | SYSTEM canary PID, creation time, executable and token remain identical through start, off/on cycles and Quit; unowned old PID sentinel remains untouched |

The pure Win32 comparisons and historical scheduler comparison remain in
`win32-parity.mjs`. Only its two compatibility startup cases move, explicitly
excluded from worker pass counts when the required installed suite is selected.
Both workflows collect worker/startup/traffic failures and finish with a hard
failure if any stage failed or did not run. The proof wrapper requires every
named installed PASS, including parents; a skip or empty filter fails.

Two external TestISP processes provide separately observed primary/secondary
paths over the same real uplink. The default secondary identity is unchanged;
the additional primary has its own GUID, name, address and counters. Both map
the same public test destination to the local TLS peer. This is **not** a claim
of two independent physical uplinks. The real automatic-main assertion remains
separate, as does the public internet request. No product destination-rewrite
hook, test-proxy mode or alternate engine is involved.

The direct lane test suspends Control, records the old and new attach epochs,
renews its explicit test lease, then stops that instance before resuming
Control. It requires Control to acquire a replacement before continuing.
DNS and cycle assertions run with normal active Control supervision.

### Literal historical representations that do not port

- A stale `engine.pid` being overwritten/deleted is not a native ownership
  operation. The native counterpart preserves that unowned sentinel and the
  SYSTEM process it names, while checking actual SCM/IPC/child identities and
  clean service outcomes. It does not create a fake native PID-file lifecycle.
- A second-line API edit causing an engine restart is superseded by the locked
  live-update contract. Existing required lifecycle coverage remains
  `TestRealServices/binding-changes-stay-live-and-explicit-restart-retires-old-service`:
  add/remove, two-line state, held traffic/same instance, then explicit restart
  and outcome retirement. This suite does not relabel a live update as restart.
- Clash tags/config rewrites have no native byte-format counterpart. Native
  flow records and independent gateway/source evidence replace those checks.
  Local HTTPS uses client-only CA trust and external mapping, with no change
  to product route configuration. Scheduler parity is historical worker
  evidence only, never service-startup evidence.

No behavioral assertion is waived. The compile-only compatibility builds stay
in the historical Node leg until step 2(b) removes their source files; neither
binary is executed by the native job. Existing Node baseline consumers in
`ci.yml` remain for the later legacy-CI removal step.

Local validation: the 17 pure revision-witness cases and two pure TestISP
classification/tracker tests passed. The 30 dependency/gate/proof-wrapper tests
passed, including 28,932 gate scenarios. The workflow reader previously dropped
the non-runner `control` matrix axis and therefore missed conditional steps;
it now expands literal axes, with a four-combination regression. Native build
commands name their source packages explicitly so dependency discovery cannot
silently replace them with the repository root.

The first ARM64 pilot failed all seven startup cases before installation:
`newActor` refused the new `NSInstalledOwner` name. Its explicit allowlist already
contains `NSNativeControlOwner`, so the fixture now reuses that existing identity
and its unchanged validation/cleanup. No permission check was relaxed. Evidence:
[ARM64 pilot job](https://github.com/kekawia/net-switch/actions/runs/41009207760/job/123911023776).

Hosted qualification passed across x64 and ARM64 after merging the worker token
restriction prerequisite (`#119`), and review hardened `TestISPMain` inspection
and cleanup in `tests/windows/testisp/network.ps1` plus explicit `NetSwitchEngine`
teardown in `installedFixture.cleanup` ([Go control service run 41080552776](https://github.com/kekawia/net-switch/actions/runs/41080552776)).
No privileged execution ran locally. Frozen sources
and fixtures remain unchanged. Adapter runtime/protocol/child/ownership/trust and
control_compat deletion remain entirely outside this PR; Wintun adapter-loss
handling must survive the later deletion. The dedicated old-schema refusal
reader and its exact journal literals also belong to step 2(b).
