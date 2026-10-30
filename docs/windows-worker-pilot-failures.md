# Worker pilot failures on accadb41

Read directly from hosted logs; no logs saved. These results describe the old
candidate, not the replacement awaiting qualification.

## Pilot: same failures on x64 and ARM64

Run 41022898981: jobs 123954141239 (windows-latest) and 123954141662 (windows-11-arm).

| Failing test | First error |
| --- | --- |
| TestExistingMetadataHandleCannotUndoMachineProtection | metadata_handle_windows_test.go:225: Medium worker could not acquire the original grant: {Ready:false Escaped:false CertificateDenied:false Error:} EOF |
| TestReadWorkerCannotWriteControlHKLMOrTCP | isolation_windows_test.go:313: outbound TCP policy (allowed=false); OutboundDenied:false, OutboundCode:<nil> |
| TestWorkerNetworkFenceMutation | network_windows_test.go:134: current worker retained forbidden authority |

Every failing subtest is listed below. Each has the first error shown for its parent above.

`TestExistingMetadataHandleCannotUndoMachineProtection/`:

| Subtest | First error |
| --- | --- |
| root/quarantine=false/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| root/quarantine=true/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| child/quarantine=false/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| child/quarantine=true/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| nested-directory/quarantine=false/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| nested-directory/quarantine=true/historical=false/forged-marker=false | :225, grant precondition failed with EOF |
| root/quarantine=true/historical=true/forged-marker=false | :225, grant precondition failed with EOF |
| child/quarantine=true/historical=true/forged-marker=false | :225, grant precondition failed with EOF |
| nested-directory/quarantine=true/historical=true/forged-marker=false | :225, grant precondition failed with EOF |
| root/quarantine=false/historical=true/forged-marker=true | :225, grant precondition failed with EOF |
| root/quarantine=true/historical=true/forged-marker=true | :225, grant precondition failed with EOF |

`TestReadWorkerCannotWriteControlHKLMOrTCP/`:

| Subtest | First error |
| --- | --- |
| app-info | :313, outbound TCP allowed |
| installed-apps | :313, outbound TCP allowed |
| meters | :313, outbound TCP allowed |
| network | :313, outbound TCP allowed |
| tcp-port-configuration | :313, outbound TCP allowed |
| architecture | :313, outbound TCP allowed |
| policy | :313, outbound TCP allowed |
| metrics | :313, outbound TCP allowed |
| port-holder | :313, outbound TCP allowed |
| tcp-identity | :313, outbound TCP allowed |
| autostart | :313, outbound TCP allowed |

Both SYSTEM steps returned PowerShell exit code 1 without the required PASS
records. This is missing SYSTEM evidence, not a passing worker run. The mutation
test printed OLD_TOKEN_MUTATION_REPRODUCED but failed its current-policy control;
therefore it did not establish a successful fix-versus-mutation comparison.

## Machine-store cause and baseline

No production machine-store, directory protection, or ACL implementation changed
in this PR. The test changed from worker.Start to startMetadataAttacker. That new
fixture used os/exec with SysProcAttr.Token but no explicit Env.

The pinned Go source in internal/syscall/execenv/execenv_windows.go calls
CreateEnvironmentBlock(token, false) in that case. It does not inherit the
runner's environment. The test child consequently lacks its two hosted-runner
markers and exits 2 at TestMain's guard before reading the request. The parent
only reported EOF, hiding the exit reason. This is the behavior described in
[Go issue 29534](https://github.com/golang/go/issues/29534).

The repair explicitly inherits os.Environ for this test-only launcher and
reports exit status plus bounded stderr when its readiness handshake fails.
No production token exception or machine-store ACL grant is added.

Baseline main run 41008018851 at 6355be89 passed all 11 subcases on x64 job
123910032328 and ARM64 job 123910032345. The machine-directory source and this
test did not change between that commit and this PR's base 9a185893. Thus the
new EOF failure is not an established main-branch flake.

## Other supplied Windows jobs

| Job | Failing test | First error |
| --- | --- | --- |
| 123954195398, Native services ARM64 | TestNativeControlCutover/live-network-update-preserves-held-traffic (and parent) | native_control_test.go:309: timeout: Control learned adapter GUID |
| 123954189425, Lifecycle ARM64 | TestRealServices/service-isolation-and-hung-workers | lifecycle_test.go:732: timeout: two live worker streams |
| 123954189425 | TestRealServices/control-crash-reattaches | lifecycle_test.go:785: timeout: two live worker streams |
| 123954189425 | TestRealServices/binding-changes-stay-live-and-explicit-restart-retires-old-service | lifecycle_test.go:888: add fixture binding 400, connection unavailable |
| 123954189425 | TestRealServices | Aggregate of the three failures above |
| 123954916852, Control Windows x64 | TestReadWorkerCannotWriteControlHKLMOrTCP and the 11 subcases listed above | :313, outbound TCP allowed |

Native-services and lifecycle logs also show SYSTEM network/meters worker
startup failing at CLSIDFromString with error 1114. The missing streams and
adapter state are consistent with that failure, not evidence of a Linux issue.
The SYSTEM token identity/DLL comparison is now included in the replacement relay
harness; until it executes, the exact denied native object remains unproven.

## Actual elevated-admin results, both architectures

| Workers | Real native operation | HKLM SET_VALUE / process injection / TCP deletion | Outbound TCP |
| --- | --- | --- | --- |
| app-info, installed-apps | Passed, including metadata comparison | Denied | Incorrectly allowed |
| network, meters, policy | Passed, including stream modes | Denied | Incorrectly allowed |
| architecture, tcp-port-configuration, port-holder, tcp-identity, autostart | Passed | Denied | Incorrectly allowed |
| metrics | Passed against a real interface | Denied | Incorrectly allowed |
| line-check | Bound TCP and certificate-verified HTTPS passed | Denied | Allowed as required |
| probe | Bound TCP passed | Denied | Allowed as required |
| outside | Native stream passed | Administrative authority retained | Allowed |
| policy-set, metrics-set/restore, protect-directory, stop-process, close-tcp, autostart-set/upgrade | Authority probe passed; this pilot did not execute every real mutation | Administrative authority retained | Allowed |

These rows do not claim SYSTEM qualification or IPv6 qualification. The
replacement explicitly tests both address families and registry WRITE_DAC too.
