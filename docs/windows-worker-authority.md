# Windows worker authority

Candidate design, 2026-10-30. Hosted qualification and independent security review
are required before this can merge.

## Boundary and evidence

Assume a helper is compromised after parsing untrusted OS metadata. It must not
gain Control's write authority through its inherited SYSTEM identity. Control,
administrative mutation helpers, and the OS remain trusted. Jobs limit lifetime,
process count, memory and UI; they are not a substitute for token restrictions.

Hosted jobs 123920681774 and 123920681383 both show read helpers opening the HKLM
fixture for write and succeeding at SetTcpEntry under SYSTEM. The old test's TCP
check means deleting another connection, not outbound networking. Both are now
tested separately; timeout or connection refusal is not counted as access denial.

## Contract

SYSTEM-DESIGN.md section 2 calls workers “blocking OS reads (adapter scans, outside
connections, Wi-Fi)” and gives their identity as “same as Control”. It requires
creation suspended, job assignment, then resume. It does not specify individual
network permissions. The narrower authority below records this hardening decision.

| Worker | Outbound TCP/HTTPS | HKLM write | Other process write/injection | Delete TCP connection | Integrity |
| --- | --- | --- | --- | --- | --- |
| app-info, installed-apps | deny | deny | deny | deny | Medium |
| meters, network | deny | deny | deny | deny | Medium |
| probe | allow | deny | deny | deny | Medium |
| line-check | allow | deny | deny | deny | Medium |
| outside | inherited administrative authority | allow | allow | allow | parent's High or System |
| policy-set, metrics-set/restore, protect-directory, stop-process, close-tcp, autostart-set/upgrade | inherited administrative authority | allow | allow | allow | parent's High or System |
| other modes | deny | deny | deny | deny | Medium |

For probe and line-check, section 4.5 requires “Quick check (TCP)” and “Full check
(HTTPS” and says a down line recovers only after HTTPS passes. The implementation
uses bound outbound TCP sockets in both helpers; line-check additionally performs
HTTPS. There is no narrower token-level network distinction between those two.
Their destination validation remains the responsibility of the operation parser;
the token is not an endpoint allowlist. The owner explicitly approved the same
network exception for line-check on 2026-10-30.

The read-only modes need no outbound sockets. Outside enables TCP EStats and
therefore remains administrative, consistent with section 2's identity contract.
This is not a claim that outside is a sandbox against arbitrary code execution.
The harness must expect System integrity for SYSTEM and High for elevated admin,
not weaken the expectation to any integrity label.

## Mechanism and alternatives

Use CreateRestrictedToken with DISABLE_MAX_PRIVILEGE, elevated groups deny-only,
SYSTEM user deny-only, Medium integrity, and WRITE_RESTRICTED for non-admin modes.
Read-only workers use RESTRICTED as the sole restricting SID; network probes
also include Builtin Users. No SYSTEM, Administrators, Everyone or logon SID is added to
the restricting list. These are candidate grants, subject to hosted startup and
functional compatibility checks. Existing explicit pipe inheritance and detached,
suspended launch remain in place.

[Microsoft's API reference](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
documents that DISABLE_MAX_PRIVILEGE retains SeChangeNotifyPrivilege, deny-only
can apply to the user SID, and WRITE_RESTRICTED applies the additional check to
writes. [Restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
require both normal and restricting-SID access checks to succeed. Merely removing
privileges does not remove an ACL's SYSTEM grant.

[CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
normally requires increase-quota and sometimes assign-primary-token privileges;
using a restricted version of the caller's primary token exempts assign-primary.
The launcher keeps the parent token and creates the restricted child in the same
session. DETACHED_PROCESS avoids the previously reproduced console initialization
failure with CREATE_NO_WINDOW and lowered integrity.

[AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
provides explicit capability-based network isolation. It is the alternative if
the restricted-token candidate cannot enforce socket denial without breaking
required reads. It also changes file, registry, process and device access, so
all native metadata APIs would need compatibility qualification.

[Chromium's sandbox design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
uses a broker, restricted tokens, jobs, integrity and desktops; its strongest
targets rely on broker-supplied handles. Its lowbox/AppContainer layer explicitly
adds network denial. Chromium is a user-browser broker example, not evidence
that its policy works unchanged for a SYSTEM service. No implementation code is
copied. Our read helpers still need native metadata access, which is why full
read restrictions or Chromium's fully locked-down policy are not adopted blindly.

## Qualification still required

### Results from diagnostic run 41016341189

The x64 diagnostic (job 123933429628) demonstrates that RESTRICTED alone lets
all six tested DLLs initialize. Null, Users, Everyone and write-restricted SID
alone fail USER32 and consequently OLE32/SHELL32 initialization. Adding the logon
SID to RESTRICTED is not necessary for this observed x64 result. The production
candidate now includes RESTRICTED; the exact underlying object denial is still
unproven. The next diagnostic evaluates the actual station and desktop ACLs
against each token rather than claiming that error 1114 identifies an object.

**Network isolation is not implemented by this candidate.** Every x64 variant,
including Null, successfully opened the outbound socket. No network-denial
assertion has been removed or relaxed. A successful DLL fix must not be reported
as successful worker isolation. The authority table above remains the required
contract, not a statement of achieved protection.

The ARM64 pilot (123933429866) did not run the tests: -race is unsupported and
PSTools did not contain the assumed PsExec64a.exe. The workflow now applies race
checks only on x64 and uses the signed x64 launcher for both runners. The x64
empty restricted-SID query exposed an allocation smaller than the Go
TOKEN_GROUPS struct; the test now reserves at least the typed structure size.
SYSTEM output was incomplete with the prior PsExec invocation, so the launch
now explicitly selects session 0 with interactive I/O, as its usage documents.
These are harness repairs, not evidence of SYSTEM qualification.

The same OLE32/CLSIDFromString package-init stack appears in native-services
ARM64 job 123933410231 and initial network scans in lifecycle jobs 123933496511
and 123933496437. Other failures must still be checked after the loader repair.
No shared or Linux source is changed; Linux job 123934294693 is outside scope.

### Loader failure found in the first candidate

Job 123928118497 failed before the TCP-settings worker reached its operation:
`winengine.init -> mustGUID -> windows.GUIDFromString -> clsidFromString ->
LazyProc.mustFind`. The vendored wrapper binds CLSIDFromString to **ole32.dll**.
This is DLL initialization failure (1114), not a missing entry point. Our
production flags include WRITE_RESTRICTED, so it is incorrect to infer that
ordinary read access was denied merely because the token has restricting SIDs.
The failing internal object has not yet been identified.

[Chromium's token policy source](https://raw.githubusercontent.com/chromium/chromium/main/sandbox/win/src/restricted_token_utils.cc)
adds the logon SID for BaseNamedObjects creation in USER_LIMITED. Its
[token construction](https://raw.githubusercontent.com/chromium/chromium/main/sandbox/win/src/restricted_token.cc)
also adjusts the default DACL; a restricting-SID list alone is not the complete
compatibility recipe. [Microsoft's service SID description](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
lists World, service logon and write-restricted SIDs for restricted services.
That policy is not equivalent to a worker forbidden outbound networking.

| Candidate grant | Compatibility reason to test | Boundary risk |
| --- | --- | --- |
| RESTRICTED (S-1-5-12) | Objects explicitly accessible to restricted code | Grants every matching object's writes, not only loader objects |
| actual logon SID | Named objects within that logon | Other objects shared with that session; absent in some SYSTEM tokens |
| Everyone | Common object grants | May restore sockets and world-writable objects |
| Users | Ordinary application access | Intended for probes, potentially too permissive for metadata workers |
| write-restricted SID (S-1-5-33) | Windows service compatibility | Needs measured object access, not an assumption |

The next two-job pilot compares these without changing production policy. It
reports named DLL initialization errors, anonymous event creation, registry and
process write denial, and outbound socket access. It also runs real native read
operations separately from synthetic authority probes. A candidate's diagnostic
completion is **not** a passing isolation result. The production test now covers
every named worker mode's token, and fails on any tested DLL initialization error.
No candidate is promoted until the original denials and functional calls pass.

The focused dispatch uses two jobs total: x64 and ARM64. Each exercises elevated
admin, then SYSTEM using Microsoft's signed PsExec on the disposable runner only.
The SYSTEM test asserts its actual user SID. No local service, engine or TUN runs.

Before merging: prove denial and legitimate read/probe functionality under both
identities, prove the old-token mutation fails and revert it, and obtain an
independent security review. TCP socket success alone does not prove HTTPS or
interface binding, and a token-layout unit test alone does not prove isolation.
