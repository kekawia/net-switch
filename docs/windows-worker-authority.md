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
Read-only workers use the Null SID as the sole restricting SID; network probes
use Builtin Users. No SYSTEM, Administrators, Everyone or logon SID is added to
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

The focused dispatch uses two jobs total: x64 and ARM64. Each exercises elevated
admin, then SYSTEM using Microsoft's signed PsExec on the disposable runner only.
The SYSTEM test asserts its actual user SID. No local service, engine or TUN runs.

Before merging: prove denial and legitimate read/probe functionality under both
identities, prove the old-token mutation fails and revert it, and obtain an
independent security review. TCP socket success alone does not prove HTTPS or
interface binding, and a token-layout unit test alone does not prove isolation.
