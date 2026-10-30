# Windows worker authority

Implementation candidate, 2026-10-30. Not merge-ready until hosted qualification
and independent security review pass. The previous pilot's complete failure
inventory and actual results are in [windows-worker-pilot-failures.md](windows-worker-pilot-failures.md).

## Threat model and required authority

Assume arbitrary code execution in a read helper after it consumes OS metadata.
Control, the OS security mechanisms and administrative mutation workers remain
trusted. A read helper must not write protected HKLM data, inject into Control,
delete another process's TCP connection, remove its network fence, or open
outbound TCP. Network probes need outbound TCP/HTTPS but none of those privileged
writes. A local administrator modifying binaries or OS security is outside this
boundary.

SYSTEM-DESIGN.md section 2 calls workers “blocking OS reads (adapter scans, outside
connections, Wi-Fi)” with identity “same as Control”. Its worker job containment
contract requires assignment before execution. Section 4.5 specifies “Quick
check (TCP)” and “Full check (HTTPS”; it also requires a full HTTPS success to
restore a failed line. These establish the probe and line-check network need.
The owner explicitly approved the same network exception for line-check.

| Worker | Network | HKLM write / process injection / TCP deletion | Integrity |
| --- | --- | --- | --- |
| app-info, installed-apps, meters, network | deny outbound TCP, both families | deny | Medium |
| architecture, policy, metrics, port-holder, tcp-identity, autostart | deny outbound TCP, both families | deny | Medium |
| tcp-port-configuration | local WMI read; deny outbound TCP | deny | Medium |
| probe, line-check | allow bound outbound TCP and HTTPS | deny | Medium |
| outside | existing administrative authority for EStats | existing authority | parent's High or System |
| policy-set, metrics-set/restore, protect-directory, stop-process, close-tcp, autostart-set/upgrade | existing administrative authority | existing authority | parent's High or System |

The table is a contract, not a claim that the current candidate has passed.

This WFP rule covers direct socket creation by the private image. It does not
by itself cover service-mediated egress or a broker creating a different image.
Microsoft specifically notes that WMI-created processes are not automatically
associated with the caller's job. Those paths need separate security review;
the direct-connect and job-count tests must not be called a general Windows
sandbox proof.

## Token construction and native compatibility

Non-administrative workers keep their normal user identity for native reads,
disable privileged group grants, remove privileges except SeChangeNotifyPrivilege,
and run at Medium integrity. WRITE_RESTRICTED adds an independent restricting-SID
check for writes. The restricting set never contains SYSTEM or Administrators:
it contains RESTRICTED, plus Users for probes, and Authenticated Users for the
TCP-settings query. Retaining SYSTEM in the normal identity is now compared
against SYSTEM deny-only in the hosted diagnostic; privileged operations must
still be denied by the real tests, including registry WRITE_DAC.

[CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
documents the independent normal/restricting access checks and WRITE_RESTRICTED
semantics. Disabling SYSTEM in the normal identity is not equivalent to removing
it from the restricting set. Our prior SYSTEM coverage was missing, so the
identity choice remains subject to hosted functional and denial proofs.

[CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
exempts restricted versions of the caller's token from the usual assign-primary
privilege requirement. DETACHED_PROCESS avoids the previously reproduced console
initialization failure. Only the three explicit I/O pipes are inherited.

The earlier Null-SID candidate broke OLE32/USER32 initialization. RESTRICTED
restored all six tested DLLs under elevated admin. SYSTEM service logs still
showed error 1114; no report claims that an unobserved native object denial has
been identified. The replacement SYSTEM relay and identity variants are required
to close that gap.

## TCP settings

Both jobs 123944520917 and 123944520716 reached WMI ExecQuery and returned
0x80041003 after DLL initialization was repaired for the elevated-runner case.
The query returns per-template dynamic and auto-reuse ranges, including nulls.
Searches did not establish a documented GetDynamicPortRange API or registry
mapping that preserves this complete result.

[MSFT_NetTCPSetting](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-nettcpsetting)
is the documented source. [WMI namespace security](https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces)
describes ordinary Authenticated Users read permission. Adding that SID only to
this query's restricting set passed the real native read under elevated admin
on both architectures in accadb41. No namespace ACL is changed, and the worker
does not regain administrator group grants. SYSTEM parity remains a gate.

## Network fence: private image identity

The accadb41 SID-based WFP predicate failed: every read worker connected.
It has been removed. The replacement uses WFP's documented executable-path
condition. Each read worker receives a private executable copy beneath a fresh,
random, admin-owned ProgramData directory. The file permits read/execute but not
write by ordinary principals and has a High mandatory label. Control and probes
keep their original image path.

This is a separate copy, not a hard link: changing a hard link's ACL changes the
original file's ACL too, and a mapped executable can prevent deleting its hard
links. Source binaries and machine-store ACLs are never modified. The copy cost
must be measured in qualification before merge.

[FwpmGetAppIdFromFileName](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)
provides the application's identifier.
[Microsoft's application filtering example](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users)
documents ALE_APP_ID matching. Each private image gets IPv4 and IPv6
ALE_AUTH_CONNECT block filters in its own sublayer before its suspended process
is resumed. No broad rule is added for the shared Control/probe executable.

[AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
without network capabilities was considered. It changes integrity to Low and
requires independent file/COM grants. The image-based WFP approach preserves the
required Medium integrity and existing metadata APIs. Chromium's
[sandbox design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
is a reference for separating broker authority from helper authority; none of
its implementation code was copied.

## Lifetime and crash cleanup

The private directory name includes the owner PID, its creation time and a
random nonce. A durable policy record contains fresh filter/sublayer keys before
any WFP object is added. Native objects also carry a directory-specific ownership
tag. All writes to this state occur inside the new private directory.

[JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
assigns the child to its unnamed, kill-on-close job atomically at process creation.
This prevents parent death from stranding a suspended child before assignment.
The job retains its one-process, memory and UI restrictions.

Filters are static rather than dynamic: [WFP object lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
say dynamic filters disappear on session/parent exit, which would race child
termination. Normal cleanup waits for child exit, removes filters, then removes
the private image and record.

On the next worker launch, recovery validates the directory without following
reparse points, checks its owner and exact private ACL, and checks the recorded
parent incarnation when preparation has not completed. It retains protection while
the durably recorded child incarnation is alive, and can reclaim an exited child
even when its parent continues running. The child record is flushed before WFP
installation and resume. No named job is exposed that a worker could open to
keep it alive. [Microsoft's job lifetime](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
ties cleanup to closing handles and terminating associated processes.
The executable is removed before the fence; a sharing failure retains the rules
and record for a later sweep. Recovery validates WFP ownership tags before deleting the recorded keys. It
never recursively deletes directories or deletes an arbitrary path from a record.

## Qualification

The two-job pilot covers x64 and ARM64, each under elevated admin and a scheduled
SYSTEM task. Output is relayed directly in memory to the runner; no PsExec
console assumptions or saved log files are involved. A missing PASS or missing
SYSTEM identity is failure.

Tests cover native reads, metadata comparison (so empty fallback results cannot
pass), bound TCP and certificate-verified HTTPS, per-mode authority, IPv4 and IPv6
outbound denial, registry WRITE_DAC, Control-handle duplication, and attempts to
delete the worker's own WFP filters. The local TLS fixture changes no machine
certificate store. A separate HTTPS check uses Windows' real system trust and
the product's existing Cloudflare endpoint, with a parent positive control and
no retries; the local fallback-root fixture cannot stand in for that check.

The old constructor is substituted into a disposable child while keeping the
image fence: its missing restricting SIDs and original SYSTEM write authority
must be exposed. A separate network mutation removes only that fixture's rules,
proves the same image/current token can connect, restores the rules, and proves
denial returns. No production constructor override is exposed.

The crash test first proves the live owner and child exist, confirms recovery
leaves them alone, kills the owner, waits for job termination, then proves the
image and WFP objects still exist. Only then does it credit recovery for their
removal. Independent security review and all hosted results remain required.
