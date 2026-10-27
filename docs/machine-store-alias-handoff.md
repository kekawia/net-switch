# Machine-store alias hardening: reproduction checkpoint

2026-10-27. Paused at the user's request. **No product fix yet.**

Base: `3c7b26d038a1d004b48f26623e0c76381f8483fe` (origin/main when work began).
The analysis on PR #108 was read through its fetched ref; none of that branch
was merged. The locked system design's ownership, machine-store and migration
requirements were read before writing the regression fixtures.

## What is committed

`internal/platform/windows/directory_alias_windows_test.go` adds hosted-only
regressions for verification and preparation through case and short-parent
spellings, fallback location lookup through both spellings, and staged recovery
through a short-parent spelling at the `staged` and `quarantined` checkpoints.
Marker bytes must remain identical: a replacement store cannot count as success.

The fixture assigns an explicit 8.3 directory name with SetFileShortNameW and
proves it identifies the long-name directory. Failure to assign it is fatal;
disabled automatic short-name creation never causes a skip. The hosted/elevation
guard prevents privileged execution on a developer's PC.

These are **candidate reproductions, not measured failures yet**. No tests were
executed locally. `gofmt -d` and `git diff --check` are the available local checks.
The focused hosted control-security workflow was dispatched for the test-only
commit, then cancelled to leave no background run when pausing:
[run 40524267578](https://github.com/kekawia/net-switch/actions/runs/40524267578).
It was queued when inspected; no passing or failing case result was obtained.
The fallback regression was added after that dispatch.

## Remaining work, in order

1. Run the candidate regressions on hosted Windows against this unchanged
   production code. Read the individual case results and distinguish fixture
   failures from the spelling defect. Add a short alias for the final store
   component too; current fixtures vary the parent component. Extend staged
   recovery to case changes and assert preserved Undo and original quarantine
   identity, in addition to the already-checked stage marker.
2. Implement canonical identity from no-follow handles, preserving the original
   ancestor pins, reparse refusal, ownership checks and hostile-occupant recovery.
   A staged directory's object identity and its intended destination are distinct:
   after quarantine the destination may not exist, so the destination's trusted
   parent plus normalized leaf must still be representable. An alias must be
   normalized before constructing `.migrating` or quarantine sibling names.
3. Design and implement certificate and location compatibility. Authenticate an
   old record against the canonical directory identity before atomically publishing
   its replacement. Existing certificate values contain directory ID plus nonce;
   old location values contain **only a target path**, not a source directory ID.
   Do not treat either an old hashed value name or a sibling-name prefix as
   identity evidence. This compatibility detail remains unresolved, not approved.
4. Cover migration of genuine old certificate/location records across aliases,
   mismatched identities, transplanted markers, replacement directories, failed
   writes and staged recovery. Preserve nonce protection against file-ID reuse.
5. Audit all callers: VerifyDirectory, prepareDirectory/ProtectDirectory,
   ResolveMachineDirectory/PrepareMachineDirectory and CleanupMachineData.
   Cleanup and metadata-handle tests delete the old certificate key directly;
   they must be updated with the representation, rather than silently leaving
   certificates behind. Keep standard-user certificate-write denial tested.
6. Run the existing privileged Windows jobs (including race checks and both
   architectures) and inspect actual case results. Open the implementation PR
   with the measured baseline failure, final fix and evidence. Do not merge it.

## References studied

- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew):
  normalized names, VOLUME_NAME_GUID, buffer sizing and failure behavior.
- [Naming a volume](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume):
  volume GUID identity versus drive letters.
- [SetFileShortNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfileshortnamew):
  DELETE access and backup semantics for current Windows.
- The pinned x/sys wrapper for GetFinalPathNameByHandle was inspected; any new
  buffers must still meet this task's explicit heap-allocation and alignment rule.

No engine, service, TUN, route, privileged local fixture or background watcher
was started. No production source or external locked design file was edited.
