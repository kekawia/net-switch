# Replay CI shell and machine-store follow-up

2026-10-27. Investigation of Windows x64
[job 122241328699](https://github.com/kekawia/net-switch/actions/runs/40516991664/job/122241328699)
on `91999f6b`. Product files are unchanged in this PR.

## What the log establishes

- The new internal-package step ran under Git Bash. Paths in that step used
  `C:\Users\RUNNER~1\AppData\Local\Temp`.
- `TestVerifyMachineStoreWithLiveEngineDirectory` failed at line 58, rejecting
  ownership/permissions on `C:\ProgramData\NetSwitch-live-store-...\active-engine`.
  This path is outside Temp and contains no short-name component.
- All ten `TestCertifiedMigrationQuarantinesPublishRace` cases reached their
  publication check but lacked the migrated `windows-undo.json` (line 198).
  Other migration/uninstall cases in the same log explicitly reported an
  untrusted tree and refused to import Undo. Restoring only TMP/TEMP would not
  address the live-directory failure's ownership check.

## The shell changes more than the spelling of Temp

Git for Windows' MSYS runtime sets the process token's default owner to its user
SID during initialization. See
[uinfo.cc, lines 72–85](https://github.com/git-for-windows/msys2-runtime/blob/81d9bd3d1c3680aa611ff2e5d1950787ffc95c6a/winsup/cygwin/uinfo.cc#L72).
Windows uses that [TokenOwner](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner)
when a new object has no explicitly supplied owner. This differs from the
Administrators/SYSTEM ownership these fixtures expect from their elevated
native-shell execution.

The source paths explain both observed failures:

1. The live-store test creates `active-engine` with `os.Mkdir`, without an
   explicit security descriptor (`directory_verify_windows_test.go:32`).
   `VerifyDirectory` checks its handle's security descriptor at
   `internal/platform/windows/directory_verify_windows.go:62`.
   `trustedMachineSecurity` accepts only Administrators or SYSTEM as owner
   (`internal/platform/windows/directory_windows.go:579`). An individual admin
   user's SID is deliberately insufficient.
2. The migration test explicitly gives the root its trusted owner, then writes
   Undo with `os.WriteFile` (`lockout_windows_test.go:130`). The new file has no
   explicit owner. `inspect` ANDs the trust of every descendant into the tree's
   result (`directory_windows.go:212`). A user-owned Undo file makes it false.
   The salvage loop is entered only for a trusted tree (`:418`); otherwise
   the original data is retained in quarantine and **not imported** (`:438`).
   Thus the new live store has no Undo file and the test fails at `:198`.

This is the source-supported explanation, not a measured token SID from that
old runner: the failed job did not log TokenOwner or the rejected descriptor.
The corrected step prints TMP/TEMP and the token owner to make the next result
auditable. The live-store path rules out short Temp spelling as a sufficient
explanation. No trust check is relaxed; user-owned records must remain refused.

## Separate product defect: two path spellings are two certificates

There **is** a real alias-sensitivity problem to schedule outside this PR:

- `directory_certificate_windows.go:21` hashes the lowercased path string for
  the registry value name. `VerifyDirectory` only applies `filepath.Abs` before
  looking it up (`directory_verify_windows.go:20–29`). The pinned standard
  library uses GetFullPathName, not a long-name or file-identity normalization.
  Long and 8.3 spellings of one folder therefore select different certificates.
- `directory_windows.go:507` also requires exact `m.Target == target`. The same
  physical directory ID does not overcome a different path spelling (including
  case in this second comparison).
- `directory_location_windows.go:31` uses the same path-string key to resolve
  a previously recorded fallback store. An alias can miss that record too.

**Impact:** if installation certifies a machine store under its long path and a
later service/maintenance caller supplies its 8.3 alias, verification can report
no installation certificate and refuse the existing store. A prepare operation
can treat the already-certified tree as needing migration (`:66–79` in
`directory_location_windows.go`), quarantine it, and retain only the migration
allowlist (Undo/backup/PID); other state remains in the quarantined tree instead
of the live store. With an active lock, it may instead refuse exclusive
protection or select a fresh fallback store. A spelling change during a staged
migration can also prevent recognition of the certified stage. These are
source-derived consequences, not an installed-user reproduction.

This alias issue is distinct from the observed test failures. The current walk
constructs children from the same input prefix and wraps handles with
`os.NewFile(handle, name)` (`directory_windows.go:94,220`), so short ancestors
are not silently expanded into long ones in its salvage comparison at `:424`.
The live-store failure stopped on security permissions before marker comparison.

Follow-up should establish identity-safe alias handling across certificate
lookup, location records, markers and staged recovery, while retaining no-follow
and ancestor protections. Do not merely loosen string checks or trust a record
because its name matches. No product fix or privileged local test was made here.

## CI correction and count check

The internal-package step returns to PowerShell, preserving the native runner
environment and token context. It streams the identical
`go test -json -count=1 -timeout=10m ./internal/... ./cmd/... ./tests/...` command
into the report process, without saving output. The upstream exit code is saved
inside its script block, before the joiner can replace LASTEXITCODE. Both exit
codes and completion of the producer are checked explicitly.

The next hosted log must show the environment diagnostic, the one live-store
test and all ten publication-race subcases, with no new skips. The overall test
scope is unchanged; the ledger suite itself has added round-2 cases, so its
count is expected to increase. Actual next-head counts and Windows results
remain pending until that hosted run finishes; no claim of hosted success is
made from local pure-package validation.
