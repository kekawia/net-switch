param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted runners only.' }
& "$PSScriptRoot/../windows/testisp/fetch-wintun.ps1" -Directory $Directory
icacls $Directory /setowner '*S-1-5-32-544' /T /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not set installation ownership.' }
