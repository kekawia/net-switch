# Stages the pinned WebView2Loader.dll for local/CI Go tests.
[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64',
  [string] $OutDir = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'build-common.ps1')

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $repoRoot 'dist'
$cache = Get-BuildCache $dist
if (-not (Test-Path -LiteralPath $cache)) { New-Item -ItemType Directory -Path $cache | Out-Null }

$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json
$wv2Pin = $pins.nativeSources.webview2
$wv2Nupkg = Get-Artifact $wv2Pin $cache

if (-not $OutDir) {
  $OutDir = Join-Path $dist "webview2-test-$Arch"
}
if (Test-Path -LiteralPath $OutDir) { Assert-NoLink $OutDir }
else { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$filePin = $wv2Pin.files.$Arch
$dllPath = Join-Path $OutDir 'WebView2Loader.dll'
if (Test-Path -LiteralPath $dllPath) {
  Assert-NoLink $dllPath
  try {
    Assert-Hash $dllPath $filePin.sha256
    Write-Output $OutDir
    exit 0
  } catch {
    Remove-Item -LiteralPath $dllPath -Force
  }
}

Copy-ArchiveFile $wv2Nupkg $filePin.entry $dllPath
Assert-Hash $dllPath $filePin.sha256
Assert-PeArchitecture $dllPath $Arch
Write-Output $OutDir
