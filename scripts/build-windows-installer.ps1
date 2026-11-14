# Builds the allowlisted Net Switch 1.0 Windows staging directory and compiles
# dist\NetSwitch-Setup-<version>-<arch>.exe with the pinned Go toolchain,
# pinned Wintun DLL, and pinned Inno Setup 7 compiler.
[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64',
  [string] $Version = '',
  [switch] $SkipInstaller,
  [switch] $AllowLocalCompilerInstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'build-common.ps1')

$hostArch = Get-NativeArchitecture
$goArch = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $repoRoot 'dist'
$cache = Get-BuildCache $dist
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json

if (-not $Version) {
  $pkg = Get-Content -LiteralPath (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json
  if (-not $pkg.PSObject.Properties['version']) {
    throw 'package.json has no version property and -Version was not supplied.'
  }
  $Version = [string]$pkg.version
}
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
  throw "Invalid release version '$Version' (expected semantic version, e.g. 1.0.0)."
}

$stage = Join-Path $dist "stage-$Version-$Arch"
if ([IO.Path]::GetFullPath($stage) -ne [IO.Path]::Combine($repoRoot, 'dist', "stage-$Version-$Arch")) {
  throw "Unsafe staging directory: $stage"
}

foreach ($requiredPath in @(
  (Join-Path $repoRoot 'LICENSE'),
  (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md'),
  (Join-Path $repoRoot 'assets/net-switch.ico'),
  (Join-Path $repoRoot 'docs/user-guide.md'),
  (Join-Path $repoRoot 'licenses/lucide-ISC.txt'),
  (Join-Path $repoRoot 'packaging/NetSwitch.iss'),
  (Join-Path $repoRoot 'third_party/gvisor/LICENSE'),
  (Join-Path $repoRoot 'third_party/gvisor/AUTHORS'),
  (Join-Path $repoRoot 'vendor/github.com/google/btree/LICENSE')
)) {
  if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
    throw "Missing required packaging input: $requiredPath"
  }
  Assert-NoLink $requiredPath
}

$docsDir = Join-Path $repoRoot 'docs'
$docFiles = @(Get-SafeFiles $docsDir)
if (-not $docFiles.Count) {
  throw 'Required docs/ packaging directory is empty.'
}

foreach ($directory in @($repoRoot, $dist, $cache)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory | Out-Null }
}

$goPin = $pins.go
if ($goPin.version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid Go version pin: $($goPin.version)" }
if ($goPin.archiveRoot -ne [IO.Path]::GetFileName($goPin.archiveRoot)) { throw "Invalid Go archive root: $($goPin.archiveRoot)" }

$goZip = Get-Artifact $goPin $cache
$wintunPin = $pins.nativeSources.wintun
$wintunZip = Get-Artifact $wintunPin $cache
$wv2Pin = $pins.nativeSources.webview2
$wv2Nupkg = Get-Artifact $wv2Pin $cache

$toolchain = Join-Path $cache "go-$($goPin.version)"
if (-not (Test-Path -LiteralPath $toolchain)) {
  $partial = "$toolchain.partial"
  if (Test-Path -LiteralPath $partial) {
    $null = @(Get-SafeFiles $partial)
    Remove-Item -LiteralPath $partial -Recurse -Force
  }
  Write-Host "Unpacking Go $($goPin.version)"
  [IO.Compression.ZipFile]::ExtractToDirectory($goZip, $partial)
  Rename-Item -LiteralPath $partial -NewName ([IO.Path]::GetFileName($toolchain))
}
Assert-NoLink $toolchain
$goRoot = Join-Path $toolchain $goPin.archiveRoot
$go = Join-Path $goRoot 'bin\go.exe'
if (-not (Test-Path -LiteralPath $go -PathType Leaf)) {
  throw "The unpacked Go toolchain has no $go. Delete $toolchain and retry."
}

if (Test-Path -LiteralPath $stage) {
  $null = @(Get-SafeFiles $stage)
  Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null

$goHome = Join-Path $cache 'go-home'
$goEnv = [ordered]@{
  GOROOT = $goRoot
  GOTOOLCHAIN = 'local'
  GOWORK = 'off'
  CGO_ENABLED = '0'
  GOOS = 'windows'
  GOARCH = $goArch
  GOAMD64 = 'v1'
  GOEXPERIMENT = $null
  GOFLAGS = '-mod=vendor -p=2'
  GOMAXPROCS = '2'
  GOENV = 'off'
  GOPATH = Join-Path $goHome 'gopath'
  GOMODCACHE = Join-Path $goHome 'modcache'
  GOCACHE = Join-Path $goHome 'buildcache'
  GOTMPDIR = Join-Path $goHome 'tmp'
  APPDATA = Join-Path $goHome 'appdata'
}
foreach ($directory in @($goHome, $goEnv.GOPATH, $goEnv.GOTMPDIR, $goEnv.APPDATA)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory | Out-Null }
}

$savedEnv = @{}
foreach ($name in $goEnv.Keys) {
  $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
  [Environment]::SetEnvironmentVariable($name, $goEnv[$name], 'Process')
}
try {
  $reported = & $go version
  if ($LASTEXITCODE -ne 0 -or $reported -ne "go version go$($goPin.version) windows/amd64") {
    throw "Expected Go $($goPin.version), got '$reported'."
  }
  Write-Host $reported

  $baseLdflags = "-s -w -buildid= -X github.com/AyoubAchour/net-switch/internal/buildinfo.Version=v$Version"
  $guiLdflags = "-s -w -buildid= -H=windowsgui -X github.com/AyoubAchour/net-switch/internal/buildinfo.Version=v$Version"

  & $go build -C $repoRoot -trimpath -buildvcs=false -ldflags $baseLdflags -o (Join-Path $stage 'netswitch.exe') ./cmd/netswitch
  if ($LASTEXITCODE -ne 0) { throw "Building netswitch.exe failed (exit $LASTEXITCODE)." }

  & $go build -C $repoRoot -trimpath -buildvcs=false -ldflags $baseLdflags -o (Join-Path $stage 'netswitch-engine.exe') ./cmd/netswitch-engine
  if ($LASTEXITCODE -ne 0) { throw "Building netswitch-engine.exe failed (exit $LASTEXITCODE)." }

  & $go build -C $repoRoot -trimpath -buildvcs=false -ldflags $baseLdflags -o (Join-Path $stage 'netswitchctl.exe') ./cmd/netswitchctl
  if ($LASTEXITCODE -ne 0) { throw "Building netswitchctl.exe failed (exit $LASTEXITCODE)." }

  & $go build -C $repoRoot -trimpath -buildvcs=false -ldflags $guiLdflags -o (Join-Path $stage 'netswitch-desktop.exe') ./cmd/netswitch-desktop
  if ($LASTEXITCODE -ne 0) { throw "Building netswitch-desktop.exe failed (exit $LASTEXITCODE)." }
} finally {
  foreach ($name in $savedEnv.Keys) {
    [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process')
  }
}

$expectedWintunSha = if ($Arch -eq 'arm64') { $wintunPin.embeddedArm64Sha256 } else { $wintunPin.embeddedAmd64Sha256 }
Copy-ArchiveFile $wintunZip "wintun/bin/$goArch/wintun.dll" (Join-Path $stage 'wintun.dll')
Assert-Hash (Join-Path $stage 'wintun.dll') $expectedWintunSha
$wv2FilePin = $wv2Pin.files.$Arch
Copy-ArchiveFile $wv2Nupkg $wv2FilePin.entry (Join-Path $stage 'WebView2Loader.dll')
Assert-Hash (Join-Path $stage 'WebView2Loader.dll') $wv2FilePin.sha256

New-Item -ItemType Directory -Path (Join-Path $stage 'assets') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses') -Force | Out-Null

Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $stage 'LICENSE')
Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $stage 'THIRD_PARTY_NOTICES.md')
Copy-Item -LiteralPath (Join-Path $repoRoot 'assets/net-switch.ico') -Destination (Join-Path $stage 'assets/net-switch.ico')
Copy-Item -LiteralPath (Join-Path $repoRoot 'licenses/lucide-ISC.txt') -Destination (Join-Path $stage 'licenses/lucide-ISC.txt')
Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party/gvisor/LICENSE') -Destination (Join-Path $stage 'licenses/gvisor-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party/gvisor/AUTHORS') -Destination (Join-Path $stage 'licenses/gvisor-AUTHORS.txt')
Copy-Item -LiteralPath (Join-Path $repoRoot 'vendor/github.com/google/btree/LICENSE') -Destination (Join-Path $stage 'licenses/btree-LICENSE.txt')

foreach ($docFile in $docFiles) {
  $relDoc = $docFile.FullName.Substring($docsDir.Length + 1)
  $dstDoc = Join-Path (Join-Path $stage 'docs') $relDoc
  New-Item -ItemType Directory -Path (Split-Path $dstDoc -Parent) -Force | Out-Null
  Copy-Item -LiteralPath $docFile.FullName -Destination $dstDoc
}

Copy-ArchiveFile $wintunZip $pins.licenses.wintun.archiveEntry (Join-Path $stage 'licenses/wintun-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/wintun-LICENSE.txt') $pins.licenses.wintun.sha256
Copy-ArchiveFile $wv2Nupkg $pins.licenses.webview2.archiveEntry (Join-Path $stage 'licenses/webview2-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/webview2-LICENSE.txt') $pins.licenses.webview2.sha256

Copy-ArchiveFile $goZip $pins.licenses.go.archiveEntry (Join-Path $stage 'licenses/go-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/go-LICENSE.txt') $pins.licenses.go.sha256

foreach ($binary in @(Get-SafeFiles $stage | Where-Object { $_.Extension -in @('.exe', '.dll') })) {
  Assert-PeArchitecture $binary.FullName $Arch
}
Assert-PeWindowless (Join-Path $stage 'netswitch-desktop.exe')

if ($Arch -eq $hostArch) {
  $ctlVer = (& (Join-Path $stage 'netswitchctl.exe') version).Trim()
  if ($LASTEXITCODE -ne 0 -or $ctlVer -ne "netswitchctl v$Version") {
    throw "Expected 'netswitchctl v$Version', got '$ctlVer'."
  }
  Write-Host "Verified binary version: $ctlVer"
}

$stageSums = @(Get-SafeFiles $stage | Sort-Object FullName | ForEach-Object {
  $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
  '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
})
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllLines((Join-Path $stage 'STAGE-SHA256SUMS.txt'), $stageSums, $utf8NoBom)
[IO.File]::WriteAllLines((Join-Path $dist "STAGE-SHA256SUMS-$Version-$Arch.txt"), $stageSums, $utf8NoBom)
[IO.File]::WriteAllLines((Join-Path $dist "STAGE-SHA256SUMS-$Arch.txt"), $stageSums, $utf8NoBom)
Write-Host "Staged Net Switch $Version ($($stageSums.Count) hashed files) at $stage"

if ($SkipInstaller) {
  return
}
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $AllowLocalCompilerInstall) {
  throw 'Compiling the Inno Setup .exe runs the Inno Setup compiler unpacker; pass -SkipInstaller locally or -AllowLocalCompilerInstall if intended.'
}

$innoInstaller = Get-Artifact $pins.innoSetup $cache
$compilerDir = Join-Path $cache "inno-$($pins.innoSetup.version)"
if (Test-Path -LiteralPath $compilerDir) { $null = @(Get-SafeFiles $compilerDir) }
$installArgs = '/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /NOICONS /TASKS="" /DIR="{0}"' -f $compilerDir
$innoProc = Start-Process -FilePath $innoInstaller -ArgumentList $installArgs -WindowStyle Hidden -Wait -PassThru
if ($innoProc.ExitCode -ne 0) {
  throw "Pinned Inno Setup installation failed (exit $($innoProc.ExitCode))."
}
$iscc = Join-Path $compilerDir 'ISCC.exe'
if (-not (Test-Path -LiteralPath $iscc -PathType Leaf)) {
  throw "Inno Setup did not install ISCC.exe at $iscc"
}
$compilerVersion = (& $iscc --version).Trim()
if ($LASTEXITCODE -ne 0 -or $compilerVersion -ne $pins.innoSetup.version) {
  throw "Expected Inno Setup $($pins.innoSetup.version), got '$compilerVersion'."
}

$installer = Join-Path $dist "NetSwitch-Setup-$Version-$Arch.exe"
if (Test-Path -LiteralPath $installer) {
  Assert-NoLink $installer
  Remove-Item -LiteralPath $installer -Force
}
& $iscc --no-ide-signtools "/DAppVersion=$Version" "/DAppArch=$Arch" "/DStageDir=$stage" "/DOutputDir=$dist" (Join-Path $repoRoot 'packaging/NetSwitch.iss')
if ($LASTEXITCODE -ne 0) {
  throw "ISCC failed (exit $LASTEXITCODE)."
}
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
  throw "ISCC did not produce $installer"
}
$installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Built $installer (SHA-256 $installerHash)"
