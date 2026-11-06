# End-to-end Windows installer, 0.3.x -> 1.0 migration, rollback, upgrade, and
# uninstall verification suite against real released 0.3.0, 0.3.1, and 0.3.2
# installers on disposable GitHub-hosted x64 and ARM64 runners.
[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'This destructive installer and migration suite runs only on disposable GitHub-hosted Windows runners.'
}

. (Join-Path $PSScriptRoot 'build-common.ps1')

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges are required.'
}

$hostArch = Get-NativeArchitecture
if ($hostArch -ne $Arch) {
  throw "Requested -Arch $Arch on a $hostArch Windows runner."
}
$goArch = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $repoRoot 'dist'
$cache = Get-BuildCache $dist
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json
$ispNetworkScript = Join-Path $repoRoot 'tests/windows/testisp/network.ps1'

$diagDir = Join-Path $dist "installer-logs-$Arch"
New-Item -ItemType Directory -Force -Path $diagDir | Out-Null

$baseTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$tempRoot = Join-Path $baseTemp ("netswitch-installer-suite-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

$appDir = Join-Path $env:ProgramFiles 'Net Switch'
$machineData = Join-Path $env:ProgramData 'Net Switch'
$userData = Join-Path $env:LOCALAPPDATA 'Net Switch'
$runKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$policyRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
$tempUserName = 'NSMigrUser'
$tempProfileSid = $null

function Save-SuiteDiagnostics([string] $Label) {
  $safe = ($Label -replace '[^A-Za-z0-9._-]', '_')
  $dest = Join-Path $diagDir $safe
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  foreach ($src in @(
    (Join-Path $machineData 'migration-journal.json'),
    (Join-Path $machineData 'netswitch.log'),
    (Join-Path $machineData 'netswitch-engine.log'),
    (Join-Path $machineData 'settings.json'),
    (Join-Path $machineData 'windows-undo.json'),
    (Join-Path $userData 'server.log'),
    (Join-Path $userData 'launch.log')
  )) {
    if (Test-Path -LiteralPath $src -PathType Leaf) {
      Copy-Item -LiteralPath $src -Destination (Join-Path $dest ([IO.Path]::GetFileName($src))) -Force -ErrorAction SilentlyContinue
    }
  }
}

function Wait-Until([string] $Description, [int] $Seconds, [scriptblock] $Condition) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  $lastErr = $null
  while ((Get-Date) -lt $deadline) {
    try {
      $val = & $Condition
      if ($val) { return $val }
    } catch {
      $lastErr = $_.Exception.Message
    }
    Start-Sleep -Milliseconds 300
  }
  $suffix = if ($lastErr) { " (last error: $lastErr)" } else { '' }
  throw "Timed out after ${Seconds}s waiting for: ${Description}${suffix}"
}

function Invoke-LegacyApi([int] $Port, [string] $Token, [string] $Method, [string] $Path, $Body = $null, [int] $TimeoutSec = 30) {
  $headers = @{ 'X-Token' = $Token }
  $uri = "http://127.0.0.1:${Port}${Path}"
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json -TimeoutSec $TimeoutSec
  }
  return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -TimeoutSec $TimeoutSec
}

function Start-LegacyInstalledServer {
  $nodeExe = Join-Path $env:ProgramFiles 'Net Switch\runtime\node.exe'
  $serverMjs = Join-Path $env:ProgramFiles 'Net Switch\server.mjs'
  if (-not (Test-Path -LiteralPath $nodeExe -PathType Leaf)) { throw "Missing legacy node.exe at $nodeExe" }
  if (-not (Test-Path -LiteralPath $serverMjs -PathType Leaf)) { throw "Missing legacy entrypoint at $serverMjs" }
  $serverJson = Join-Path $userData 'server.json'
  Remove-Item -LiteralPath $serverJson -Force -ErrorAction SilentlyContinue
  $procArgs = @(
    "`"$serverMjs`"",
    '--user-data', "`"$userData`"",
    '--machine-data', "`"$machineData`""
  )
  Start-Process -FilePath $nodeExe -ArgumentList $procArgs -WorkingDirectory $appDir -WindowStyle Hidden | Out-Null
  return Wait-Until '0.3.x server /api/ping' 60 {
    if (-not (Test-Path -LiteralPath $serverJson -PathType Leaf)) { return $null }
    $sess = Get-Content -LiteralPath $serverJson -Raw | ConvertFrom-Json
    $ping = Invoke-LegacyApi -Port ([int]$sess.port) -Token ([string]$sess.token) -Method 'GET' -Path '/api/ping' -TimeoutSec 3
    if ($ping.ok) { return $sess }
    return $null
  }
}

function Reset-CleanSlate {
  foreach ($svcName in @('NetSwitchEngine', 'NetSwitch')) {
    if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
      Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
      & sc.exe delete $svcName | Out-Null
    }
  }
  foreach ($procName in @('netswitch-desktop', 'netswitch-engine', 'netswitch', 'NetSwitchTray', 'net-switch-helper')) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($appDir, [StringComparison]::OrdinalIgnoreCase)
  } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  foreach ($taskName in @('\Net Switch\Sign-in', '\Net Switch\Server')) {
    & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
  }
  & schtasks.exe /Delete /TN '\Net Switch' /F 2>$null | Out-Null
  Remove-ItemProperty -LiteralPath $runKeyPath -Name 'NetSwitch' -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  foreach ($dir in @($appDir, $machineData, $userData)) {
    if (Test-Path -LiteralPath $dir) {
      & takeown.exe /F $dir /R /D Y 2>$null | Out-Null
      & icacls.exe $dir /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>$null | Out-Null
      Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Assert-TaskPresent([string] $TaskName, [bool] $Expected) {
  $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\schtasks.exe') -ArgumentList @('/Query', '/TN', "`"$TaskName`"") -WindowStyle Hidden -Wait -PassThru
  $exists = ($p.ExitCode -eq 0)
  if ($exists -ne $Expected) {
    throw "Expected scheduled task $TaskName present=$Expected, got $exists (exit $($p.ExitCode))."
  }
}

function Invoke-SilentInstaller([string] $ExePath, [string] $LogName, [string[]] $ExtraArgs = @(), [switch] $AllowFailure) {
  $logPath = Join-Path $diagDir $LogName
  $allArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "`"/LOG=$logPath`"") + $ExtraArgs
  $p = Start-Process -FilePath $ExePath -ArgumentList $allArgs -Wait -PassThru
  if (-not $AllowFailure -and $p.ExitCode -ne 0) {
    $tail = if (Test-Path -LiteralPath $logPath) { (Get-Content -LiteralPath $logPath -Tail 40) -join "`n" } else { '<no log>' }
    throw "Installer $ExePath failed with exit $($p.ExitCode). Log tail:`n$tail"
  }
  return [pscustomobject]@{ ExitCode = $p.ExitCode; LogPath = $logPath }
}

function Invoke-SilentUninstaller([string] $LogName) {
  $unins = Join-Path $appDir 'unins000.exe'
  if (-not (Test-Path -LiteralPath $unins -PathType Leaf)) {
    throw "Missing uninstaller at $unins"
  }
  $logPath = Join-Path $diagDir $LogName
  $p = Start-Process -FilePath $unins -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "`"/LOG=$logPath`"") -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    $tail = if (Test-Path -LiteralPath $logPath) { (Get-Content -LiteralPath $logPath -Tail 40) -join "`n" } else { '<no log>' }
    throw "Uninstaller failed with exit $($p.ExitCode). Log tail:`n$tail"
  }
  Wait-Until 'uninstaller removes Program Files\Net Switch' 25 {
    -not (Test-Path -LiteralPath $appDir)
  } | Out-Null
  return $logPath
}

Write-Host "=== Warming up Windows PowerShell 5.1 before timed migration checks ==="
& (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()' | Write-Host

Write-Host "=== Building Net Switch 1.0.0 and 1.0.1 $Arch installers ==="
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Arch $Arch -Version '1.0.0'
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Arch $Arch -Version '1.0.1'
$setup100 = Join-Path $dist "NetSwitch-Setup-1.0.0-$Arch.exe"
$setup101 = Join-Path $dist "NetSwitch-Setup-1.0.1-$Arch.exe"

$legacyPins = @{
  '0.3.0' = if ($Arch -eq 'arm64') {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.0-arm64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-arm64.exe'; sha256 = '47b58347ba7d14432bae31eb1a1b5c34b946a407c26647caafca0fbb560d1bce' }
  } else {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.0-x64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-x64.exe'; sha256 = '31f2883e4e939f362afe263f19aad5da2f6e995e111c51f839fc3a723229515f' }
  }
  '0.3.1' = if ($Arch -eq 'arm64') {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.1-arm64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.1/NetSwitch-Setup-0.3.1-arm64.exe'; sha256 = 'cadbfccc00410da9999924249b1a1670227fb6bc499b9c55239c45de245a0ca3' }
  } else {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.1-x64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.1/NetSwitch-Setup-0.3.1-x64.exe'; sha256 = '824b939526d4ac251d570b66de046aca4186811f387d6072fc132ff291a5f28f' }
  }
  '0.3.2' = if ($Arch -eq 'arm64') {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.2-arm64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.2/NetSwitch-Setup-0.3.2-arm64.exe'; sha256 = '32ee2fb156e76392cca550a9078684f1b2ee1440c15487a41967c96da92d7b11' }
  } else {
    [pscustomobject]@{ file = 'NetSwitch-Setup-0.3.2-x64.exe'; url = 'https://github.com/kekawia/net-switch/releases/download/v0.3.2/NetSwitch-Setup-0.3.2-x64.exe'; sha256 = '0193582d10fcede15f3119b3ec72a20dfad7ad94b87f8465b5e90e835865791b' }
  }
}

$setup030 = Get-Artifact $legacyPins['0.3.0'] $cache
$setup031 = Get-Artifact $legacyPins['0.3.1'] $cache
$setup032 = Get-Artifact $legacyPins['0.3.2'] $cache

$goRoot = Join-Path (Join-Path $cache "go-$($pins.go.version)") $pins.go.archiveRoot
$goExe = Join-Path $goRoot 'bin\go.exe'
$ispBinDir = Join-Path $dist "testisp-$Arch"
New-Item -ItemType Directory -Force -Path $ispBinDir | Out-Null
$ispExe = Join-Path $ispBinDir 'testisp.exe'

$savedGoEnv = @{
  GOROOT = $env:GOROOT
  GOTOOLCHAIN = $env:GOTOOLCHAIN
  GOARCH = $env:GOARCH
  CGO_ENABLED = $env:CGO_ENABLED
  GOFLAGS = $env:GOFLAGS
}
try {
  $env:GOROOT = $goRoot
  $env:GOTOOLCHAIN = 'local'
  $env:GOARCH = $goArch
  $env:CGO_ENABLED = '0'
  $env:GOFLAGS = '-mod=vendor -p=2'
  & $goExe build -C $repoRoot -o $ispExe ./tests/windows/testisp
  if ($LASTEXITCODE -ne 0) { throw "Failed to compile testisp.exe (exit $LASTEXITCODE)." }
} finally {
  foreach ($k in $savedGoEnv.Keys) { [Environment]::SetEnvironmentVariable($k, $savedGoEnv[$k], 'Process') }
}
Copy-Item -LiteralPath (Join-Path $dist "stage-1.0.0-$Arch\wintun.dll") -Destination (Join-Path $ispBinDir 'wintun.dll') -Force

$ispProcs = @()
$echoProc = $null
$origPolicyExists = $false
$origPolicyVal = $null
if (Test-Path -LiteralPath $policyRegPath) {
  $prop = Get-ItemProperty -LiteralPath $policyRegPath -Name 'fMinimizeConnections' -ErrorAction SilentlyContinue
  if ($null -ne $prop -and $prop.PSObject.Properties['fMinimizeConnections']) {
    $origPolicyExists = $true
    $origPolicyVal = [int]$prop.fMinimizeConnections
  }
}

try {
  Write-Host "=== Starting two-line TestISP gateway rig ($Arch) ==="
  $uplink = (& pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $ispNetworkScript -Action inspect | ConvertFrom-Json)
  Write-Host ("Uplink: index={0} alias={1} ip={2}" -f $uplink.index, $uplink.alias, $uplink.address)

  $ispToken = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'))
  $env:TESTISP_TOKEN = $ispToken

  $primaryStatePath = Join-Path $tempRoot 'isp-primary.json'
  $secondaryStatePath = Join-Path $tempRoot 'isp-secondary.json'

  $pPrimary = Start-Process -FilePath $ispExe -ArgumentList @('serve', '--uplink-index', "$($uplink.index)", '--uplink-ip', "$($uplink.address)", '--state', "`"$primaryStatePath`"", '--role', 'primary') -WindowStyle Hidden -PassThru
  $ispProcs += $pPrimary
  $primaryIsp = Wait-Until 'primary TestISP ready' 30 {
    if (-not (Test-Path -LiteralPath $primaryStatePath -PathType Leaf)) { return $null }
    $s = Get-Content -LiteralPath $primaryStatePath -Raw | ConvertFrom-Json
    if ($s.index -gt 0) { return $s }
    return $null
  }
  $env:TESTISP_ROLE = 'primary'
  $env:TESTISP_INDEX = "$($primaryIsp.index)"
  & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $ispNetworkScript -Action configure | Out-Null

  $pSecondary = Start-Process -FilePath $ispExe -ArgumentList @('serve', '--uplink-index', "$($uplink.index)", '--uplink-ip', "$($uplink.address)", '--state', "`"$secondaryStatePath`"", '--role', 'secondary') -WindowStyle Hidden -PassThru
  $ispProcs += $pSecondary
  $secondaryIsp = Wait-Until 'secondary TestISP ready' 30 {
    if (-not (Test-Path -LiteralPath $secondaryStatePath -PathType Leaf)) { return $null }
    $s = Get-Content -LiteralPath $secondaryStatePath -Raw | ConvertFrom-Json
    if ($s.index -gt 0) { return $s }
    return $null
  }
  $env:TESTISP_ROLE = 'secondary'
  $env:TESTISP_INDEX = "$($secondaryIsp.index)"
  & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $ispNetworkScript -Action configure | Out-Null
  Remove-Item Env:TESTISP_ROLE, Env:TESTISP_INDEX, Env:TESTISP_TOKEN -ErrorAction SilentlyContinue

  $echoPortFile = Join-Path $tempRoot 'echo-port.txt'
  $echoScriptPath = Join-Path $tempRoot 'echo-server.js'
  $echoStderrPath = Join-Path $diagDir 'echo-stderr.log'
  $echoJs = @'
const http = require('node:http');
const fs = require('node:fs');
const host = process.argv[2];
const portFile = process.argv[3];
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ nonce: u.searchParams.get('nonce') || '' }));
});
server.listen(0, host, () => {
  fs.writeFileSync(portFile, String(server.address().port));
});
setInterval(() => {}, 60000);
'@
  [IO.File]::WriteAllText($echoScriptPath, $echoJs, [Text.UTF8Encoding]::new($false))
  $echoProc = Start-Process -FilePath 'node.exe' -ArgumentList @("`"$echoScriptPath`"", "`"$($uplink.address)`"", "`"$echoPortFile`"") -RedirectStandardError $echoStderrPath -WindowStyle Hidden -PassThru
  $echoPort = [int](Wait-Until 'local HTTP echo server port' 15 {
    if ($echoProc.HasExited) {
      $errDetail = if (Test-Path -LiteralPath $echoStderrPath -PathType Leaf) { (Get-Content -LiteralPath $echoStderrPath -Raw).Trim() } else { '' }
      throw "echo server exited early (code $($echoProc.ExitCode)): $errDetail"
    }
    if (Test-Path -LiteralPath $echoPortFile -PathType Leaf) {
      $txt = (Get-Content -LiteralPath $echoPortFile -Raw).Trim()
      if ($txt -match '^\d+$') { return $txt }
    }
    return $null
  })
  $echoTarget = "198.19.128.2:$echoPort"
  $ispHeaders = @{ Authorization = "Bearer $ispToken" }
  $targetsBody = (@{ ports = @($echoPort) } | ConvertTo-Json -Compress)
  Invoke-RestMethod -Method POST -Uri "$($primaryIsp.control)/targets" -Headers $ispHeaders -ContentType 'application/json' -Body $targetsBody -TimeoutSec 5 | Out-Null
  Invoke-RestMethod -Method POST -Uri "$($secondaryIsp.control)/targets" -Headers $ispHeaders -ContentType 'application/json' -Body $targetsBody -TimeoutSec 5 | Out-Null

  function Assert-RoutedEcho([string] $Tag) {
    $beforeStats = Invoke-RestMethod -Method GET -Uri "$($primaryIsp.control)/stats" -Headers $ispHeaders -TimeoutSec 5
    $beforeCount = 0
    if ($beforeStats.destinations -and $beforeStats.destinations.PSObject.Properties[$echoTarget]) {
      $beforeCount = [int64]$beforeStats.destinations.PSObject.Properties[$echoTarget].Value
    }
    $nonce = [Guid]::NewGuid().ToString('N')
    $reply = Invoke-RestMethod -Method GET -Uri "http://${echoTarget}/echo?nonce=${nonce}" -TimeoutSec 10
    if ($reply.nonce -ne $nonce) {
      throw "[$Tag] Routed HTTP echo nonce mismatch: expected '$nonce', got '$($reply.nonce)'."
    }
    $afterStats = Invoke-RestMethod -Method GET -Uri "$($primaryIsp.control)/stats" -Headers $ispHeaders -TimeoutSec 5
    $afterCount = 0
    if ($afterStats.destinations -and $afterStats.destinations.PSObject.Properties[$echoTarget]) {
      $afterCount = [int64]$afterStats.destinations.PSObject.Properties[$echoTarget].Value
    }
    if ($afterCount -le $beforeCount) {
      throw "[$Tag] Primary TestISP destination counter for $echoTarget did not advance ($beforeCount -> $afterCount)."
    }
    Write-Host "[$Tag] Verified live routed HTTP traffic via $($primaryIsp.alias) ($beforeCount -> $afterCount)"
  }

  $passedCases = 0
  $utf8NoBom = [Text.UTF8Encoding]::new($false)

  # =========================================================================
  # CASE 1: Real v0.3.0 -> 1.0.0 migration (legacy schema, tasks, pins, usage)
  # =========================================================================
  Write-Host "=== CASE 1: v0.3.0 -> 1.0.0 migration and clean uninstall ==="
  Reset-CleanSlate
  Invoke-SilentInstaller -ExePath $setup030 -LogName 'case1-install-0.3.0.log' | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Net Switch\server.mjs') -PathType Leaf)) {
    throw 'Case 1: v0.3.0 did not install legacy entrypoint'
  }

  New-Item -ItemType Directory -Force -Path $userData | Out-Null
  $pinnedExe = Join-Path $env:SystemRoot 'System32\curl.exe'
  $legacy030Settings = [ordered]@{
    mainAlias = $primaryIsp.alias
    mainGuid = $primaryIsp.guid
    secondAlias = $secondaryIsp.alias
    secondGuid = $secondaryIsp.guid
    secondLabel = 'Backup Hotspot'
    secondKind = 'phone'
    secondApps = @($pinnedExe)
    combine = $true
    combineMode = 'manual'
    checkForUpdates = $false
  } | ConvertTo-Json -Depth 5
  [IO.File]::WriteAllText((Join-Path $userData 'settings.json'), $legacy030Settings, $utf8NoBom)

  $sess030 = Start-LegacyInstalledServer
  Invoke-LegacyApi -Port ([int]$sess030.port) -Token ([string]$sess030.token) -Method 'POST' -Path '/api/settings' -Body @{ autostart = $true } | Out-Null
  Assert-TaskPresent -TaskName '\Net Switch\Server' -Expected $true
  Assert-TaskPresent -TaskName '\Net Switch\Sign-in' -Expected $true
  Invoke-LegacyApi -Port ([int]$sess030.port) -Token ([string]$sess030.token) -Method 'POST' -Path '/api/quit' -Body @{} | Out-Null
  Start-Sleep -Seconds 1

  # Re-seed pure 0.2/0.3.0 mainAlias/secondAlias schema + usage record while server is stopped
  # so 1.0's Go settings migrator converts the legacy keys directly during Phase 4.
  [IO.File]::WriteAllText((Join-Path $userData 'settings.json'), $legacy030Settings, $utf8NoBom)
  $beforeUserSettingsBytes = [IO.File]::ReadAllBytes((Join-Path $userData 'settings.json'))
  $legacy030Usage = '{"periods":{"aa":{"period":"2026-11","rx":1024,"tx":2048}}}'
  [IO.File]::WriteAllText((Join-Path $userData 'usage.json'), $legacy030Usage, $utf8NoBom)

  Invoke-SilentInstaller -ExePath $setup100 -LogName 'case1-migrate-1.0.0.log' -ExtraArgs @('/TASKS=desktopicon') | Out-Null

  $current1 = (Get-Content -LiteralPath (Join-Path $appDir 'current') -Raw).Trim()
  if ($current1 -ne 'app-1.0.0') { throw "Case 1: expected {app}\current == 'app-1.0.0', got '$current1'" }
  foreach ($removedRel in @(
    'Net Switch\server.mjs',
    'Net Switch\launch.ps1',
    'Net Switch\tray.ps1',
    'Net Switch\runtime',
    'Net Switch\engine',
    'Net Switch\lib',
    'Net Switch\tools'
  )) {
    if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles $removedRel)) {
      throw "Case 1: legacy 0.3.0 path '$removedRel' remained after commit"
    }
  }
  Assert-TaskPresent -TaskName '\Net Switch\Server' -Expected $false
  Assert-TaskPresent -TaskName '\Net Switch\Sign-in' -Expected $false

  $runVal1 = (Get-ItemProperty -LiteralPath $runKeyPath -Name 'NetSwitch' -ErrorAction Stop).NetSwitch
  $expectedRunVal = "`"$appDir\netswitch-desktop.exe`" --background"
  if ($runVal1 -ne $expectedRunVal) {
    throw "Case 1: expected HKCU Run NetSwitch='$expectedRunVal', got '$runVal1'"
  }
  $startMenuLnk = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Net Switch.lnk'
  $desktopLnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Net Switch.lnk'
  if (-not (Test-Path -LiteralPath $startMenuLnk -PathType Leaf)) { throw "Case 1: missing Start Menu shortcut $startMenuLnk" }
  if (-not (Test-Path -LiteralPath $desktopLnk -PathType Leaf)) { throw "Case 1: missing Desktop shortcut $desktopLnk" }

  $afterUserSettingsBytes = [IO.File]::ReadAllBytes((Join-Path $userData 'settings.json'))
  if ([Convert]::ToBase64String($beforeUserSettingsBytes) -ne [Convert]::ToBase64String($afterUserSettingsBytes)) {
    throw 'Case 1: original %LOCALAPPDATA%\Net Switch\settings.json was mutated during migration'
  }

  $ctl100 = Join-Path $appDir 'app-1.0.0\netswitchctl.exe'
  $status1 = (& $ctl100 status | ConvertFrom-Json)
  if ($status1.pending -or $status1.routing -ne 'off') {
    throw "Case 1: unexpected status after migration: $($status1 | ConvertTo-Json -Compress)"
  }
  $migratedSettings1 = Get-Content -LiteralPath (Join-Path $machineData 'settings.json') -Raw | ConvertFrom-Json
  if ($migratedSettings1.lines.Count -ne 2 -or $migratedSettings1.lines[0].alias -ne $primaryIsp.alias -or $migratedSettings1.lines[1].alias -ne $secondaryIsp.alias) {
    throw "Case 1: migrated lines mismatch: $($migratedSettings1.lines | ConvertTo-Json -Compress)"
  }
  $secondLineId1 = $migratedSettings1.lines[1].id
  if ($migratedSettings1.appLines.PSObject.Properties[$pinnedExe].Value -ne $secondLineId1) {
    throw "Case 1: app pin for $pinnedExe was not migrated to second line $secondLineId1"
  }

  Invoke-SilentUninstaller -LogName 'case1-uninstall-1.0.0.log' | Out-Null
  if (Get-Service -Name 'NetSwitch' -ErrorAction SilentlyContinue) { throw 'Case 1: NetSwitch service survived uninstall' }
  if (Get-Service -Name 'NetSwitchEngine' -ErrorAction SilentlyContinue) { throw 'Case 1: NetSwitchEngine service survived uninstall' }
  if (Test-Path -LiteralPath $machineData) { throw "Case 1: $machineData survived clean uninstall" }
  if (-not (Test-Path -LiteralPath (Join-Path $userData 'settings.json') -PathType Leaf)) {
    throw 'Case 1: %LOCALAPPDATA%\Net Switch\settings.json was not retained across uninstall'
  }
  $passedCases += 1
  Write-Host 'CASE 1 PASS'

  # =========================================================================
  # CASE 2: Real v0.3.1 -> 1.0.0 fault-injected rollback + live routing cutover
  # =========================================================================
  Write-Host "=== CASE 2: v0.3.1 -> 1.0.0 pre-commit rollback + live routing cutover ==="
  Reset-CleanSlate
  Invoke-SilentInstaller -ExePath $setup031 -LogName 'case2-install-0.3.1.log' | Out-Null

  New-Item -ItemType Directory -Force -Path $userData | Out-Null
  New-Item -ItemType Directory -Force -Path $machineData | Out-Null
  $settings031 = [ordered]@{
    lines = @(
      [ordered]@{ id = 'aa01'; alias = $primaryIsp.alias; guid = $primaryIsp.guid; label = 'Primary Fibre'; kind = 'wired'; metered = $false; strict = $false; cap = $null; weight = 1 },
      [ordered]@{ id = 'bb02'; alias = $secondaryIsp.alias; guid = $secondaryIsp.guid; label = 'Backup LTE'; kind = 'phone'; metered = $true; strict = $false; cap = [ordered]@{ bytes = 5000000000; period = 'month'; resetDay = 5 }; weight = 1 }
    )
    appLines = [ordered]@{}
    combine = $false
    combineMode = 'auto'
    checkForUpdates = $false
  } | ConvertTo-Json -Depth 6
  [IO.File]::WriteAllText((Join-Path $userData 'settings.json'), $settings031, $utf8NoBom)

  # Apply a real fMinimizeConnections Windows policy change and record original value in windows-undo.json
  New-Item -Path $policyRegPath -Force | Out-Null
  Set-ItemProperty -LiteralPath $policyRegPath -Name 'fMinimizeConnections' -Value 0 -Type DWord
  $undoValueField = if ($origPolicyExists) { $origPolicyVal } else { $null }
  $undo031 = (@{ metrics = @{}; policy = @{ value = $undoValueField } } | ConvertTo-Json -Depth 4 -Compress)
  [IO.File]::WriteAllText((Join-Path $machineData 'windows-undo.json'), $undo031, $utf8NoBom)
  [IO.File]::WriteAllText((Join-Path $machineData 'windows-undo.json.bak'), $undo031, $utf8NoBom)

  $sess031 = Start-LegacyInstalledServer
  Invoke-LegacyApi -Port ([int]$sess031.port) -Token ([string]$sess031.token) -Method 'POST' -Path '/api/settings' -Body @{ autostart = $true } | Out-Null
  Invoke-LegacyApi -Port ([int]$sess031.port) -Token ([string]$sess031.token) -Method 'POST' -Path '/api/routing' -Body @{ on = $true } | Out-Null
  Wait-Until '0.3.1 routing status == on' 30 {
    $st = Invoke-LegacyApi -Port ([int]$sess031.port) -Token ([string]$sess031.token) -Method 'GET' -Path '/api/state' -TimeoutSec 5
    return ($st.routing.status -eq 'on')
  } | Out-Null

  # Inject pre-commit fault at Phase 5 ('healthy') after 1.0 services start and verify!
  $env:NETSWITCH_MIGRATE_FAULT_PHASE = 'healthy'
  try {
    $faultRun = Invoke-SilentInstaller -ExePath $setup100 -LogName 'case2-fault-rollback.log' -AllowFailure
  } finally {
    Remove-Item Env:NETSWITCH_MIGRATE_FAULT_PHASE -ErrorAction SilentlyContinue
  }
  if ($faultRun.ExitCode -eq 0) {
    throw 'Case 2: Setup unexpectedly succeeded despite NETSWITCH_MIGRATE_FAULT_PHASE=healthy'
  }
  $faultLogText = Get-Content -LiteralPath $faultRun.LogPath -Raw
  if ($faultLogText -notmatch 'injected migration fault at phase healthy') {
    $faultTail = (Get-Content -LiteralPath $faultRun.LogPath -Tail 30) -join "`n"
    throw "Case 2: Setup failed before reaching NETSWITCH_MIGRATE_FAULT_PHASE=healthy:`n$faultTail"
  }

  if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Net Switch\server.mjs') -PathType Leaf)) {
    throw 'Case 2: legacy entrypoint missing after pre-commit rollback'
  }
  if (Test-Path -LiteralPath (Join-Path $appDir 'current')) {
    throw 'Case 2: {app}\current marker exists after pre-commit rollback'
  }
  if (Test-Path -LiteralPath (Join-Path $appDir 'app-1.0.0')) {
    throw 'Case 2: uncommitted {app}\app-1.0.0 directory remained after rollback'
  }
  if (Get-Service -Name 'NetSwitch' -ErrorAction SilentlyContinue) {
    throw 'Case 2: NetSwitch 1.0 service remained registered after rollback'
  }
  if (Get-Service -Name 'NetSwitchEngine' -ErrorAction SilentlyContinue) {
    throw 'Case 2: NetSwitchEngine 1.0 service remained registered after rollback'
  }
  if (-not (Test-Path -LiteralPath (Join-Path $machineData 'windows-undo.json') -PathType Leaf)) {
    throw 'Case 2: windows-undo.json was lost from %ProgramData%\Net Switch on rollback'
  }
  Assert-TaskPresent -TaskName '\Net Switch\Server' -Expected $true
  Assert-TaskPresent -TaskName '\Net Switch\Sign-in' -Expected $true

  # Verify 0.3.1 server and live routing were automatically restarted by rollback!
  Wait-Until '0.3.1 server restarted with routing.status == on after rollback' 45 {
    $serverJson = Join-Path $userData 'server.json'
    if (-not (Test-Path -LiteralPath $serverJson -PathType Leaf)) { return $false }
    $restartedSess = Get-Content -LiteralPath $serverJson -Raw | ConvertFrom-Json
    $st = Invoke-LegacyApi -Port ([int]$restartedSess.port) -Token ([string]$restartedSess.token) -Method 'GET' -Path '/api/state' -TimeoutSec 5
    return ($st.routing.status -eq 'on')
  } | Out-Null
  Write-Host 'Case 2: Verified full pre-commit rollback and automatic 0.3.1 routing restart'

  # Now run the real migration without fault injection over live 0.3.1 routing!
  Invoke-SilentInstaller -ExePath $setup100 -LogName 'case2-migrate-1.0.0.log' | Out-Null
  if ((Get-Content -LiteralPath (Join-Path $appDir 'current') -Raw).Trim() -ne 'app-1.0.0') {
    throw 'Case 2: expected {app}\current == app-1.0.0 after real migration'
  }
  if (-not (Test-Path -LiteralPath (Join-Path $machineData 'windows-undo.json') -PathType Leaf)) {
    throw 'Case 2: windows-undo.json was not preserved in 1.0 machine store'
  }
  $ctl100 = Join-Path $appDir 'app-1.0.0\netswitchctl.exe'
  Wait-Until '1.0 routing == on after migrating live 0.3.1 session' 30 {
    $st = (& $ctl100 status | ConvertFrom-Json)
    return ($st.routing -eq 'on' -and -not [string]::IsNullOrWhiteSpace($st.engineInstanceId))
  } | Out-Null
  Assert-RoutedEcho 'Case 2 (1.0.0 post-migration)'
  $passedCases += 1
  Write-Host 'CASE 2 PASS'

  # =========================================================================
  # CASE 3: 1.0.0 -> 1.0.1 versioned upgrade, launcher delegation & undo restore
  # =========================================================================
  Write-Host "=== CASE 3: 1.0.0 -> 1.0.1 versioned upgrade and uninstall with Windows Undo ==="
  Invoke-SilentInstaller -ExePath $setup101 -LogName 'case3-upgrade-1.0.1.log' | Out-Null

  $current3 = (Get-Content -LiteralPath (Join-Path $appDir 'current') -Raw).Trim()
  if ($current3 -ne 'app-1.0.1') { throw "Case 3: expected {app}\current == 'app-1.0.1', got '$current3'" }

  $delegatedVer = (& (Join-Path $appDir 'netswitch-desktop.exe') --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $delegatedVer -ne 'netswitch-desktop v1.0.1') {
    throw "Case 3: expected top-level launcher --version == 'netswitch-desktop v1.0.1', got '$delegatedVer' (exit $LASTEXITCODE)"
  }

  $ctl101 = Join-Path $appDir 'app-1.0.1\netswitchctl.exe'
  Wait-Until '1.0.1 routing == on after upgrade' 30 {
    $st = (& $ctl101 status | ConvertFrom-Json)
    return ($st.routing -eq 'on')
  } | Out-Null
  Assert-RoutedEcho 'Case 3 (1.0.1 post-upgrade)'

  $uninsLog3 = Invoke-SilentUninstaller -LogName 'case3-uninstall-1.0.1.log'
  $uninsText3 = Get-Content -LiteralPath $uninsLog3 -Raw
  if ($uninsText3 -notmatch 'Net Switch Windows restore result: 0') {
    throw "Case 3: uninstall log did not record successful native restore-windows:`n$uninsText3"
  }
  if (Test-Path -LiteralPath $machineData) {
    throw "Case 3: $machineData was not cleaned up after successful restore-windows"
  }

  $restoredProp = if (Test-Path -LiteralPath $policyRegPath) {
    Get-ItemProperty -LiteralPath $policyRegPath -Name 'fMinimizeConnections' -ErrorAction SilentlyContinue
  } else { $null }
  $hasNow = ($null -ne $restoredProp -and $restoredProp.PSObject.Properties['fMinimizeConnections'])
  if ($origPolicyExists) {
    if (-not $hasNow -or [int]$restoredProp.fMinimizeConnections -ne $origPolicyVal) {
      throw "Case 3: fMinimizeConnections was not restored to $origPolicyVal"
    }
  } else {
    if ($hasNow) {
      throw "Case 3: fMinimizeConnections remained set ($($restoredProp.fMinimizeConnections)) instead of being deleted"
    }
  }
  $passedCases += 1
  Write-Host 'CASE 3 PASS'

  # =========================================================================
  # CASE 4: Real v0.3.2 -> 1.0.0 multi-profile conflict refusal & /PROFILE=
  # =========================================================================
  Write-Host "=== CASE 4: v0.3.2 -> 1.0.0 multi-profile conflict detection and /PROFILE= selection ==="
  Reset-CleanSlate
  Invoke-SilentInstaller -ExePath $setup032 -LogName 'case4-install-0.3.2.log' | Out-Null

  New-Item -ItemType Directory -Force -Path $userData | Out-Null
  $profileOneSettings = [ordered]@{
    lines = @(
      [ordered]@{ id = 'aa11'; alias = $primaryIsp.alias; label = 'Runner Admin Fibre'; kind = 'wired'; metered = $false; strict = $false; cap = $null; weight = 1 }
    )
    appLines = [ordered]@{}
    combine = $false
    combineMode = 'auto'
    checkForUpdates = $false
  } | ConvertTo-Json -Depth 5
  [IO.File]::WriteAllText((Join-Path $userData 'settings.json'), $profileOneSettings, $utf8NoBom)

  $randPwd = 'Ns!' + [Guid]::NewGuid().ToString('N').Substring(0, 12) + '9aA'
  & net.exe user $tempUserName $randPwd /add | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Case 4: failed to create temporary local user $tempUserName" }
  $tempSidObj = ([Security.Principal.NTAccount]$tempUserName).Translate([Security.Principal.SecurityIdentifier])
  $tempProfileSid = $tempSidObj.Value

  $secondProfileDir = Join-Path $tempRoot 'second-profile'
  $secondUserData = Join-Path $secondProfileDir 'AppData\Local\Net Switch'
  New-Item -ItemType Directory -Force -Path $secondUserData | Out-Null
  $profileTwoSettings = [ordered]@{
    lines = @(
      [ordered]@{ id = 'cc22'; alias = $secondaryIsp.alias; label = 'Second Account LTE'; kind = 'phone'; metered = $true; strict = $false; cap = $null; weight = 1 }
    )
    appLines = [ordered]@{}
    combine = $true
    combineMode = 'manual'
    checkForUpdates = $false
  } | ConvertTo-Json -Depth 5
  $secondSettingsPath = Join-Path $secondUserData 'settings.json'
  [IO.File]::WriteAllText($secondSettingsPath, $profileTwoSettings, $utf8NoBom)
  & icacls.exe $secondUserData /setowner "*$tempProfileSid" /T /C /Q | Out-Null

  $profileListReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$tempProfileSid"
  New-Item -Path $profileListReg -Force | Out-Null
  New-ItemProperty -LiteralPath $profileListReg -Name 'ProfileImagePath' -Value $secondProfileDir -PropertyType ExpandString -Force | Out-Null

  $stageCtl = Join-Path $dist "stage-1.0.0-$Arch\netswitchctl.exe"
  $profDiscovery = (& $stageCtl migrate-profiles --app-dir $appDir | ConvertFrom-Json)
  if (-not $profDiscovery.conflict) {
    throw "Case 4: expected migrate-profiles conflict=true, got: $($profDiscovery | ConvertTo-Json -Depth 5 -Compress)"
  }

  # Silent install WITHOUT /PROFILE= must fail pre-flight without stopping or modifying v0.3.2!
  $conflictRun = Invoke-SilentInstaller -ExePath $setup100 -LogName 'case4-conflict-refused.log' -AllowFailure
  if ($conflictRun.ExitCode -eq 0) {
    throw 'Case 4: silent migration unexpectedly succeeded without /PROFILE= when multiple profiles conflict'
  }
  if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Net Switch\server.mjs') -PathType Leaf)) {
    throw 'Case 4: legacy entrypoint was modified despite pre-flight profile conflict refusal'
  }

  # Silent install WITH /PROFILE=<secondSID> must succeed and import the second profile's settings!
  Invoke-SilentInstaller -ExePath $setup100 -LogName 'case4-migrate-selected-profile.log' -ExtraArgs @("/PROFILE=$tempProfileSid") | Out-Null
  $migratedSettings4 = Get-Content -LiteralPath (Join-Path $machineData 'settings.json') -Raw | ConvertFrom-Json
  if ($migratedSettings4.lines.Count -ne 1 -or $migratedSettings4.lines[0].label -ne 'Second Account LTE') {
    throw "Case 4: expected Second Account LTE from /PROFILE=$tempProfileSid, got: $($migratedSettings4.lines | ConvertTo-Json -Compress)"
  }

  Invoke-SilentUninstaller -LogName 'case4-uninstall-1.0.0.log' | Out-Null
  $passedCases += 1
  Write-Host 'CASE 4 PASS'

  if ($passedCases -ne 4) {
    throw "Expected 4 passed installer cases, got $passedCases"
  }
  Write-Host "INSTALLER SUITE SUMMARY ($Arch): $passedCases/4 cases passed"
} catch {
  Save-SuiteDiagnostics 'failure'
  throw
} finally {
  Remove-Item Env:NETSWITCH_MIGRATE_FAULT_PHASE, Env:TESTISP_ROLE, Env:TESTISP_INDEX, Env:TESTISP_TOKEN -ErrorAction SilentlyContinue
  if ($tempProfileSid) {
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$tempProfileSid" -Recurse -Force -ErrorAction SilentlyContinue
  }
  & net.exe user $tempUserName /delete 2>$null | Out-Null
  if ($origPolicyExists) {
    New-Item -Path $policyRegPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath $policyRegPath -Name 'fMinimizeConnections' -Value $origPolicyVal -Type DWord -ErrorAction SilentlyContinue
  } else {
    Remove-ItemProperty -LiteralPath $policyRegPath -Name 'fMinimizeConnections' -ErrorAction SilentlyContinue
  }
  Reset-CleanSlate
  if ($echoProc -and -not $echoProc.HasExited) {
    Stop-Process -Id $echoProc.Id -Force -ErrorAction SilentlyContinue
  }
  foreach ($p in $ispProcs) {
    if ($p -and -not $p.HasExited) {
      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
      $p.WaitForExit(10000) | Out-Null
    }
  }
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
