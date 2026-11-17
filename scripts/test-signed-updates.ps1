# Dot-sourced by test-windows-installer.ps1 after its four production-installer
# cases. Reuses that suite's real TestISP rig, cleanup and diagnostic helpers.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'Signed update installation tests require disposable hosted Windows.'
}

$signedBase = '1.0.10'
$signedTarget = '1.0.11'
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Arch $Arch -Version $signedBase -UpdateTestFixture
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Arch $Arch -Version $signedTarget -UpdateTestFixture
$signedSetup = Join-Path $dist "NetSwitch-Setup-$signedBase-$Arch.exe"
$signedTargetSetup = Join-Path $dist "NetSwitch-Setup-$signedTarget-$Arch.exe"
$fixtureExe = Join-Path $tempRoot 'update-fixture.exe'
$fixtureState = Join-Path $tempRoot 'update-source.json'
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$signedPassed = 0
$signedExpected = 17

$oldFixtureGoEnv = @{}
$fixtureGoEnv = @{ GOROOT=$goRoot; GOTOOLCHAIN='local'; GOARCH=$goArch; CGO_ENABLED='0'; GOMAXPROCS='2'; GOFLAGS='-mod=vendor -p=2' }
foreach ($entry in $fixtureGoEnv.GetEnumerator()) {
  $oldFixtureGoEnv[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key,'Process')
  [Environment]::SetEnvironmentVariable($entry.Key,$entry.Value,'Process')
}
try {
  & $goExe build -C $repoRoot -trimpath -o $fixtureExe ./tests/windows/updatefixture
  if ($LASTEXITCODE -ne 0) { throw 'Building signed installer fixture failed.' }
} finally {
  foreach ($name in $oldFixtureGoEnv.Keys) { [Environment]::SetEnvironmentVariable($name,$oldFixtureGoEnv[$name],'Process') }
}

function Write-UpdateFixtureFile([string] $Name, [string] $Text) {
  if ($Name -notmatch '^[a-z0-9.-]+$') { throw 'Invalid protected fixture filename.' }
  $target = Join-Path $machineData $Name
  [IO.File]::WriteAllText($target,$Text,[Text.UTF8Encoding]::new($false))
  # /setowner is a separate icacls operation, not a modifier of /grant.
  & icacls.exe $target /setowner '*S-1-5-32-544' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not set fixture owner: $Name" }
  & icacls.exe $target /inheritance:r | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not protect fixture inheritance: $Name" }
  & icacls.exe $target /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not grant fixture service permissions: $Name" }
}

function Get-SignedCtl {
  $sub = (Get-Content -LiteralPath (Join-Path $appDir 'current') -Raw).Trim()
  if ($sub -notmatch '^app-\d+\.\d+\.\d+$') { throw 'Invalid installed current marker.' }
  return Join-Path $appDir "$sub\netswitchctl.exe"
}

function Invoke-UpdateCtl([string[]] $Arguments, [switch] $AllowFailure) {
  $ctl = Get-SignedCtl
  $text = & $ctl @Arguments 2>&1
  $code = $LASTEXITCODE
  if ($code -ne 0 -and -not $AllowFailure) { throw "Update command failed ($code): $text" }
  return [pscustomobject]@{ Code=$code; Text=($text -join "`n") }
}

function Read-SignedStatus {
  $answer = Invoke-UpdateCtl -Arguments @('status')
  return $answer.Text | ConvertFrom-Json
}

function Read-UpdateJournal {
  $file = Join-Path $machineData 'update-journal.json'
  if (-not (Test-Path -LiteralPath $file)) { return $null }
  return Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
}

function Wait-UpdateTerminal([string] $Expected) {
  $deadline = [DateTime]::UtcNow.AddSeconds(240)
  $lastPhase = ''
  while ([DateTime]::UtcNow -lt $deadline) {
    if ($sourceProcess.HasExited) { throw 'Signed update source exited during the transaction.' }
    $journal = Read-UpdateJournal
    if ($null -ne $journal) {
      $phase = $journal.status.phase
      if ($phase -ne $lastPhase) {
        Write-Host "SIGNED UPDATE PHASE: $phase"
        $lastPhase = $phase
      }
      if ($phase -in @('complete','reboot-required','rolled-back','failed','download-error','signature-error')) {
        $detail = if ($journal.PSObject.Properties['lastError']) { $journal.lastError } else { '' }
        if ($phase -ne $Expected) { throw "Expected $Expected, got $phase : $detail" }
        return $journal
      }
    }
    Start-Sleep -Milliseconds 300
  }
  throw "Update did not finish as $Expected within 240 seconds."
}

function Set-UpdateSourceMode([string] $Mode) {
  Invoke-RestMethod -Method POST -Uri "$($script:updateConnection.url)/mode" -Headers @{ 'X-Update-Fixture'=$script:updateConnection.token } -ContentType 'application/json' -Body (@{ mode=$Mode }|ConvertTo-Json -Compress) -TimeoutSec 5 | Out-Null
}

function Start-SignedBase([bool] $RoutingOn) {
  Reset-CleanSlate
  Invoke-SilentInstaller -ExePath $signedSetup -LogName "signed-$signedPassed-base.log" -ExtraArgs @("/OWNER=$ownerSid") | Out-Null
  Stop-Service -Name 'NetSwitch'
  Wait-Until 'base Control stops before fixture writes' 20 { (Get-Service NetSwitch).Status -eq 'Stopped' } | Out-Null
  Write-UpdateFixtureFile 'update-fixture.json' ($script:updateConnection|ConvertTo-Json -Compress)
  # Real owner tokens and IPC are used. Hosted runners have no interactive WTS
  # desktop; this existing test-build hook supplies only session presence.
  Write-UpdateFixtureFile 'fault-owner-sessions.json' (@{ $ownerSid=$true }|ConvertTo-Json -Compress)
  $settings = [ordered]@{
    lines=@(
      [ordered]@{ id='aa11'; alias=$primaryIsp.alias; guid=$primaryIsp.guid; label='Update primary'; kind='wired'; metered=$false; strict=$false; cap=$null; weight=1 },
      [ordered]@{ id='bb22'; alias=$secondaryIsp.alias; guid=$secondaryIsp.guid; label='Update backup'; kind='phone'; metered=$true; strict=$false; cap=$null; weight=1 }
    )
    appLines=@{ (Join-Path $env:SystemRoot 'System32\curl.exe')='bb22' }
    combine=$false; combineMode='manual'; checkForUpdates=$false
  }
  Write-UpdateFixtureFile 'settings.json' ($settings|ConvertTo-Json -Depth 8 -Compress)
  $journalFile = Join-Path $machineData 'control-journal.json'
  $journal = Get-Content -LiteralPath $journalFile -Raw | ConvertFrom-Json -AsHashtable
  $journal.settings=$settings; $journal.wanted=$false; $journal.Remove('updateIntent') | Out-Null
  Write-UpdateFixtureFile 'control-journal.json' ($journal|ConvertTo-Json -Depth 20 -Compress)
  Write-UpdateFixtureFile 'control-journal.json.bak' ($journal|ConvertTo-Json -Depth 20 -Compress)
  Set-UpdateSourceMode 'valid'
  Start-Service -Name 'NetSwitch'
  Start-Process -FilePath (Join-Path $appDir 'netswitch-desktop.exe') -ArgumentList @('--resume','--background') -WindowStyle Hidden | Out-Null
  $before = Wait-Until 'owner desktop connects without sign-in routing' 40 {
    $status = Read-SignedStatus
    if ($status.desktopPID -gt 0 -and $status.routing -eq 'off') { return $status }
    return $null
  }
  if ($RoutingOn) {
    Invoke-UpdateCtl -Arguments @('start') | Out-Null
    Wait-Until 'base routing turns on' 30 { (Read-SignedStatus).routing -eq 'on' } | Out-Null
    Assert-RoutedEcho "signed base $signedPassed"
  }
  return $before
}

function Assert-SignedResult([string] $Version, [bool] $RoutingOn, [uint32] $OldDesktop) {
  $expected = if ($RoutingOn) { 'on' } else { 'off' }
  $status = Wait-Until "updated desktop and routing $expected" 45 {
    $current = Read-SignedStatus
    if ($current.routing -eq $expected -and $current.desktopPID -gt 0 -and $current.desktopPID -ne $OldDesktop) { return $current }
    return $null
  }
  $marker = (Get-Content -LiteralPath (Join-Path $appDir 'current') -Raw).Trim()
  if ($marker -ne "app-$Version") { throw "Signed update selected $marker instead of app-$Version" }
  $desktopProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($status.desktopPID)"
  if ($desktopProcess.ExecutablePath -ne (Join-Path $appDir "app-$Version\netswitch-desktop.exe")) { throw 'Desktop restarted from the wrong version.' }
  $saved = Get-Content -LiteralPath (Join-Path $machineData 'settings.json') -Raw | ConvertFrom-Json
  $pin = Join-Path $env:SystemRoot 'System32\curl.exe'
  if ($saved.lines[0].label -ne 'Update primary' -or $saved.lines[1].label -ne 'Update backup' -or $saved.appLines.PSObject.Properties[$pin].Value -ne 'bb22') { throw 'Signed update lost line settings or app pin.' }
  # WMI returned an empty PathName in the hosted proof. Read the actual SCM
  # configuration with SERVICE_QUERY_CONFIG, preserving the restricted ACL.
  $servicePathsJson = & $fixtureExe --service-paths
  if ($LASTEXITCODE -ne 0) { throw 'Could not independently read installed SCM paths.' }
  $servicePaths = $servicePathsJson | ConvertFrom-Json -AsHashtable
  foreach ($entry in @(@('NetSwitch','netswitch.exe'),@('NetSwitchEngine','netswitch-engine.exe'))) {
    $servicePath = $servicePaths[$entry[0]]
    if (-not $servicePath -or $servicePath -notlike "*app-$Version\$($entry[1])*--data*") { throw "Wrong service path for $($entry[0]): $servicePath" }
  }
  if ($RoutingOn) { Assert-RoutedEcho "signed result $signedPassed" }
  Wait-Until 'updater exits after desktop handoff' 25 {
    $journal = Read-UpdateJournal
    if (-not $journal.desktopRestarted) { return $false }
    $process = Get-Process -Id $journal.runnerPid -ErrorAction SilentlyContinue
    return $null -eq $process -or $process.Path -notlike '*\updates\runner\*\netswitchctl.exe'
  } | Out-Null
}

$sourceProcess = Start-Process -FilePath $fixtureExe -ArgumentList @('--installer',"`"$signedTargetSetup`"",'--version',$signedTarget,'--arch',$Arch,'--state',"`"$fixtureState`"") -WindowStyle Hidden -PassThru
try {
  $script:updateConnection = Wait-Until 'signed update fixture source' 15 {
    if ($sourceProcess.HasExited) { throw 'Signed update fixture exited.' }
    if (Test-Path -LiteralPath $fixtureState) { return Get-Content -LiteralPath $fixtureState -Raw|ConvertFrom-Json }
    return $null
  }

  # Signed metadata refusals must not stop services or even enter an update.
  $before = Start-SignedBase $false
  foreach ($mode in @('bad-signature','expired','wrong-arch','downgrade')) {
    Set-UpdateSourceMode $mode
    $answer = Invoke-UpdateCtl -Arguments @('update','--request','--version',$signedTarget) -AllowFailure
    if ($answer.Code -eq 0) { throw "Accepted refused metadata mode $mode" }
    $after = Read-SignedStatus
    if ($after.controlPID -ne $before.controlPID -or $after.desktopPID -ne $before.desktopPID -or $null -ne (Read-UpdateJournal)) { throw "Refused $mode changed the running installation." }
    $signedPassed++; Write-Host "SIGNED UPDATE PASS: reject $mode before service changes"
  }
  Set-UpdateSourceMode 'tampered-installer'
  Invoke-UpdateCtl -Arguments @('update','--request','--version',$signedTarget) | Out-Null
  $null = Wait-UpdateTerminal 'signature-error'
  if ((Read-SignedStatus).controlPID -ne $before.controlPID) { throw 'Installer tampering stopped Control.' }
  $signedPassed++; Write-Host 'SIGNED UPDATE PASS: reject tampered installer before service changes'

  foreach ($routingOn in @($false,$true)) {
    foreach ($rollback in @($false,$true)) {
      $before = Start-SignedBase $routingOn
      if ($rollback) { Write-UpdateFixtureFile 'fault-update-health' 'fail' }
      Invoke-UpdateCtl -Arguments @('update','--request','--version',$signedTarget) | Out-Null
      $phase = if ($rollback) { 'rolled-back' } else { 'complete' }
      $null = Wait-UpdateTerminal $phase
      $expectedVersion = if ($rollback) { $signedBase } else { $signedTarget }
      Assert-SignedResult $expectedVersion $routingOn $before.desktopPID
      $signedPassed++; Write-Host "SIGNED UPDATE PASS: $phase routing=$routingOn with settings and desktop restart"
    }
  }

  $before = Start-SignedBase $false
  Write-UpdateFixtureFile 'fault-update-reboot' '1'
  Invoke-UpdateCtl -Arguments @('update','--request','--version',$signedTarget) | Out-Null
  $journal = Wait-UpdateTerminal 'reboot-required'
  if (-not $journal.status.rebootRequired) { throw 'Real Inno 3010 result was lost.' }
  Assert-SignedResult $signedTarget $false $before.desktopPID
  $signedPassed++; Write-Host 'SIGNED UPDATE PASS: real Inno reboot exit 3010'

  foreach ($point in @('preparing','stopped','snapshotted','applying','checking','rolling-back','complete')) {
    $before = Start-SignedBase $false
    if ($point -eq 'rolling-back') { Write-UpdateFixtureFile 'fault-update-health' 'fail' }
    Write-UpdateFixtureFile "fault-update-$point" 'crash'
    Invoke-UpdateCtl -Arguments @('update','--request','--version',$signedTarget) | Out-Null
    $hit = Wait-Until "updater checkpoint $point" 180 {
      $file = Join-Path $machineData 'fault-hit.json'
      if (-not (Test-Path -LiteralPath $file)) { return $null }
      $hit = Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
      if ($hit.point -eq "update-$point") { return $hit }; return $null
    }
    $journal = Read-UpdateJournal
    if ($journal.runnerPid -ne $hit.pid) { throw 'Crash barrier did not identify the recorded updater.' }
    $crashing = Get-Process -Id $hit.pid
    $expectedRunner = Join-Path $appDir "updates\runner\$($journal.status.operation)\netswitchctl.exe"
    $createdTicks = [Int64][System.Numerics.BigInteger]::Divide([bigint]$journal.runnerCreated,100) + [DateTime]::UnixEpoch.Ticks
    if ($crashing.Path -ne $expectedRunner -or $crashing.StartTime.ToUniversalTime().Ticks -ne $createdTicks) { throw 'Refusing to kill an unrelated or reused process.' }
    $crashing.Kill(); if (-not $crashing.WaitForExit(10000)) { throw 'Updater did not exit at crash barrier.' }
    # The owner desktop reconnects through the preserved Control registration.
    # No test helper invokes rollback or repairs the service paths for it.
    $expectedPhase = if ($point -eq 'complete') { 'complete' } else { 'rolled-back' }
    $null = Wait-UpdateTerminal $expectedPhase
    $expectedVersion = if ($point -eq 'complete') { $signedTarget } else { $signedBase }
    Assert-SignedResult $expectedVersion $false $before.desktopPID
    $signedPassed++; Write-Host "SIGNED UPDATE PASS: updater death at $point recovered without fixture repair"
  }
  if ($signedPassed -ne $signedExpected) { throw "Expected $signedExpected signed-update cases, got $signedPassed" }
  Write-Host "SIGNED UPDATE SUMMARY ($Arch): $signedPassed/$signedExpected cases passed"
} finally {
  if (-not $sourceProcess.HasExited) { $sourceProcess.Kill(); $sourceProcess.WaitForExit(10000)|Out-Null }
}
