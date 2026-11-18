# Run from the guarded, disposable Windows installer rig after both gateways
# have been configured. The workload client/server use the runner's Node binary.
$m6Root=Join-Path $repoRoot 'tests/m6'
$m6Driver=Join-Path $m6Root 'traffic.mjs'
$m6Profile=Join-Path $m6Root 'accounting/cpu.wprp'
$m6Reader=Join-Path $repoRoot 'dist/m6-reader/M6Cpu.exe'
$m6Node=(Get-Command node.exe -CommandType Application | Select-Object -First 1).Source
$m6PortFile=Join-Path $tempRoot 'm6-port'
$m6Server=Start-Process -FilePath $m6Node -ArgumentList @('--max-old-space-size=2048',"`"$m6Driver`"",'serve',$uplink.address,"`"$m6PortFile`"") -PassThru -WindowStyle Hidden
try {
  $m6Port=[int](Wait-Until 'M6 responder ready' 20 {
    if ($m6Server.HasExited) { throw 'M6 responder exited during setup' }
    if (Test-Path -LiteralPath $m6PortFile) { return [int](Get-Content -Raw $m6PortFile) }
    return $null
  })
  $m6Target="198.19.128.2:$m6Port"
  $ports=@{ports=@($echoPort,$m6Port)}|ConvertTo-Json -Compress
  foreach ($isp in @($primaryIsp,$secondaryIsp)) {
    Invoke-RestMethod -Method POST -Uri "$($isp.control)/targets" -Headers $ispHeaders -ContentType 'application/json' -Body $ports -TimeoutSec 5 | Out-Null
  }
  . (Join-Path $m6Root 'measure.ps1')
  # Verify exited-child CPU visibility before observing either product.
  if ($Qualification -eq 'compare') {
    & wpr.exe -start "$m6Profile!NetSwitchCPU.Light" -filemode
    if ($LASTEXITCODE -ne 0) {throw 'Calibration trace could not start'}
    try {
      & $m6Reader calibrate "$tempRoot/calibration.json"
      if ($LASTEXITCODE -ne 0) {throw 'Calibration child failed'}
    } finally {
      & wpr.exe -stop "$tempRoot/calibration.etl"
      if ($LASTEXITCODE -ne 0) { throw 'Calibration trace could not stop' }
    }
    & $m6Reader "$tempRoot/calibration.etl" "$tempRoot/calibration.json" "$tempRoot/calibration-cpu.json"
    if ($LASTEXITCODE -ne 0) {throw 'Exited-child CPU calibration failed'}
  }
  Reset-CleanSlate
  Invoke-SilentInstaller -ExePath $setup032 -LogName 'm6-baseline.log' | Out-Null
  $null=New-Item -Force -ItemType Directory -Path $userData
  $settings=@{lines=@(@{id='aa01';alias=$primaryIsp.alias;guid=$primaryIsp.guid;label='Main';kind='wired';metered=$false;weight=1},@{id='bb02';alias=$secondaryIsp.alias;guid=$secondaryIsp.guid;label='Second';kind='wired';metered=$false;weight=1});appLines=@{};combine=$false;checkForUpdates=$false}
  [IO.File]::WriteAllText((Join-Path $userData 'settings.json'),($settings|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
  $oldSession=Start-LegacyInstalledServer
  Invoke-LegacyApi -Port $oldSession.port -Token $oldSession.token -Method POST -Path '/api/routing' -Body @{on=$true} | Out-Null
  Wait-Until 'released product routing' 40 { (Invoke-LegacyApi -Port $oldSession.port -Token $oldSession.token -Method GET -Path '/api/state').routing.status -eq 'on' } | Out-Null
  $legacyTray=Join-Path $appDir 'tray/NetSwitchTray.exe'
  Start-Process $legacyTray -ArgumentList @('-DataDir',"`"$userData`"") -WindowStyle Hidden
  Assert-RoutedEcho 'M6 released product'
  if ($Qualification -eq 'compare') {
    Measure-M6Product 'baseline' '0.3.2' $setup032
    Measure-M6Product 'baseline-repeat' '0.3.2' $setup032
  }
  # A real installed migration preserves these exact gateways and default line.
  Invoke-SilentInstaller -ExePath $setup100 -LogName 'm6-candidate.log' | Out-Null
  Start-Process (Join-Path $appDir 'netswitch-desktop.exe') -ArgumentList @('--resume','--background') -WindowStyle Hidden
  $ctl=Join-Path $appDir "app-$candidateVersion/netswitchctl.exe"
  Wait-Until 'installed candidate routing with connected desktop' 45 {
    $text=& $ctl status
    if ($LASTEXITCODE -eq 0) {
      $s=$text | ConvertFrom-Json
      return ($s.routing -eq 'on' -and $s.desktopPID -gt 0 -and $s.engineInstanceId)
    }
    return $false
  } | Out-Null
  Assert-RoutedEcho 'M6 installed candidate'
  if ($Qualification -eq 'compare') {
    Measure-M6Product 'candidate' $candidateVersion $setup100
    Measure-M6Product 'candidate-repeat' $candidateVersion $setup100
    & $m6Node --max-old-space-size=2048 (Join-Path $m6Root 'compare.mjs') "$diagDir/m6-baseline/report.json" "$diagDir/m6-candidate/report.json" "$diagDir/m6-comparison.json"
    if ($LASTEXITCODE -ne 0) {throw 'Performance comparison failed'}
  } else {
    $before=Get-M6Count
    $result=Join-Path $diagDir 'm6-soak.json'
    $initial=(& $ctl status | ConvertFrom-Json)
    $images=@(Get-M6ProductProcesses | Where-Object ExecutablePath | Select-Object -ExpandProperty ExecutablePath -Unique |
      ForEach-Object { @{name=[IO.Path]::GetFileName($_);hash=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()} })
    $client=Start-M6Client soak $result
    $soak=$client.Process
    $null=$soak.Handle
    $started=[Diagnostics.Stopwatch]::StartNew()
    try {
      while (!$soak.WaitForExit(30000)) {
        if ($started.Elapsed.TotalMinutes -gt 125) { throw 'Soak worker exceeded exposure deadline' }
        $state=(& $ctl status | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0 -or $state.routing -ne 'on' -or $state.engineInstanceId -ne $initial.engineInstanceId -or $state.controlPID -ne $initial.controlPID) {
          throw 'Installed routing stopped or changed lifetime during soak'
        }
        Write-Host ("M6_SOAK elapsed_seconds={0:N0} engine={1}" -f $started.Elapsed.TotalSeconds,$initial.engineInstanceId)
      }
      if ($soak.ExitCode -ne 0) { throw "Installed traffic soak failed: $($client.Errors.Result)" }
    } finally {
      if (!$soak.HasExited) { $soak.Kill(); $soak.WaitForExit() }
    }
    $record=Get-Content -Raw $result|ConvertFrom-Json
    if (!$record.complete -or $record.seconds -lt 7200 -or (Get-M6Count)-$before -ne $record.successes) {throw 'Incomplete routed exposure'}
    Assert-RoutedEcho 'M6 after two hours'
    @{arch=$Arch;commit=$env:GITHUB_SHA;images=$images;installerHash=(Get-FileHash -LiteralPath $setup100).Hash;engine=$initial.engineInstanceId;exposure=$record;gatewayConnections=((Get-M6Count)-$before)} |
       ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8NoBOM (Join-Path $diagDir 'm6-soak-proof.json')
  }
} finally {
  if (!$m6Server.HasExited) { $m6Server.Kill(); $m6Server.WaitForExit() }
}
