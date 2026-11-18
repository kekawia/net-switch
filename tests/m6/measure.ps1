# Hosted measurement helper, dot-sourced after the installer fixture is ready.
function Start-M6Client([string]$ModeName,[string]$ResultPath) {
  $info=[Diagnostics.ProcessStartInfo]::new($m6Node)
  $info.UseShellExecute=$false
  $info.CreateNoWindow=$true
  $info.RedirectStandardError=$true
  $info.Environment['M6_TCP_READER']=$m6Reader
  $info.Environment['M6_TCP_UPLINK']=[string]$uplink.address
  foreach($value in @('--max-old-space-size=2048',$m6Driver,$ModeName,'198.19.128.2',"$m6Port",$ResultPath)) {
    $info.ArgumentList.Add($value)
  }
  $proc=[Diagnostics.Process]::Start($info)
  return [pscustomobject]@{Process=$proc;Errors=$proc.StandardError.ReadToEndAsync()}
}
function Get-M6ProductProcesses {
  $all = @(Get-CimInstance Win32_Process -Property ExecutablePath,ProcessId,ParentProcessId,WorkingSetSize,CreationDate)
  $included = @{}
  foreach ($p in $all) {
    if ($p.ExecutablePath -and $p.ExecutablePath.StartsWith(($appDir.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)) {
      $included[[int]$p.ProcessId] = $p
    }
  }
  do {
    $previous = $included.Count
    foreach ($p in $all) {
      $parent = $included[[int]$p.ParentProcessId]
      if ($parent -and $parent.CreationDate -le $p.CreationDate) { $included[[int]$p.ProcessId] = $p }
    }
  } while ($previous -ne $included.Count)
  return @($included.Values)
}
function Get-M6Count {
  $stats = Invoke-RestMethod -Uri "$($primaryIsp.control)/stats" -Headers $ispHeaders -TimeoutSec 5
  $record = $stats.destinations.PSObject.Properties[$m6Target]
  if ($null -eq $record) { return [long]0 }; return [long]$record.Value
}
function Measure-M6Product([string]$label,[string]$release,[string]$setup) {
  $out = Join-Path $diagDir "m6-$label"
  $null=New-Item -ItemType Directory -Path $out -Force
  $trace=Join-Path $tempRoot "$label.etl"
  $traffic=Join-Path $out 'traffic.json'
  $inputData=Join-Path $out 'input.json'
  $usage=Join-Path $out 'cpu.json'
  $memory=[Collections.Generic.List[object]]::new()
  # Give both installs the same 64-entry gateway history, then let Windows
  # retire this test target's rows naturally before starting either trace.
  $primeFile=Join-Path $out 'prime.json'
  $initialCount=Get-M6Count
  $prime=Start-M6Client prime $primeFile
  if (!$prime.Process.WaitForExit(120000)) {
    $prime.Process.Kill()
    $prime.Process.WaitForExit()
    throw 'Gateway priming client did not finish'
  }
  if ($prime.Process.ExitCode -ne 0) {throw $prime.Errors.Result}
  $primed=Get-Content -Raw -LiteralPath $primeFile | ConvertFrom-Json
  if ($primed.connections -ne 64 -or (Get-M6Count)-$initialCount -ne 64) {throw 'Gateway priming connection count differs'}
  & $m6Reader settle $m6Port $uplink.address (Join-Path $out 'initial-table.json')
  if ($LASTEXITCODE -ne 0) {throw 'Could not establish matched initial socket state'}
  $table=@(Get-Content -Raw -LiteralPath (Join-Path $out 'initial-table.json') | ConvertFrom-Json)
  if (!$table.Count -or $table[-1].TargetRows -ne 0) {throw 'Incomplete initial socket observation'}
  $before=Get-M6Count
  & wpr.exe -start "$m6Profile!NetSwitchCPU.Light" -filemode
  if ($LASTEXITCODE -ne 0) { throw "WPR start failed ($LASTEXITCODE)" }
  $finished=$false
  try {
    $rootsFrom=[DateTimeOffset]::UtcNow.ToString('o')
    $members=@(Get-M6ProductProcesses)
    $rootsAt=[DateTimeOffset]::UtcNow.ToString('o')
    $roots=@($members | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith(($appDir.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase) } |
      ForEach-Object { @{pid=[int]$_.ProcessId; image=$_.ExecutablePath; createdAt=$_.CreationDate.ToUniversalTime().ToString('o')} })
    $paths=@($members.ExecutablePath | Where-Object {$_} | Sort-Object -Unique)
    $images=@($paths | ForEach-Object { @{name=[IO.Path]::GetFileName($_);hash=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()} })
    if ($label -eq 'baseline') {
      $enginePid=[int](Get-Content -Raw -LiteralPath (Join-Path $machineData 'engine.pid'))
      if ('node.exe' -notin $images.name -or 'NetSwitchTray.exe' -notin $images.name -or $enginePid -notin $roots.pid) {
        throw 'Missing installed legacy Control, engine or desktop'
      }
      $installedEntry=Join-Path $env:ProgramFiles 'Net Switch\server.mjs'
      $images += @{name=[IO.Path]::GetFileName($installedEntry);hash=(Get-FileHash -LiteralPath $installedEntry).Hash.ToLowerInvariant()}
    } elseif ('netswitch.exe' -notin $images.name -or 'netswitch-engine.exe' -notin $images.name -or 'netswitch-desktop.exe' -notin $images.name) { throw 'Missing installed native process roots' }
    $client=Start-M6Client measure $traffic
    $worker=$client.Process
    $null=$worker.Handle
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while (!$worker.HasExited) {
      if ($timer.Elapsed.TotalMinutes -gt 8) { $worker.Kill(); throw 'Measurement did not finish in eight minutes' }
      $sample=@(Get-M6ProductProcesses)
      $memory.Add(@{utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');workingSetBytes=[long](($sample | Measure-Object WorkingSetSize -Sum).Sum)})
      $null=$worker.WaitForExit(300)
    }
    $worker.WaitForExit()
    if ($worker.ExitCode -ne 0) { throw "Measurement failed ($($worker.ExitCode)): $($client.Errors.Result)" }
    $finished=$true
  } finally {
    if ($finished) { & wpr.exe -stop $trace; if ($LASTEXITCODE -ne 0) { throw 'WPR stop failed' } }
    else { & wpr.exe -cancel }
  }
  $t=Get-Content -Raw -LiteralPath $traffic | ConvertFrom-Json
  $connections=(Get-M6Count)-$before
  if ($connections -ne $t.connections) { throw "TestISP saw $connections benchmark connections, expected $($t.connections)" }
  @{rootsFrom=$rootsFrom;rootsAt=$rootsAt;roots=$roots;installDirectory=$appDir;samples=$t.samples} | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8NoBOM $inputData
  & $m6Reader $trace $inputData $usage
  if ($LASTEXITCODE -ne 0) { throw 'CPU trace analysis failed' }
  $report=@{arch=$Arch;runner=$env:COMPUTERNAME;commit=$env:GITHUB_SHA;release=$release;installerHash=(Get-FileHash -LiteralPath $setup).Hash.ToLowerInvariant();images=$images;gatewayConnections=$connections;traffic=$t;memory=$memory.ToArray();accounting=(Get-Content -Raw $usage|ConvertFrom-Json)}
  $report.precondition=@{verifiedConnections=$primed.connections;before=$table[0];after=$table[-1]}
  $report | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8NoBOM (Join-Path $out 'report.json')
}
