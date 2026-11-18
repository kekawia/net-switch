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
  $all = @(Get-CimInstance Win32_Process -Property Name,ExecutablePath,ProcessId,ParentProcessId,WorkingSetSize,CreationDate)
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
function Add-M6Inventory($receipts,$known,$members,[string]$from,[string]$at) {
  $changed=$false
  foreach ($member in $members) {
    $key=[string]$member.ProcessId+'|'+$member.CreationDate.ToFileTimeUtc()
    if (!$known.ContainsKey($key)) { $known[$key]=$true; $changed=$true }
  }
  if (!$changed) {return}
  $rows=@($members|ForEach-Object {
    $image=if ($_.ExecutablePath) { $_.ExecutablePath } else { $_.Name }
    @{pid=[int]$_.ProcessId;parentPid=[int]$_.ParentProcessId;image=$image;createdAt=$_.CreationDate.ToUniversalTime().ToString('o')}
  })
  $receipts.Add(@{from=$from;at=$at;processes=$rows})
}
function Get-M6MemoryObservation($members) {
  $at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $rows=@($members | ForEach-Object {
    @{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;name=$_.Name;created=$_.CreationDate.ToUniversalTime().ToString('o');workingSet=[long]$_.WorkingSetSize}
  })
  return @{utc=$at;workingSetBytes=[long](($members|Measure-Object WorkingSetSize -Sum).Sum);processes=$rows}
}
function Save-M6PrivateObservation([string]$file) {
  $members=@(Get-M6ProductProcesses)
  $result=Get-M6MemoryObservation $members
  try {
    $perf=@{}
    foreach ($row in @(Get-CimInstance Win32_PerfRawData_PerfProc_Process -Property IDProcess,WorkingSetPrivate,WorkingSet,PrivateBytes -ErrorAction Stop)) {
      $perf[[int]$row.IDProcess]=$row
    }
    foreach ($member in $result.processes) {
      $counter=$perf[$member.pid]
      if ($null -ne $counter) {
        $member.privateWorkingSet=[long]$counter.WorkingSetPrivate
        $member.counterWorkingSet=[long]$counter.WorkingSet
        $member.privateCommitted=[long]$counter.PrivateBytes
      }
    }
  } catch { $result.counterError=$_.Exception.Message }
  $result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $file
}
function Measure-M6Product([string]$label,[string]$release,[string]$setup) {
  $out = Join-Path $diagDir "m6-$label"
  $null=New-Item -ItemType Directory -Path $out -Force
  $trace=Join-Path $tempRoot "$label.etl"
  $traffic=Join-Path $out 'traffic.json'
  $inputData=Join-Path $out 'input.json'
  $usage=Join-Path $out 'cpu.json'
  $memory=[Collections.Generic.List[object]]::new()
  $inventories=[Collections.Generic.List[object]]::new()
  $known=@{}
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
  Save-M6PrivateObservation (Join-Path $out 'settled-memory.json')
  $before=Get-M6Count
  & wpr.exe -start "$m6Profile!NetSwitchCPU.Light" -filemode
  if ($LASTEXITCODE -ne 0) { throw "WPR start failed ($LASTEXITCODE)" }
  $finished=$false
  try {
    $rootsFrom=[DateTimeOffset]::UtcNow.ToString('o')
    $members=@(Get-M6ProductProcesses)
    $rootsAt=[DateTimeOffset]::UtcNow.ToString('o')
    Add-M6Inventory $inventories $known $members $rootsFrom $rootsAt
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
      $sampleFrom=[DateTimeOffset]::UtcNow.ToString('o')
      $sample=@(Get-M6ProductProcesses)
      Add-M6Inventory $inventories $known $sample $sampleFrom ([DateTimeOffset]::UtcNow.ToString('o'))
      $memory.Add((Get-M6MemoryObservation $sample))
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
  Save-M6PrivateObservation (Join-Path $out 'post-traffic-memory.json')
  $connections=(Get-M6Count)-$before
  if ($connections -ne $t.connections) { throw "TestISP saw $connections benchmark connections, expected $($t.connections)" }
  @{rootsFrom=$rootsFrom;rootsAt=$rootsAt;roots=$roots;inventories=$inventories.ToArray();installDirectory=$appDir;samples=$t.samples} | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8NoBOM $inputData
  & $m6Reader $trace $inputData $usage
  if ($LASTEXITCODE -ne 0) {
    $memory.ToArray() | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'memory-before-accounting-failure.json')
    throw 'CPU trace analysis failed'
  }
  $report=@{arch=$Arch;runner=$env:COMPUTERNAME;commit=$env:GITHUB_SHA;release=$release;installerHash=(Get-FileHash -LiteralPath $setup).Hash.ToLowerInvariant();images=$images;gatewayConnections=$connections;traffic=$t;memory=$memory.ToArray();accounting=(Get-Content -Raw $usage|ConvertFrom-Json)}
  $report.precondition=@{verifiedConnections=$primed.connections;before=$table[0];after=$table[-1]}
  $report.gatewayHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $ispExe).Hash.ToLowerInvariant()
  $gateway=(Invoke-RestMethod -Uri "$($primaryIsp.control)/stats" -Headers $ispHeaders -TimeoutSec 5).benchmarkOutput
  if (!$gateway -or $gateway.writes -lt 1 -or $gateway.failures -ne 0) {throw 'TestISP packet publication evidence incomplete'}
  $report.gatewayOutput=$gateway
  $report | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8NoBOM (Join-Path $out 'report.json')
}
