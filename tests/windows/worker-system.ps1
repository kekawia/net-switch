param([Parameter(Mandatory)][string]$ProbeDirectory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows only' }
$worker = (Resolve-Path (Join-Path $ProbeDirectory 'worker.test.exe')).Path.Replace("'", "''")
$platform = (Resolve-Path (Join-Path $ProbeDirectory 'platform.test.exe')).Path.Replace("'", "''")
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$nonce = [Guid]::NewGuid().ToString('N')
$taskName = "NetSwitch-Worker-Proof-$nonce"
# A scheduled SYSTEM process has no inherited console. Relay its test output
# directly to the runner in memory, rather than relying on PsExec console I/O.
$command = @"
`$ErrorActionPreference='Stop'
`$PSNativeCommandUseErrorActionPreference=`$false
`$env:GITHUB_ACTIONS='true'
`$env:RUNNER_ENVIRONMENT='github-hosted'
`$env:NETSWITCH_EXPECT_SYSTEM='1'
`$client=[Net.Sockets.TcpClient]::new('127.0.0.1',$port)
`$writer=[IO.StreamWriter]::new(`$client.GetStream())
`$writer.AutoFlush=`$true
`$writer.WriteLine('$nonce')
try {
  & '$worker' '-test.v' '-test.timeout=3m' '-test.run=^(TestWorkerDLLCompatibility|TestReadWorkerCannotWriteControlHKLMOrTCP|TestWorkerRestrictingSIDs|TestWorkerNetworkFenceMutation|TestWorkerFenceRecovery)$' 2>&1 | ForEach-Object { `$writer.WriteLine(`$_.ToString()) }
  `$workerResult=`$LASTEXITCODE
  & '$platform' '-test.v' '-test.timeout=6m' '-test.run=^(TestWorkerNativeReads|TestWorkerNetworkOperations)$' 2>&1 | ForEach-Object { `$writer.WriteLine(`$_.ToString()) }
  `$result=0
  if (`$workerResult -ne 0 -or `$LASTEXITCODE -ne 0) { `$result=1 }
  `$writer.WriteLine("SYSTEM_RESULT=`$result")
} catch {
  `$writer.WriteLine(`$_.ToString())
  `$writer.WriteLine('SYSTEM_RESULT=1')
} finally {
  `$writer.Dispose()
  `$client.Dispose()
}
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action = New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$client = $null
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $pending = $listener.AcceptTcpClientAsync()
    if (-not $pending.Wait(60000)) { throw 'SYSTEM task did not connect to its output relay' }
    $client = $pending.Result
    $reader = [IO.StreamReader]::new($client.GetStream())
    $deadline = [DateTime]::UtcNow.AddMinutes(9)
    $proof = [Collections.Generic.List[string]]::new()
    $authenticated = $false
    while ($true) {
        $read = $reader.ReadLineAsync()
        $remaining = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0 -or -not $read.Wait($remaining)) { throw 'SYSTEM proof exceeded its test deadline' }
        $line = $read.Result
        if ($null -eq $line) { break }
        if (-not $authenticated) {
            if ($line -ne $nonce) { throw 'Unexpected SYSTEM relay peer' }
            $authenticated = $true
            continue
        }
        Write-Output $line
        $proof.Add($line)
    }
    if (-not $proof.Contains('SYSTEM_RESULT=0')) { throw 'SYSTEM proof failed or did not finish' }
    foreach ($test in @('TestWorkerDLLCompatibility','TestReadWorkerCannotWriteControlHKLMOrTCP','TestWorkerRestrictingSIDs','TestWorkerNetworkFenceMutation','TestWorkerNativeReads','TestWorkerNetworkOperations','TestWorkerFenceRecovery')) {
        if (-not ($proof -match ('^--- PASS: ' + [regex]::Escape($test) + ' '))) { throw "Missing SYSTEM PASS: $test" }
    }
} finally {
    if ($null -ne $client) { $client.Dispose() }
    $listener.Stop()
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}
