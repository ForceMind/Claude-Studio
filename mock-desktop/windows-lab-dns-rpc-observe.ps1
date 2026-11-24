# Loaded into the temporary elevated observer with $directory and $prefix.
$ErrorActionPreference = 'Stop'
$traceFile = Join-Path $directory 'dns-rpc.etl'
$providersPath = Join-Path $directory 'providers.txt'
$summary = [ordered]@{}
try {
    $summary.dnscachePidBefore = Get-LabDnsServicePid
    if (!$summary.dnscachePidBefore) { throw 'DNS Client service is unavailable' }
    $listedFilters = @(& netsh.exe rpc filter show filter 2>&1)
    $summary.rpcFilterReadback = @{exitCode=$LASTEXITCODE; lines=$listedFilters.Count}
    if ($LASTEXITCODE -eq 0) {
        $summary.rpcFilterReadback.keys = @(
            [regex]::Matches(($listedFilters -join ' '), '[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}') |
                ForEach-Object Value | Sort-Object -Unique
        ).Count
    }
    # RPC level 4 excludes packet body events 10 and 11.
    [IO.File]::WriteAllLines($providersPath, [string[]]@(
        '{1c95126e-7eea-49a9-a3fe-a378b03ddb4d} 0xffffffffffffffff 5',
        '{6ad52b32-d609-4be9-ae07-ce8dae937e39} 0x4000000000000000 4'
    ))
    $msg = @(& logman.exe create trace $prefix -o $traceFile -pf $providersPath -max 32 -ets 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('Failed to start DNS/RPC ETW: ' + ($msg -join ' ')) }
    [IO.File]::WriteAllText((Join-Path $directory 'ready'), '1')
    if ($rpcFilterTest) {
        $summary.rule = [ordered]@{sublayer=$subKey; filterKey=$filterKey; session='dynamic'}
        Invoke-LabRpcRule $summary.rule $summary.dnscachePidBefore
    }
    $stop = Join-Path $directory 'stop'
    $deadline = [datetime]::UtcNow.AddSeconds(75)
    while (!(Test-Path -LiteralPath $stop)) {
        if ([datetime]::UtcNow -gt $deadline) { throw 'Observer timed out' }
        Start-Sleep -Milliseconds 100
    }
    $summary.loss = Get-LabDnsTraceLoss $prefix
    $null = & logman.exe stop $prefix -ets
    if ($LASTEXITCODE -ne 0) { throw 'Failed to stop DNS/RPC ETW' }
    $summary.dnscachePidAfter = Get-LabDnsServicePid
    $probes = Get-Content -LiteralPath (Join-Path $directory 'probes.json') -Raw | ConvertFrom-Json
    $pids = @($probes.pid)
    $testNames = @($probes | ForEach-Object { $_.name.TrimEnd('.') })
    $service = $summary.dnscachePidBefore
    $dns = [Collections.Generic.List[object]]::new()
    $rpc = [Collections.Generic.List[object]]::new()
    $filter = [Collections.Generic.List[object]]::new()
    foreach ($event in Get-WinEvent -Path $traceFile -Oldest) {
        try {
            $id = $event.Id
            $emitter = $event.ProcessId
            $properties = $event.Properties
            if (!$properties.Count) { continue }
            $value0 = [string]$properties[0].Value
            switch ($event.ProviderName) {
                'Microsoft-Windows-DNS-Client' {
                    if ($id -notin 3006,3008,3010,3011 -or $value0.TrimEnd('.') -notin $testNames) { continue }
                    $row = @{id=$id; pid=$emitter; name=$value0; utc=$event.TimeCreated.ToUniversalTime().ToString('o')}
                    if ($id -eq 3010 -and $properties.Count -gt 3) { $row.clientPid = [int]$properties[3].Value }
                    if ($id -eq 3011 -and $properties.Count -gt 4) { $row.clientPid = [int]$properties[4].Value }
                    $dns.Add($row)
                }
                'Microsoft-Windows-RPC' {
                    if ($emitter -notin $pids -and $emitter -ne $service) { continue }
                    if ($id -eq 2 -and $properties.Count -ge 3) {
                        $filter.Add(@{source='RPC'; id=$id; pid=$emitter; interface=[string]$properties[1].Value
                            filterKey=[string]$properties[2].Value; utc=$event.TimeCreated.ToUniversalTime().ToString('o')
                            tid=$event.ThreadId; activity=[string]$event.ActivityId; relatedActivity=[string]$event.RelatedActivityId
                            blockReported=$true})
                    } elseif ($id -in 5,6,7,8) {
                        $row = @{id=$id; pid=$emitter; tid=$event.ThreadId; utc=$event.TimeCreated.ToUniversalTime().ToString('o')
                            activity=[string]$event.ActivityId; relatedActivity=[string]$event.RelatedActivityId}
                        if ($id -in 5,6) {
                            $row.interface=$value0
                            $row.operation=[int]$properties[1].Value
                            $row.protocol=[int]$properties[2].Value
                            $row.endpoint=[string]$properties[4].Value
                            $description=$event.FormatDescription()
                            if ($description -match '\b(LRPC|ncalrpc)\b') { $row.protocolName=$Matches[1] }
                        } else { $row.status=[uint32]$properties[0].Value }
                        $rpc.Add($row)
                    }
                }
            }
        } finally { $event.Dispose() }
    }
    $summary.dns = $dns.ToArray()
    $summary.rpc = $rpc.ToArray()
    $summary.rpcFilterEvents = $filter.ToArray()
} catch {
    $summary.error = $_.Exception.Message
} finally {
    $null = & logman.exe query $prefix -ets 2>&1
    if ($LASTEXITCODE -eq 0) { $null = & logman.exe stop $prefix -ets 2>&1 }
    $null = & logman.exe query $prefix -ets 2>&1
    $summary.sessionGone = $LASTEXITCODE -ne 0
    if (Test-Path -LiteralPath $traceFile) { Remove-Item -LiteralPath $traceFile }
    $summary.rawTraceGone = !(Test-Path -LiteralPath $traceFile)
    [IO.File]::WriteAllText((Join-Path $directory 'result.json'), ($summary | ConvertTo-Json -Depth 9))
}
