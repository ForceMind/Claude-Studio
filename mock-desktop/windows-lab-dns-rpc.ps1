param(
    [Parameter(ParameterSetName='FilterBaseline')][switch]$FilterBaseline,
    [Parameter(ParameterSetName='FilterTest')][switch]$FilterTest
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
$accountA = (Get-LabAccounts).A
$prefix = 'studio-' + [guid]::NewGuid().ToString('N').Substring(0,16)
$lab = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
$scratch = (New-Item -ItemType Directory -Path (Join-Path $lab ('dns-rpc-' + $prefix))).FullName
$directory = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioDnsRpc-' + $prefix)
$exe = Join-Path $scratch 'StudioProbe.exe'
$results = Join-Path (Split-Path -Parent $lab) 'mock-results'
$reportName = if ($FilterBaseline) { 'windows-dns-rpc-filter-baseline.json' }
    elseif ($FilterTest) { 'windows-dns-rpc-filter-test.json' }
    else { 'windows-dns-rpc-observation.json' }
$output = Join-Path $results $reportName
$probes = [Collections.Generic.List[object]]::new()
$observer = $null
$report = [ordered]@{run=$prefix}
$interface = '45776b01-5956-4485-9f80-f428f7d60129'

function Get-ResolverEvidence($Trace, $Probe) {
    $dns = @($Trace.dns | Where-Object { $_.name.TrimEnd('.') -ieq $Probe.name.TrimEnd('.') })
    $serviceDns = @($dns | Where-Object { $_.pid -eq $Trace.dnscachePidBefore -and $_.clientPid -eq $Probe.pid })
    $client = @($Trace.rpc | Where-Object { $_.id -eq 5 -and $_.pid -eq $Probe.pid -and $_.tid -eq $Probe.tid -and
        ([string]$_.interface).Trim('{}') -eq $interface -and $_.endpoint -eq 'DNSResolver' -and $_.protocol -eq 3 -and
        $_.operation -eq 4 -and $_.utc -ge $Probe.startedUtc -and $_.utc -le $Probe.finishedUtc })
    $sends = @($serviceDns | Where-Object id -eq 3010)
    $server = @()
    if ($client.Count -eq 1 -and $sends.Count) {
        $server = @($Trace.rpc | Where-Object { $_.id -eq 6 -and $_.pid -eq $Trace.dnscachePidBefore -and
            ([string]$_.interface).Trim('{}') -eq $interface -and $_.endpoint -eq 'DNSResolver' -and $_.protocol -eq 3 -and
            $_.operation -eq 4 -and $_.utc -ge $client[0].utc -and $_.utc -le $sends[0].utc })
    }
    return [pscustomobject]@{
        role=$Probe.role; api=$Probe.api; phase=$Probe.phase; status=$Probe.status; pid=$Probe.pid
        serviceSends=$sends.Count; serviceReplies=@($serviceDns | Where-Object id -eq 3011).Count
        sendsAtAnyEmitter=@($dns | Where-Object id -eq 3010).Count
        resolverPair=($client.Count -eq 1 -and $server.Count -eq 1)
    }
}

function Test-LosslessTrace($Trace) {
    return [bool]($Trace -and !$Trace.error -and $Trace.sessionGone -and $Trace.rawTraceGone -and
        $Trace.dnscachePidBefore -gt 0 -and $Trace.dnscachePidBefore -eq $Trace.dnscachePidAfter -and
        $null -ne $Trace.loss -and $Trace.loss.eventsLost -eq 0 -and $Trace.loss.logBuffersLost -eq 0 -and $Trace.loss.realtimeBuffersLost -eq 0)
}

function Get-PositiveBaseline([string]$Build) {
    $basePath = Join-Path $results 'windows-dns-rpc-filter-baseline.json'
    $base = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($base.windowsBuild -ne $Build -or $base.probes.Count -ne 4 -or $base.error -or !(Test-LosslessTrace $base.trace)) {
        throw 'DNS/RPC baseline is missing or incomplete'
    }
    $keys = @($base.probes | ForEach-Object { $_.role + '-' + $_.api } | Sort-Object -Unique)
    if (($keys -join ',') -ne 'a-addr,a-dns,h-addr,h-dns') { throw 'Unexpected DNS/RPC baseline cases' }
    foreach ($probe in $base.probes) {
        $evidence = Get-ResolverEvidence $base.trace $probe
        if ($evidence.status -ne 0 -or !$evidence.resolverPair -or !$evidence.serviceSends -or !$evidence.serviceReplies) {
            throw 'A or host baseline lacks a correlated successful RPC and DNS query'
        }
    }
    return $base
}

function Wait-LabMarker([string]$Name, [int]$Seconds, [string]$StopMarker) {
    $target = Join-Path $directory $Name
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    while (!(Test-Path -LiteralPath $target)) {
        if ($observer.HasExited -or [datetime]::UtcNow -gt $deadline -or
            ($StopMarker -and (Test-Path -LiteralPath (Join-Path $directory $StopMarker)))) {
            throw ('Observer did not reach ' + $Name)
        }
        Start-Sleep -Milliseconds 50
    }
}

function Invoke-ResolverProbe([string]$Role, [string]$Api, [string]$Phase) {
    if ($Phase -in 'healthy','outage' -and (Test-Path -LiteralPath (Join-Path $directory 'rule-gone'))) {
        throw 'Rule window ended before the probe'
    }
    if ($Role -eq 'a') {
        $body = '& ' + (ConvertTo-LabLiteral $exe) + " resolver $prefix $Role $Api $Phase"
        $probe = Read-LabProbe (Start-LabProbe $accountA $body) 10000
        if ($probe.userSid -ne $accountA.Sid -or $probe.container) { throw 'Unexpected A probe token' }
    } else {
        $probe = (& $exe resolver $prefix $Role $Api $Phase) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $probe.userSid -ne $hostSid) { throw 'Host control did not complete' }
    }
    if (!$probe.pid -or !$probe.tid -or $probe.name -cne "$prefix-$Role-$Api-$Phase.test.") { throw 'Unexpected probe identity' }
    $probe.PSObject.Properties.Remove('userSid')
    $probes.Add($probe)
    if ($Role -eq 'h' -and $probe.status -ne 0) { throw ('Host DNS control failed, status ' + $probe.status) }
}

try {
    $build = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($build.CurrentBuildNumber).$($build.UBR)"
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /target:exe /platform:x64 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$exe" (Join-Path $PSScriptRoot 'windows-lab-psec-probe.cs') (Join-Path $PSScriptRoot 'windows-lab-portguard-flow.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Simulator compilation failed' }
    if (Test-Path -LiteralPath $directory) { throw 'Temporary observer path collision' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $hostSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($sid in $hostSid,'S-1-5-18','S-1-5-32-544') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    [void][IO.Directory]::CreateDirectory($directory, $acl)
    $nl = [Environment]::NewLine
    $code = '$directory=' + (ConvertTo-LabLiteral $directory) + $nl + '$prefix=' + (ConvertTo-LabLiteral $prefix) + $nl +
        [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-dns-trace.ps1')) + $nl
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($FilterTest) {
        $base = Get-PositiveBaseline $report.windowsBuild
        $report.baselineRun = $base.run
        $subKey = [guid]::NewGuid().ToString()
        $filterKey = [guid]::NewGuid().ToString()
        $ruleExe = Join-Path $directory 'StudioRpcRule.exe'
        & $csc /nologo /target:exe /platform:x64 "/out:$ruleExe" (Join-Path $PSScriptRoot 'windows-lab-wfp.cs') (Join-Path $PSScriptRoot 'windows-lab-wfp-rpc.cs')
        if ($LASTEXITCODE -ne 0) { throw 'Dynamic rule helper failed to compile' }
        $code += '$rpcFilterTest=$true' + $nl + '$baselineServicePid=' + [int]$base.trace.dnscachePidBefore + $nl +
            '$accountSid=' + (ConvertTo-LabLiteral $accountA.Sid) + $nl + '$subKey=' + (ConvertTo-LabLiteral $subKey) + $nl +
            '$filterKey=' + (ConvertTo-LabLiteral $filterKey) + $nl +
            [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-dns-rpc-filter-control.ps1')) + $nl
    }
    $scriptPath = Join-Path $directory 'observe.ps1'
    $code += [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-dns-rpc-observe.ps1'))
    [IO.File]::WriteAllText($scriptPath, $code, [Text.UTF8Encoding]::new($true))
    $observer = Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',('"' + $scriptPath + '"')) -PassThru
    Wait-LabMarker 'ready' 15
    if ($FilterTest) {
        [IO.File]::WriteAllText((Join-Path $directory 'apply'), '1')
        Wait-LabMarker 'rule-live' 16 'rule-gone'
        foreach ($api in 'dns','addr') { Invoke-ResolverProbe 'h' $api 'healthy' }
        foreach ($role in 'a','h') {
            foreach ($api in 'dns','addr') { Invoke-ResolverProbe $role $api 'outage' }
        }
    } else {
        foreach ($role in 'a','h') {
            foreach ($api in 'dns','addr') { Invoke-ResolverProbe $role $api 'baseline' }
        }
    }
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($FilterTest -and $observer -and (Test-Path -LiteralPath (Join-Path $directory 'apply'))) {
        [IO.File]::WriteAllText((Join-Path $directory 'release'), '1')
        try {
            Wait-LabMarker 'rule-gone' 20
            foreach ($role in 'a','h') {
                foreach ($api in 'dns','addr') { Invoke-ResolverProbe $role $api 'recovered' }
            }
            Start-Sleep -Seconds 2
        } catch { $report.rollbackProbeError = $_.Exception.Message }
    }
    $report.probes = $probes.ToArray()
    if ($observer) {
        [IO.File]::WriteAllText((Join-Path $directory 'probes.json'), (ConvertTo-Json -InputObject $report.probes -Depth 7))
        [IO.File]::WriteAllText((Join-Path $directory 'stop'), '1')
        $resultPath = Join-Path $directory 'result.json'
        if ($observer.WaitForExit(52000) -and (Test-Path -LiteralPath $resultPath)) {
            try { $report.trace = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json }
            catch { $report.observerError = 'Invalid observer result: ' + $_.Exception.Message }
        } else { $report.observerError = 'Observer produced no result' }
        $observer.Dispose()
    }
    if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe }
    [IO.Directory]::Delete($scratch)
    $report.scratchGone = !(Test-Path -LiteralPath $scratch)
    if (Test-Path -LiteralPath $directory) {
        foreach ($name in 'providers.txt','ready','stop','probes.json','result.json','observe.ps1','StudioRpcRule.exe','apply','rule-live','release','rule-gone') {
            $owned = Join-Path $directory $name
            if (Test-Path -LiteralPath $owned) { Remove-Item -LiteralPath $owned }
        }
        if (!@(Get-ChildItem -LiteralPath $directory -Force).Count) { [IO.Directory]::Delete($directory) }
    }
    $report.privateDirectoryGone = !(Test-Path -LiteralPath $directory)
    [IO.File]::WriteAllText($output, ($report | ConvertTo-Json -Depth 11))
    [pscustomobject]@{
        file=$output; run=$prefix; error=$report.error; observerError=$report.observerError; traceError=$report.trace.error
        probes=$probes.Count; rpcRecords=@($report.trace.rpc).Count; filterRecords=@($report.trace.rpcFilterEvents).Count
        dnsRecords=@($report.trace.dns).Count; loss=$report.trace.loss
        sessionGone=$report.trace.sessionGone; rawTraceGone=$report.trace.rawTraceGone
    } | ConvertTo-Json -Depth 5
}
if ($report.error -or $report.observerError -or $report.trace.error) { exit 1 }
