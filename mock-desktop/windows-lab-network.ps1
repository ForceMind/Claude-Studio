param([Parameter(Mandatory)][string]$Workspace, [switch]$WithWindows, [switch]$WithDns)
Set-StrictMode -Version Latest
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $Workspace 'mock-desktop\windows-lab-local.ps1'))))
$root = Join-Path $Workspace ('.prototype\windows-lab\net-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$guard = Join-Path $root 'wfp.json'
$reportName = if ($WithDns) { 'windows-ipv6-dns.json' } elseif ($WithWindows) { 'windows-network-windows.json' } else { 'windows-network.json' }
$reportPath = Join-Path (Join-Path $Workspace '.prototype\mock-results') $reportName
$report = [ordered]@{passed=$false; rollback=$false; fixture=(Split-Path -Leaf $root); kind='loopback WFP account verification'}
$accounts = Get-LabAccounts
$children = @{}
$helper = $null
$fixture = $null
$hostOld = $null
$phase = Join-Path $root 'phase'
$dnsPrefix = if ($WithDns) { 'studio-' + [guid]::NewGuid().ToString('N').Substring(0,16) } else { $null }

$sockets = @'
function Open-Tcp([string]$Address, [int]$Port, [switch]$Mapped) {
    $ip = [Net.IPAddress]::Parse($Address)
    $tcp = [Net.Sockets.TcpClient]::new($ip.AddressFamily)
    try {
        if ($Mapped) { $tcp.Client.DualMode = $true }
        if (!$tcp.ConnectAsync($ip, $Port).Wait(2200)) { throw [TimeoutException]::new('TCP connect timed out') }
        $tcp.ReceiveTimeout = 1600
        $tcp.SendTimeout = 1600
        return $tcp
    } catch { $tcp.Close(); throw }
}
function Echo-Tcp($Tcp, [byte]$Value) {
    $s = $Tcp.GetStream()
    $s.WriteByte($Value)
    if ($s.ReadByte() -ne $Value) { throw [IO.IOException]::new('TCP echo was not received') }
}
function Test-Tcp([string]$Address, [int]$Port, [switch]$Mapped, [byte]$Value = 81) {
    $tcp = $null
    try { $tcp = Open-Tcp $Address $Port -Mapped:$Mapped; Echo-Tcp $tcp $Value; return $true }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [IO.IOException] -or $ex -is [TimeoutException] -or $ex -is [Net.Sockets.SocketException]) { return $false }
        throw
    } finally { if ($tcp) { $tcp.Close() } }
}
function Test-Udp([string]$Address, [int]$Port) {
    $ip = [Net.IPAddress]::Parse($Address)
    $udp = [Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try {
        $udp.Client.ReceiveTimeout = 700
        $udp.Connect($ip, $Port)
        [void]$udp.Send([byte[]]@(91), 1)
        $sender = [Net.IPEndPoint]::new($ip, 0)
        $bytes = $udp.Receive([ref]$sender)
        return $bytes.Length -eq 1 -and $bytes[0] -eq 91
    } catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [Net.Sockets.SocketException]) { return $false }
        throw
    } finally { $udp.Close() }
}
function Wait-Phase([int]$Wanted) {
    $until = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $until) {
        if ([int][IO.File]::ReadAllText($phase) -ge $Wanted) { return }
        Start-Sleep -Milliseconds 70
    }
    throw 'Timed out awaiting simulator phase'
}
'@
. ([scriptblock]::Create($sockets))

function Assert-Net($Value, [string]$Message) { if (!$Value) { throw $Message } }
function Wait-LabFile([string]$Path, [int]$Seconds) {
    $end = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $end) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
        if ($helper -and $helper.HasExited) { throw 'Elevated WFP helper stopped before test readiness' }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $(Split-Path -Leaf $Path)"
}
function Wait-WfpState([string]$Flag, [int]$Seconds) {
    Wait-LabFile $guard $Seconds
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try { $state = Get-Content -Raw -LiteralPath $guard | ConvertFrom-Json }
        catch [IO.IOException] { Start-Sleep -Milliseconds 100; continue }
        if ($state.PSObject.Properties['error']) { throw ("WFP helper failed: " + $state.error) }
        $found = $state.PSObject.Properties[$Flag]
        if ($found -and $found.Value) { return $state }
        if ($helper.HasExited) { throw "WFP helper exited before $Flag" }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for WFP status $Flag"
}

function Test-DefaultDns([string]$DnsPhase) {
    $probeBody = @'
$result = [ordered]@{clientPid=$PID}
try {
    $answer = @(Resolve-DnsName -Name $q -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    $result.result = if ($answer.Count) { 'answer' } else { 'empty' }
} catch {
    $result.result = $_.FullyQualifiedErrorId
}
[pscustomobject]$result | ConvertTo-Json -Compress
'@
    $results = [ordered]@{}
    $queries = @{}
    try {
        foreach ($id in 'A','B') {
            $name = $dnsPrefix + '-' + $id.ToLowerInvariant() + '-' + $DnsPhase + '.test.'
            $code = '$q = ' + (ConvertTo-LabLiteral $name) + [Environment]::NewLine + $probeBody
            $queries[$id] = Start-LabProbe $accounts[$id] $code
        }
        $q = $dnsPrefix + '-h-' + $DnsPhase + '.test.'
        $results.H = & ([scriptblock]::Create($probeBody)) | ConvertFrom-Json
        foreach ($id in 'A','B') {
            $probe = $queries[$id]
            $queries.Remove($id)
            $results[$id] = Read-LabProbe $probe 10000
        }
        return $results
    } finally { foreach ($probe in $queries.Values) { Stop-LabProbe $probe } }
}
function Launch-NetworkProbe([string]$Profile, [string]$Body) {
    $prefix = @(
        ('$phase = ' + (ConvertTo-LabLiteral $phase)),
        ('$root = ' + (ConvertTo-LabLiteral $root)),
        ('$profile = ' + (ConvertTo-LabLiteral $Profile)),
        ('$port4 = ' + [int]$fixture.Port4),
        ('$port6 = ' + [int]$fixture.Port6),
        ('$udp4 = ' + [int]$fixture.Udp4),
        ('$udp6 = ' + [int]$fixture.Udp6),
        ('$proxy = ' + [int]$fixture.ProxyPort),
        ('$simulator = ' + (ConvertTo-LabLiteral (Join-Path $Workspace 'mock-desktop\windows-lab-window.cjs')))
    ) -join [Environment]::NewLine
    Start-LabProbe $accounts[$Profile] ($prefix + [Environment]::NewLine + $sockets + [Environment]::NewLine + $Body)
}
function Wait-BothAccounts([string]$Stage, [int]$Seconds) {
    foreach ($id in 'A','B') { Wait-LabFile (Join-Path $root ($id + '-' + $Stage)) $Seconds }
    if ($WithWindows) {
        foreach ($id in 'A','B') { Wait-LabFile (Join-Path $root ($id + '-window-' + $Stage)) $Seconds }
    }
}
$direct = @'
function Check-Direct {
    [ordered]@{
        ipv4 = Test-Tcp '127.0.0.1' $port4 -Value 85
        ipv6 = Test-Tcp '::1' $port6 -Value 85
        mapped = Test-Tcp '::ffff:127.0.0.1' $port4 -Mapped -Value 85
        udp4 = Test-Udp '127.0.0.1' $udp4
        udp6 = Test-Udp '::1' $udp6
    }
}
'@
$client = @'
$result = [ordered]@{}
$old = Open-Tcp '127.0.0.1' $proxy
try {
    Echo-Tcp $old 43
    $result.oldViaProxyBefore = $true
    $result.mappedViaProxyBefore = Test-Tcp '::ffff:127.0.0.1' $proxy -Mapped
    $result.healthyDirect = Check-Direct
    [IO.File]::WriteAllText((Join-Path $root ($profile + '-ready')), 'ready')
    Wait-Phase 1
    try { Echo-Tcp $old 44; $result.oldClosedAfterFailure = $false }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -isnot [IO.IOException] -and $ex -isnot [Net.Sockets.SocketException]) { throw }
        $result.oldClosedAfterFailure = $true
    }
    $result.refusingProxy = Test-Tcp '127.0.0.1' $proxy
    $result.failureDirect = Check-Direct
    [IO.File]::WriteAllText((Join-Path $root ($profile + '-failed')), 'observed')
    Wait-Phase 2
    $result.stoppedProxy = Test-Tcp '127.0.0.1' $proxy
    [IO.File]::WriteAllText((Join-Path $root ($profile + '-stopped')), 'observed')
    Wait-Phase 3
    $result.recoveredViaProxy = Test-Tcp '127.0.0.1' $proxy
    $result.recoveryDirect = Check-Direct
} finally { $old.Close() }
$result | ConvertTo-Json -Depth 4 -Compress
'@
try {
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Workspace 'mock-desktop\windows-lab-transport.cs')))
    $fixture = [StudioLabTransport]::new()
    [IO.File]::WriteAllText($phase, '0')
    $hostOld = Open-Tcp '127.0.0.1' $fixture.Port4
    Echo-Tcp $hostOld 31
    $report.hostOldBeforeRules = $true
    $report.hostNativeIpv6Baseline = Test-Tcp '::1' $fixture.Port6
    $report.hostNativeUdp6Baseline = Test-Udp '::1' $fixture.Udp6
    $report.baseline = [ordered]@{}
    foreach ($id in 'A','B') {
        $baseline = Read-LabProbe (Launch-NetworkProbe $id ($direct + [Environment]::NewLine + 'Check-Direct | ConvertTo-Json -Compress'))
        $report.baseline[$id] = $baseline
    }
    foreach ($id in 'A','B') {
        $failed = @($report.baseline[$id].PSObject.Properties | Where-Object { $_.Name -in 'ipv4','mapped','udp4' -and !$_.Value } | ForEach-Object Name)
        Assert-Net (!$failed.Count) ("Baseline target unreachable for $id : " + ($failed -join ', '))
    }
    $report.nativeIpv6BaselineReachable = $report.baseline.A.ipv6 -and $report.baseline.B.ipv6 -and
        $report.baseline.A.udp6 -and $report.baseline.B.udp6
    $baseDirect = $fixture.DirectSignals
    $baseUdp = $fixture.UdpSignals
    $manifest = [ordered]@{ sidA=$accounts.A.Sid; sidB=$accounts.B.Sid; port=$fixture.ProxyPort; dnsPrefix=$dnsPrefix;
        sublayer=[guid]::NewGuid(); filters=@(1..20 | ForEach-Object { [guid]::NewGuid() }) }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Encoding UTF8
    $elevatedScript = Join-Path $Workspace 'mock-desktop\windows-lab-wfp-run.ps1'
    $command = '& ([scriptblock]::Create([IO.File]::ReadAllText(' + (ConvertTo-LabLiteral $elevatedScript) +
        '))) -RunDirectory ' + (ConvertTo-LabLiteral $root)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    'Waiting for Windows UAC approval for the scoped WFP helper.'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $helper = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -Verb RunAs -WindowStyle Hidden -PassThru
    if ($WithDns) {
        [void](Wait-WfpState 'dnsTraceReady' 20)
        $report.dnsClients = [ordered]@{baseline=(Test-DefaultDns 'baseline')}
        [IO.File]::WriteAllText((Join-Path $root 'install-wfp'), '')
    }
    $state = Wait-WfpState 'installed' 20
    $report.filtersReadBack = $state.filtersReadBack
    Echo-Tcp $hostOld 32
    foreach ($id in 'A','B') { $children[$id] = Launch-NetworkProbe $id ($direct + [Environment]::NewLine + $client) }
    if ($WithWindows) {
        $windowScript = @'
$env:STUDIO_LAB_ROOT = $root
$env:STUDIO_LAB_ACCOUNT = $profile
$env:STUDIO_LAB_PROXY = [string]$proxy
$env:STUDIO_LAB_TARGET = [string]$port4
& (Join-Path $env:ProgramFiles 'nodejs\node.exe') $simulator
if ($LASTEXITCODE -ne 0) { throw 'Simulated window test failed' }
'@
        foreach ($id in 'A','B') { $children[$id + '-window'] = Launch-NetworkProbe $id $windowScript }
    }
    Wait-BothAccounts 'ready' 20
    $fixture.FailProxy()
    [IO.File]::WriteAllText($phase, '1')
    Echo-Tcp $hostOld 33
    $report.hostOldDuringFailure = $true
    $report.hostNewDuringFailure = Test-Tcp '127.0.0.1' $fixture.Port4
    Assert-Net $report.hostNewDuringFailure 'Host new connection failed during proxy failure'
    if ($WithDns) {
        $report.dnsClients.outage = Test-DefaultDns 'outage'
        Echo-Tcp $hostOld 36
    }
    Wait-BothAccounts 'failed' 15
    $fixture.StopProxy()
    [IO.File]::WriteAllText($phase, '2')
    Echo-Tcp $hostOld 34
    $report.hostOldDuringShutdown = $true
    $report.hostNewDuringShutdown = Test-Tcp '127.0.0.1' $fixture.Port4
    Assert-Net $report.hostNewDuringShutdown 'Host new connection failed during proxy shutdown'
    if ($WithDns) { $report.dnsClients.stopped = Test-DefaultDns 'stopped' }
    Wait-BothAccounts 'stopped' 10
    $fixture.ResumeProxy()
    Assert-Net (Test-Tcp '127.0.0.1' $fixture.ProxyPort) 'Recovered proxy failed to reach target'
    [IO.File]::WriteAllText($phase, '3')
    $report.accounts = [ordered]@{}
    foreach ($id in 'A','B') {
        $probe = $children[$id]
        $children.Remove($id)
        $outcome = Read-LabProbe $probe
        $report.accounts[$id] = $outcome
        foreach ($case in 'healthyDirect','failureDirect','recoveryDirect') {
            Assert-Net (@($outcome.$case.PSObject.Properties.Value) -notcontains $true) "$id unexpectedly reached a direct target: $case"
        }
        Assert-Net ($outcome.oldViaProxyBefore -and $outcome.mappedViaProxyBefore -and
            $outcome.oldClosedAfterFailure -and !$outcome.refusingProxy -and !$outcome.stoppedProxy -and
            $outcome.recoveredViaProxy) "Proxy/failure behavior mismatch for $id"
    }
    $report.directTcpTargetHits = $fixture.DirectSignals - $baseDirect
    $report.directUdpTargetHits = $fixture.UdpSignals - $baseUdp
    Assert-Net ($report.directTcpTargetHits -eq 0 -and $report.directUdpTargetHits -eq 0) 'Target received direct lab traffic'
    if ($WithWindows) {
        $report.windows = [ordered]@{}
        foreach ($id in 'A','B') {
            $name = $id + '-window'
            $probe = $children[$name]
            $children.Remove($name)
            $window = Read-LabProbe $probe
            $report.windows[$id] = $window
            Assert-Net ($window.profile -eq $id -and $window.visible -and $window.healthy -and
                !$window.refusing -and !$window.stopped -and $window.recovered -and
                $window.exit.code -eq 0) ("Simulated window results mismatch for $id : " + ($window | ConvertTo-Json -Compress))
        }
    }
    $report.passed = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($children.Count -and !$report.passed) {
        [IO.File]::WriteAllText($phase, '3')
        foreach ($name in @($children.Keys | Where-Object { $_ -like '*-window' })) {
            $probe = $children[$name]
            $children.Remove($name)
            try { [void](Read-LabProbe $probe 18000) } catch {}
        }
    }
    foreach ($probe in $children.Values) { Stop-LabProbe $probe }
    if ($hostOld) { $hostOld.Close() }
    if ($fixture) { $fixture.Dispose() }
    if ($helper) {
        try {
            [IO.File]::WriteAllText((Join-Path $root 'remove-wfp'), '')
            Assert-Net ($helper.WaitForExit(15000)) 'Elevated WFP rollback did not finish in the expected time'
            $report.wfp = Get-Content -Raw -LiteralPath $guard | ConvertFrom-Json
            $report.rollback = $report.wfp.rollback
            if ($WithDns -and $report.Contains('dnsClients') -and $report.wfp.PSObject.Properties['dns']) {
                $dns = $report.wfp.PSObject.Properties['dns']
                $events = @($dns.Value.events)
                $report.dnsEvidence = [ordered]@{}
                foreach ($id in 'A','B','H') {
                    $report.dnsEvidence[$id] = [ordered]@{}
                    foreach ($dnsCase in 'baseline','outage','stopped') {
                        if (!$report.dnsClients.Contains($dnsCase)) { continue }
                        $clientPid = $report.dnsClients[$dnsCase][$id].clientPid
                        $service = @($events | Where-Object {
                            $_.profile -eq $id -and $_.phase -eq $dnsCase -and $_.event -in 3010,3011 -and
                            $_.emitterPid -eq $dns.Value.servicePid -and $_.clientPid -eq $clientPid
                        })
                        $report.dnsEvidence[$id][$dnsCase] = @{
                            sent=@($service | Where-Object event -eq 3010).Count
                            replies=@($service | Where-Object event -eq 3011).Count
                        }
                    }
                }
            }
        } catch { $report.rollbackError = $_.Exception.Message }
        finally { $helper.Dispose() }
    }
    foreach ($account in $accounts.Values) { $account.Credential.Password.Dispose() }
    $report.finished = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
}
$report | ConvertTo-Json -Depth 8
if (!$report.passed -or !$report.rollback) { exit 1 }
