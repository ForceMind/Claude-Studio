[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$RunId,
    [string]$ReportPath,
    [string]$SummaryPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    throw 'Run in x64 Windows PowerShell 5.1'
}

function Get-ErrDetail($Record) {
    $ex = $Record.Exception
    while ($ex.InnerException -and $ex -isnot [ComponentModel.Win32Exception]) { $ex = $ex.InnerException }
    return [ordered]@{
        message = $ex.Message
        type = $ex.GetType().FullName
        nativeError = if ($ex -is [ComponentModel.Win32Exception]) { $ex.NativeErrorCode } else { $null }
        line = $Record.InvocationInfo.ScriptLineNumber
    }
}

function New-PrivateAcl([string]$HostSid) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($HostSid, 'S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    return $acl
}

function New-RandomStrongPassword {
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $raw = 'Aa1!' + ([Convert]::ToBase64String($bytes))
    $sec = New-Object Security.SecureString
    foreach ($ch in $raw.ToCharArray()) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()
    return $sec
}

function Get-DistinctHighPorts([int]$Count) {
    $listeners = @(); $ports = @()
    try {
        for ($attempt = 0; $attempt -lt 20 -and $ports.Count -lt $Count; $attempt++) {
            $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $l.ExclusiveAddressUse = $true
            $l.Start()
            $p = [uint16]$l.LocalEndpoint.Port
            if ($p -ge 49152 -and $p -ne 10810 -and ($ports -notcontains $p)) { $listeners += $l; $ports += $p }
            else { $l.Stop() }
        }
        if ($ports.Count -ne $Count) { throw "Could not allocate $Count distinct high ports" }
        return $ports
    } finally { foreach ($l in $listeners) { try { $l.Stop() } catch { } } }
}

function Test-GrantedAll($Target) {
    $core = @($Target.processRights) + @($Target.threadRights)
    $term = @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' -or $_.right -ceq 'PROCESS_QUERY_LIMITED_INFORMATION' }) +
            @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })
    return @($Target.processRights).Count -eq 9 -and @($Target.threadRights).Count -eq 5 -and
        @($core + $term | Where-Object { !$_.granted -or $_.error -ne 0 }).Count -eq 0
}

function Get-Violations($Target, [string]$Perspective) {
    $out = @(); $all = @()
    foreach ($r in @($Target.processRights)) { $all += [pscustomobject]@{ part = 'process'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.threadRights)) { $all += [pscustomobject]@{ part = 'thread'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' })) { $all += [pscustomobject]@{ part = 'processExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })) { $all += [pscustomobject]@{ part = 'threadExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($e in $all) { if ($e.granted -or $e.error -ne 5) { $out += [ordered]@{ perspective = $Perspective; role = $Target.role; part = $e.part; right = $e.right; granted = $e.granted; error = $e.error } } }
    return $out
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    if (!(Test-Path -LiteralPath $reportDir)) { throw "Expected report directory: $reportDir" }
    $ReportPath = Join-Path $reportDir ('windows-ab-phase4-protocol-audit-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioABPhase4-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $outerTimer = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $outerTimer.ElapsedMilliseconds -lt 240000) { Start-Sleep -Milliseconds 100 }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if ($proc.HasExited -and $proc.ExitCode -ne 0 -and !(Test-Path -LiteralPath $SummaryPath)) { throw ('Elevated runner exited with code ' + $proc.ExitCode) }
    }
    if (!(Test-Path -LiteralPath $SummaryPath)) { throw 'Missing summary receipt from elevated runner' }
    $summaryText = Get-Content -LiteralPath $SummaryPath -Raw -Encoding UTF8
    Remove-Item -LiteralPath $SummaryPath -Force
    Write-Output $summaryText
    return
}

if (!$isAdmin) { throw 'Elevated mode requires Administrator token' }
if ($RunId -cnotmatch '^[a-f0-9]{16}$') { throw 'Invalid RunId' }

$fixtureDir = $PSScriptRoot
$mockDesktopDir = Split-Path (Split-Path $fixtureDir -Parent) -Parent
. (Join-Path $mockDesktopDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDesktopDir 'windows-lab-bind-gate.ps1') -FunctionsOnly
. (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeStudioABPhase4-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$buildDir = Join-Path $base 'build'
$n3Dir = Join-Path $base 'n3'
$harnessDll = Join-Path $base 'StudioPhase4Harness.dll'
$ownerExe = Join-Path $base 'StudioPhase4ProxyOwner.exe'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId
    prefix = $prefix
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase4-protocol-audit'
    nativeIPv6 = 'readback only (deferred by user boundary)'
    ipv4Inbound = 'readback only'
    realExternalBrowserAndMsix = 'deferred to Phase 6'
    hostSid = $hostSid
    wfpStaticWrites = 0
    sources = [ordered]@{}
    positiveControl = [ordered]@{}
    spaces = [ordered]@{ A = [ordered]@{}; B = [ordered]@{} }
    auditMatrix = [ordered]@{}
    checks = [ordered]@{}
    hostHealth = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$dirCreated = $false; $assemblyLoaded = $false
$dnsTrace = $null; $sentinels = $null; $extraSentinels = $null
$hostListener = $null; $hostOld = $null; $topology = $null

function New-SpaceState([string]$Key, [string]$UserName, [string]$ColdPhase) {
    return @{
        key = $Key; peerKey = if ($Key -eq 'A') { 'B' } else { 'A' }; userName = $UserName; coldPhase = $ColdPhase
        accountCreated = $false; accountSid = $null; password = $null
        origToken = [IntPtr]::Zero; loadedProfileHandle = [IntPtr]::Zero; copyToken = [IntPtr]::Zero
        ordinaryToken = [IntPtr]::Zero; auditorToken = [IntPtr]::Zero; ordinaryHeld = $null
        workRoot = $null; sealed = $null; scratch = $null
        launcherExe = $null; clientExe = $null; psecBin = $null; clientCfgPath = $null
        l1 = $null; l1Receipt = $null; l1Stop = $null; containerSid = $null
        wfpSub = [guid]::Empty; wfpKeys = $null; wfpWeight = [uint16]0; wfpInstalled = $false
        proxyPort = [uint16]0; peerPort = [uint16]0; entry = $null; entryLog = $null; settingsPath = $null; proxyOwner = $null; cmdSeq = 0
    }
}

$spaces = [ordered]@{
    A = New-SpaceState 'A' 'ClaudeStudioLabA' 'cold1'
    B = New-SpaceState 'B' 'ClaudeStudioLabB' 'cold2'
}

function Test-HostHealth([string]$Phase, [byte]$Marker) {
    $fresh = Open-GatePair $hostListener
    try {
        $dnsName = $prefix + '-host-' + $Phase + '-dns.test.'
        $null = Resolve-DnsName -Name $dnsName -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue
        $publicOk = $false
        for ($try = 0; $try -lt 3 -and !$publicOk; $try++) {
            try { if ([Net.Dns]::GetHostAddresses('example.com').Count -gt 0) { $publicOk = $true } }
            catch { Start-Sleep -Milliseconds 250 }
        }
        $res = [ordered]@{ phase = $Phase; dnsQueryName = $dnsName; publicDnsOk = $publicOk; oldTcp = (Send-GateMarker $hostOld $Marker); freshTcp = (Send-GateMarker $fresh ($Marker + 1)) }
        $report.hostHealth[$Phase] = $res
        return $res
    } finally { Close-GatePair $fresh }
}

function Read-NdjsonFile([string]$Path) {
    $rows = @()
    if (!(Test-Path -LiteralPath $Path)) { return $rows }
    $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $sr = [IO.StreamReader]::new($fs, [Text.Encoding]::UTF8)
        try { while ($null -ne ($line = $sr.ReadLine())) { if ($line.Trim().Length -gt 0) { $rows += @($line | ConvertFrom-Json) } } }
        finally { $sr.Dispose() }
    } finally { $fs.Dispose() }
    return $rows
}

function Read-DualN3Events {
    return @{ entryA = Read-NdjsonFile $spaces.A.entryLog; entryB = Read-NdjsonFile $spaces.B.entryLog; upstream = Read-NdjsonFile $topology.upstreamLog; target = Read-NdjsonFile $topology.targetLog }
}

function Start-SpaceProxyOwner($Sp) {
    $args = @($Sp.wfpSub.ToString(), $Sp.wfpKeys[0].ToString(), $Sp.wfpKeys[1].ToString(), $Sp.wfpKeys[2].ToString(), $Sp.wfpKeys[3].ToString(), $Sp.wfpKeys[4].ToString(), $Sp.containerSid, ("$($Sp.proxyPort):$($Sp.wfpWeight)"))
    $p = Start-N3Process $ownerExe $args $base
    $r = Read-N3Line $p 5000
    if ($r.kind -cne 'ready' -or $r.pid -ne $p.process.Id) { throw "ProxyOwner_$($Sp.key) ready handshake mismatch" }
    $p.ready = $r
    return $p
}

function Invoke-ProxyOwner($Owner, [string]$Cmd) {
    if (!$Owner -or $Owner.process.HasExited) { throw 'ProxyOwner already exited' }
    $Owner.process.StandardInput.WriteLine($Cmd); $Owner.process.StandardInput.Flush()
    $r = Read-N3Line $Owner 3000
    if ($r.cmd -cne $Cmd -or !$r.ok) { throw "ProxyOwner command $Cmd failed" }
    return $r
}

function Stop-SpaceProxyOwner($Sp) {
    $Owner = $Sp.proxyOwner; if (!$Owner) { return }
    try {
        if (!$Owner.process.HasExited) {
            try { $Owner.process.StandardInput.WriteLine('exit'); $Owner.process.StandardInput.Close() } catch { }
            if (!$Owner.process.WaitForExit(2000)) { $Owner.process.Kill(); [void]$Owner.process.WaitForExit(2000) }
        }
    } finally { $Owner.process.Dispose(); $Sp.proxyOwner = $null }
}

function Open-SpaceProxyGate($Sp) {
    if (!$Sp.proxyOwner -or $Sp.proxyOwner.process.HasExited) { $Sp.proxyOwner = Start-SpaceProxyOwner $Sp }
    $armed = Invoke-N3Child $Sp.entry ("arm-owner $($Sp.proxyOwner.ready.pid) $($Sp.proxyOwner.ready.startTicks)") 3000
    if (!$armed.admitting -or !$armed.lastProbe.ok) { throw "Entry_$($Sp.key) arm-owner failed" }
    $opened = Invoke-ProxyOwner $Sp.proxyOwner 'open'
    if (!$opened.open) { throw "ProxyOwner_$($Sp.key) open failed" }
    return [StudioLabWfp]::VerifyStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight, $true)
}

function Invoke-SpaceCmd($Sp, [string]$Action, [string]$Phase = 'none', [string]$ChildPhase = 'none', [int]$TimeoutMs = 18000) {
    $Sp.cmdSeq++
    $seq = $Sp.cmdSeq
    $cmdPath = Join-Path $Sp.scratch ("cmd-$seq.cfg")
    $resPath = Join-Path $Sp.scratch ("res-$seq.json")
    $tmp = $cmdPath + '.tmp'
    [IO.File]::WriteAllText($tmp, ("action=$Action`nphase=$Phase`nchildPhase=$ChildPhase`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($tmp, $cmdPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $resPath) -and $sw.ElapsedMilliseconds -lt $TimeoutMs) { Start-Sleep -Milliseconds 20 }
    if (!(Test-Path -LiteralPath $resPath)) { throw "Layer-2 $($Sp.key) did not respond to $Action within ${TimeoutMs}ms" }
    return (Get-Content -LiteralPath $resPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Drain-AllSentinels {
    $baseDrain = $sentinels.DrainMarkers()
    $extraDrain = $extraSentinels.Drain()
    return [ordered]@{
        tcpCount = $baseDrain.tcpCount; udpCount = $baseDrain.udpCount
        quicUdpCount = $extraDrain.quicUdpCount; dotTcpCount = $extraDrain.dotTcpCount
        dohTcpCount = $extraDrain.dohTcpCount; altLoopbackCount = $extraDrain.altLoopbackCount
    }
}

function Assert-AuditUnit($Sp, $Unit, [bool]$ExpectOnline, [bool]$IsChild) {
    $d = $Unit.direct
    $identityOk = ($Unit.appContainer -eq $true) -and ($Unit.containerSid -ceq $Sp.containerSid)
    $directBlocked = (!$d.sentinelTcp.connected -and $d.sentinelTcp.error -eq 10013) -and
        (!$d.crossPort.connected -and $d.crossPort.error -eq 10013) -and
        (!$d.directPu.connected -and $d.directPu.error -eq 10013) -and
        (!$d.directTargetHttp.connected -and $d.directTargetHttp.error -eq 10013) -and
        (!$d.directTargetTls.connected -and $d.directTargetTls.error -eq 10013) -and
        (!$d.dotTcpLocal.connected -and $d.dotTcpLocal.error -eq 10013) -and
        (!$d.dotTcpExt853.connected -and $d.dotTcpExt853.error -eq 10013) -and
        (!$d.dohTcpLocal.connected -and $d.dohTcpLocal.error -eq 10013) -and
        (!$d.dohTcpExt443.connected -and $d.dohTcpExt443.error -eq 10013) -and
        (!$d.altLoopback127_0_0_2.connected -and $d.altLoopback127_0_0_2.error -eq 10013)
    $dnsBlocked = ($Unit.dns.dnsQueryStatus -eq 5) -and ($Unit.dns.getAddrInfoStatus -ne 0)

    $ev = Read-DualN3Events
    $ownEntry = $ev['entry' + $Sp.key]; $peerEntry = $ev['entry' + $Sp.peerKey]
    $evForSpace = @{ entry = $ownEntry; upstream = $ev.upstream; target = $ev.target }
    $peerCross = @($peerEntry | Where-Object { ($_.marker -ceq $Unit.http.marker) -or ($_.marker -ceq $Unit.tls.marker) }).Count

    $httpMatched = $false; $tlsMatched = $false; $streamsOk = $true
    if ($ExpectOnline) {
        $httpMatched = ($null -ne (Find-N3Path $evForSpace $Unit.http 'http' $prefix))
        $tlsMatched = ($null -ne (Find-N3Path $evForSpace $Unit.tls 'tls' $prefix))
        $proxyOk = ($Unit.http.ok -eq $true -and $Unit.http.status -eq 200 -and $httpMatched) -and
            ($Unit.tls.ok -eq $true -and $Unit.tls.status -eq 200 -and $tlsMatched) -and ($peerCross -eq 0)
        if (!$IsChild) {
            $streamsOk = ($Unit.streams.httpMarks -ge 2) -and ($Unit.streams.tlsMarks -ge 2)
        }
    } else {
        $hHits = @($ev.target | Where-Object { $_.marker -ceq $Unit.http.marker }).Count
        $tHits = @($ev.target | Where-Object { $_.marker -ceq $Unit.tls.marker }).Count
        $proxyOk = (!$Unit.http.ok) -and (!$Unit.tls.ok) -and ($hHits -eq 0) -and ($tHits -eq 0) -and ($peerCross -eq 0)
    }

    return [ordered]@{
        passed = ($identityOk -and $directBlocked -and $dnsBlocked -and $proxyOk -and $streamsOk)
        identityOk = $identityOk; pid = $Unit.pid; containerSid = $Unit.containerSid
        directBlocked = $directBlocked; dnsBlocked = $dnsBlocked; proxyOk = $proxyOk; streamsOk = $streamsOk
        httpStatus = $Unit.http.status; tlsStatus = $Unit.tls.status
        peerCrossHits = $peerCross
        quicExt443Error = $d.quicUdpExt443.error; dotLocalErr = $d.dotTcpLocal.error; dotExt853Err = $d.dotTcpExt853.error
        dohLocalErr = $d.dohTcpLocal.error; dohExt443Err = $d.dohTcpExt443.error; altLoopbackErr = $d.altLoopback127_0_0_2.error
        dnsQueryStatus = $Unit.dns.dnsQueryStatus; getAddrInfoStatus = $Unit.dns.getAddrInfoStatus
    }
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'layer1_psec_launcher.c'),
        (Join-Path $fixtureDir 'layer2_phase4_audit.c'),
        (Join-Path $fixtureDir 'Phase1ProxyOwner.cs'),
        (Join-Path $fixtureDir 'PsecStartupGuard.cs'),
        (Join-Path $fixtureDir 'DesktopRead.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-wfp.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n3-target.cjs'),
        $PSCommandPath
    )) {
        $report.sources[(Split-Path $src -Leaf)] = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    if ((Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue) -or
        (Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)) {
        throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent before starting'
    }

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($buildDir, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($n3Dir, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Compile extra sentinels helper (QUIC UDP, DoT TCP, DoH TCP, 127.0.0.2 Alt-Loopback TCP)
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

public sealed class Phase4ExtraSentinels : IDisposable {
    readonly UdpClient quicUdp;
    readonly TcpListener dotTcp, dohTcp, altTcp;
    volatile bool stopping;
    int quicCount, dotCount, dohCount, altCount;
    readonly Thread tQuic, tDot, tDoh, tAlt;

    public int QuicUdpPort { get; private set; }
    public int DotTcpPort { get; private set; }
    public int DohTcpPort { get; private set; }
    public int AltLoopbackPort { get; private set; }

    public Phase4ExtraSentinels() {
        quicUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        QuicUdpPort = ((IPEndPoint)quicUdp.Client.LocalEndPoint).Port;

        dotTcp = new TcpListener(IPAddress.Loopback, 0); dotTcp.Server.ExclusiveAddressUse = true; dotTcp.Start(8);
        DotTcpPort = ((IPEndPoint)dotTcp.LocalEndpoint).Port;

        dohTcp = new TcpListener(IPAddress.Loopback, 0); dohTcp.Server.ExclusiveAddressUse = true; dohTcp.Start(8);
        DohTcpPort = ((IPEndPoint)dohTcp.LocalEndpoint).Port;

        altTcp = new TcpListener(IPAddress.Parse("127.0.0.2"), 0); altTcp.Server.ExclusiveAddressUse = true; altTcp.Start(8);
        AltLoopbackPort = ((IPEndPoint)altTcp.LocalEndpoint).Port;

        tQuic = new Thread(() => {
            var ep = new IPEndPoint(IPAddress.Any, 0);
            while (!stopping) { try { var b = quicUdp.Receive(ref ep); if (b != null && b.Length > 0) Interlocked.Increment(ref quicCount); } catch { if (stopping) break; } }
        }) { IsBackground = true };
        tDot = MakeTcpLoop(dotTcp, () => Interlocked.Increment(ref dotCount));
        tDoh = MakeTcpLoop(dohTcp, () => Interlocked.Increment(ref dohCount));
        tAlt = MakeTcpLoop(altTcp, () => Interlocked.Increment(ref altCount));
        tQuic.Start(); tDot.Start(); tDoh.Start(); tAlt.Start();
    }

    Thread MakeTcpLoop(TcpListener l, Action hit) {
        return new Thread(() => {
            while (!stopping) {
                try {
                    using (var c = l.AcceptTcpClient()) {
                        c.ReceiveTimeout = 600;
                        var b = new byte[64];
                        if (c.GetStream().Read(b, 0, b.Length) > 0) hit();
                    }
                } catch { if (stopping) break; }
            }
        }) { IsBackground = true };
    }

    public Dictionary<string, int> Drain() {
        return new Dictionary<string, int> {
            { "quicUdpCount", Interlocked.Exchange(ref quicCount, 0) },
            { "dotTcpCount", Interlocked.Exchange(ref dotCount, 0) },
            { "dohTcpCount", Interlocked.Exchange(ref dohCount, 0) },
            { "altLoopbackCount", Interlocked.Exchange(ref altCount, 0) }
        };
    }

    public void Dispose() {
        stopping = true;
        try { quicUdp.Close(); } catch { }
        try { dotTcp.Stop(); } catch { }
        try { dohTcp.Stop(); } catch { }
        try { altTcp.Stop(); } catch { }
    }
}
'@

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $cscOut = & $csc /nologo /platform:x64 /target:library /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$harnessDll" `
        (Join-Path $fixtureDir 'DesktopRead.cs') `
        (Join-Path $fixtureDir 'PsecStartupGuard.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Harness compile failed: ' + ($cscOut -join '; ')) }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($harnessDll))
    $assemblyLoaded = $true

    $ownerOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$ownerExe" `
        (Join-Path $fixtureDir 'Phase1ProxyOwner.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('ProxyOwner compile failed: ' + ($ownerOut -join '; ')) }

    $builtL1 = Join-Path $buildDir 'StudioLayer1Psec.exe'
    $builtL2 = Join-Path $buildDir 'StudioPhase4Audit.exe'
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL1 + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_phase4_audit.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL2 + '" kernel32.lib advapi32.lib ws2_32.lib dnsapi.lib secur32.lib crypt32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $builtL1) -or !(Test-Path -LiteralPath $builtL2)) {
        throw ('Native compile failed: ' + ($clOut -join '; '))
    }

    $report.qpcFrequency = [StudioPsecGuardHost]::QpcFreq()
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Allocate ports & start shared proxy topology + sentinels
    $ports = Get-DistinctHighPorts 3
    $portPa = [uint16]$ports[0]; $portPb = [uint16]$ports[1]; $portPu = [uint16]$ports[2]
    $spaces.A.proxyPort = $portPa; $spaces.A.peerPort = $portPb
    $spaces.B.proxyPort = $portPb; $spaces.B.peerPort = $portPa

    $relayExe = Join-Path $n3Dir 'StudioN3Relay.exe'
    $rOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$relayExe" (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('N3 relay compile failed: ' + ($rOut -join '; ')) }

    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $pwsh -NoProfile -NonInteractive -File (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $n3Dir -CertificatePrefix $prefix
    if ($LASTEXITCODE -ne 0) { throw 'N3 certificate generation failed' }

    $entryDirA = Join-Path $n3Dir 'entry-A'; $entryDirB = Join-Path $n3Dir 'entry-B'
    [void][IO.Directory]::CreateDirectory($entryDirA, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($entryDirB, (New-PrivateAcl $hostSid))
    $topology = @{ directory = $n3Dir; prefix = $prefix; exe = $relayExe; upstreamLog = (Join-Path $n3Dir 'upstream.ndjson'); targetLog = (Join-Path $n3Dir 'target.ndjson') }
    $spaces.A.entryLog = Join-Path $entryDirA 'entry-a.ndjson'
    $spaces.B.entryLog = Join-Path $entryDirB 'entry-b.ndjson'
    foreach ($lf in @($topology.upstreamLog, $topology.targetLog, $spaces.A.entryLog, $spaces.B.entryLog)) { [IO.File]::WriteAllText($lf, '') }

    $targetScript = Join-Path $n3Dir 'n3-target.cjs'
    Copy-Item -LiteralPath (Join-Path $mockDesktopDir 'windows-lab-n3-target.cjs') -Destination $targetScript
    $node = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $certArgs = @('target.crt','target.key','wrong.crt','wrong.key' | ForEach-Object { Join-Path $n3Dir $_ })
    $topology.target = Start-N3Process $node (@($targetScript, $prefix, $topology.targetLog) + $certArgs) $n3Dir
    $tReady = Read-N3Line $topology.target 5000
    if ($tReady.kind -cne 'ready') { throw 'N3 target failed to start' }
    $topology.targetReady = $tReady
    $topology.pin = [IO.File]::ReadAllText((Join-Path $n3Dir 'pin.txt')).Trim()

    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.settingsPath = Join-Path $n3Dir ("n3-settings-$k.json")
        [IO.File]::WriteAllText($sp.settingsPath, (@{ prefix = $prefix; p = [int]$sp.proxyPort; u = [int]$portPu; http = $tReady.http; tls = $tReady.tls; half = $tReady.half; wrongCertificate = $tReady.wrongCertificate; pin = $topology.pin } | ConvertTo-Json -Compress))
    }
    $topology.upstream = Start-N3Process $relayExe @('upstream', $spaces.A.settingsPath, $topology.upstreamLog) $n3Dir
    $uReady = Read-N3Line $topology.upstream 4500
    if ($uReady.kind -cne 'ready' -or $uReady.port -ne $portPu) { throw 'Upstream relay failed' }
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.entry = Start-N3Process $relayExe @('entry-n4', $sp.settingsPath, $sp.entryLog) (Split-Path $sp.entryLog -Parent)
        $eReady = Read-N3Line $sp.entry 4500
        if ($eReady.kind -cne 'ready' -or $eReady.port -ne $sp.proxyPort) { throw "Entry_$k relay failed" }
    }

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $extraSentinels = New-Object Phase4ExtraSentinels
    $report.ports = [ordered]@{
        pa = $portPa; pb = $portPb; pu = $portPu; targetHttp = $tReady.http; targetTls = $tReady.tls
        sentinelTcp = $sentinels.TcpPort; sentinelUdp = $sentinels.UdpPort
        quicUdp = $extraSentinels.QuicUdpPort; dotTcp = $extraSentinels.DotTcpPort
        dohTcp = $extraSentinels.DohTcpPort; altLoopbackTcp = $extraSentinels.AltLoopbackPort
    }

    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # Create standard local users ClaudeStudioLabA & ClaudeStudioLabB
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.password = New-RandomStrongPassword
        $u = New-LocalUser -Name $sp.userName -Password $sp.password -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $k Phase4 audit"
        $sp.accountCreated = $true; $sp.accountSid = $u.SID.Value
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $sp.origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($sp.userName, $env:COMPUTERNAME, $sp.password)
        $sp.loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($sp.origToken, $sp.userName)
        $sp.copyToken = [StudioPsecGuardHost]::DuplicateHardened($sp.origToken, $hostSid)
        $sp.ordinaryToken = [StudioPsecGuardHost]::LogonInteractive($sp.userName, $env:COMPUTERNAME, $sp.password)
        $sp.auditorToken = [StudioPsecGuardHost]::LogonInteractive($sp.userName, $env:COMPUTERNAME, $sp.password)

        $profTemp = "C:\Users\$($sp.userName)\AppData\Local\Temp"
        $sp.workRoot = Join-Path $profTemp $tag
        $sp.sealed = Join-Path $sp.workRoot 'sealed'
        $sp.scratch = Join-Path $sp.workRoot 'scratch'
        $sp.launcherExe = Join-Path $sp.sealed ("Studio${k}Layer1Psec.exe")
        $sp.clientExe = Join-Path $sp.sealed ("Studio${k}Phase4Audit.exe")
        $sp.psecBin = Join-Path $sp.sealed 'psec-loopback.bin'
        $sp.clientCfgPath = Join-Path $sp.sealed 'phase4-audit.cfg'

        $rxAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) { $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
        [void][IO.Directory]::CreateDirectory($sp.workRoot, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sp.sealed, $rxAcl)
        $rwAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) { $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
        [void][IO.Directory]::CreateDirectory($sp.scratch, $rwAcl)

        Copy-Item -LiteralPath $builtL1 -Destination $sp.launcherExe
        Copy-Item -LiteralPath $builtL2 -Destination $sp.clientExe
        [IO.File]::WriteAllBytes($sp.psecBin, [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1($sp.scratch, $sp.sealed, $false))

        $cfgText = @(
            "space=$k"
            "prefix=$prefix"
            "host=$prefix-a-window-healthy.test"
            "pin=$($topology.pin)"
            "workDir=$($sp.scratch)"
            "coldPhase=$($sp.coldPhase)"
            "p=$($sp.proxyPort)"
            "peerPort=$($sp.peerPort)"
            "u=$portPu"
            "http=$($tReady.http)"
            "tls=$($tReady.tls)"
            "sentinelTcp=$($sentinels.TcpPort)"
            "sentinelUdp=$($sentinels.UdpPort)"
            "quicUdp=$($extraSentinels.QuicUdpPort)"
            "dotTcp=$($extraSentinels.DotTcpPort)"
            "dohTcp=$($extraSentinels.DohTcpPort)"
            "altLoopbackTcp=$($extraSentinels.AltLoopbackPort)"
        ) -join "`n"
        [IO.File]::WriteAllText($sp.clientCfgPath, $cfgText + "`n", (New-Object Text.UTF8Encoding($false)))
        $sp.ordinaryHeld = [StudioPsecGuardHost]::StartSuspended($sp.ordinaryToken, $sp.clientExe, 'unused', $false, 'WinSta0\Default')
    }

    # =========================================================================
    # STEP 0: POSITIVE CONTROL (ORDINARY A OUTSIDE PSEC MUST HIT ALL 6 SENTINELS!)
    # =========================================================================
    $posOut = Join-Path $spaces.A.scratch 'positive-control.json'
    $posProc = [StudioPsecGuardHost]::StartSuspended($spaces.A.origToken, $spaces.A.clientExe, "--positive-control `"$($spaces.A.clientCfgPath)`" `"$posOut`"", $true, 'WinSta0\Default')
    try {
        [void]$posProc.ResumeMainThread()
        $null = $posProc.WaitExit(8000)
    } finally { $posProc.Dispose() }
    Start-Sleep -Milliseconds 150
    $posHits = Drain-AllSentinels
    $posJson = if (Test-Path -LiteralPath $posOut) { Get-Content -LiteralPath $posOut -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $report.positiveControl = [ordered]@{ client = $posJson; sentinelHits = $posHits }
    $report.checks.positiveControlReachable = ($null -ne $posJson) -and
        ($posHits.tcpCount -eq 1) -and ($posHits.udpCount -eq 1) -and
        ($posHits.quicUdpCount -eq 1) -and ($posHits.dotTcpCount -eq 1) -and
        ($posHits.dohTcpCount -eq 1) -and ($posHits.altLoopbackCount -eq 1)
    if (!$report.checks.positiveControlReachable) { throw ('Positive control failed to hit all 6 sentinels: ' + ($posHits | ConvertTo-Json -Compress)) }

    # =========================================================================
    # STEP 1: LAUNCH A & B SUSPENDED -> 6-WAY HANDLE AUDIT -> WFP -> RESUME -> COLD BLOCK
    # =========================================================================
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $readyPath = Join-Path $sp.scratch 'l1-ready.json'
        $sp.l1Stop = Join-Path $sp.scratch 'l1-stop'
        $l1Args = "`"$($sp.psecBin)`" `"$($sp.clientExe)`" `"$($sp.clientCfgPath)`" `"$($sp.scratch)`" `"$hostSid`" `"$readyPath`" `"$($sp.l1Stop)`""
        $sp.l1 = [StudioPsecGuardHost]::StartSuspended($sp.copyToken, $sp.launcherExe, $l1Args, $true, 'WinSta0\Default')
        $restore = $sp.l1.RestoreTokenObjectDaclOnly($sp.origToken, $hostSid, $sp.accountSid)
        if (!$restore.processSecurityAfterRestore.hardenedExpected -or !$restore.threadSecurityAfterRestore.hardenedExpected) { throw "Layer-1 $k SD weakened" }
        [void]$sp.l1.ResumeMainThread()
        $poll = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $readyPath) -and $poll.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
        $sp.l1Receipt = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, $hostSid, $sp.accountSid)
        $sp.containerSid = $insp.identity.containerSid
        if ($insp.identity.userSid -cne $sp.accountSid -or !$insp.identity.appContainer -or !$insp.identity.inJob -or
            (@($insp.identity.networkCapabilities).Count -ne 1) -or ($insp.identity.networkCapabilities[0] -cne $loopbackCapSid) -or
            $insp.threadUserTime -ne 0 -or $insp.threadKernelTime -ne 0 -or !$insp.processSecurity.hardenedExpected -or !$insp.threadSecurity.hardenedExpected) {
            throw "Suspended identity pre-check failed for $k"
        }
        [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$sp.l1Receipt.childPid, $hostSid, $sp.containerSid)
    }

    $violations = @(); $ordOk = $true
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]; $peer = $spaces[$sp.peerKey]
        $a1 = [StudioPsecGuardHost]::RunAudit($sp.auditorToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks, $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $a2 = [StudioPsecGuardHost]::RunAudit($sp.origToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks, $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $a3 = [StudioPsecGuardHost]::RunAudit($peer.auditorToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks, $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $m1 = @{}; foreach ($t in $a1.targets) { $m1[$t.role] = $t }
        $m2 = @{}; foreach ($t in $a2.targets) { $m2[$t.role] = $t }
        $m3 = @{}; foreach ($t in $a3.targets) { $m3[$t.role] = $t }
        if (!(Test-GrantedAll $m1['ordinary']) -or !(Test-GrantedAll $m2['ordinary'])) { $ordOk = $false }
        foreach ($r in 'layer1','layer2') { $violations += Get-Violations $m1[$r] "${k}-1"; $violations += Get-Violations $m2[$r] "${k}-2"; $violations += Get-Violations $m3[$r] "${k}-X" }
        $violations += Get-Violations $m3['ordinary'] "${k}-OrdX"
    }
    $report.checks.handleGatePassed = $ordOk -and ($violations.Count -eq 0)
    if (!$report.checks.handleGatePassed) { throw 'Handle gate failed' }

    $coldOk = $true
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.wfpSub = [guid]::NewGuid()
        $sp.wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
        $g = [StudioLabWfp]::CreateStaticGuard()
        try {
            $sp.wfpWeight = $g.PrepareStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.clientExe)
            $t1 = [StudioPsecGuardHost]::QpcNow()
            $g.InstallStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.clientExe, $sp.wfpWeight)
            $t2 = [StudioPsecGuardHost]::QpcNow()
            $sp.wfpInstalled = $true; $report.wfpStaticWrites += 4
        } finally { $g.Dispose() }
        $rbCold = [StudioLabWfp]::VerifyStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.wfpWeight, $false)
        $report.spaces[$k].wfpReadbackCold = [ordered]@{ weight = $sp.wfpWeight; ruleCount = @($rbCold.rules | Where-Object { $_.present -ne $false }).Count; ipv6AndInboundStaticRulesVerified = (@($rbCold.rules | Where-Object { $_.rule -in @('D4','D6','I4','I6') -and $_.action -eq 4097 }).Count -eq 4) }
        $res = [StudioPsecGuardHost]::HostResumeChildOnly([int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid)
        $cPath = Join-Path $sp.scratch 'cold-result.json'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $cPath) -and $sw.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
        $cold = Get-Content -LiteralPath $cPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $cSent = Drain-AllSentinels
        if ($t1 -gt $t2 -or $t2 -gt $res.qpcBeforeResume -or $res.qpcBeforeResume -gt $cold.qpcEntry -or $cold.qpcEntry -gt $cold.qpcFirstSocket -or
            $cold.directPa.connected -or $cold.directPa.error -ne 10013 -or $cold.crossPort.error -ne 10013 -or
            $cold.sentinelTcp.error -ne 10013 -or $cSent.tcpCount -ne 0 -or $cSent.udpCount -ne 0 -or $cold.dns.dnsQueryStatus -ne 5) { $coldOk = $false }
    }
    $report.checks.coldStartBlockedAndReadback = $coldOk -and $report.spaces.A.wfpReadbackCold.ipv6AndInboundStaticRulesVerified -and $report.spaces.B.wfpReadbackCold.ipv6AndInboundStaticRulesVerified
    if (!$report.checks.coldStartBlockedAndReadback) { throw 'Cold start or WFP readback failed' }
    $null = Test-HostHealth 'blocked' 51

    # =========================================================================
    # STEP 2: ONLINE FULL PROTOCOL + CHILD-INHERITANCE AUDIT (BOTH A & B)
    # =========================================================================
    $null = Open-SpaceProxyGate $spaces.A
    $null = Open-SpaceProxyGate $spaces.B

    $onlineA = (Invoke-SpaceCmd $spaces.A 'audit-online' 'healthy1' 'healthy2').data
    Start-Sleep -Milliseconds 120
    $onlineSentA = Drain-AllSentinels
    $onlineB = (Invoke-SpaceCmd $spaces.B 'audit-online' 'healthy3' 'healthy4').data
    Start-Sleep -Milliseconds 120
    $onlineSentB = Drain-AllSentinels

    $evalOnlineAMain = Assert-AuditUnit $spaces.A $onlineA.main $true $false
    $evalOnlineAChild = Assert-AuditUnit $spaces.A $onlineA.child $true $true
    $evalOnlineBMain = Assert-AuditUnit $spaces.B $onlineB.main $true $false
    $evalOnlineBChild = Assert-AuditUnit $spaces.B $onlineB.child $true $true

    $onlineSentZero = (($onlineSentA.Values | Measure-Object -Sum).Sum -eq 0) -and (($onlineSentB.Values | Measure-Object -Sum).Sum -eq 0)
    $report.auditMatrix.online = [ordered]@{
        A = [ordered]@{ main = $evalOnlineAMain; child = $evalOnlineAChild; sentinels = $onlineSentA }
        B = [ordered]@{ main = $evalOnlineBMain; child = $evalOnlineBChild; sentinels = $onlineSentB }
        childDistinctPids = ($onlineA.child.pid -ne $onlineA.main.pid) -and ($onlineB.child.pid -ne $onlineB.main.pid)
        allSentinelsZero = $onlineSentZero
    }
    $report.checks.onlineProtocolAndChildMatrix = $evalOnlineAMain.passed -and $evalOnlineAChild.passed -and
        $evalOnlineBMain.passed -and $evalOnlineBChild.passed -and
        $report.auditMatrix.online.childDistinctPids -and $onlineSentZero
    if (!$report.checks.onlineProtocolAndChildMatrix) { throw 'Online protocol & child inheritance audit failed' }
    $null = Test-HostHealth 'healthy1' 61

    # =========================================================================
    # STEP 3: OFFLINE (REVOKED EXCEPTIONS) FULL PROTOCOL + CHILD AUDIT (BOTH A & B)
    # =========================================================================
    $null = Invoke-ProxyOwner $spaces.A.proxyOwner 'close'
    $null = Invoke-ProxyOwner $spaces.B.proxyOwner 'close'
    $null = [StudioLabWfp]::VerifyStatic($spaces.A.wfpSub, $spaces.A.wfpKeys, $spaces.A.containerSid, $spaces.A.proxyPort, $spaces.A.wfpWeight, $false)
    $null = [StudioLabWfp]::VerifyStatic($spaces.B.wfpSub, $spaces.B.wfpKeys, $spaces.B.containerSid, $spaces.B.proxyPort, $spaces.B.wfpWeight, $false)

    $offlineA = (Invoke-SpaceCmd $spaces.A 'audit-offline' 'fault1' 'fault2').data
    Start-Sleep -Milliseconds 120
    $offlineSentA = Drain-AllSentinels
    $offlineB = (Invoke-SpaceCmd $spaces.B 'audit-offline' 'fault3' 'fault4').data
    Start-Sleep -Milliseconds 120
    $offlineSentB = Drain-AllSentinels

    $evalOffAMain = Assert-AuditUnit $spaces.A $offlineA.main $false $false
    $evalOffAChild = Assert-AuditUnit $spaces.A $offlineA.child $false $true
    $evalOffBMain = Assert-AuditUnit $spaces.B $offlineB.main $false $false
    $evalOffBChild = Assert-AuditUnit $spaces.B $offlineB.child $false $true
    $offlineSentZero = (($offlineSentA.Values | Measure-Object -Sum).Sum -eq 0) -and (($offlineSentB.Values | Measure-Object -Sum).Sum -eq 0)

    $report.auditMatrix.offline = [ordered]@{
        A = [ordered]@{ main = $evalOffAMain; child = $evalOffAChild; sentinels = $offlineSentA }
        B = [ordered]@{ main = $evalOffBMain; child = $evalOffBChild; sentinels = $offlineSentB }
        allSentinelsZero = $offlineSentZero
    }
    $report.checks.offlineProtocolAndChildMatrix = $evalOffAMain.passed -and $evalOffAChild.passed -and
        $evalOffBMain.passed -and $evalOffBChild.passed -and $offlineSentZero
    if (!$report.checks.offlineProtocolAndChildMatrix) { throw 'Offline protocol & child inheritance audit failed' }
    $null = Test-HostHealth 'fault1' 71

    foreach ($k in @('A', 'B')) { try { $null = Invoke-SpaceCmd $spaces[$k] 'finish' 'done' 'done' 2500 } catch { } }
} catch {
    $report.error = Get-ErrDetail $_
} finally {
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        try { Stop-SpaceProxyOwner $sp } catch { $report.cleanup.errors += @("owner-$k`: $($_.Exception.Message)") }
        if ($sp.l1Stop -and $sp.scratch -and (Test-Path -LiteralPath $sp.scratch)) { try { [IO.File]::WriteAllText($sp.l1Stop, 'stop') } catch { } }
        if ($sp.l1Receipt -and $sp.l1Receipt.childPid) { try { [StudioPsecGuardHost]::HostTerminatePid([int]$sp.l1Receipt.childPid) } catch { } }
        if ($sp.l1) { try { [void]$sp.l1.WaitExit(4000); $sp.l1.Dispose() } catch { $report.cleanup.errors += @("l1-$k`: $($_.Exception.Message)") }; $sp.l1 = $null }
        if ($sp.ordinaryHeld) { try { $null = $sp.ordinaryHeld.TerminateNow(); $sp.ordinaryHeld.Dispose() } catch { $report.cleanup.errors += @("ord-$k`: $($_.Exception.Message)") }; $sp.ordinaryHeld = $null }
        if ($sp.entry) {
            try { Stop-N3Process $sp.entry } catch {
                $report.cleanup.errors += @("entry-$k`: $($_.Exception.Message)")
                try { if (!$sp.entry.process.HasExited) { $sp.entry.process.Kill(); [void]$sp.entry.process.WaitForExit(2000) } } catch { }
                try { $sp.entry.process.Dispose() } catch { }
            }
            $sp.entry = $null
        }
    }
    if ($topology) {
        foreach ($role in @('upstream', 'target')) {
            if ($topology[$role]) { try { Stop-N3Process $topology[$role] } catch { $report.cleanup.errors += @("stop-$role`: $($_.Exception.Message)") }; $topology[$role] = $null }
        }
    }
    Start-Sleep -Milliseconds 200

    $allowedExes = @($spaces.A.launcherExe, $spaces.A.clientExe, $spaces.B.launcherExe, $spaces.B.clientExe, $ownerExe) | Where-Object { $_ }
    $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Psec.exe' OR Name = 'StudioBLayer1Psec.exe' OR Name = 'StudioAPhase4Audit.exe' OR Name = 'StudioBPhase4Audit.exe' OR Name = 'StudioPhase4ProxyOwner.exe'" | Where-Object { $_.ExecutablePath -in $allowedExes })
    foreach ($p in $rem) { $report.cleanup.remainingPids += @([int]$p.ProcessId) }

    $allWfpRemoved = ($report.cleanup.remainingPids.Count -eq 0)
    if ($allWfpRemoved) {
        foreach ($k in @('A', 'B')) {
            $sp = $spaces[$k]
            if ($sp.wfpInstalled -and $assemblyLoaded) {
                try {
                    [StudioLabWfp]::RemoveStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.wfpWeight)
                    Start-Sleep -Milliseconds 80
                    $res = [StudioLabWfp]::CountFiltersReferencingPackage($sp.containerSid)
                    $report.cleanup["wfpRemoved_$k"] = $true; $report.cleanup["residualPackageFilters_$k"] = $res
                    if ($res -ne 0) { $allWfpRemoved = $false }
                } catch { $report.cleanup["wfpRemoved_$k"] = $false; $allWfpRemoved = $false; $report.cleanup.errors += @("wfp-$k`: $($_.Exception.Message)") }
            }
        }
    }
    $report.cleanup.wfpRemovedAndVerifiedAbsent = $allWfpRemoved

    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { $report.cleanup.errors += @("host-restored: $($_.Exception.Message)") } }
    if ($dnsTrace) {
        try {
            $dnsResult = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $report.dnsTrace = $dnsResult
            $psecSendReply = @($dnsResult.events | Where-Object { $_.role -eq 'psec' -and ($_.event -in 3010, 3011) }).Count
            $unknownSendReply = @($dnsResult.events | Where-Object { !$_.role -and ($_.event -in 3010, 3011) }).Count
            $hostSends = @($dnsResult.events | Where-Object { $_.role -eq 'host' -and $_.event -eq 3010 }).Count
            $lossZero = ($null -ne $dnsResult.lossBeforeStop) -and ($dnsResult.lossBeforeStop.eventsLost -eq 0) -and ($dnsResult.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsResult.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{ servicePidStable = ($dnsResult.servicePid -eq $dnsResult.servicePidAfter); lossZero = $lossZero; psecSendReplyCount = $psecSendReply; unknownSendReplyCount = $unknownSendReply; hostSendCount = $hostSends }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lossZero -and ($psecSendReply -eq 0) -and ($unknownSendReply -eq 0) -and ($hostSends -ge 5)
        } catch { $report.cleanup.errors += @("dns-stop: $($_.Exception.Message)"); $report.checks.dnsZeroLeak = $false }
    }
    if ($extraSentinels) { try { $extraSentinels.Dispose() } catch { } }
    if ($sentinels) { try { $sentinels.Dispose() } catch { } }
    if ($hostOld) { try { Close-GatePair $hostOld } catch { } }
    if ($hostListener) { try { $hostListener.Dispose() } catch { } }

    if ($assemblyLoaded) {
        try {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()
            $defaultMatch = ($report.defaultDesktopBefore.readable -eq $report.defaultDesktopAfter.readable) -and ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
            $report.desktopAclUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and $defaultMatch
            $report.checks.desktopUnchanged = $report.desktopAclUnchanged
        } catch { $report.cleanup.errors += @("desktop: $($_.Exception.Message)"); $report.checks.desktopUnchanged = $false }
    }

    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        if ($assemblyLoaded) {
            try { [StudioPsecGuardHost]::UnloadLabProfile($sp.origToken, $sp.loadedProfileHandle) } catch { $report.cleanup.errors += @("unload-$k`: $($_.Exception.Message)") }
            foreach ($tName in @('auditorToken', 'ordinaryToken', 'copyToken', 'origToken')) {
                if ($sp[$tName] -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($sp[$tName]) } catch { }; $sp[$tName] = [IntPtr]::Zero }
            }
        }
        if ($sp.workRoot -and (Test-Path -LiteralPath $sp.workRoot)) { try { Remove-Item -LiteralPath $sp.workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
        if ($sp.accountCreated) {
            try { if ($sp.accountSid) { $prof = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $sp.accountSid + "'") -ErrorAction SilentlyContinue; if ($prof) { Remove-CimInstance -InputObject $prof -ErrorAction Stop } } } catch { $report.cleanup.errors += @("prof-$k`: $($_.Exception.Message)") }
            try { $profDir = "C:\Users\$($sp.userName)"; if (Test-Path -LiteralPath $profDir) { Remove-Item -LiteralPath $profDir -Recurse -Force -ErrorAction Stop } } catch { $report.cleanup.errors += @("profdir-$k`: $($_.Exception.Message)") }
            try { Remove-LocalUser -Name $sp.userName -ErrorAction Stop } catch { $report.cleanup.errors += @("user-$k`: $($_.Exception.Message)") }
        }
    }
    if ($dirCreated -and (Test-Path -LiteralPath $base) -and $allWfpRemoved) {
        try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") }
    }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.labBProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabB')
    $report.cleanup.labAProfileRecordGone = !($spaces.A.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.A.accountSid + "'") -ErrorAction SilentlyContinue))
    $report.cleanup.labBProfileRecordGone = !($spaces.B.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.B.accountSid + "'") -ErrorAction SilentlyContinue))

    $hostOk = $true
    foreach ($st in @('baseline', 'blocked', 'healthy1', 'fault1', 'restored')) {
        $h = $report.hostHealth[$st]
        if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hostOk = $false }
    }
    $report.checks.hostContinuous = $hostOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.remainingPids.Count -eq 0) -and
        $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.directoryGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labBProfileDirGone -and
        $report.cleanup.labAProfileRecordGone -and $report.cleanup.labBProfileRecordGone

    $allPassed = (!$report.error) -and $report.checks.positiveControlReachable -and $report.checks.handleGatePassed -and
        $report.checks.coldStartBlockedAndReadback -and $report.checks.onlineProtocolAndChildMatrix -and
        $report.checks.offlineProtocolAndChildMatrix -and $report.checks.dnsZeroLeak -and
        $report.checks.hostContinuous -and $report.checks.desktopUnchanged -and $report.checks.cleanup

    if ($allPassed) { $report.outcome = 'passed-ab-phase4-protocol-audit' }
    else { $report.outcome = 'stopped-ab-phase4-protocol-audit' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 14), (New-Object Text.UTF8Encoding($false)))
    $hash12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    $summary = [ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $hash12; error = $report.error
        ports = $report.ports; positiveControlHits = $report.positiveControl.sentinelHits
        checks = $report.checks; auditMatrix = $report.auditMatrix; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
