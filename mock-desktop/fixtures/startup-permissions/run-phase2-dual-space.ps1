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
    $listeners = @()
    $ports = @()
    try {
        for ($attempt = 0; $attempt -lt 20 -and $ports.Count -lt $Count; $attempt++) {
            $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $l.ExclusiveAddressUse = $true
            $l.Start()
            $p = [uint16]$l.LocalEndpoint.Port
            if ($p -ge 49152 -and $p -ne 10810 -and ($ports -notcontains $p)) {
                $listeners += $l
                $ports += $p
            } else {
                $l.Stop()
            }
        }
        if ($ports.Count -ne $Count) { throw "Could not allocate $Count distinct high ephemeral ports" }
        return $ports
    } finally {
        foreach ($l in $listeners) { try { $l.Stop() } catch { } }
    }
}

function Test-GrantedAll($Target) {
    $core = @($Target.processRights) + @($Target.threadRights)
    $term = @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' -or $_.right -ceq 'PROCESS_QUERY_LIMITED_INFORMATION' }) +
            @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })
    return @($Target.processRights).Count -eq 9 -and @($Target.threadRights).Count -eq 5 -and
        @($core + $term | Where-Object { !$_.granted -or $_.error -ne 0 }).Count -eq 0
}

function Get-Violations($Target, [string]$Perspective) {
    $out = @()
    $all = @()
    foreach ($r in @($Target.processRights)) { $all += [pscustomobject]@{ part = 'process'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.threadRights)) { $all += [pscustomobject]@{ part = 'thread'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' })) { $all += [pscustomobject]@{ part = 'processExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })) { $all += [pscustomobject]@{ part = 'threadExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($e in $all) {
        if ($e.granted -or $e.error -ne 5) {
            $out += [ordered]@{ perspective = $Perspective; role = $Target.role; part = $e.part; right = $e.right; granted = $e.granted; error = $e.error }
        }
    }
    return $out
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    if (!(Test-Path -LiteralPath $reportDir)) { throw "Expected report directory: $reportDir" }
    $ReportPath = Join-Path $reportDir ('windows-ab-phase2-dual-space-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioABPhase2-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $outerTimer = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $outerTimer.ElapsedMilliseconds -lt 240000) {
            Start-Sleep -Milliseconds 100
        }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if ($proc.HasExited -and $proc.ExitCode -ne 0 -and !(Test-Path -LiteralPath $SummaryPath)) {
            throw ('Elevated runner exited with code ' + $proc.ExitCode)
        }
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
$tag = 'ClaudeStudioABPhase2-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$buildDir = Join-Path $base 'build'
$n3Dir = Join-Path $base 'n3'
$harnessDll = Join-Path $base 'StudioPhase2Harness.dll'
$ownerExe = Join-Path $base 'StudioPhase2ProxyOwner.exe'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId
    prefix = $prefix
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase2-dual-space'
    nativeIPv6 = 'readback only'
    ipv4Inbound = 'readback only'
    hostSid = $hostSid
    wfpStaticWrites = 0
    sources = [ordered]@{}
    spaces = [ordered]@{ A = [ordered]@{}; B = [ordered]@{} }
    checks = [ordered]@{}
    hostHealth = [ordered]@{}
    phases = @()
    faults = @()
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$dirCreated = $false
$assemblyLoaded = $false
$dnsTrace = $null
$sentinels = $null
$hostListener = $null
$hostOld = $null
$topology = $null

function New-SpaceState([string]$Key, [string]$UserName, [string]$ColdPhase) {
    return @{
        key = $Key
        peerKey = if ($Key -eq 'A') { 'B' } else { 'A' }
        userName = $UserName
        coldPhase = $ColdPhase
        accountCreated = $false
        accountSid = $null
        password = $null
        origToken = [IntPtr]::Zero
        loadedProfileHandle = [IntPtr]::Zero
        copyToken = [IntPtr]::Zero
        ordinaryToken = [IntPtr]::Zero
        auditorToken = [IntPtr]::Zero
        ordinaryHeld = $null
        workRoot = $null
        sealed = $null
        scratch = $null
        launcherExe = $null
        clientExe = $null
        psecBin = $null
        clientCfgPath = $null
        l1 = $null
        l1Receipt = $null
        l1Stop = $null
        containerSid = $null
        wfpSub = [guid]::Empty
        wfpKeys = $null
        wfpWeight = [uint16]0
        wfpInstalled = $false
        manifestFile = (Join-Path $base ("wfp-recovery-manifest-$Key.json"))
        proxyPort = [uint16]0
        peerPort = [uint16]0
        entry = $null
        entryLog = $null
        settingsPath = $null
        proxyOwner = $null
        cmdSeq = 0
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
            try {
                if ([Net.Dns]::GetHostAddresses('example.com').Count -gt 0) { $publicOk = $true }
            } catch { Start-Sleep -Milliseconds 250 }
        }
        $res = [ordered]@{
            phase = $Phase
            dnsQueryName = $dnsName
            publicDnsOk = $publicOk
            oldTcp = (Send-GateMarker $hostOld $Marker)
            freshTcp = (Send-GateMarker $fresh ($Marker + 1))
        }
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
        try {
            while ($null -ne ($line = $sr.ReadLine())) {
                if ($line.Trim().Length -gt 0) {
                    $rows += @($line | ConvertFrom-Json)
                }
            }
        } finally { $sr.Dispose() }
    } finally { $fs.Dispose() }
    return $rows
}

function Read-DualN3Events {
    return @{
        entryA = Read-NdjsonFile $spaces.A.entryLog
        entryB = Read-NdjsonFile $spaces.B.entryLog
        upstream = Read-NdjsonFile $topology.upstreamLog
        target = Read-NdjsonFile $topology.targetLog
    }
}

function Start-SpaceProxyOwner($Sp) {
    $args = @(
        $Sp.wfpSub.ToString(),
        $Sp.wfpKeys[0].ToString(), $Sp.wfpKeys[1].ToString(), $Sp.wfpKeys[2].ToString(), $Sp.wfpKeys[3].ToString(), $Sp.wfpKeys[4].ToString(),
        $Sp.containerSid,
        ("$($Sp.proxyPort):$($Sp.wfpWeight)")
    )
    $p = Start-N3Process $ownerExe $args $base
    $r = Read-N3Line $p 5000
    if ($r.kind -cne 'ready' -or $r.pid -ne $p.process.Id) { throw "ProxyOwner_$($Sp.key) ready handshake mismatch" }
    $p.ready = $r
    return $p
}

function Invoke-ProxyOwner($Owner, [string]$Cmd) {
    if (!$Owner -or $Owner.process.HasExited) { throw 'ProxyOwner already exited' }
    $Owner.process.StandardInput.WriteLine($Cmd)
    $Owner.process.StandardInput.Flush()
    $r = Read-N3Line $Owner 3000
    if ($r.cmd -cne $Cmd -or !$r.ok) { throw "ProxyOwner command $Cmd failed" }
    return $r
}

function Stop-SpaceProxyOwner($Sp, [switch]$HardKill) {
    $Owner = $Sp.proxyOwner
    if (!$Owner) { return }
    try {
        if (!$Owner.process.HasExited) {
            if ($HardKill) {
                $Owner.process.Kill()
                [void]$Owner.process.WaitForExit(3000)
            } else {
                try { $Owner.process.StandardInput.WriteLine('exit'); $Owner.process.StandardInput.Close() } catch { }
                if (!$Owner.process.WaitForExit(2000)) { $Owner.process.Kill(); [void]$Owner.process.WaitForExit(2000) }
            }
        }
    } finally {
        $Owner.process.Dispose()
        $Sp.proxyOwner = $null
    }
}

function Open-SpaceProxyGate($Sp) {
    if (!$Sp.proxyOwner -or $Sp.proxyOwner.process.HasExited) {
        $Sp.proxyOwner = Start-SpaceProxyOwner $Sp
    }
    $armCmd = "arm-owner $($Sp.proxyOwner.ready.pid) $($Sp.proxyOwner.ready.startTicks)"
    $armed = Invoke-N3Child $Sp.entry $armCmd 3000
    if (!$armed.admitting -or !$armed.lastProbe.ok) { throw "Entry_$($Sp.key) arm-owner failed health check" }
    $opened = Invoke-ProxyOwner $Sp.proxyOwner 'open'
    if (!$opened.open) { throw "ProxyOwner_$($Sp.key) failed to open dynamic exception E" }
    $rb = [StudioLabWfp]::VerifyStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight, $true)
    return [ordered]@{ space = $Sp.key; ownerPid = $Sp.proxyOwner.ready.pid; armed = $armed; readback = $rb }
}

function Invoke-SpaceCmd($Sp, [string]$Action, [string]$Phase = 'none', [int]$TimeoutMs = 12000) {
    $Sp.cmdSeq++
    $seq = $Sp.cmdSeq
    $cmdPath = Join-Path $Sp.scratch ("cmd-$seq.cfg")
    $resPath = Join-Path $Sp.scratch ("res-$seq.json")
    $tmp = $cmdPath + '.tmp'
    [IO.File]::WriteAllText($tmp, ("action=$Action`nphase=$Phase`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($tmp, $cmdPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $resPath) -and $sw.ElapsedMilliseconds -lt $TimeoutMs) { Start-Sleep -Milliseconds 20 }
    if (!(Test-Path -LiteralPath $resPath)) { throw "Layer-2 $($Sp.key) did not respond to $Action ($Phase) within ${TimeoutMs}ms" }
    return (Get-Content -LiteralPath $resPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Assert-DualProbeOutcome($Sp, $ProbeData, [bool]$ExpectOnline, [string]$PhaseLabel) {
    $sentinelDrain = $sentinels.DrainMarkers()
    $crossBlocked = ($null -ne $ProbeData.direct.crossPort) -and (!$ProbeData.direct.crossPort.connected) -and ($ProbeData.direct.crossPort.error -eq 10013)
    $directBlocked = (!$ProbeData.direct.sentinelTcp.connected -and $ProbeData.direct.sentinelTcp.error -eq 10013) -and
        (!$ProbeData.direct.directPu.connected -and $ProbeData.direct.directPu.error -eq 10013) -and
        (!$ProbeData.direct.directTargetHttp.connected -and $ProbeData.direct.directTargetHttp.error -eq 10013) -and
        (!$ProbeData.direct.directTargetTls.connected -and $ProbeData.direct.directTargetTls.error -eq 10013) -and
        $crossBlocked -and ($sentinelDrain.tcpCount -eq 0) -and ($sentinelDrain.udpCount -eq 0)
    $dnsBlocked = ($ProbeData.dns.dnsQueryStatus -eq 5) -and ($ProbeData.dns.getAddrInfoStatus -ne 0)

    $ev = Read-DualN3Events
    $ownEntry = $ev['entry' + $Sp.key]
    $peerEntry = $ev['entry' + $Sp.peerKey]
    $evForSpace = @{ entry = $ownEntry; upstream = $ev.upstream; target = $ev.target }

    $peerCrossHits = @($peerEntry | Where-Object {
        ($_.marker -ceq $ProbeData.http.marker) -or ($_.marker -ceq $ProbeData.tls.marker)
    }).Count

    $httpPath = $null; $tlsPath = $null
    if ($ExpectOnline) {
        $httpPath = Find-N3Path $evForSpace $ProbeData.http 'http' $prefix
        $tlsPath = Find-N3Path $evForSpace $ProbeData.tls 'tls' $prefix
        $proxyOk = ($ProbeData.http.ok -eq $true -and $ProbeData.http.status -eq 200 -and $null -ne $httpPath) -and
            ($ProbeData.tls.ok -eq $true -and $ProbeData.tls.status -eq 200 -and $null -ne $tlsPath) -and
            ($peerCrossHits -eq 0)
    } else {
        $httpTargetHits = @($ev.target | Where-Object { $_.marker -ceq $ProbeData.http.marker }).Count
        $tlsTargetHits = @($ev.target | Where-Object { $_.marker -ceq $ProbeData.tls.marker }).Count
        $proxyOk = ($ProbeData.http.ok -eq $false) -and ($ProbeData.tls.ok -eq $false) -and
            ($httpTargetHits -eq 0) -and ($tlsTargetHits -eq 0) -and ($peerCrossHits -eq 0)
    }

    $ok = $directBlocked -and $dnsBlocked -and $proxyOk
    $rec = [ordered]@{
        space = $Sp.key
        phase = $PhaseLabel
        expectOnline = $ExpectOnline
        passed = $ok
        directBlocked = $directBlocked
        crossPortBlocked = $crossBlocked
        peerEntryCrossHits = $peerCrossHits
        dnsBlocked = $dnsBlocked
        proxyOk = $proxyOk
        sentinels = $sentinelDrain
        http = $ProbeData.http
        tls = $ProbeData.tls
        httpPathMatched = ($null -ne $httpPath)
        tlsPathMatched = ($null -ne $tlsPath)
        dns = $ProbeData.dns
    }
    $report.phases += @($rec)
    if (!$ok) { throw ("Probe assertion failed for $($Sp.key) in phase $PhaseLabel : " + ($rec | ConvertTo-Json -Compress -Depth 6)) }
    return $rec
}

function Start-AndWaitHeld($Sp, [string]$Phase) {
    $null = Invoke-SpaceCmd $Sp 'hold' $Phase
    $sw = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 120
        $snap = (Invoke-SpaceCmd $Sp 'held' $Phase).data
        if ($sw.ElapsedMilliseconds -gt 4000) { throw "Held HTTP/TLS streams for $($Sp.key) did not become active in $Phase" }
    } until ($snap.http.state -ceq 'active' -and $snap.tls.state -ceq 'active' -and
        @($snap.http.marks).Count -ge 2 -and @($snap.tls.marks).Count -ge 2)
    return $snap
}

function Wait-SpaceCutoff($Sp, [long]$InjectQpc, [bool]$CloseOwnerOnEntryHalt) {
    $freq = [StudioPsecGuardHost]::QpcFreq()
    $entryClosed = $false; $excGone = $false; $closeSent = $false; $elapsedMs = 0.0; $entrySnap = $null
    while ($true) {
        $entrySnap = Invoke-N3Child $Sp.entry 'status' 1600
        $entryClosed = (!$entrySnap.admitting -and $entrySnap.active -eq 0)
        if ($CloseOwnerOnEntryHalt -and !$closeSent -and $entryClosed -and $Sp.proxyOwner -and !$Sp.proxyOwner.process.HasExited) {
            $null = Invoke-ProxyOwner $Sp.proxyOwner 'close'
            $closeSent = $true
        }
        $excGone = ![StudioLabWfp]::StaticExceptionPresent($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight)
        $elapsedMs = ([StudioPsecGuardHost]::QpcNow() - $InjectQpc) * 1000.0 / $freq
        if ($entryClosed -and $excGone) { break }
        if ($elapsedMs -gt 3000.0) {
            throw "Space $($Sp.key) exceeded 3000ms cutoff budget (elapsed=${elapsedMs}ms, entryClosed=$entryClosed, excGone=$excGone)"
        }
        Start-Sleep -Milliseconds 35
    }
    $rbOff = [StudioLabWfp]::VerifyStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight, $false)
    return [ordered]@{
        cutoffMs = [Math]::Round($elapsedMs, 2)
        entryCloseReason = $entrySnap.closeReason
        exceptionAbsentReadback = ($rbOff.exceptionPresent -eq $false)
    }
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'layer1_psec_launcher.c'),
        (Join-Path $fixtureDir 'layer2_phase1_client.c'),
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

    # Compile host C# harness DLL + standalone ProxyOwner EXE + N3 Relay EXE
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
    $builtL2 = Join-Path $buildDir 'StudioPhase2Client.exe'
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL1 + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_phase1_client.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL2 + '" kernel32.lib advapi32.lib ws2_32.lib dnsapi.lib secur32.lib crypt32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $builtL1) -or !(Test-Path -LiteralPath $builtL2)) {
        throw ('Native compile failed: ' + ($clOut -join '; '))
    }

    $report.launcherSha256 = (Get-FileHash -LiteralPath $builtL1 -Algorithm SHA256).Hash
    $report.clientSha256 = (Get-FileHash -LiteralPath $builtL2 -Algorithm SHA256).Hash
    $report.ownerSha256 = (Get-FileHash -LiteralPath $ownerExe -Algorithm SHA256).Hash
    $report.qpcFrequency = [StudioPsecGuardHost]::QpcFreq()
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Allocate 3 distinct high ephemeral ports (Pa, Pb, Pu)
    $ports = Get-DistinctHighPorts 3
    $portPa = [uint16]$ports[0]
    $portPb = [uint16]$ports[1]
    $portPu = [uint16]$ports[2]
    $spaces.A.proxyPort = $portPa; $spaces.A.peerPort = $portPb
    $spaces.B.proxyPort = $portPb; $spaces.B.peerPort = $portPa

    # Start shared N3 Target + shared Upstream(Pu) + independent Entry_A(Pa) & Entry_B(Pb)
    $relayExe = Join-Path $n3Dir 'StudioN3Relay.exe'
    $rOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$relayExe" (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('N3 relay compile failed: ' + ($rOut -join '; ')) }

    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $pwsh -NoProfile -NonInteractive -File (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $n3Dir -CertificatePrefix $prefix
    if ($LASTEXITCODE -ne 0) { throw 'N3 certificate generation failed' }

    $topology = @{
        directory = $n3Dir; prefix = $prefix; exe = $relayExe
        upstreamLog = (Join-Path $n3Dir 'upstream.ndjson')
        targetLog = (Join-Path $n3Dir 'target.ndjson')
    }
    $entryDirA = Join-Path $n3Dir 'entry-A'
    $entryDirB = Join-Path $n3Dir 'entry-B'
    [void][IO.Directory]::CreateDirectory($entryDirA, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($entryDirB, (New-PrivateAcl $hostSid))
    $spaces.A.entryLog = Join-Path $entryDirA 'entry-a.ndjson'
    $spaces.B.entryLog = Join-Path $entryDirB 'entry-b.ndjson'
    foreach ($lf in @($topology.upstreamLog, $topology.targetLog, $spaces.A.entryLog, $spaces.B.entryLog)) {
        [IO.File]::WriteAllText($lf, '')
    }

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
        [IO.File]::WriteAllText($sp.settingsPath, (@{
            prefix = $prefix; p = [int]$sp.proxyPort; u = [int]$portPu;
            http = $tReady.http; tls = $tReady.tls; half = $tReady.half; wrongCertificate = $tReady.wrongCertificate;
            pin = $topology.pin
        } | ConvertTo-Json -Compress))
    }

    $topology.upstream = Start-N3Process $relayExe @('upstream', $spaces.A.settingsPath, $topology.upstreamLog) $n3Dir
    $uReady = Read-N3Line $topology.upstream 4500
    if ($uReady.kind -cne 'ready' -or $uReady.port -ne $portPu) { throw 'Shared upstream relay failed' }

    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $entryCwd = Split-Path $sp.entryLog -Parent
        $sp.entry = Start-N3Process $relayExe @('entry-n4', $sp.settingsPath, $sp.entryLog) $entryCwd
        $eReady = Read-N3Line $sp.entry 4500
        if ($eReady.kind -cne 'ready' -or $eReady.port -ne $sp.proxyPort) { throw "Entry_$k relay failed" }
    }

    # Host loopback control + non-proxy sentinels + DNS ETW trace
    $hostListener = New-GateSocket
    $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $report.ports = [ordered]@{
        pa = $portPa; pb = $portPb; pu = $portPu;
        targetHttp = $tReady.http; targetTls = $tReady.tls;
        sentinelTcp = $sentinels.TcpPort; sentinelUdp = $sentinels.UdpPort
    }

    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # Create standard local users ClaudeStudioLabA & ClaudeStudioLabB, acquire tokens, stage sealed/scratch dirs
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.password = New-RandomStrongPassword
        $u = New-LocalUser -Name $sp.userName -Password $sp.password -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $k Phase2 dual-space test"
        $sp.accountCreated = $true
        $sp.accountSid = $u.SID.Value
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
        $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
        if ($sp.accountSid -in $admins -or $sp.accountSid -notin $users) { throw "Unexpected group membership for $($sp.userName)" }
        $report.spaces[$k].account = [ordered]@{ name = $sp.userName; sid = $sp.accountSid; inUsers = $true; inAdmins = $false }

        $sp.origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($sp.userName, $env:COMPUTERNAME, $sp.password)
        $sp.loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($sp.origToken, $sp.userName)
        $sp.copyToken = [StudioPsecGuardHost]::DuplicateHardened($sp.origToken, $hostSid)
        $sp.ordinaryToken = [StudioPsecGuardHost]::LogonInteractive($sp.userName, $env:COMPUTERNAME, $sp.password)
        $sp.auditorToken = [StudioPsecGuardHost]::LogonInteractive($sp.userName, $env:COMPUTERNAME, $sp.password)

        $profTemp = "C:\Users\$($sp.userName)\AppData\Local\Temp"
        if (!(Test-Path -LiteralPath $profTemp)) { throw "Expected profile temp: $profTemp" }
        $sp.workRoot = Join-Path $profTemp $tag
        $sp.sealed = Join-Path $sp.workRoot 'sealed'
        $sp.scratch = Join-Path $sp.workRoot 'scratch'
        $sp.launcherExe = Join-Path $sp.sealed ("Studio${k}Layer1Psec.exe")
        $sp.clientExe = Join-Path $sp.sealed ("Studio${k}Phase2Client.exe")
        $sp.psecBin = Join-Path $sp.sealed 'psec-loopback.bin'
        $sp.clientCfgPath = Join-Path $sp.sealed 'phase2-client.cfg'

        $rxAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) {
            $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($s),
                [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($sp.workRoot, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sp.sealed, $rxAcl)

        $scratchAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) {
            $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($s),
                [Security.AccessControl.FileSystemRights]::Modify,
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($sp.scratch, $scratchAcl)

        Copy-Item -LiteralPath $builtL1 -Destination $sp.launcherExe
        Copy-Item -LiteralPath $builtL2 -Destination $sp.clientExe
        $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1($sp.scratch, $sp.sealed, $false)
        [IO.File]::WriteAllBytes($sp.psecBin, $psecBytes)

        $cfgText = @(
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
        ) -join "`n"
        [IO.File]::WriteAllText($sp.clientCfgPath, $cfgText + "`n", (New-Object Text.UTF8Encoding($false)))

        $sp.ordinaryHeld = [StudioPsecGuardHost]::StartSuspended($sp.ordinaryToken, $sp.clientExe, 'unused', $false, 'WinSta0\Default')
    }

    # =========================================================================
    # STEP 1: CREATE SUSPENDED LAYER-2 FOR BOTH A & B + 6-WAY HANDLE AUDIT
    # =========================================================================
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $readyPath = Join-Path $sp.scratch 'l1-ready.json'
        $sp.l1Stop = Join-Path $sp.scratch 'l1-stop'
        $l1Args = "`"$($sp.psecBin)`" `"$($sp.clientExe)`" `"$($sp.clientCfgPath)`" `"$($sp.scratch)`" `"$hostSid`" `"$readyPath`" `"$($sp.l1Stop)`""

        $sp.l1 = [StudioPsecGuardHost]::StartSuspended($sp.copyToken, $sp.launcherExe, $l1Args, $true, 'WinSta0\Default')
        $restore = $sp.l1.RestoreTokenObjectDaclOnly($sp.origToken, $hostSid, $sp.accountSid)
        $report.spaces[$k].layer1Restore = $restore
        if (!$restore.processSecurityAfterRestore.hardenedExpected -or !$restore.threadSecurityAfterRestore.hardenedExpected) {
            throw "Layer-1 $k SD weakened after token object DACL restore"
        }
        [void]$sp.l1.ResumeMainThread()
        $poll = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $readyPath) -and $poll.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
        if (!(Test-Path -LiteralPath $readyPath)) { throw "Layer-1 $k did not write ready receipt" }
        $sp.l1Receipt = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $report.spaces[$k].layer1 = $sp.l1Receipt
        if (!$sp.l1Receipt.psecCreated -or !$sp.l1Receipt.childCreated -or !$sp.l1Receipt.childInJob) {
            throw ("Layer-1 $k PSEC creation failed: " + ($sp.l1Receipt | ConvertTo-Json -Compress))
        }

        $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, $hostSid, $sp.accountSid)
        $report.spaces[$k].targetSuspendedInspect = $insp
        $sp.containerSid = $insp.identity.containerSid
        $idOk = $insp.identity.userSid -ceq $sp.accountSid -and
            !$insp.identity.admin -and $insp.identity.appContainer -and
            ($sp.containerSid -match '^S-1-15-2(-[0-9]+){7}$') -and
            (@($insp.identity.networkCapabilities).Count -eq 1) -and ($insp.identity.networkCapabilities[0] -ceq $loopbackCapSid) -and
            $insp.identity.inJob -and ($insp.threadUserTime -eq 0) -and ($insp.threadKernelTime -eq 0) -and
            $insp.processSecurity.hardenedExpected -and $insp.threadSecurity.hardenedExpected
        $report.spaces[$k].suspendedIdentityOk = $idOk
        if (!$idOk) { throw "Suspended Layer-2 $k failed identity/capability/SD pre-check" }

        [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$sp.l1Receipt.childPid, $hostSid, $sp.containerSid)
    }

    $report.checks.distinctIdentities = ($spaces.A.accountSid -cne $spaces.B.accountSid) -and ($spaces.A.containerSid -cne $spaces.B.containerSid)
    $report.checks.targetSuspendedIdentity = $report.spaces.A.suspendedIdentityOk -and $report.spaces.B.suspendedIdentityOk -and $report.checks.distinctIdentities
    if (!$report.checks.targetSuspendedIdentity) { throw 'Dual-space suspended identity check failed' }

    # 6-way handle audit: same-user distinct logon, same-user same logon, AND cross-user!
    $allViolations = @()
    $ordinaryPositiveOk = $true
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $peer = $spaces[$sp.peerKey]
        $audSameDistinct = [StudioPsecGuardHost]::RunAudit($sp.auditorToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks,
            $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $audSameLogon = [StudioPsecGuardHost]::RunAudit($sp.origToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks,
            $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $audCrossUser = [StudioPsecGuardHost]::RunAudit($peer.auditorToken, $sp.ordinaryHeld.Pid, $sp.ordinaryHeld.Tid, $sp.ordinaryHeld.StartTicks,
            $sp.l1.Pid, $sp.l1.Tid, $sp.l1.StartTicks, [int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid, [long]$sp.l1Receipt.childStartTicks)
        $report.spaces[$k].auditSameDistinct = $audSameDistinct
        $report.spaces[$k].auditSameLogon = $audSameLogon
        $report.spaces[$k].auditCrossUser = $audCrossUser

        $m1 = @{}; foreach ($t in $audSameDistinct.targets) { $m1[$t.role] = $t }
        $m2 = @{}; foreach ($t in $audSameLogon.targets) { $m2[$t.role] = $t }
        $m3 = @{}; foreach ($t in $audCrossUser.targets) { $m3[$t.role] = $t }
        if (!(Test-GrantedAll $m1['ordinary']) -or !(Test-GrantedAll $m2['ordinary'])) { $ordinaryPositiveOk = $false }
        foreach ($r in 'layer1','layer2') {
            $allViolations += Get-Violations $m1[$r] "${k}-SameDistinct"
            $allViolations += Get-Violations $m2[$r] "${k}-SameLogon"
            $allViolations += Get-Violations $m3[$r] "${k}-CrossFrom$($peer.key)"
        }
        # Cross-user must also be denied on peer's ordinary process!
        $allViolations += Get-Violations $m3['ordinary'] "${k}-OrdinaryCrossFrom$($peer.key)"
    }
    $report.handleViolations = $allViolations
    $report.checks.handleGatePassed = $ordinaryPositiveOk -and ($allViolations.Count -eq 0)
    if (!$report.checks.handleGatePassed) { throw 'Dual-space 6-way handle gate failed' }

    # =========================================================================
    # STEP 2: PRE-STARTUP 4-STATIC-BLOCK WFP INSTALL + READBACK + RESUME (A & B)
    # =========================================================================
    $bothMonotonic = $true
    $bothColdBlocked = $true
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.wfpSub = [guid]::NewGuid()
        $sp.wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
        $wfpGuard = [StudioLabWfp]::CreateStaticGuard()
        try {
            $sp.wfpWeight = $wfpGuard.PrepareStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.clientExe)
            $report.spaces[$k].wfpArbitration = [ordered]@{
                chosenSublayerWeight = $sp.wfpWeight
                totalExamined = @($wfpGuard.PriorityEvidence).Count
                excludedByApplicationCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.excludedByApplication }).Count
                singTunExcludedCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.excludedByApplication -and ($_.filterName -match 'sing' -or $_.sublayerName -match 'sing') }).Count
                requiringHigherPriorityCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.requiresHigherPriority }).Count
            }
            $manifest = [ordered]@{
                runId = $RunId; space = $k; containerSid = $sp.containerSid; sublayer = $sp.wfpSub.ToString();
                keys = @($sp.wfpKeys | ForEach-Object { $_.ToString() }); proxyPort = $sp.proxyPort; weight = $sp.wfpWeight;
                clientExe = $sp.clientExe; clientSha256 = $report.clientSha256
            }
            [IO.File]::WriteAllText($sp.manifestFile, ($manifest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
            $report.spaces[$k].wfpManifest = $manifest

            $qpcCommitStart = [StudioPsecGuardHost]::QpcNow()
            $wfpGuard.InstallStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.clientExe, $sp.wfpWeight)
            $qpcCommitEnd = [StudioPsecGuardHost]::QpcNow()
            $sp.wfpInstalled = $true
            $report.wfpStaticWrites += 4
        } finally { $wfpGuard.Dispose() }

        $qpcRbStart = [StudioPsecGuardHost]::QpcNow()
        $rbCold = [StudioLabWfp]::VerifyStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.wfpWeight, $false)
        $qpcRbEnd = [StudioPsecGuardHost]::QpcNow()
        $report.spaces[$k].wfpColdReadback = $rbCold

        $resume = [StudioPsecGuardHost]::HostResumeChildOnly([int]$sp.l1Receipt.childPid, [int]$sp.l1Receipt.childTid)
        $report.spaces[$k].targetResume = $resume

        $coldResultPath = Join-Path $sp.scratch 'cold-result.json'
        $swCold = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $coldResultPath) -and $swCold.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
        if (!(Test-Path -LiteralPath $coldResultPath)) { throw "Layer-2 $k did not write cold-result.json" }
        $cold = Get-Content -LiteralPath $coldResultPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $coldSent = $sentinels.DrainMarkers()
        $report.spaces[$k].coldProbe = $cold
        $report.spaces[$k].coldSentinels = $coldSent

        $tQpc = [ordered]@{
            wfpCommitStart = $qpcCommitStart; wfpCommitEnd = $qpcCommitEnd
            wfpReadbackStart = $qpcRbStart; wfpReadbackEnd = $qpcRbEnd
            hostResumeBefore = $resume.qpcBeforeResume; hostResumeAfter = $resume.qpcAfterResume
            probeEntry = $cold.qpcEntry; probeFirstSocket = $cold.qpcFirstSocket; probeDone = $cold.qpcDone
        }
        $report.spaces[$k].timingQpc = $tQpc
        $mono = ($tQpc.wfpCommitStart -le $tQpc.wfpCommitEnd) -and
            ($tQpc.wfpCommitEnd -le $tQpc.wfpReadbackStart) -and
            ($tQpc.wfpReadbackStart -le $tQpc.wfpReadbackEnd) -and
            ($tQpc.wfpReadbackEnd -le $tQpc.hostResumeBefore) -and
            ($tQpc.hostResumeBefore -le $tQpc.probeEntry) -and
            ($tQpc.probeEntry -le $tQpc.probeFirstSocket) -and
            ($resume.previousSuspendCount -eq 1)
        $cBlk = (!$cold.directPa.connected -and $cold.directPa.error -eq 10013) -and
            ($null -ne $cold.crossPort -and !$cold.crossPort.connected -and $cold.crossPort.error -eq 10013) -and
            (!$cold.sentinelTcp.connected -and $cold.sentinelTcp.error -eq 10013) -and
            (!$cold.directPu.connected -and $cold.directPu.error -eq 10013) -and
            ($coldSent.tcpCount -eq 0 -and $coldSent.udpCount -eq 0) -and
            ($cold.dns.dnsQueryStatus -eq 5 -and $cold.dns.getAddrInfoStatus -ne 0)
        $report.spaces[$k].monotonicOrder = $mono
        $report.spaces[$k].coldStartBlocked = $cBlk
        if (!$mono) { $bothMonotonic = $false }
        if (!$cBlk) { $bothColdBlocked = $false }
    }
    $report.checks.distinctSublayerWeights = ($spaces.A.wfpWeight -ne $spaces.B.wfpWeight)
    $report.checks.monotonicOrder = $bothMonotonic
    $report.checks.coldStartBlocked = $bothColdBlocked
    if (!$bothMonotonic -or !$bothColdBlocked) { throw 'Dual-space pre-startup blocking or monotonic QPC check failed' }

    $null = Test-HostHealth 'blocked' 51

    # =========================================================================
    # STEP 3: CONCURRENT HEALTHY DUAL-SPACE PROXY-ONLY (healthy1)
    # =========================================================================
    $report.spaces.A.healthyOpen = Open-SpaceProxyGate $spaces.A
    $report.spaces.B.healthyOpen = Open-SpaceProxyGate $spaces.B

    $h1A = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' 'healthy1').data $true 'healthy1'
    $h1B = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' 'healthy1').data $true 'healthy1'
    $report.checks.concurrentHealthyAndCrossPortBlocked = $h1A.passed -and $h1B.passed -and $h1A.crossPortBlocked -and $h1B.crossPortBlocked
    $null = Test-HostHealth 'healthy1' 61

    # =========================================================================
    # STEP 4: FAULT 1 — INDEPENDENT SPACE ISOLATION (HARD-KILL ProxyOwner_A ONLY!)
    # =========================================================================
    $bHeldBeforeA = Start-AndWaitHeld $spaces.B 'healthy2'
    $aHeldBeforeA = Start-AndWaitHeld $spaces.A 'fault1'
    $bMarksBeforeKill = @{ http = @($bHeldBeforeA.http.marks).Count; tls = @($bHeldBeforeA.tls.marks).Count }

    $tKillA = [StudioPsecGuardHost]::QpcNow()
    Stop-SpaceProxyOwner $spaces.A -HardKill
    $cutA = Wait-SpaceCutoff $spaces.A $tKillA $false

    # Verify A is offline & A's old streams closed
    $f1AProbe = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' 'fault1').data $false 'fault1'
    $aHeldAfterA = (Invoke-SpaceCmd $spaces.A 'held' 'fault1').data
    $aOldClosed = ($aHeldAfterA.http.state -cnotin @('active','starting')) -and ($aHeldAfterA.tls.state -cnotin @('active','starting'))
    if (!$aOldClosed) { throw 'A old streams remained active after ProxyOwner_A hard kill' }

    # Verify B is 100% UNAFFECTED: E_B still present, B active streams STILL advancing, B healthy2 probe returns 200!
    $rbBStillOpen = [StudioLabWfp]::VerifyStatic($spaces.B.wfpSub, $spaces.B.wfpKeys, $spaces.B.containerSid, $spaces.B.proxyPort, $spaces.B.wfpWeight, $true)
    $swBAdv = [Diagnostics.Stopwatch]::StartNew()
    $bAdvanced = $false
    $bHeldAfterA = $null
    while ($swBAdv.ElapsedMilliseconds -lt 2500) {
        Start-Sleep -Milliseconds 120
        $bHeldAfterA = (Invoke-SpaceCmd $spaces.B 'held' 'healthy2').data
        if ($bHeldAfterA.http.state -ceq 'active' -and $bHeldAfterA.tls.state -ceq 'active' -and
            @($bHeldAfterA.http.marks).Count -gt $bMarksBeforeKill.http -and
            @($bHeldAfterA.tls.marks).Count -gt $bMarksBeforeKill.tls) {
            $bAdvanced = $true; break
        }
    }
    $h2BProbe = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' 'healthy2').data $true 'healthy2'
    if (!$bAdvanced -or !$h2BProbe.passed -or !$rbBStillOpen.exceptionPresent) {
        throw "B was impacted when ProxyOwner_A was killed (bAdvanced=$bAdvanced, eB=$($rbBStillOpen.exceptionPresent))"
    }

    # Recover A and confirm A old streams do NOT replay
    $null = Open-SpaceProxyGate $spaces.A
    $h2AProbe = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' 'healthy2').data $true 'healthy2'
    $aHeldAfterRec = (Invoke-SpaceCmd $spaces.A 'held' 'healthy2').data
    $aNoReplay = ($aHeldAfterRec.http.marker -ceq $aHeldAfterA.http.marker) -and ($aHeldAfterRec.tls.marker -ceq $aHeldAfterA.tls.marker) -and
        ((@($aHeldAfterRec.http.marks) -join ',') -ceq (@($aHeldAfterA.http.marks) -join ',')) -and
        ((@($aHeldAfterRec.tls.marks) -join ',') -ceq (@($aHeldAfterA.tls.marks) -join ','))
    if (!$aNoReplay) { throw 'A old streams replayed after ProxyOwner_A recovery' }

    $f1Rec = [ordered]@{
        name = 'a-only-owner-exit'
        kind = 'owner-exit-a-only'
        aCutoffMs = $cutA.cutoffMs
        aCloseReason = $cutA.entryCloseReason
        aExceptionAbsentReadback = $cutA.exceptionAbsentReadback
        aOfflineProbePassed = $f1AProbe.passed
        aRecovered = $h2AProbe.passed
        aOldNoReplayAfterRecovery = $aNoReplay
        bExceptionStillPresent = ($rbBStillOpen.exceptionPresent -eq $true)
        bActiveStreamsAdvanced = $bAdvanced
        bMarksBefore = $bMarksBeforeKill
        bMarksAfter = @{ http = @($bHeldAfterA.http.marks).Count; tls = @($bHeldAfterA.tls.marks).Count }
        bHealthyProbePassed = $h2BProbe.passed
    }
    $report.faults += @($f1Rec)
    $report.checks.independentSpaceIsolation = ($cutA.cutoffMs -le 3000.0) -and $cutA.exceptionAbsentReadback -and
        $f1AProbe.passed -and $h2AProbe.passed -and $aNoReplay -and
        $f1Rec.bExceptionStillPresent -and $bAdvanced -and $h2BProbe.passed

    # =========================================================================
    # STEP 5: SHARED UPSTREAM FAULTS (refuse, silent, upstream-exit)
    # =========================================================================
    $sharedSpecs = @(
        @{ name = 'shared-refuse'; kind = 'refuse'; faultPhase = 'fault2'; recPhase = 'healthy3'; recover = $true; hostCheck = $false },
        @{ name = 'shared-silent'; kind = 'silent'; faultPhase = 'fault3'; recPhase = 'healthy4'; recover = $true; hostCheck = $true },
        @{ name = 'shared-upstream-exit'; kind = 'upstream-exit'; faultPhase = 'fault4'; recPhase = 'none'; recover = $false; hostCheck = $false }
    )
    $allSharedOk = $true
    foreach ($spec in $sharedSpecs) {
        $beforeA = Start-AndWaitHeld $spaces.A $spec.faultPhase
        $beforeB = Start-AndWaitHeld $spaces.B $spec.faultPhase

        $tInj = [StudioPsecGuardHost]::QpcNow()
        if ($spec.kind -eq 'refuse' -or $spec.kind -eq 'silent') {
            $null = Invoke-N3Child $topology.upstream $spec.kind
        } elseif ($spec.kind -eq 'upstream-exit') {
            $topology.upstream.process.Kill()
            [void]$topology.upstream.process.WaitForExit(2000)
            $topology.upstream.process.Dispose()
            $topology.upstream = $null
        }

        $cutBothA = Wait-SpaceCutoff $spaces.A $tInj $true
        $cutBothB = Wait-SpaceCutoff $spaces.B $tInj $true

        $offA = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' $spec.faultPhase).data $false $spec.faultPhase
        $offB = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' $spec.faultPhase).data $false $spec.faultPhase
        $afterA = (Invoke-SpaceCmd $spaces.A 'held' $spec.faultPhase).data
        $afterB = (Invoke-SpaceCmd $spaces.B 'held' $spec.faultPhase).data
        $oldClosedA = ($afterA.http.state -cnotin @('active','starting')) -and ($afterA.tls.state -cnotin @('active','starting'))
        $oldClosedB = ($afterB.http.state -cnotin @('active','starting')) -and ($afterB.tls.state -cnotin @('active','starting'))
        if (!$oldClosedA -or !$oldClosedB) { throw "Old streams still active after $($spec.name) (A=$oldClosedA, B=$oldClosedB)" }

        if ($spec.hostCheck) {
            $null = Test-HostHealth $spec.faultPhase 71
        }

        $recAOk = $false; $recBOk = $false; $noRepA = $null; $noRepB = $null
        if ($spec.recover) {
            $null = Invoke-N3Child $topology.upstream 'serve'
            $null = Open-SpaceProxyGate $spaces.A
            $null = Open-SpaceProxyGate $spaces.B
            $recA = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' $spec.recPhase).data $true $spec.recPhase
            $recB = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' $spec.recPhase).data $true $spec.recPhase
            $postA = (Invoke-SpaceCmd $spaces.A 'held' $spec.recPhase).data
            $postB = (Invoke-SpaceCmd $spaces.B 'held' $spec.recPhase).data
            $noRepA = ($postA.http.marker -ceq $afterA.http.marker) -and ($postA.tls.marker -ceq $afterA.tls.marker) -and
                ((@($postA.http.marks) -join ',') -ceq (@($afterA.http.marks) -join ',')) -and
                ((@($postA.tls.marks) -join ',') -ceq (@($afterA.tls.marks) -join ','))
            $noRepB = ($postB.http.marker -ceq $afterB.http.marker) -and ($postB.tls.marker -ceq $afterB.tls.marker) -and
                ((@($postB.http.marks) -join ',') -ceq (@($afterB.http.marks) -join ',')) -and
                ((@($postB.tls.marks) -join ',') -ceq (@($afterB.tls.marks) -join ','))
            if (!$noRepA -or !$noRepB) { throw "Old streams replayed after recovery from $($spec.name) (A=$noRepA, B=$noRepB)" }
            $recAOk = $recA.passed; $recBOk = $recB.passed
        }

        $fRec = [ordered]@{
            name = $spec.name
            kind = $spec.kind
            aCutoffMs = $cutBothA.cutoffMs
            bCutoffMs = $cutBothB.cutoffMs
            aCloseReason = $cutBothA.entryCloseReason
            bCloseReason = $cutBothB.entryCloseReason
            aExceptionAbsentReadback = $cutBothA.exceptionAbsentReadback
            bExceptionAbsentReadback = $cutBothB.exceptionAbsentReadback
            aOfflineProbePassed = $offA.passed
            bOfflineProbePassed = $offB.passed
            aRecovered = $recAOk
            bRecovered = $recBOk
            aOldNoReplay = $noRepA
            bOldNoReplay = $noRepB
        }
        $report.faults += @($fRec)
        $stepOk = ($cutBothA.cutoffMs -le 3000.0) -and ($cutBothB.cutoffMs -le 3000.0) -and
            $cutBothA.exceptionAbsentReadback -and $cutBothB.exceptionAbsentReadback -and
            $offA.passed -and $offB.passed -and
            (!$spec.recover -or ($recAOk -and $recBOk -and $noRepA -and $noRepB))
        if (!$stepOk) { $allSharedOk = $false }
    }
    $report.checks.sharedUpstreamFaultsConvergedAndRecovered = $allSharedOk

    # Gracefully finish both Layer-2 clients
    foreach ($k in @('A', 'B')) {
        try { $null = Invoke-SpaceCmd $spaces[$k] 'finish' 'done' 3000 } catch { }
    }
} catch {
    $report.error = Get-ErrDetail $_
} finally {
    # 1. Stop ProxyOwners & Layer-1/Layer-2/Ordinary processes for both A & B
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        try { Stop-SpaceProxyOwner $sp } catch { $report.cleanup.errors += @("stop-owner-$k`: $($_.Exception.Message)") }
        if ($sp.l1Stop -and $sp.scratch -and (Test-Path -LiteralPath $sp.scratch)) {
            try { [IO.File]::WriteAllText($sp.l1Stop, 'stop') } catch { }
        }
        if ($sp.l1Receipt -and $sp.l1Receipt.childPid) {
            try { [StudioPsecGuardHost]::HostTerminatePid([int]$sp.l1Receipt.childPid) } catch { }
        }
        if ($sp.l1) {
            try {
                $report.cleanup["layer1Exit_$k"] = $sp.l1.WaitExit(4000)
                $sp.l1.Dispose()
            } catch { $report.cleanup.errors += @("layer1-$k`: $($_.Exception.Message)") }
            $sp.l1 = $null
        }
        if ($sp.ordinaryHeld) {
            try { $report.cleanup["ordinaryExit_$k"] = $sp.ordinaryHeld.TerminateNow(); $sp.ordinaryHeld.Dispose() }
            catch { $report.cleanup.errors += @("ordinary-$k`: $($_.Exception.Message)") }
            $sp.ordinaryHeld = $null
        }
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
            if ($topology[$role]) {
                try { Stop-N3Process $topology[$role] } catch { $report.cleanup.errors += @("stop-$role`: $($_.Exception.Message)") }
                $topology[$role] = $null
            }
        }
    }
    Start-Sleep -Milliseconds 200

    # Verify 0 remaining fixture processes for A & B
    $allowedExes = @($spaces.A.launcherExe, $spaces.A.clientExe, $spaces.B.launcherExe, $spaces.B.clientExe, $ownerExe) | Where-Object { $_ }
    $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Psec.exe' OR Name = 'StudioBLayer1Psec.exe' OR Name = 'StudioAPhase2Client.exe' OR Name = 'StudioBPhase2Client.exe' OR Name = 'StudioPhase2ProxyOwner.exe'" | Where-Object {
        $_.ExecutablePath -in $allowedExes
    })
    foreach ($p in $rem) { $report.cleanup.remainingPids += @([int]$p.ProcessId) }

    # 2. Remove static WFP rules & sublayers for BOTH A and B (only when 0 remaining PIDs)
    $allWfpRemoved = $true
    if ($report.cleanup.remainingPids.Count -eq 0) {
        foreach ($k in @('A', 'B')) {
            $sp = $spaces[$k]
            if ($sp.wfpInstalled -and $assemblyLoaded) {
                try {
                    [StudioLabWfp]::RemoveStatic($sp.wfpSub, $sp.wfpKeys, $sp.containerSid, $sp.proxyPort, $sp.wfpWeight)
                    Start-Sleep -Milliseconds 100
                    $res = [StudioLabWfp]::CountFiltersReferencingPackage($sp.containerSid)
                    $report.cleanup["wfpRemoved_$k"] = $true
                    $report.cleanup["residualPackageFilters_$k"] = $res
                    if ($res -ne 0) { $allWfpRemoved = $false }
                } catch {
                    $report.cleanup["wfpRemoved_$k"] = $false
                    $allWfpRemoved = $false
                    $report.cleanup.errors += @("wfp-remove-$k`: $($_.Exception.Message)")
                }
            }
        }
    } else {
        $allWfpRemoved = $false
        $report.cleanup.errors += @('Refused WFP removal because target PIDs remained')
    }
    $report.cleanup.wfpRemovedAndVerifiedAbsent = $allWfpRemoved

    # 3. Host restored health + DNS ETW stop + desktop digest
    if ($hostListener -and $hostOld) {
        try { $null = Test-HostHealth 'restored' 81 } catch { $report.cleanup.errors += @("host-restored: $($_.Exception.Message)") }
    }
    if ($dnsTrace) {
        try {
            $dnsResult = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $report.dnsTrace = $dnsResult
            $psecSendReply = @($dnsResult.events | Where-Object { $_.role -eq 'psec' -and ($_.event -in 3010, 3011) }).Count
            $unknownSendReply = @($dnsResult.events | Where-Object { !$_.role -and ($_.event -in 3010, 3011) }).Count
            $hostSends = @($dnsResult.events | Where-Object { $_.role -eq 'host' -and $_.event -eq 3010 }).Count
            $lossZero = ($null -ne $dnsResult.lossBeforeStop) -and
                ($dnsResult.lossBeforeStop.eventsLost -eq 0) -and
                ($dnsResult.lossBeforeStop.logBuffersLost -eq 0) -and
                ($dnsResult.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsResult.servicePid -eq $dnsResult.servicePidAfter)
                lossZero = $lossZero
                psecSendReplyCount = $psecSendReply
                unknownSendReplyCount = $unknownSendReply
                hostSendCount = $hostSends
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lossZero -and
                ($psecSendReply -eq 0) -and ($unknownSendReply -eq 0) -and ($hostSends -ge 5)
        } catch {
            $report.cleanup.errors += @("dns-stop: $($_.Exception.Message)")
            $report.checks.dnsZeroLeak = $false
        }
    }

    if ($sentinels) { try { $sentinels.Dispose() } catch { } }
    if ($hostOld) { try { Close-GatePair $hostOld } catch { } }
    if ($hostListener) { try { $hostListener.Dispose() } catch { } }

    if ($assemblyLoaded) {
        try {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()
            $defaultMatch = ($report.defaultDesktopBefore.readable -eq $report.defaultDesktopAfter.readable) -and
                ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
            $report.desktopAclUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
                $defaultMatch
            $report.checks.desktopUnchanged = $report.desktopAclUnchanged
        } catch {
            $report.cleanup.errors += @("desktop-after: $($_.Exception.Message)")
            $report.checks.desktopUnchanged = $false
        }
    }

    # 4. Unload profiles, close tokens, delete temp dirs, remove BOTH A & B accounts & profiles
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        if ($assemblyLoaded) {
            try { [StudioPsecGuardHost]::UnloadLabProfile($sp.origToken, $sp.loadedProfileHandle) } catch { $report.cleanup.errors += @("unload-$k`: $($_.Exception.Message)") }
            foreach ($tName in @('auditorToken', 'ordinaryToken', 'copyToken', 'origToken')) {
                if ($sp[$tName] -ne [IntPtr]::Zero) {
                    try { [StudioPsecGuardHost]::CloseToken($sp[$tName]) } catch { }
                    $sp[$tName] = [IntPtr]::Zero
                }
            }
        }
        if ($sp.workRoot -and (Test-Path -LiteralPath $sp.workRoot)) {
            try { Remove-Item -LiteralPath $sp.workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
        if ($sp.accountCreated) {
            try {
                if ($sp.accountSid) {
                    $prof = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $sp.accountSid + "'") -ErrorAction SilentlyContinue
                    if ($prof) { Remove-CimInstance -InputObject $prof -ErrorAction Stop }
                }
            } catch { $report.cleanup.errors += @("remove-profile-$k`: $($_.Exception.Message)") }
            try {
                $profDir = "C:\Users\$($sp.userName)"
                if (Test-Path -LiteralPath $profDir) { Remove-Item -LiteralPath $profDir -Recurse -Force -ErrorAction Stop }
            } catch { $report.cleanup.errors += @("remove-profile-dir-$k`: $($_.Exception.Message)") }
            try { Remove-LocalUser -Name $sp.userName -ErrorAction Stop }
            catch { $report.cleanup.errors += @("remove-user-$k`: $($_.Exception.Message)") }
        }
    }

    if ($dirCreated -and (Test-Path -LiteralPath $base) -and $allWfpRemoved) {
        try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop }
        catch { $report.cleanup.errors += @("remove-base: $($_.Exception.Message)") }
    }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.labBProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabB')
    $report.cleanup.labAProfileRecordGone = !($spaces.A.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.A.accountSid + "'") -ErrorAction SilentlyContinue))
    $report.cleanup.labBProfileRecordGone = !($spaces.B.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.B.accountSid + "'") -ErrorAction SilentlyContinue))

    $hostOk = $true
    foreach ($st in @('baseline', 'blocked', 'healthy1', 'fault3', 'restored')) {
        $h = $report.hostHealth[$st]
        if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hostOk = $false }
    }
    $report.checks.hostContinuous = $hostOk

    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and
        ($report.cleanup.remainingPids.Count -eq 0) -and
        $report.cleanup.wfpRemovedAndVerifiedAbsent -and
        $report.cleanup.directoryGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labBProfileDirGone -and
        $report.cleanup.labAProfileRecordGone -and $report.cleanup.labBProfileRecordGone

    $allPassed = (!$report.error) -and
        $report.checks.targetSuspendedIdentity -and
        $report.checks.handleGatePassed -and
        $report.checks.distinctSublayerWeights -and
        $report.checks.monotonicOrder -and
        $report.checks.coldStartBlocked -and
        $report.checks.concurrentHealthyAndCrossPortBlocked -and
        $report.checks.independentSpaceIsolation -and
        $report.checks.sharedUpstreamFaultsConvergedAndRecovered -and
        $report.checks.dnsZeroLeak -and
        $report.checks.hostContinuous -and
        $report.checks.desktopUnchanged -and
        $report.checks.cleanup

    if ($allPassed) { $report.outcome = 'passed-ab-phase2-dual-space' }
    else { $report.outcome = 'stopped-ab-phase2-dual-space' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    $json = $report | ConvertTo-Json -Depth 14
    [IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
    $hash12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)

    $summary = [ordered]@{
        runId = $RunId
        outcome = $report.outcome
        reportPath = $ReportPath
        reportSha256Prefix12 = $hash12
        error = $report.error
        ports = $report.ports
        weights = [ordered]@{ A = $spaces.A.wfpWeight; B = $spaces.B.wfpWeight }
        checks = $report.checks
        faults = $report.faults
        dnsSummary = $report.dnsSummary
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
