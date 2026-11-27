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
            } else { $l.Stop() }
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

function Get-CanonicalDir([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -and $item.Target) {
        $t = if ($item.Target -is [array]) { $item.Target[0] } else { [string]$item.Target }
        return ([IO.Path]::GetFullPath($t)).TrimEnd('\').ToLowerInvariant()
    }
    return ([IO.Path]::GetFullPath($item.FullName)).TrimEnd('\').ToLowerInvariant()
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    if (!(Test-Path -LiteralPath $reportDir)) { throw "Expected report directory: $reportDir" }
    $ReportPath = Join-Path $reportDir ('windows-ab-phase3-dual-workflow-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioABPhase3-summary-' + $RunId + '.json')
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
$tag = 'ClaudeStudioABPhase3-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$projectRoot = Join-Path $env:ProgramData $tag
$sharedRepo = Join-Path $projectRoot 'shared-repo'
$sharedAlias = Join-Path $projectRoot 'shared-alias'
$ungrantedRepo = Join-Path $projectRoot 'ungranted-repo'
$buildDir = Join-Path $base 'build'
$n3Dir = Join-Path $base 'n3'
$harnessDll = Join-Path $base 'StudioPhase3Harness.dll'
$ownerExe = Join-Path $base 'StudioPhase3ProxyOwner.exe'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId
    prefix = $prefix
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase3-dual-workflow'
    nativeIPv6 = 'readback only'
    ipv4Inbound = 'readback only'
    hostSid = $hostSid
    wfpStaticWrites = 0
    sources = [ordered]@{}
    spaces = [ordered]@{ A = [ordered]@{ launches = @() }; B = [ordered]@{ launches = @() } }
    workflow = [ordered]@{}
    localeTimezoneMatrix = [ordered]@{}
    checks = [ordered]@{}
    hostHealth = [ordered]@{}
    phases = @()
    cleanup = [ordered]@{ errors = @(); remainingPids = @(); retiredContainerSids = @() }
}

$dirCreated = $false
$projectRootCreated = $false
$assemblyLoaded = $false
$dnsTrace = $null
$sentinels = $null
$hostListener = $null
$hostOld = $null
$topology = $null
$activeWriterLeases = @{}

function New-SpaceState([string]$Key, [string]$UserName, [string]$Email, [string]$UiLang, [string]$AcceptLang, [string]$RendererTz, [int]$TzOffsetMin, [string]$ChildLang) {
    return @{
        key = $Key
        peerKey = if ($Key -eq 'A') { 'B' } else { 'A' }
        userName = $UserName
        email = $Email
        uiLang = $UiLang
        acceptLang = $AcceptLang
        rendererTz = $RendererTz
        tzOffsetMin = $TzOffsetMin
        childLang = $ChildLang
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
        profileDir = $null
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
        proxyPort = [uint16]0
        peerPort = [uint16]0
        entry = $null
        entryLog = $null
        settingsPath = $null
        proxyOwner = $null
        cmdSeq = 0
        launchCount = 0
    }
}

$spaces = [ordered]@{
    A = New-SpaceState 'A' 'ClaudeStudioLabA' 'a@example.invalid' 'zh-CN' 'zh-CN,zh;q=0.9' 'Asia/Shanghai' 480 'zh_CN.UTF-8'
    B = New-SpaceState 'B' 'ClaudeStudioLabB' 'b@example.invalid' 'en-US' 'en-US,en;q=0.9' 'America/Los_Angeles' -420 'en_US.UTF-8'
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
                if ($line.Trim().Length -gt 0) { $rows += @($line | ConvertFrom-Json) }
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

function Stop-SpaceProxyOwner($Sp) {
    $Owner = $Sp.proxyOwner
    if (!$Owner) { return }
    try {
        if (!$Owner.process.HasExited) {
            try { $Owner.process.StandardInput.WriteLine('exit'); $Owner.process.StandardInput.Close() } catch { }
            if (!$Owner.process.WaitForExit(2000)) { $Owner.process.Kill(); [void]$Owner.process.WaitForExit(2000) }
        }
    } finally {
        $Owner.process.Dispose()
        $Sp.proxyOwner = $null
    }
}

function Open-SpaceProxyGate($Sp) {
    if (!$Sp.proxyOwner -or $Sp.proxyOwner.process.HasExited) { $Sp.proxyOwner = Start-SpaceProxyOwner $Sp }
    $armCmd = "arm-owner $($Sp.proxyOwner.ready.pid) $($Sp.proxyOwner.ready.startTicks)"
    $armed = Invoke-N3Child $Sp.entry $armCmd 3000
    if (!$armed.admitting -or !$armed.lastProbe.ok) { throw "Entry_$($Sp.key) arm-owner failed health check" }
    $opened = Invoke-ProxyOwner $Sp.proxyOwner 'open'
    if (!$opened.open) { throw "ProxyOwner_$($Sp.key) failed to open dynamic exception E" }
    $rb = [StudioLabWfp]::VerifyStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight, $true)
    return [ordered]@{ space = $Sp.key; ownerPid = $Sp.proxyOwner.ready.pid; armed = $armed; readback = $rb }
}

function Invoke-SpaceCmd($Sp, [string]$Action, [string]$Phase = 'none', [string]$Arg1 = '', [string]$Arg2 = '', [string]$Arg3 = '', [int]$TimeoutMs = 12000) {
    $Sp.cmdSeq++
    $seq = $Sp.cmdSeq
    $cmdPath = Join-Path $Sp.scratch ("cmd-$seq.cfg")
    $resPath = Join-Path $Sp.scratch ("res-$seq.json")
    $tmp = $cmdPath + '.tmp'
    $lines = @("action=$Action", "phase=$Phase")
    if ($Arg1 -ne '') { $lines += "arg1=$Arg1" }
    if ($Arg2 -ne '') { $lines += "arg2=$Arg2" }
    if ($Arg3 -ne '') { $lines += "arg3=$Arg3" }
    [IO.File]::WriteAllText($tmp, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($tmp, $cmdPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $resPath) -and $sw.ElapsedMilliseconds -lt $TimeoutMs) { Start-Sleep -Milliseconds 20 }
    if (!(Test-Path -LiteralPath $resPath)) { throw "Layer-2 $($Sp.key) did not respond to $Action ($Phase) within ${TimeoutMs}ms" }
    return (Get-Content -LiteralPath $resPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Set-RepoSingleWriterAcl([string]$WriterKey) {
    $readerKey = if ($WriterKey -eq 'A') { 'B' } else { 'A' }
    $acl = New-PrivateAcl $hostSid
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($spaces[$WriterKey].accountSid),
        [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($spaces[$readerKey].accountSid),
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-15-2-1'),
        [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $sharedRepo -AclObject $acl
    Get-ChildItem -LiteralPath $sharedRepo -Recurse -Force | ForEach-Object {
        $subAcl = Get-Acl -LiteralPath $_.FullName
        $subAcl.SetAccessRuleProtection($false, $false)
        Set-Acl -LiteralPath $_.FullName -AclObject $subAcl
    }
    $canon = Get-CanonicalDir $sharedRepo
    $activeWriterLeases[$canon] = $WriterKey
}

function Request-WriterLease([string]$SpaceKey, [string]$CandidatePath) {
    $canon = Get-CanonicalDir $CandidatePath
    if ($activeWriterLeases.ContainsKey($canon) -and $activeWriterLeases[$canon] -cne $SpaceKey) {
        return [ordered]@{ granted = $false; reason = 'WRITE_CONFLICT'; canonicalPath = $canon; holder = $activeWriterLeases[$canon] }
    }
    $activeWriterLeases[$canon] = $SpaceKey
    return [ordered]@{ granted = $true; reason = 'OK'; canonicalPath = $canon; holder = $SpaceKey }
}

function Stop-SpaceContainer($Sp) {
    try { $null = Invoke-SpaceCmd $Sp 'finish' 'done' '' '' '' 2500 } catch { }
    Stop-SpaceProxyOwner $Sp
    if ($Sp.l1Stop -and $Sp.scratch -and (Test-Path -LiteralPath $Sp.scratch)) {
        try { [IO.File]::WriteAllText($Sp.l1Stop, 'stop') } catch { }
    }
    if ($Sp.l1Receipt -and $Sp.l1Receipt.childPid) {
        try { [StudioPsecGuardHost]::HostTerminatePid([int]$Sp.l1Receipt.childPid) } catch { }
    }
    if ($Sp.l1) {
        try { [void]$Sp.l1.WaitExit(4000); $Sp.l1.Dispose() } catch { }
        $Sp.l1 = $null
    }
    Start-Sleep -Milliseconds 180
    if ($Sp.wfpInstalled -and $assemblyLoaded) {
        [StudioLabWfp]::RemoveStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight)
        Start-Sleep -Milliseconds 80
        $res = [StudioLabWfp]::CountFiltersReferencingPackage($Sp.containerSid)
        if ($res -ne 0) { throw "Residual WFP filters ($res) after stopping $($Sp.key)" }
        $report.cleanup.retiredContainerSids += @($Sp.containerSid)
        $Sp.wfpInstalled = $false
    }
    if ($Sp.scratch -and (Test-Path -LiteralPath $Sp.scratch)) {
        Get-ChildItem -LiteralPath $Sp.scratch -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    $Sp.l1Receipt = $null
    $Sp.cmdSeq = 0
}

function Start-SpaceContainer($Sp, [string]$RepoMode, [string]$ColdPhaseName, [bool]$RunSixWayAudit = $false) {
    $Sp.launchCount++
    $rwDirs = @($Sp.scratch, $Sp.profileDir)
    $roDirs = @($Sp.sealed)
    if ($RepoMode -eq 'rw') { $rwDirs += @($sharedRepo) }
    elseif ($RepoMode -eq 'ro') { $roDirs += @($sharedRepo) }

    $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Multi([string[]]$rwDirs, [string[]]$roDirs, $false)
    [IO.File]::WriteAllBytes($Sp.psecBin, $psecBytes)

    $peer = $spaces[$Sp.peerKey]
    $cfgText = @(
        "space=$($Sp.key)"
        "email=$($Sp.email)"
        "uiLang=$($Sp.uiLang)"
        "acceptLang=$($Sp.acceptLang)"
        "rendererTz=$($Sp.rendererTz)"
        "tzOffsetMin=$($Sp.tzOffsetMin)"
        "childLang=$($Sp.childLang)"
        "prefix=$prefix"
        "host=$prefix-a-window-healthy.test"
        "pin=$($topology.pin)"
        "workDir=$($Sp.scratch)"
        "profileDir=$($Sp.profileDir)"
        "peerProfileDir=$($peer.profileDir)"
        "repoDir=$sharedRepo"
        "ungrantedDir=$ungrantedRepo"
        "coldPhase=$ColdPhaseName"
        "p=$($Sp.proxyPort)"
        "peerPort=$($Sp.peerPort)"
        "u=$($topology.portPu)"
        "http=$($topology.targetReady.http)"
        "tls=$($topology.targetReady.tls)"
        "sentinelTcp=$($sentinels.TcpPort)"
        "sentinelUdp=$($sentinels.UdpPort)"
    ) -join "`n"
    [IO.File]::WriteAllText($Sp.clientCfgPath, $cfgText + "`n", (New-Object Text.UTF8Encoding($false)))

    $readyPath = Join-Path $Sp.scratch 'l1-ready.json'
    $Sp.l1Stop = Join-Path $Sp.scratch 'l1-stop'
    $l1Args = "`"$($Sp.psecBin)`" `"$($Sp.clientExe)`" `"$($Sp.clientCfgPath)`" `"$($Sp.scratch)`" `"$hostSid`" `"$readyPath`" `"$($Sp.l1Stop)`""

    $Sp.l1 = [StudioPsecGuardHost]::StartSuspended($Sp.copyToken, $Sp.launcherExe, $l1Args, $true, 'WinSta0\Default')
    $restore = $Sp.l1.RestoreTokenObjectDaclOnly($Sp.origToken, $hostSid, $Sp.accountSid)
    if (!$restore.processSecurityAfterRestore.hardenedExpected -or !$restore.threadSecurityAfterRestore.hardenedExpected) {
        throw "Layer-1 $($Sp.key) SD weakened after token object DACL restore"
    }
    [void]$Sp.l1.ResumeMainThread()
    $poll = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $readyPath) -and $poll.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    if (!(Test-Path -LiteralPath $readyPath)) { throw "Layer-1 $($Sp.key) did not write ready receipt" }
    $Sp.l1Receipt = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (!$Sp.l1Receipt.psecCreated -or !$Sp.l1Receipt.childCreated -or !$Sp.l1Receipt.childInJob) {
        throw ("Layer-1 $($Sp.key) PSEC creation failed: " + ($Sp.l1Receipt | ConvertTo-Json -Compress))
    }

    $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$Sp.l1Receipt.childPid, [int]$Sp.l1Receipt.childTid, $hostSid, $Sp.accountSid)
    $Sp.containerSid = $insp.identity.containerSid
    $idOk = $insp.identity.userSid -ceq $Sp.accountSid -and !$insp.identity.admin -and $insp.identity.appContainer -and
        ($Sp.containerSid -match '^S-1-15-2(-[0-9]+){7}$') -and
        (@($insp.identity.networkCapabilities).Count -eq 1) -and ($insp.identity.networkCapabilities[0] -ceq $loopbackCapSid) -and
        $insp.identity.inJob -and ($insp.threadUserTime -eq 0) -and ($insp.threadKernelTime -eq 0) -and
        $insp.processSecurity.hardenedExpected -and $insp.threadSecurity.hardenedExpected
    if (!$idOk) { throw "Suspended Layer-2 $($Sp.key) failed identity/capability/SD pre-check" }

    [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$Sp.l1Receipt.childPid, $hostSid, $Sp.containerSid)

    $auditViolations = @()
    $ordinaryPosOk = $true
    if ($RunSixWayAudit) {
        $aud1 = [StudioPsecGuardHost]::RunAudit($Sp.auditorToken, $Sp.ordinaryHeld.Pid, $Sp.ordinaryHeld.Tid, $Sp.ordinaryHeld.StartTicks,
            $Sp.l1.Pid, $Sp.l1.Tid, $Sp.l1.StartTicks, [int]$Sp.l1Receipt.childPid, [int]$Sp.l1Receipt.childTid, [long]$Sp.l1Receipt.childStartTicks)
        $aud2 = [StudioPsecGuardHost]::RunAudit($Sp.origToken, $Sp.ordinaryHeld.Pid, $Sp.ordinaryHeld.Tid, $Sp.ordinaryHeld.StartTicks,
            $Sp.l1.Pid, $Sp.l1.Tid, $Sp.l1.StartTicks, [int]$Sp.l1Receipt.childPid, [int]$Sp.l1Receipt.childTid, [long]$Sp.l1Receipt.childStartTicks)
        $aud3 = [StudioPsecGuardHost]::RunAudit($peer.auditorToken, $Sp.ordinaryHeld.Pid, $Sp.ordinaryHeld.Tid, $Sp.ordinaryHeld.StartTicks,
            $Sp.l1.Pid, $Sp.l1.Tid, $Sp.l1.StartTicks, [int]$Sp.l1Receipt.childPid, [int]$Sp.l1Receipt.childTid, [long]$Sp.l1Receipt.childStartTicks)
        $m1 = @{}; foreach ($t in $aud1.targets) { $m1[$t.role] = $t }
        $m2 = @{}; foreach ($t in $aud2.targets) { $m2[$t.role] = $t }
        $m3 = @{}; foreach ($t in $aud3.targets) { $m3[$t.role] = $t }
        if (!(Test-GrantedAll $m1['ordinary']) -or !(Test-GrantedAll $m2['ordinary'])) { $ordinaryPosOk = $false }
        foreach ($r in 'layer1','layer2') {
            $auditViolations += Get-Violations $m1[$r] "$($Sp.key)-SameDistinct"
            $auditViolations += Get-Violations $m2[$r] "$($Sp.key)-SameLogon"
            $auditViolations += Get-Violations $m3[$r] "$($Sp.key)-CrossFrom$($peer.key)"
        }
        $auditViolations += Get-Violations $m3['ordinary'] "$($Sp.key)-OrdinaryCrossFrom$($peer.key)"
        if (!$ordinaryPosOk -or $auditViolations.Count -gt 0) { throw "Handle audit failed for $($Sp.key)" }
    }

    $Sp.wfpSub = [guid]::NewGuid()
    $Sp.wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
    $wfpGuard = [StudioLabWfp]::CreateStaticGuard()
    try {
        $Sp.wfpWeight = $wfpGuard.PrepareStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.clientExe)
        $qpcCommitStart = [StudioPsecGuardHost]::QpcNow()
        $wfpGuard.InstallStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.clientExe, $Sp.wfpWeight)
        $qpcCommitEnd = [StudioPsecGuardHost]::QpcNow()
        $Sp.wfpInstalled = $true
        $report.wfpStaticWrites += 4
    } finally { $wfpGuard.Dispose() }

    $qpcRbStart = [StudioPsecGuardHost]::QpcNow()
    $null = [StudioLabWfp]::VerifyStatic($Sp.wfpSub, $Sp.wfpKeys, $Sp.containerSid, $Sp.proxyPort, $Sp.wfpWeight, $false)
    $qpcRbEnd = [StudioPsecGuardHost]::QpcNow()

    $resume = [StudioPsecGuardHost]::HostResumeChildOnly([int]$Sp.l1Receipt.childPid, [int]$Sp.l1Receipt.childTid)
    $coldPath = Join-Path $Sp.scratch 'cold-result.json'
    $swCold = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $coldPath) -and $swCold.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    if (!(Test-Path -LiteralPath $coldPath)) { throw "Layer-2 $($Sp.key) launch #$($Sp.launchCount) did not write cold-result.json" }
    $cold = Get-Content -LiteralPath $coldPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $coldSent = $sentinels.DrainMarkers()

    $mono = ($qpcCommitStart -le $qpcCommitEnd) -and ($qpcCommitEnd -le $qpcRbStart) -and
        ($qpcRbStart -le $qpcRbEnd) -and ($qpcRbEnd -le $resume.qpcBeforeResume) -and
        ($resume.qpcBeforeResume -le $cold.qpcEntry) -and ($cold.qpcEntry -le $cold.qpcFirstSocket) -and
        ($resume.previousSuspendCount -eq 1)
    $cBlk = (!$cold.directPa.connected -and $cold.directPa.error -eq 10013) -and
        ($null -ne $cold.crossPort -and !$cold.crossPort.connected -and $cold.crossPort.error -eq 10013) -and
        (!$cold.sentinelTcp.connected -and $cold.sentinelTcp.error -eq 10013) -and
        (!$cold.directPu.connected -and $cold.directPu.error -eq 10013) -and
        ($coldSent.tcpCount -eq 0 -and $coldSent.udpCount -eq 0) -and
        ($cold.dns.dnsQueryStatus -eq 5 -and $cold.dns.getAddrInfoStatus -ne 0)
    if (!$mono -or !$cBlk) { throw "Pre-startup blocking or monotonic QPC failed for $($Sp.key) launch #$($Sp.launchCount)" }

    $openInfo = Open-SpaceProxyGate $Sp

    $launchRec = [ordered]@{
        launchNumber = $Sp.launchCount
        repoMode = $RepoMode
        coldPhase = $ColdPhaseName
        containerSid = $Sp.containerSid
        wfpWeight = $Sp.wfpWeight
        pid = $cold.pid
        windowHandle = $cold.windowHandle
        windowVisible = $cold.windowVisible
        windowTitle = $cold.windowTitle
        persistedAuthState = $cold.persistedAuthState
        persistedAuthEmail = $cold.persistedAuthEmail
        monotonicOrder = $mono
        coldStartBlocked = $cBlk
        sixWayAuditPassed = if ($RunSixWayAudit) { $ordinaryPosOk -and ($auditViolations.Count -eq 0) } else { $null }
        proxyOwnerPid = $openInfo.ownerPid
    }
    $report.spaces[$Sp.key].launches += @($launchRec)
    return $launchRec
}

function Assert-DualProbeOutcome($Sp, $ProbeData, [string]$PhaseLabel) {
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
    $peerCrossHits = @($peerEntry | Where-Object { ($_.marker -ceq $ProbeData.http.marker) -or ($_.marker -ceq $ProbeData.tls.marker) }).Count
    $httpPath = Find-N3Path $evForSpace $ProbeData.http 'http' $prefix
    $tlsPath = Find-N3Path $evForSpace $ProbeData.tls 'tls' $prefix
    $proxyOk = ($ProbeData.http.ok -eq $true -and $ProbeData.http.status -eq 200 -and $null -ne $httpPath) -and
        ($ProbeData.tls.ok -eq $true -and $ProbeData.tls.status -eq 200 -and $null -ne $tlsPath) -and
        ($peerCrossHits -eq 0)

    $ok = $directBlocked -and $dnsBlocked -and $proxyOk
    $rec = [ordered]@{
        space = $Sp.key; phase = $PhaseLabel; passed = $ok
        directBlocked = $directBlocked; crossPortBlocked = $crossBlocked; peerEntryCrossHits = $peerCrossHits
        dnsBlocked = $dnsBlocked; proxyOk = $proxyOk
        http = $ProbeData.http; tls = $ProbeData.tls
    }
    $report.phases += @($rec)
    if (!$ok) { throw ("Probe assertion failed for $($Sp.key) in $PhaseLabel : " + ($rec | ConvertTo-Json -Compress -Depth 6)) }
    return $rec
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'layer1_psec_launcher.c'),
        (Join-Path $fixtureDir 'layer2_phase3_workflow.c'),
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

    # Compile harness DLL, ProxyOwner EXE, native Layer-1 & Layer-2 Workflow EXE
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
    $builtL2 = Join-Path $buildDir 'StudioPhase3Workflow.exe'
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL1 + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_phase3_workflow.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL2 + '" kernel32.lib advapi32.lib user32.lib ws2_32.lib dnsapi.lib secur32.lib crypt32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $builtL1) -or !(Test-Path -LiteralPath $builtL2)) {
        throw ('Native compile failed: ' + ($clOut -join '; '))
    }

    $report.qpcFrequency = [StudioPsecGuardHost]::QpcFreq()
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Host native timezone baseline (for honest comparison with Layer-2 & child Win32 GetTimeZoneInformation)
    $hostTzInfo = [TimeZoneInfo]::Local
    $report.localeTimezoneMatrix.hostNativeTimezone = [ordered]@{
        id = $hostTzInfo.Id
        standardName = $hostTzInfo.StandardName
        daylightName = $hostTzInfo.DaylightName
        baseUtcOffsetMinutes = [int]$hostTzInfo.BaseUtcOffset.TotalMinutes
    }

    # Allocate 3 distinct high ephemeral ports (Pa, Pb, Pu) & start shared proxy topology
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
    $topology = @{
        directory = $n3Dir; prefix = $prefix; exe = $relayExe; portPu = $portPu
        upstreamLog = (Join-Path $n3Dir 'upstream.ndjson')
        targetLog = (Join-Path $n3Dir 'target.ndjson')
    }
    $spaces.A.entryLog = Join-Path $entryDirA 'entry-a.ndjson'
    $spaces.B.entryLog = Join-Path $entryDirB 'entry-b.ndjson'
    foreach ($lf in @($topology.upstreamLog, $topology.targetLog, $spaces.A.entryLog, $spaces.B.entryLog)) {
        [IO.File]::WriteAllText($lf, '')
    }

    # Copy n3-target.cjs into temp $n3Dir and record req.headers['accept-language'] on target events
    $targetScript = Join-Path $n3Dir 'n3-target.cjs'
    $targetSrc = [IO.File]::ReadAllText((Join-Path $mockDesktopDir 'windows-lab-n3-target.cjs'))
    $targetPatched = $targetSrc.Replace(
        "event('target', { protocol, action, marker, peer, host });",
        "event('target', { protocol, action, marker, peer, host, acceptLanguage: req.headers['accept-language'] || null });"
    )
    if ($targetPatched -ceq $targetSrc) { throw 'Failed to instrument temp n3-target.cjs with acceptLanguage logging' }
    [IO.File]::WriteAllText($targetScript, $targetPatched, (New-Object Text.UTF8Encoding($false)))

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
        $sp.entry = Start-N3Process $relayExe @('entry-n4', $sp.settingsPath, $sp.entryLog) (Split-Path $sp.entryLog -Parent)
        $eReady = Read-N3Line $sp.entry 4500
        if ($eReady.kind -cne 'ready' -or $eReady.port -ne $sp.proxyPort) { throw "Entry_$k relay failed" }
    }

    $hostListener = New-GateSocket
    $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $report.ports = [ordered]@{ pa = $portPa; pb = $portPb; pu = $portPu; targetHttp = $tReady.http; targetTls = $tReady.tls; sentinelTcp = $sentinels.TcpPort; sentinelUdp = $sentinels.UdpPort }

    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # Create standard local users ClaudeStudioLabA & ClaudeStudioLabB + isolated profile/sealed/scratch dirs
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $sp.password = New-RandomStrongPassword
        $u = New-LocalUser -Name $sp.userName -Password $sp.password -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $k Phase3 dual-workflow test"
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
        $sp.profileDir = Join-Path $sp.workRoot 'profile'
        $sp.launcherExe = Join-Path $sp.sealed ("Studio${k}Layer1Psec.exe")
        $sp.clientExe = Join-Path $sp.sealed ("Studio${k}Phase3Workflow.exe")
        $sp.psecBin = Join-Path $sp.sealed 'psec-loopback.bin'
        $sp.clientCfgPath = Join-Path $sp.sealed 'phase3-client.cfg'

        $rxAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) {
            $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($sp.workRoot, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sp.sealed, $rxAcl)

        $rwAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) {
            $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify,
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($sp.scratch, $rwAcl)
        [void][IO.Directory]::CreateDirectory($sp.profileDir, $rwAcl)

        Copy-Item -LiteralPath $builtL1 -Destination $sp.launcherExe
        Copy-Item -LiteralPath $builtL2 -Destination $sp.clientExe
        $sp.ordinaryHeld = [StudioPsecGuardHost]::StartSuspended($sp.ordinaryToken, $sp.clientExe, 'unused', $false, 'WinSta0\Default')
    }

    # Create temporary synthetic shared Git repo + ungranted directory under $env:ProgramData\$tag (zero host repo edits!)
    $rootAcl = New-PrivateAcl $hostSid
    foreach ($s in @($spaces.A.accountSid, $spaces.B.accountSid, 'S-1-15-2-1')) {
        $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            'None', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($projectRoot, $rootAcl)
    $projectRootCreated = $true
    [void][IO.Directory]::CreateDirectory($sharedRepo, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($ungrantedRepo, (New-PrivateAcl $hostSid))
    [IO.File]::WriteAllText((Join-Path $ungrantedRepo 'secret.txt'), "ungranted-secret-$RunId`n", (New-Object Text.UTF8Encoding($false)))

    # Initialize synthetic Git repo with baseline note.txt
    $gitExe = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $null = & $gitExe -C $sharedRepo init -q
    $null = & $gitExe -C $sharedRepo config user.name 'Synthetic Lab'
    $null = & $gitExe -C $sharedRepo config user.email 'lab@example.invalid'
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'note.txt'), "simulated project baseline`n", (New-Object Text.UTF8Encoding($false)))
    $null = & $gitExe -C $sharedRepo add note.txt
    $null = & $gitExe -C $sharedRepo commit -q -m 'baseline'

    # Stage 1 ACL: Space A = Single Writer (Modify), Space B = Read-Only (RX)
    Set-RepoSingleWriterAcl 'A'

    # =========================================================================
    # STEP 1: LAUNCH A (rw) & B (ro) WITH 6-WAY HANDLE AUDIT + PRE-STARTUP BLOCKING
    # =========================================================================
    $launchA1 = Start-SpaceContainer $spaces.A 'rw' 'cold1' $true
    $launchB1 = Start-SpaceContainer $spaces.B 'ro' 'cold2' $true
    $null = Test-HostHealth 'blocked' 51

    $pA1 = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' 'healthy1').data 'healthy1'
    $pB1 = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' 'healthy1').data 'healthy1'
    $null = Test-HostHealth 'healthy1' 61

    $report.checks.dualPreStartupAndProxy = $launchA1.monotonicOrder -and $launchA1.coldStartBlocked -and $launchA1.sixWayAuditPassed -and
        $launchB1.monotonicOrder -and $launchB1.coldStartBlocked -and $launchB1.sixWayAuditPassed -and
        ($launchA1.containerSid -cne $launchB1.containerSid) -and $pA1.passed -and $pB1.passed -and
        $launchA1.windowVisible -and $launchB1.windowVisible

    # =========================================================================
    # STEP 2: PROFILE PHYSICAL ISOLATION (A <-> B CROSS-READ/WRITE DENIED BY OS)
    # =========================================================================
    $noteA = "space-A-profile-marker-$RunId"
    $noteB = "space-B-profile-marker-$RunId"
    $wProfA = Invoke-SpaceCmd $spaces.A 'profile-write' 'none' $noteA
    $wProfB = Invoke-SpaceCmd $spaces.B 'profile-write' 'none' $noteB
    $rProfA = (Invoke-SpaceCmd $spaces.A 'profile-read-and-cross' 'none').data
    $rProfB = (Invoke-SpaceCmd $spaces.B 'profile-read-and-cross' 'none').data

    $report.workflow.profileIsolation = [ordered]@{
        writeAOk = $wProfA.ok; writeBOk = $wProfB.ok
        aOwnMatched = ($rProfA.ownReadError -eq 0 -and $rProfA.ownText -ceq $noteA)
        bOwnMatched = ($rProfB.ownReadError -eq 0 -and $rProfB.ownText -ceq $noteB)
        aCrossReadPeerError = $rProfA.peerReadError
        aCrossWritePeerError = $rProfA.peerWriteError
        bCrossReadPeerError = $rProfB.peerReadError
        bCrossWritePeerError = $rProfB.peerWriteError
    }
    $report.checks.profilePhysicalIsolation = $wProfA.ok -and $wProfB.ok -and
        $report.workflow.profileIsolation.aOwnMatched -and $report.workflow.profileIsolation.bOwnMatched -and
        ($rProfA.peerReadError -ne 0) -and ($rProfA.peerWriteError -ne 0) -and
        ($rProfB.peerReadError -ne 0) -and ($rProfB.peerWriteError -ne 0)
    if (!$report.checks.profilePhysicalIsolation) { throw 'Profile physical isolation check failed' }

    # =========================================================================
    # STEP 3: INTERLEAVED AUTH CALLBACKS (B STARTS -> A STARTS -> CROSS DENIED -> B COMPLETES -> A COMPLETES)
    # =========================================================================
    $authBStart = (Invoke-SpaceCmd $spaces.B 'auth-begin').data
    $authAStart = (Invoke-SpaceCmd $spaces.A 'auth-begin').data
    $distinctNonces = ($authAStart.nonce -cne $authBStart.nonce) -and ($authAStart.email -ceq 'a@example.invalid') -and ($authBStart.email -ceq 'b@example.invalid')

    # Cross-delivery attacks (MUST be rejected, both remain pending)
    $crossBtoA = (Invoke-SpaceCmd $spaces.A 'auth-deliver' 'none' $authBStart.nonce $authBStart.email '1000').data
    $crossTamperAtoB = (Invoke-SpaceCmd $spaces.B 'auth-deliver' 'none' $authAStart.nonce $authBStart.email '1000').data
    # Expiry boundary check (ts == expires MUST be rejected)
    $expCheckB = (Invoke-SpaceCmd $spaces.B 'auth-deliver' 'none' $authBStart.nonce $authBStart.email ([string]$authBStart.expires)).data

    # Complete B FIRST, verify A still pending, then verify replay on B is rejected
    $doneB = (Invoke-SpaceCmd $spaces.B 'auth-deliver' 'none' $authBStart.nonce $authBStart.email '1000').data
    $replayB = (Invoke-SpaceCmd $spaces.B 'auth-deliver' 'none' $authBStart.nonce $authBStart.email '1000').data

    # Complete A SECOND, verify replay on A is rejected
    $doneA = (Invoke-SpaceCmd $spaces.A 'auth-deliver' 'none' $authAStart.nonce $authAStart.email '1000').data
    $replayA = (Invoke-SpaceCmd $spaces.A 'auth-deliver' 'none' $authAStart.nonce $authAStart.email '1000').data

    # Start a new pending re-auth on A before restarting A (stale callback after restart MUST be rejected!)
    $staleA = (Invoke-SpaceCmd $spaces.A 'auth-begin').data

    # =========================================================================
    # STEP 4: SINGLE-WRITER SHARED GIT REPO (STAGE A=RW, B=RO) + UNGRANTED + ALIAS CONFLICT
    # =========================================================================
    $wRepoA = (Invoke-SpaceCmd $spaces.A 'project-write' 'none' 'edited by simulated Code A').data
    $diffAfterA = ((& $gitExe -C $sharedRepo diff --no-ext-diff -- note.txt) -join "`n")
    $rRepoB = (Invoke-SpaceCmd $spaces.B 'project-read').data
    $wRepoB = (Invoke-SpaceCmd $spaces.B 'project-write' 'none' 'illegal write by B').data
    $rRepoA = (Invoke-SpaceCmd $spaces.A 'project-read').data

    # Create temporary junction alias -> shared-repo and verify direct & alias write conflict while A holds lease
    $null = & cmd.exe /c ("mklink /J `"$sharedAlias`" `"$sharedRepo`"") 2>&1
    if (!(Test-Path -LiteralPath $sharedAlias)) { throw 'Failed to create temporary junction alias' }
    $conflictDirect = Request-WriterLease 'B' $sharedRepo
    $conflictAlias = Request-WriterLease 'B' $sharedAlias

    # =========================================================================
    # STEP 5: 5-CATEGORY LOCALE & TIMEZONE MATRIX (BEFORE HANDOFF)
    # =========================================================================
    $locA = (Invoke-SpaceCmd $spaces.A 'locale-tz-matrix' 'healthy2').data
    $locB = (Invoke-SpaceCmd $spaces.B 'locale-tz-matrix' 'healthy2').data
    $evAfterLoc = Read-DualN3Events
    $targetRowA = @($evAfterLoc.target | Where-Object { $_.marker -ceq $locA.requestLanguage.tlsProbe.marker } | Select-Object -Last 1)[0]
    $targetRowB = @($evAfterLoc.target | Where-Object { $_.marker -ceq $locB.requestLanguage.tlsProbe.marker } | Select-Object -Last 1)[0]

    $report.localeTimezoneMatrix.A = [ordered]@{
        windowLanguage = $locA.windowLanguage
        rendererTimezone = $locA.rendererTimezone
        requestLanguage = [ordered]@{
            sent = $locA.requestLanguage.sentAcceptLanguage
            targetReceived = if ($targetRowA) { $targetRowA.acceptLanguage } else { $null }
            tlsOk = $locA.requestLanguage.tlsProbe.ok
        }
        childProcessPreferences = $locA.childProcessPreferences
        windowsNativeTimezone = $locA.windowsNativeTimezone
    }
    $report.localeTimezoneMatrix.B = [ordered]@{
        windowLanguage = $locB.windowLanguage
        rendererTimezone = $locB.rendererTimezone
        requestLanguage = [ordered]@{
            sent = $locB.requestLanguage.sentAcceptLanguage
            targetReceived = if ($targetRowB) { $targetRowB.acceptLanguage } else { $null }
            tlsOk = $locB.requestLanguage.tlsProbe.ok
        }
        childProcessPreferences = $locB.childProcessPreferences
        windowsNativeTimezone = $locB.windowsNativeTimezone
    }
    $hostBias = -$report.localeTimezoneMatrix.hostNativeTimezone.baseUtcOffsetMinutes
    $report.localeTimezoneMatrix.windowsNativeTzMatchesHostBoundary = ($locA.windowsNativeTimezone.biasMinutes -eq $hostBias) -and
        ($locB.windowsNativeTimezone.biasMinutes -eq $hostBias) -and
        ($locA.windowsNativeTimezone.standardName -ceq $locB.windowsNativeTimezone.standardName) -and
        ($locA.childProcessPreferences.windowsNativeTimezone.biasMinutes -eq $hostBias) -and
        ($locB.childProcessPreferences.windowsNativeTimezone.biasMinutes -eq $hostBias)

    $report.checks.localeTimezoneFiveReadings = ($locA.windowLanguage.configuredUiLang -ceq 'zh-CN') -and
        ($locB.windowLanguage.configuredUiLang -ceq 'en-US') -and
        ($locA.windowLanguage.windowTitle -match 'Space A \| zh-CN') -and
        ($locB.windowLanguage.windowTitle -match 'Space B \| en-US') -and
        ($locA.rendererTimezone.refUtcFormatted -ceq '2026-07-01T20:00:00+08:00') -and
        ($locB.rendererTimezone.refUtcFormatted -ceq '2026-07-01T05:00:00-07:00') -and
        ($report.localeTimezoneMatrix.A.requestLanguage.targetReceived -ceq 'zh-CN,zh;q=0.9') -and
        ($report.localeTimezoneMatrix.B.requestLanguage.targetReceived -ceq 'en-US,en;q=0.9') -and
        ($locA.childProcessPreferences.appContainer -eq $true -and $locA.childProcessPreferences.langEnv -ceq 'zh_CN.UTF-8' -and $locA.childProcessPreferences.tzEnv -ceq 'Asia/Shanghai') -and
        ($locB.childProcessPreferences.appContainer -eq $true -and $locB.childProcessPreferences.langEnv -ceq 'en_US.UTF-8' -and $locB.childProcessPreferences.tzEnv -ceq 'America/Los_Angeles') -and
        $report.localeTimezoneMatrix.windowsNativeTzMatchesHostBoundary
    if (!$report.checks.localeTimezoneFiveReadings) { throw 'Locale/timezone 5-reading verification failed' }

    # =========================================================================
    # STEP 6: RESTART A (PERSISTENCE + STALE CALLBACK REJECTION) & SINGLE-WRITER HANDOFF (A->B)
    # =========================================================================
    Stop-SpaceContainer $spaces.A
    $activeWriterLeases.Remove((Get-CanonicalDir $sharedRepo))
    $retainedAfterStopA = [IO.File]::ReadAllText((Join-Path $sharedRepo 'note.txt'))

    # Flip single-writer lease & NTFS ACL to B (A becomes R/O, B becomes R/W)
    $leaseB = Request-WriterLease 'B' $sharedAlias
    Set-RepoSingleWriterAcl 'B'

    # Restart B into R/W mode and A into R/O mode (both fresh PSEC containers with new container SIDs!)
    Stop-SpaceContainer $spaces.B
    $launchA2 = Start-SpaceContainer $spaces.A 'ro' 'cold3' $false
    $launchB2 = Start-SpaceContainer $spaces.B 'rw' 'cold4' $false
    $null = Test-HostHealth 'healthy2' 71

    # Verify A persisted profile + persisted auth email + rejects stale pre-restart callback!
    $postRestartProfA = (Invoke-SpaceCmd $spaces.A 'profile-read-and-cross').data
    $staleDeliverA = (Invoke-SpaceCmd $spaces.A 'auth-deliver' 'none' $staleA.nonce $staleA.email '1000').data
    $postRestartProfB = (Invoke-SpaceCmd $spaces.B 'profile-read-and-cross').data

    $report.workflow.interleavedAuthAndRestart = [ordered]@{
        distinctNonces = $distinctNonces
        crossBtoARejected = (!$crossBtoA.accepted -and $crossBtoA.reason -ceq 'INVALID_CALLBACK')
        crossTamperAtoBRejected = (!$crossTamperAtoB.accepted -and $crossTamperAtoB.reason -ceq 'INVALID_CALLBACK')
        expiryBoundaryRejected = (!$expCheckB.accepted -and $expCheckB.reason -ceq 'EXPIRED_CALLBACK')
        bCompletedFirst = ($doneB.accepted -and $doneB.authEmail -ceq 'b@example.invalid')
        bReplayRejected = (!$replayB.accepted)
        aCompletedSecond = ($doneA.accepted -and $doneA.authEmail -ceq 'a@example.invalid')
        aReplayRejected = (!$replayA.accepted)
        aNewContainerSidOnRestart = ($launchA2.containerSid -cne $launchA1.containerSid)
        bNewContainerSidOnRestart = ($launchB2.containerSid -cne $launchB1.containerSid)
        aProfilePersistedAcrossRestart = ($postRestartProfA.ownReadError -eq 0 -and $postRestartProfA.ownText -ceq $noteA)
        bProfilePersistedAcrossRestart = ($postRestartProfB.ownReadError -eq 0 -and $postRestartProfB.ownText -ceq $noteB)
        aAuthPersistedAcrossRestart = ($launchA2.persistedAuthState -ceq 'authenticated' -and $launchA2.persistedAuthEmail -ceq 'a@example.invalid')
        bAuthPersistedAcrossRestart = ($launchB2.persistedAuthState -ceq 'authenticated' -and $launchB2.persistedAuthEmail -ceq 'b@example.invalid')
        aStalePreRestartCallbackRejected = (!$staleDeliverA.accepted -and $staleDeliverA.reason -ceq 'NO_PENDING_LOGIN')
    }
    $report.checks.interleavedAuthAndRestartPersistence = ($report.workflow.interleavedAuthAndRestart.Values -notcontains $false)
    if (!$report.checks.interleavedAuthAndRestartPersistence) { throw 'Interleaved auth or restart persistence check failed' }

    # Verify post-handoff repo: B can write, A can read B's edit, A write is OS-denied!
    $wRepoB2 = (Invoke-SpaceCmd $spaces.B 'project-write' 'none' 'edited by simulated Code B').data
    $diffAfterB = ((& $gitExe -C $sharedRepo diff --no-ext-diff -- note.txt) -join "`n")
    $rRepoA2 = (Invoke-SpaceCmd $spaces.A 'project-read').data
    $wRepoA2 = (Invoke-SpaceCmd $spaces.A 'project-write' 'none' 'illegal write by A after handoff').data

    $pA2 = Assert-DualProbeOutcome $spaces.A (Invoke-SpaceCmd $spaces.A 'probe' 'healthy3').data 'healthy3'
    $pB2 = Assert-DualProbeOutcome $spaces.B (Invoke-SpaceCmd $spaces.B 'probe' 'healthy3').data 'healthy3'

    $report.workflow.singleWriterProjectHandoff = [ordered]@{
        stage1_aWriteOk = ($wRepoA.writeError -eq 0 -and $wRepoA.createNewError -eq 0)
        stage1_hostDiffHasA = ($diffAfterA -match 'edited by simulated Code A')
        stage1_bReadMatchedA = ($rRepoB.readError -eq 0 -and $rRepoB.text.Trim() -ceq 'edited by simulated Code A')
        stage1_bWriteDeniedByOs = ($wRepoB.writeError -eq 5 -and $wRepoB.createNewError -eq 5)
        stage1_aUngrantedDenied = ($rRepoA.ungrantedReadError -ne 0 -and $rRepoA.ungrantedWriteError -ne 0)
        stage1_bUngrantedDenied = ($rRepoB.ungrantedReadError -ne 0 -and $rRepoB.ungrantedWriteError -ne 0)
        stage1_directWriteConflictDenied = (!$conflictDirect.granted -and $conflictDirect.reason -ceq 'WRITE_CONFLICT')
        stage1_aliasWriteConflictDenied = (!$conflictAlias.granted -and $conflictAlias.reason -ceq 'WRITE_CONFLICT')
        retainedAfterAStopped = ($retainedAfterStopA.Trim() -ceq 'edited by simulated Code A')
        handoffLeaseBGranted = $leaseB.granted
        stage2_bWriteOk = ($wRepoB2.writeError -eq 0 -and $wRepoB2.createNewError -eq 0)
        stage2_hostDiffHasB = ($diffAfterB -match 'edited by simulated Code B')
        stage2_aReadMatchedB = ($rRepoA2.readError -eq 0 -and $rRepoA2.text.Trim() -ceq 'edited by simulated Code B')
        stage2_aWriteDeniedByOs = ($wRepoA2.writeError -eq 5 -and $wRepoA2.createNewError -eq 5)
        postHandoffNetworkProbesPassed = ($pA2.passed -and $pB2.passed)
    }
    $report.checks.singleWriterProjectHandoff = ($report.workflow.singleWriterProjectHandoff.Values -notcontains $false)
    if (!$report.checks.singleWriterProjectHandoff) { throw 'Single-writer project handoff check failed' }
} catch {
    $report.error = Get-ErrDetail $_
} finally {
    # 1. Stop both containers & remove active WFP rules
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        try { Stop-SpaceContainer $sp } catch { $report.cleanup.errors += @("stop-container-$k`: $($_.Exception.Message)") }
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

    $allowedExes = @($spaces.A.launcherExe, $spaces.A.clientExe, $spaces.B.launcherExe, $spaces.B.clientExe, $ownerExe) | Where-Object { $_ }
    $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Psec.exe' OR Name = 'StudioBLayer1Psec.exe' OR Name = 'StudioAPhase3Workflow.exe' OR Name = 'StudioBPhase3Workflow.exe' OR Name = 'StudioPhase3ProxyOwner.exe'" | Where-Object {
        $_.ExecutablePath -in $allowedExes
    })
    foreach ($p in $rem) { $report.cleanup.remainingPids += @([int]$p.ProcessId) }

    $allWfpRemoved = ($report.cleanup.remainingPids.Count -eq 0) -and (!$spaces.A.wfpInstalled) -and (!$spaces.B.wfpInstalled)
    if ($assemblyLoaded -and $allWfpRemoved) {
        $totalRes = 0
        foreach ($sid in ($report.cleanup.retiredContainerSids | Select-Object -Unique)) {
            $totalRes += [StudioLabWfp]::CountFiltersReferencingPackage($sid)
        }
        $report.cleanup.totalResidualPackageFilters = $totalRes
        if ($totalRes -ne 0) { $allWfpRemoved = $false }
    }
    $report.cleanup.wfpRemovedAndVerifiedAbsent = $allWfpRemoved

    # 2. Host restored check + DNS ETW stop + desktop 5-field digest check
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
            $lossZero = ($null -ne $dnsResult.lossBeforeStop) -and ($dnsResult.lossBeforeStop.eventsLost -eq 0) -and
                ($dnsResult.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsResult.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsResult.servicePid -eq $dnsResult.servicePidAfter)
                lossZero = $lossZero
                psecSendReplyCount = $psecSendReply
                unknownSendReplyCount = $unknownSendReply
                hostSendCount = $hostSends
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lossZero -and
                ($psecSendReply -eq 0) -and ($unknownSendReply -eq 0) -and ($hostSends -ge 4)
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

    # 3. Remove junction, temporary project root, temp dirs, unload profiles, delete BOTH A & B accounts
    if (Test-Path -LiteralPath $sharedAlias) {
        try { $null = & cmd.exe /c ("rmdir `"$sharedAlias`"") 2>&1 } catch { }
    }
    if ($projectRootCreated -and (Test-Path -LiteralPath $projectRoot)) {
        try { Remove-Item -LiteralPath $projectRoot -Recurse -Force -ErrorAction Stop }
        catch { $report.cleanup.errors += @("remove-projectRoot: $($_.Exception.Message)") }
    }
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        if ($assemblyLoaded) {
            try { [StudioPsecGuardHost]::UnloadLabProfile($sp.origToken, $sp.loadedProfileHandle) } catch { $report.cleanup.errors += @("unload-$k`: $($_.Exception.Message)") }
            foreach ($tName in @('auditorToken', 'ordinaryToken', 'copyToken', 'origToken')) {
                if ($sp[$tName] -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($sp[$tName]) } catch { }; $sp[$tName] = [IntPtr]::Zero }
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
    $report.cleanup.projectRootGone = !(Test-Path -LiteralPath $projectRoot)
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.labBProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabB')
    $report.cleanup.labAProfileRecordGone = !($spaces.A.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.A.accountSid + "'") -ErrorAction SilentlyContinue))
    $report.cleanup.labBProfileRecordGone = !($spaces.B.accountSid -and (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $spaces.B.accountSid + "'") -ErrorAction SilentlyContinue))

    $hostOk = $true
    foreach ($st in @('baseline', 'blocked', 'healthy1', 'healthy2', 'restored')) {
        $h = $report.hostHealth[$st]
        if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hostOk = $false }
    }
    $report.checks.hostContinuous = $hostOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.remainingPids.Count -eq 0) -and
        $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.directoryGone -and $report.cleanup.projectRootGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labBProfileDirGone -and
        $report.cleanup.labAProfileRecordGone -and $report.cleanup.labBProfileRecordGone

    $allPassed = (!$report.error) -and
        $report.checks.dualPreStartupAndProxy -and
        $report.checks.profilePhysicalIsolation -and
        $report.checks.interleavedAuthAndRestartPersistence -and
        $report.checks.singleWriterProjectHandoff -and
        $report.checks.localeTimezoneFiveReadings -and
        $report.checks.dnsZeroLeak -and
        $report.checks.hostContinuous -and
        $report.checks.desktopUnchanged -and
        $report.checks.cleanup

    if ($allPassed) { $report.outcome = 'passed-ab-phase3-dual-workflow' }
    else { $report.outcome = 'stopped-ab-phase3-dual-workflow' }
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
        checks = $report.checks
        workflow = $report.workflow
        localeTimezoneMatrix = $report.localeTimezoneMatrix
        dnsSummary = $report.dnsSummary
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
