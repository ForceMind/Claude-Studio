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
    $ReportPath = Join-Path $reportDir ('windows-a-phase1-proxy-guard-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioAPhase1-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $outerTimer = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $outerTimer.ElapsedMilliseconds -lt 150000) {
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
$tag = 'ClaudeStudioAPhase1-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$n3Dir = Join-Path $base 'n3'
$harnessDll = Join-Path $base 'StudioPhase1Harness.dll'
$ownerExe = Join-Path $base 'StudioPhase1ProxyOwner.exe'
$manifestFile = Join-Path $base 'wfp-recovery-manifest.json'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId
    prefix = $prefix
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-a-phase1-proxy-guard'
    nativeIPv6 = 'readback only'
    ipv4Inbound = 'readback only'
    hostSid = $hostSid
    wfpStaticWrites = 0
    sources = [ordered]@{}
    checks = [ordered]@{}
    hostHealth = [ordered]@{}
    phases = @()
    faults = @()
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$accountCreated = $false
$accountSid = $null
$dirCreated = $false
$assemblyLoaded = $false
$aWorkRoot = $null
$sealed = $null
$scratch = $null
$launcherExe = $null
$clientExe = $null
$psecBin = $null
$dnsTrace = $null
$sentinels = $null
$hostListener = $null
$hostOld = $null
$topology = $null
$proxyOwner = $null
$origToken = [IntPtr]::Zero
$copyToken = [IntPtr]::Zero
$ordinaryToken = [IntPtr]::Zero
$auditorToken = [IntPtr]::Zero
$loadedProfileHandle = [IntPtr]::Zero
$ordinaryHeld = $null
$blkL1 = $null
$wfpInstalled = $false
$wfpSub = [guid]::Empty
$wfpKeys = $null
$wfpWeight = [uint16]0
$portPa = [uint16]0
$portPu = [uint16]0
$targetContainerSid = $null
$cmdSeq = 0

function Test-HostHealth([string]$Phase, [byte]$Marker) {
    $fresh = Open-GatePair $hostListener
    try {
        $dnsName = $prefix + '-host-' + $Phase + '-dns.test.'
        $null = Resolve-DnsName -Name $dnsName -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue
        $publicOk = [Net.Dns]::GetHostAddresses('example.com').Count -gt 0
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

function Start-Phase1ProxyOwner {
    $args = @(
        $wfpSub.ToString(),
        $wfpKeys[0].ToString(), $wfpKeys[1].ToString(), $wfpKeys[2].ToString(), $wfpKeys[3].ToString(), $wfpKeys[4].ToString(),
        $targetContainerSid,
        ("$portPa`:$wfpWeight")
    )
    $p = Start-N3Process $ownerExe $args $base
    $r = Read-N3Line $p 5000
    if ($r.kind -cne 'ready' -or $r.pid -ne $p.process.Id) { throw 'ProxyOwner ready handshake mismatch' }
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

function Stop-Phase1ProxyOwner($Owner, [switch]$HardKill) {
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
    } finally { $Owner.process.Dispose() }
}

function Invoke-Layer2Cmd([string]$Action, [string]$Phase = 'none', [int]$TimeoutMs = 10000) {
    $script:cmdSeq++
    $seq = $script:cmdSeq
    $cmdPath = Join-Path $scratch ("cmd-$seq.cfg")
    $resPath = Join-Path $scratch ("res-$seq.json")
    $tmp = $cmdPath + '.tmp'
    [IO.File]::WriteAllText($tmp, ("action=$Action`nphase=$Phase`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($tmp, $cmdPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $resPath) -and $sw.ElapsedMilliseconds -lt $TimeoutMs) { Start-Sleep -Milliseconds 20 }
    if (!(Test-Path -LiteralPath $resPath)) { throw "Layer-2 did not respond to $Action ($Phase) within ${TimeoutMs}ms" }
    return (Get-Content -LiteralPath $resPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Assert-ProbeOutcome($ProbeData, [bool]$ExpectOnline, [string]$PhaseLabel) {
    $sentinelDrain = $sentinels.DrainMarkers()
    $directBlocked = (!$ProbeData.direct.sentinelTcp.connected -and $ProbeData.direct.sentinelTcp.error -eq 10013) -and
        (!$ProbeData.direct.directPu.connected -and $ProbeData.direct.directPu.error -eq 10013) -and
        (!$ProbeData.direct.directTargetHttp.connected -and $ProbeData.direct.directTargetHttp.error -eq 10013) -and
        (!$ProbeData.direct.directTargetTls.connected -and $ProbeData.direct.directTargetTls.error -eq 10013) -and
        ($sentinelDrain.tcpCount -eq 0) -and ($sentinelDrain.udpCount -eq 0)
    $dnsBlocked = ($ProbeData.dns.dnsQueryStatus -eq 5) -and ($ProbeData.dns.getAddrInfoStatus -ne 0)

    $httpPath = $null; $tlsPath = $null
    if ($ExpectOnline) {
        $ev = Read-N3Events $topology
        $httpPath = Find-N3Path $ev $ProbeData.http 'http' $prefix
        $tlsPath = Find-N3Path $ev $ProbeData.tls 'tls' $prefix
        $proxyOk = ($ProbeData.http.ok -eq $true -and $ProbeData.http.status -eq 200 -and $null -ne $httpPath) -and
            ($ProbeData.tls.ok -eq $true -and $ProbeData.tls.status -eq 200 -and $null -ne $tlsPath)
    } else {
        $ev = Read-N3Events $topology
        $httpTargetHits = @($ev.target | Where-Object { $_.marker -ceq $ProbeData.http.marker }).Count
        $tlsTargetHits = @($ev.target | Where-Object { $_.marker -ceq $ProbeData.tls.marker }).Count
        $proxyOk = ($ProbeData.http.ok -eq $false) -and ($ProbeData.tls.ok -eq $false) -and
            ($httpTargetHits -eq 0) -and ($tlsTargetHits -eq 0)
    }
    $ok = $directBlocked -and $dnsBlocked -and $proxyOk
    $rec = [ordered]@{
        phase = $PhaseLabel
        expectOnline = $ExpectOnline
        passed = $ok
        directBlocked = $directBlocked
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
    if (!$ok) { throw ("Probe assertion failed in phase $PhaseLabel : " + ($rec | ConvertTo-Json -Compress -Depth 6)) }
    return $rec
}

function Open-ProxyGate {
    if (!$proxyOwner -or $proxyOwner.process.HasExited) {
        $script:proxyOwner = Start-Phase1ProxyOwner
    }
    $armCmd = "arm-owner $($proxyOwner.ready.pid) $($proxyOwner.ready.startTicks)"
    $armed = Invoke-N3Child $topology.entry $armCmd 3000
    if (!$armed.admitting -or !$armed.lastProbe.ok) { throw 'Entry proxy arm-owner failed health check' }
    $opened = Invoke-ProxyOwner $proxyOwner 'open'
    if (!$opened.open) { throw 'ProxyOwner failed to open dynamic exception E' }
    $rb = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $wfpWeight, $true)
    return [ordered]@{ ownerPid = $proxyOwner.ready.pid; armed = $armed; readback = $rb }
}

function Invoke-FaultTest([string]$Name, [string]$Kind, [string]$FaultDnsPhase, [string]$RecDnsPhase, [bool]$RecoverAfter) {
    $null = Invoke-Layer2Cmd 'hold' $FaultDnsPhase
    $sw = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 120
        $before = (Invoke-Layer2Cmd 'held' $FaultDnsPhase).data
        if ($sw.ElapsedMilliseconds -gt 3500) { throw "Held HTTP/TLS streams did not become active before fault $Name" }
    } until ($before.http.state -ceq 'active' -and $before.tls.state -ceq 'active' -and
        @($before.http.marks).Count -ge 2 -and @($before.tls.marks).Count -ge 2)

    $tInject = [StudioPsecGuardHost]::QpcNow()
    if ($Kind -eq 'refuse' -or $Kind -eq 'silent') {
        $null = Invoke-N3Child $topology.upstream $Kind
    } elseif ($Kind -eq 'owner-exit') {
        Stop-Phase1ProxyOwner $proxyOwner -HardKill
        $script:proxyOwner = $null
    } elseif ($Kind -eq 'upstream-exit') {
        $topology.upstream.process.Kill()
        [void]$topology.upstream.process.WaitForExit(2000)
        $topology.upstream.process.Dispose()
        $topology.upstream = $null
    } else {
        throw "Unknown fault kind: $Kind"
    }

    # Wait for entry cutoff (<= 3000ms) AND revoke/confirm E absent
    $freq = [StudioPsecGuardHost]::QpcFreq()
    $entryClosed = $false; $excGone = $false; $closeSent = $false; $elapsedMs = 0.0; $entrySnap = $null
    while ($true) {
        $entrySnap = Invoke-N3Child $topology.entry 'status' 1600
        $entryClosed = (!$entrySnap.admitting -and $entrySnap.active -eq 0)
        if ($Kind -ne 'owner-exit' -and !$closeSent -and $entryClosed -and $proxyOwner -and !$proxyOwner.process.HasExited) {
            $null = Invoke-ProxyOwner $proxyOwner 'close'
            $closeSent = $true
        }
        $excGone = ![StudioLabWfp]::StaticExceptionPresent($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $wfpWeight)
        $elapsedMs = ([StudioPsecGuardHost]::QpcNow() - $tInject) * 1000.0 / $freq
        if ($entryClosed -and $excGone) { break }
        if ($elapsedMs -gt 3000.0) {
            throw "Fault $Name exceeded 3000ms cutoff budget (elapsed=${elapsedMs}ms, entryClosed=$entryClosed, excGone=$excGone)"
        }
        Start-Sleep -Milliseconds 40
    }

    # Independent readback confirming 4 Static BLOCK intact and E absent
    $rbOff = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $wfpWeight, $false)

    # Probe while offline: HTTP & TLS must fail with 0 target hits, direct/DNS blocked
    $offlineProbe = Assert-ProbeOutcome (Invoke-Layer2Cmd 'probe' $FaultDnsPhase).data $false $FaultDnsPhase
    $after = (Invoke-Layer2Cmd 'held' $FaultDnsPhase).data
    $oldClosed = ($after.http.state -cnotin @('active','starting')) -and ($after.tls.state -cnotin @('active','starting'))
    if (!$oldClosed) { throw "Old held streams still active after fault $Name" }

    $rec = [ordered]@{
        name = $Name
        kind = $Kind
        cutoffMs = [Math]::Round($elapsedMs, 2)
        entryCloseReason = $entrySnap.closeReason
        exceptionAbsentReadback = ($rbOff.exceptionPresent -eq $false)
        oldStreamsBeforeCount = @{ http = @($before.http.marks).Count; tls = @($before.tls.marks).Count }
        oldStreamsAfterState = @{ http = $after.http.state; tls = $after.tls.state; httpCount = @($after.http.marks).Count; tlsCount = @($after.tls.marks).Count }
        offlineProbePassed = $offlineProbe.passed
        recovered = $false
        oldNoReplayAfterRecovery = $null
    }

    if ($RecoverAfter) {
        if ($Kind -eq 'refuse' -or $Kind -eq 'silent') {
            $null = Invoke-N3Child $topology.upstream 'serve'
        }
        $null = Open-ProxyGate
        $recProbe = Assert-ProbeOutcome (Invoke-Layer2Cmd 'probe' $RecDnsPhase).data $true $RecDnsPhase
        $afterRec = (Invoke-Layer2Cmd 'held' $RecDnsPhase).data
        $noReplay = ($afterRec.http.marker -ceq $after.http.marker) -and ($afterRec.tls.marker -ceq $after.tls.marker) -and
            ((@($afterRec.http.marks) -join ',') -ceq (@($after.http.marks) -join ',')) -and
            ((@($afterRec.tls.marks) -join ',') -ceq (@($after.tls.marks) -join ','))
        if (!$noReplay) { throw "Old held streams advanced after recovery from $Name" }
        $rec.recovered = $recProbe.passed
        $rec.oldNoReplayAfterRecovery = $noReplay
    }

    $report.faults += @($rec)
    return $rec
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
    [void][IO.Directory]::CreateDirectory($n3Dir, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Create temporary standard local user ClaudeStudioLabA
    $password = New-RandomStrongPassword
    $createdUser = New-LocalUser -Name 'ClaudeStudioLabA' -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A Phase1 proxy guard test'
    $accountCreated = $true
    $accountSid = $createdUser.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $createdUser
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
    if ($accountSid -in $admins -or $accountSid -notin $users) { throw 'Unexpected group membership for ClaudeStudioLabA' }
    $report.account = [ordered]@{ name = 'ClaudeStudioLabA'; sid = $accountSid; inUsers = $true; inAdmins = $false }

    # Compile host C# harness DLL + standalone ProxyOwner EXE
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

    $report.qpcFrequency = [StudioPsecGuardHost]::QpcFreq()
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Acquire seclogon session-bound token (zero desktop ACL writes!) & load A profile
    $origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($origToken, 'ClaudeStudioLabA')
    $copyToken = [StudioPsecGuardHost]::DuplicateHardened($origToken, $hostSid)
    $ordinaryToken = [StudioPsecGuardHost]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $auditorToken = [StudioPsecGuardHost]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)

    $aProfileTemp = 'C:\Users\ClaudeStudioLabA\AppData\Local\Temp'
    if (!(Test-Path -LiteralPath $aProfileTemp)) { throw "Expected profile temp: $aProfileTemp" }
    $aWorkRoot = Join-Path $aProfileTemp $tag
    $sealed = Join-Path $aWorkRoot 'sealed'
    $scratch = Join-Path $aWorkRoot 'scratch'
    $launcherExe = Join-Path $sealed 'StudioALayer1Psec.exe'
    $clientExe = Join-Path $sealed 'StudioAPhase1Client.exe'
    $psecBin = Join-Path $sealed 'psec-loopback.bin'
    $clientCfgPath = Join-Path $sealed 'phase1-client.cfg'

    $rxAcl = New-PrivateAcl $hostSid
    foreach ($s in @($accountSid, 'S-1-15-2-1')) {
        $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($s),
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($aWorkRoot, $rxAcl)
    [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)

    $scratchAcl = New-PrivateAcl $hostSid
    foreach ($s in @($accountSid, 'S-1-15-2-1')) {
        $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($s),
            [Security.AccessControl.FileSystemRights]::Modify,
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($scratch, $scratchAcl)

    # Compile native Layer-1 PSEC launcher + native WinHTTP/Winsock Layer-2 client into $sealed
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $launcherExe + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_phase1_client.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $clientExe + '" kernel32.lib advapi32.lib ws2_32.lib dnsapi.lib secur32.lib crypt32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $launcherExe) -or !(Test-Path -LiteralPath $clientExe)) {
        throw ('Native compile failed: ' + ($clOut -join '; '))
    }

    $report.launcherSha256 = (Get-FileHash -LiteralPath $launcherExe -Algorithm SHA256).Hash
    $report.clientSha256 = (Get-FileHash -LiteralPath $clientExe -Algorithm SHA256).Hash
    $report.ownerSha256 = (Get-FileHash -LiteralPath $ownerExe -Algorithm SHA256).Hash

    # Build PSEC v1.0 FlatBuffer (networkLoopback only, egress deny, MXC-Loopback, no MXC proxy)
    $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1($scratch, $sealed, $false)
    [IO.File]::WriteAllBytes($psecBin, $psecBytes)

    # Start N3 synthetic proxy topology with entry in entry-n4 mode (watches ProxyOwner PID/StartTicks!)
    $ports = [int[]](Get-N3EphemeralPorts)
    $portPa = [uint16]$ports[0]
    $portPu = [uint16]$ports[1]
    if ($portPa -eq 10810 -or $portPu -eq 10810 -or $portPa -lt 40000 -or $portPu -lt 40000 -or $portPa -eq $portPu) {
        throw "Invalid ephemeral proxy ports: Pa=$portPa Pu=$portPu"
    }
    $relayExe = Join-Path $n3Dir 'StudioN3Relay.exe'
    $rOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$relayExe" (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('N3 relay compile failed: ' + ($rOut -join '; ')) }

    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $pwsh -NoProfile -NonInteractive -File (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $n3Dir -CertificatePrefix $prefix
    if ($LASTEXITCODE -ne 0) { throw 'N3 certificate generation failed' }

    $topology = @{ directory = $n3Dir; prefix = $prefix; ports = $ports; exe = $relayExe }
    foreach ($n in 'entry','upstream','target') {
        $topology[$n + 'Log'] = Join-Path $n3Dir ($n + '.ndjson')
        [IO.File]::WriteAllText($topology[$n + 'Log'], '')
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
    $topology.config = Join-Path $n3Dir 'n3-settings.json'
    [IO.File]::WriteAllText($topology.config, (@{
        prefix = $prefix; p = [int]$portPa; u = [int]$portPu;
        http = $tReady.http; tls = $tReady.tls; half = $tReady.half; wrongCertificate = $tReady.wrongCertificate;
        pin = $topology.pin
    } | ConvertTo-Json -Compress))

    $topology.upstream = Start-N3Process $relayExe @('upstream', $topology.config, $topology.upstreamLog) $n3Dir
    $uReady = Read-N3Line $topology.upstream 4500
    if ($uReady.kind -cne 'ready' -or $uReady.port -ne $portPu) { throw 'Upstream relay failed' }
    $topology.entry = Start-N3Process $relayExe @('entry-n4', $topology.config, $topology.entryLog) $n3Dir
    $eReady = Read-N3Line $topology.entry 4500
    if ($eReady.kind -cne 'ready' -or $eReady.port -ne $portPa) { throw 'Entry relay failed' }

    # Start host loopback control + non-proxy sentinels + DNS ETW trace
    $hostListener = New-GateSocket
    $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $report.ports = [ordered]@{ pa = $portPa; pu = $portPu; targetHttp = $tReady.http; targetTls = $tReady.tls; sentinelTcp = $sentinels.TcpPort; sentinelUdp = $sentinels.UdpPort }

    $cfgText = @(
        "prefix=$prefix"
        "host=$prefix-a-window-healthy.test"
        "pin=$($topology.pin)"
        "workDir=$scratch"
        "p=$portPa"
        "u=$portPu"
        "http=$($tReady.http)"
        "tls=$($tReady.tls)"
        "sentinelTcp=$($sentinels.TcpPort)"
        "sentinelUdp=$($sentinels.UdpPort)"
    ) -join "`n"
    [IO.File]::WriteAllText($clientCfgPath, $cfgText + "`n", (New-Object Text.UTF8Encoding($false)))

    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # Ordinary A suspended control for handle audit
    $ordinaryHeld = [StudioPsecGuardHost]::StartSuspended($ordinaryToken, $clientExe, 'unused', $false, 'WinSta0\Default')

    # =========================================================================
    # STEP 1: COLD-START PRE-STARTUP BLOCKING (4 Static BLOCK, NO Exception E)
    # =========================================================================
    $blkReady = Join-Path $scratch 'blk-l1-ready.json'
    $blkStop = Join-Path $scratch 'blk-l1-stop'
    $blkL1Args = "`"$psecBin`" `"$clientExe`" `"$clientCfgPath`" `"$scratch`" `"$hostSid`" `"$blkReady`" `"$blkStop`""

    $blkL1 = [StudioPsecGuardHost]::StartSuspended($copyToken, $launcherExe, $blkL1Args, $true, 'WinSta0\Default')
    $report.layer1Restore = $blkL1.RestoreTokenObjectDaclOnly($origToken, $hostSid, $accountSid)
    if (!$report.layer1Restore.processSecurityAfterRestore.hardenedExpected -or !$report.layer1Restore.threadSecurityAfterRestore.hardenedExpected) {
        throw 'Layer-1 SD weakened after token object DACL restore'
    }
    [void]$blkL1.ResumeMainThread()
    $poll = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $blkReady) -and $poll.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    if (!(Test-Path -LiteralPath $blkReady)) { throw 'Layer-1 did not write ready receipt' }
    $blkL1Receipt = Get-Content -LiteralPath $blkReady -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.layer1 = $blkL1Receipt
    if (!$blkL1Receipt.psecCreated -or !$blkL1Receipt.childCreated -or !$blkL1Receipt.childInJob) {
        throw ('Layer-1 PSEC creation failed: ' + ($blkL1Receipt | ConvertTo-Json -Compress))
    }

    $blkInspect = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, $hostSid, $accountSid)
    $report.targetSuspendedInspect = $blkInspect
    $targetContainerSid = $blkInspect.identity.containerSid
    $report.checks.targetSuspendedIdentity = $blkInspect.identity.userSid -ceq $accountSid -and
        !$blkInspect.identity.admin -and $blkInspect.identity.appContainer -and
        ($targetContainerSid -match '^S-1-15-2(-[0-9]+){7}$') -and
        (@($blkInspect.identity.networkCapabilities).Count -eq 1) -and ($blkInspect.identity.networkCapabilities[0] -ceq $loopbackCapSid) -and
        $blkInspect.identity.inJob -and ($blkInspect.threadUserTime -eq 0) -and ($blkInspect.threadKernelTime -eq 0) -and
        $blkInspect.processSecurity.hardenedExpected -and $blkInspect.threadSecurity.hardenedExpected
    if (!$report.checks.targetSuspendedIdentity) { throw 'Suspended Layer-2 failed identity/capability/SD pre-check' }

    # Allow Layer-2's own AppContainer SID in Layer-2's TokenDefaultDacl (ordinary A lacks this SID!)
    [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$blkL1Receipt.childPid, $hostSid, $targetContainerSid)

    # Handle gate audit (A1 distinct logon & A2 same logon)
    $report.auditA1 = [StudioPsecGuardHost]::RunAudit($auditorToken, $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $blkL1.Pid, $blkL1.Tid, $blkL1.StartTicks, [int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, [long]$blkL1Receipt.childStartTicks)
    $report.auditA2 = [StudioPsecGuardHost]::RunAudit($origToken, $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $blkL1.Pid, $blkL1.Tid, $blkL1.StartTicks, [int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, [long]$blkL1Receipt.childStartTicks)
    $a1Map = @{}; foreach ($t in $report.auditA1.targets) { $a1Map[$t.role] = $t }
    $a2Map = @{}; foreach ($t in $report.auditA2.targets) { $a2Map[$t.role] = $t }
    $violations = @()
    foreach ($r in 'layer1','layer2') {
        $violations += Get-Violations $a1Map[$r] 'A1-DistinctLogon'
        $violations += Get-Violations $a2Map[$r] 'A2-SameLogon'
    }
    $report.handleViolations = $violations
    $report.checks.handleGatePassed = (Test-GrantedAll $a1Map['ordinary']) -and (Test-GrantedAll $a2Map['ordinary']) -and ($violations.Count -eq 0)
    if (!$report.checks.handleGatePassed) { throw 'Startup handle gate failed before WFP install' }

    # WFP arbitration + manifest + 4 Static BLOCK install + independent readback
    $wfpSub = [guid]::NewGuid()
    $wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
    $wfpGuard = [StudioLabWfp]::CreateStaticGuard()
    try {
        $wfpWeight = $wfpGuard.PrepareStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $clientExe)
        $report.wfpArbitration = [ordered]@{
            chosenSublayerWeight = $wfpWeight
            totalExamined = @($wfpGuard.PriorityEvidence).Count
            excludedByApplicationCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.excludedByApplication }).Count
            singTunExcludedCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.excludedByApplication -and ($_.filterName -match 'sing' -or $_.sublayerName -match 'sing') }).Count
            requiringHigherPriorityCount = @($wfpGuard.PriorityEvidence | Where-Object { $_.requiresHigherPriority }).Count
        }
        $manifest = [ordered]@{
            runId = $RunId; containerSid = $targetContainerSid; sublayer = $wfpSub.ToString();
            keys = @($wfpKeys | ForEach-Object { $_.ToString() }); portPa = $portPa; weight = $wfpWeight;
            clientExe = $clientExe; clientSha256 = $report.clientSha256
        }
        [IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
        $report.wfpManifest = $manifest

        $tWfpCommitStart = [StudioPsecGuardHost]::QpcNow()
        $wfpGuard.InstallStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $clientExe, $wfpWeight)
        $tWfpCommitEnd = [StudioPsecGuardHost]::QpcNow()
        $wfpInstalled = $true
        $report.wfpStaticWrites = 4
    } finally { $wfpGuard.Dispose() }

    $tReadbackStart = [StudioPsecGuardHost]::QpcNow()
    $report.wfpColdReadback = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $wfpWeight, $false)
    $tReadbackEnd = [StudioPsecGuardHost]::QpcNow()

    $null = Test-HostHealth 'blocked' 51

    # Host directly calls ResumeThread on Layer-2
    $blkResume = [StudioPsecGuardHost]::HostResumeChildOnly([int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid)
    $report.targetResume = $blkResume

    $coldPath = Join-Path $scratch 'cold-result.json'
    $coldErrPath = Join-Path $scratch 'cold-err.txt'
    $poll.Restart()
    while (!(Test-Path -LiteralPath $coldPath) -and !(Test-Path -LiteralPath $coldErrPath) -and $poll.ElapsedMilliseconds -lt 10000) {
        $l2St = [StudioPsecGuardHost]::TryReadProcessState([int]$blkL1Receipt.childPid)
        if ($l2St.openable -and !$l2St.alive) { break }
        Start-Sleep -Milliseconds 25
    }
    if (!(Test-Path -LiteralPath $coldPath)) {
        $l2St = [StudioPsecGuardHost]::TryReadProcessState([int]$blkL1Receipt.childPid)
        $errTxt = if (Test-Path -LiteralPath $coldErrPath) { Get-Content -LiteralPath $coldErrPath -Raw } else { '' }
        $stgPath = Join-Path $scratch 'cold-stage.txt'
        $stgTxt = if (Test-Path -LiteralPath $stgPath) { Get-Content -LiteralPath $stgPath -Raw } else { '' }
        throw ("Layer-2 did not write cold-result.json | state=" + ($l2St | ConvertTo-Json -Compress) + " | stage=" + $stgTxt + " | err=" + $errTxt)
    }
    $cold = Get-Content -LiteralPath $coldPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.coldProbe = $cold
    Start-Sleep -Milliseconds 150
    $coldSentinels = $sentinels.DrainMarkers()
    $report.coldSentinels = $coldSentinels

    $report.timingQpc = [ordered]@{
        wfpCommitStart = $tWfpCommitStart; wfpCommitEnd = $tWfpCommitEnd;
        wfpReadbackStart = $tReadbackStart; wfpReadbackEnd = $tReadbackEnd;
        hostResumeBefore = $blkResume.qpcBeforeResume; hostResumeAfter = $blkResume.qpcAfterResume;
        probeEntry = $cold.qpcEntry; probeFirstSocket = $cold.qpcFirstSocket; probeDone = $cold.qpcDone
    }
    $report.checks.monotonicOrder = ($tWfpCommitStart -le $tWfpCommitEnd) -and
        ($tWfpCommitEnd -le $tReadbackStart) -and ($tReadbackStart -le $tReadbackEnd) -and
        ($tReadbackEnd -le $blkResume.qpcBeforeResume) -and ($blkResume.qpcBeforeResume -le $cold.qpcEntry) -and
        ($cold.qpcEntry -le $cold.qpcFirstSocket) -and ($blkResume.previousSuspendCount -eq 1)

    $report.checks.coldStartBlocked = (!$cold.directPa.connected -and $cold.directPa.error -eq 10013) -and
        (!$cold.sentinelTcp.connected -and $cold.sentinelTcp.error -eq 10013) -and
        (!$cold.directPu.connected -and $cold.directPu.error -eq 10013) -and
        ($coldSentinels.tcpCount -eq 0) -and ($coldSentinels.udpCount -eq 0) -and
        ($cold.dns.dnsQueryStatus -eq 5) -and ($cold.dns.getAddrInfoStatus -ne 0)
    if (!$report.checks.monotonicOrder -or !$report.checks.coldStartBlocked) {
        throw 'Cold-start pre-blocking or QPC monotonic order failed'
    }

    # =========================================================================
    # STEP 2: OPEN DYNAMIC EXCEPTION E VIA SEPARATE ProxyOwner (HEALTHY PROXY)
    # =========================================================================
    $report.healthyOpen = Open-ProxyGate
    $null = Assert-ProbeOutcome (Invoke-Layer2Cmd 'probe' 'healthy1').data $true 'healthy1'
    $null = Test-HostHealth 'healthy1' 61
    $report.checks.healthyProxyOnly = $true

    # =========================================================================
    # STEP 3: 4 FAULT INJECTIONS WITH ACTIVE HTTP/TLS STREAMS (<= 3s CUTOFF)
    # =========================================================================
    $f1 = Invoke-FaultTest 'refuse' 'refuse' 'fault1' 'healthy2' $true
    $f2 = Invoke-FaultTest 'silent' 'silent' 'fault2' 'healthy3' $true
    $null = Test-HostHealth 'fault2' 71
    $f3 = Invoke-FaultTest 'owner-exit' 'owner-exit' 'fault3' 'healthy4' $true
    $f4 = Invoke-FaultTest 'upstream-exit' 'upstream-exit' 'fault4' 'none' $false

    $report.checks.faultsConvergedAndRecovered = $f1.offlineProbePassed -and $f1.recovered -and $f1.oldNoReplayAfterRecovery -and
        $f2.offlineProbePassed -and $f2.recovered -and $f2.oldNoReplayAfterRecovery -and
        $f3.offlineProbePassed -and $f3.recovered -and $f3.oldNoReplayAfterRecovery -and ($f3.entryCloseReason -ceq 'exception-owner-exit') -and
        $f4.offlineProbePassed -and ($f4.entryCloseReason -ceq 'upstream-unhealthy')

    # Cleanly tell Layer-2 to finish before teardown
    try { $null = Invoke-Layer2Cmd 'finish' 'done' 3000 } catch { }
} catch {
    $report.error = Get-ErrDetail $_
} finally {
    # 1. Stop ProxyOwner (revokes dynamic E) and A process tree first
    if ($proxyOwner) {
        try { Stop-Phase1ProxyOwner $proxyOwner } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        $proxyOwner = $null
    }
    if ($scratch -and (Test-Path -LiteralPath $scratch)) {
        try { if ($blkL1) { [IO.File]::WriteAllText((Join-Path $scratch 'blk-l1-stop'), 'stop') } } catch { }
    }
    if ($blkL1) {
        try { $report.cleanup.layer1Exit = $blkL1.WaitExit(5000) }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { $blkL1.Dispose() }
    }
    if ($blkL1Receipt -and $blkL1Receipt.childPid) {
        try { [StudioPsecGuardHost]::HostTerminatePid([int]$blkL1Receipt.childPid) } catch { }
    }
    Start-Sleep -Milliseconds 150
    if ($ordinaryHeld) {
        try { $report.cleanup.ordinaryExit = $ordinaryHeld.TerminateNow() }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { $ordinaryHeld.Dispose() }
    }
    if ($loadedProfileHandle -ne [IntPtr]::Zero -and $origToken -ne [IntPtr]::Zero) {
        [StudioPsecGuardHost]::UnloadLabProfile($origToken, $loadedProfileHandle)
        $loadedProfileHandle = [IntPtr]::Zero
    }
    foreach ($tk in @($copyToken, $origToken, $ordinaryToken, $auditorToken)) {
        if ($tk -ne [IntPtr]::Zero) { [StudioPsecGuardHost]::CloseToken($tk) }
    }

    # Confirm 0 remaining A fixture processes
    try {
        $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Psec.exe' OR Name = 'StudioAPhase1Client.exe' OR Name = 'StudioPhase1ProxyOwner.exe'" | Where-Object {
            $_.ExecutablePath -ieq $launcherExe -or $_.ExecutablePath -ieq $clientExe -or $_.ExecutablePath -ieq $ownerExe
        })
        $report.cleanup.remainingPids = @($rem | ForEach-Object { $_.ProcessId })
        if ($rem.Count) { throw 'Fixture processes remain; retaining WFP rules for safety' }
    } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }

    # 2. Remove 4 Static BLOCKs + sublayer & independently confirm all 6 GUIDs absent
    if ($wfpInstalled -and $report.cleanup.remainingPids.Count -eq 0) {
        try {
            [StudioLabWfp]::RemoveStatic($wfpSub, $wfpKeys, $targetContainerSid, $portPa, $wfpWeight)
            $report.cleanup.wfpRemovedAndVerifiedAbsent = $true
        } catch {
            $report.cleanup.wfpRemovedAndVerifiedAbsent = $false
            $report.cleanup.errors += @(Get-ErrDetail $_)
        }
    } elseif (!$wfpInstalled) {
        $report.cleanup.wfpRemovedAndVerifiedAbsent = $true
    }
    if ($targetContainerSid -and $assemblyLoaded) {
        Start-Sleep -Milliseconds 150
        try { $report.cleanup.targetResidualPackageFilters = [StudioLabWfp]::CountFiltersReferencingPackage($targetContainerSid) }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    } else {
        $report.cleanup.targetResidualPackageFilters = 0
    }

    # 3. Stop N3 topology + sentinels + post-rollback host health
    if ($topology) {
        foreach ($role in 'entry','upstream','target') {
            if ($topology[$role]) {
                try { Stop-N3Process $topology[$role] } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
            }
        }
    }
    if ($hostOld) {
        try { $null = Test-HostHealth 'restored' 81 }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { Close-GatePair $hostOld }
    }
    if ($hostListener) { $hostListener.Dispose() }
    if ($sentinels) { $sentinels.Dispose() }

    # 4. Stop DNS ETW trace
    if ($dnsTrace) {
        try {
            $dnsReport = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $report.dnsTrace = $dnsReport
            $psecSends = @($dnsReport.events | Where-Object { ($_.event -eq 3010 -or $_.event -eq 3011) -and $_.role -ceq 'psec' })
            $unknownSends = @($dnsReport.events | Where-Object { ($_.event -eq 3010 -or $_.event -eq 3011) -and !$_.role })
            $hostSends = @($dnsReport.events | Where-Object { $_.event -eq 3010 -and $_.role -ceq 'host' })
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsReport.servicePid -eq $dnsReport.servicePidAfter)
                lossZero = ($null -ne $dnsReport.lossBeforeStop) -and ($dnsReport.lossBeforeStop.eventsLost -eq 0) -and ($dnsReport.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsReport.lossBeforeStop.realtimeBuffersLost -eq 0)
                psecSendReplyCount = $psecSends.Count
                unknownSendReplyCount = $unknownSends.Count
                hostSendCount = $hostSends.Count
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $report.dnsSummary.lossZero -and
                ($report.dnsSummary.psecSendReplyCount -eq 0) -and ($report.dnsSummary.unknownSendReplyCount -eq 0) -and
                ($report.dnsSummary.hostSendCount -ge 5)
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }

    # 5. Desktop ACL zero-change check
    try {
        if ($assemblyLoaded) {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()
            $defaultMatch = ($report.defaultDesktopBefore.readable -eq $report.defaultDesktopAfter.readable) -and
                ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
            $report.desktopAclUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
                $defaultMatch
        }
    } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }

    # 6. Delete temp dirs ONLY after WFP & process cleanup verified
    if ($aWorkRoot -and (Test-Path -LiteralPath $aWorkRoot) -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.remainingPids.Count -eq 0) {
        try { Remove-Item -LiteralPath $aWorkRoot -Recurse -Force } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    if ($dirCreated -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.remainingPids.Count -eq 0) {
        try {
            $item = Get-Item -LiteralPath $base
            if ($item.Name -cne $tag -or $item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Refusing to delete unexpected directory'
            }
            Remove-Item -LiteralPath $base -Recurse -Force
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)

    # 7. Delete temporary ClaudeStudioLabA account and profile
    if ($accountCreated) {
        try {
            Start-Sleep -Milliseconds 400
            $newProfiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
            foreach ($prof in $newProfiles) {
                try { Remove-CimInstance -InputObject $prof }
                catch {
                    Start-Sleep -Milliseconds 600
                    $retry = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid }
                    if ($retry) { Remove-CimInstance -InputObject $retry }
                }
            }
            Remove-LocalUser -Name 'ClaudeStudioLabA'
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.labAProfileRecordGone = (@(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid }).Count -eq 0)

    $hostAllOk = ($report.hostHealth.Count -ge 5)
    foreach ($k in $report.hostHealth.Keys) {
        $h = $report.hostHealth[$k]
        if (!$h.oldTcp -or !$h.freshTcp -or !$h.publicDnsOk) { $hostAllOk = $false }
    }
    $report.checks.hostContinuous = $hostAllOk
    $report.checks.desktopUnchanged = ($report.desktopAclUnchanged -eq $true)
    $report.checks.cleanup = $report.cleanup.wfpRemovedAndVerifiedAbsent -and
        ($report.cleanup.targetResidualPackageFilters -eq 0) -and
        ($report.cleanup.remainingPids.Count -eq 0) -and
        $report.cleanup.directoryGone -and $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labAProfileRecordGone -and
        ($report.cleanup.errors.Count -eq 0)

    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    if (!$report.error -and $report.checks.targetSuspendedIdentity -and $report.checks.handleGatePassed -and
        $report.checks.monotonicOrder -and $report.checks.coldStartBlocked -and $report.checks.healthyProxyOnly -and
        $report.checks.faultsConvergedAndRecovered -and $report.checks.dnsZeroLeak -and $report.checks.hostContinuous -and
        $report.checks.desktopUnchanged -and $report.checks.cleanup) {
        $report.outcome = 'passed-a-phase1-proxy-guard'
    } elseif ($report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged) {
        $report.outcome = 'stopped-a-phase1-proxy-guard'
    }

    $json = $report | ConvertTo-Json -Depth 14
    [IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
    $reportSha = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash

    $summary = [ordered]@{
        runId = $RunId
        outcome = $report.outcome
        reportPath = $ReportPath
        reportSha256Prefix12 = $reportSha.Substring(0, 12)
        error = $report.error
        ports = $report.ports
        checks = $report.checks
        timingQpc = $report.timingQpc
        wfpArbitration = $report.wfpArbitration
        faults = $report.faults
        dnsSummary = $report.dnsSummary
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
