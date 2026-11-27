[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$RunId,
    [string]$ReportPath,
    [string]$SummaryPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) { throw 'Run in x64 Windows PowerShell 5.1' }

function New-PrivateAcl([string]$HostSid) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($HostSid, 'S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), [Security.AccessControl.FileSystemRights]::FullControl,
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
        for ($i = 0; $i -lt 20 -and $ports.Count -lt $Count; $i++) {
            $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.ExclusiveAddressUse = $true; $l.Start()
            $p = [uint16]$l.LocalEndpoint.Port
            if ($p -ge 49152 -and $p -ne 10810 -and ($ports -notcontains $p)) { $listeners += $l; $ports += $p } else { $l.Stop() }
        }
        return $ports
    } finally { foreach ($l in $listeners) { try { $l.Stop() } catch { } } }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    $ReportPath = Join-Path $reportDir ("windows-phase6a-live-control-plane-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeStudioPhase6A-summary-$RunId.json")
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $sw.ElapsedMilliseconds -lt 240000) { Start-Sleep -Milliseconds 100 }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if ($proc.HasExited -and $proc.ExitCode -ne 0 -and !(Test-Path -LiteralPath $SummaryPath)) { throw "Elevated runner exited $($proc.ExitCode)" }
    }
    $txt = Get-Content -LiteralPath $SummaryPath -Raw -Encoding UTF8
    Remove-Item -LiteralPath $SummaryPath -Force
    Write-Output $txt
    return
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$mockDesktopDir = Join-Path $repoRoot 'mock-desktop'
$fixtureDir = Join-Path $mockDesktopDir 'fixtures\startup-permissions'
. (Join-Path $mockDesktopDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDesktopDir 'windows-lab-bind-gate.ps1') -FunctionsOnly
. (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeStudioPhase6A-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$buildDir = Join-Path $base 'build'
$n3Dir = Join-Path $base 'n3'
$ownerExe = Join-Path $base 'StudioPhase6ProxyOwner.exe'

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-phase6a-live-control-plane'
    checks = [ordered]@{}; hostHealth = [ordered]@{}; liveSnapshots = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$dirCreated = $false; $dnsTrace = $null; $sentinels = $null; $hostListener = $null; $hostOld = $null; $topology = $null
$liveBackend = $null; $engine = $null
$spaces = [ordered]@{
    A = @{ key='A'; userName='ClaudeStudioLabA'; coldPhase='cold1'; accountCreated=$false; accountSid=$null; origToken=[IntPtr]::Zero; copyToken=[IntPtr]::Zero; loadedProfileHandle=[IntPtr]::Zero; workRoot=$null }
    B = @{ key='B'; userName='ClaudeStudioLabB'; coldPhase='cold2'; accountCreated=$false; accountSid=$null; origToken=[IntPtr]::Zero; copyToken=[IntPtr]::Zero; loadedProfileHandle=[IntPtr]::Zero; workRoot=$null }
}

function Test-HostHealth([string]$Phase, [byte]$Marker) {
    $fresh = Open-GatePair $hostListener
    try {
        $dnsName = $prefix + '-host-' + $Phase + '-dns.test.'
        $null = Resolve-DnsName -Name $dnsName -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue
        $publicOk = $false
        for ($i = 0; $i -lt 3 -and !$publicOk; $i++) { try { if ([Net.Dns]::GetHostAddresses('example.com').Count -gt 0) { $publicOk = $true } } catch { Start-Sleep -Milliseconds 200 } }
        $res = [ordered]@{ phase = $Phase; publicDnsOk = $publicOk; oldTcp = (Send-GateMarker $hostOld $Marker); freshTcp = (Send-GateMarker $fresh ($Marker + 1)) }
        $report.hostHealth[$Phase] = $res
        return $res
    } finally { Close-GatePair $fresh }
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"
    if ((Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue) -or (Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)) {
        throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent'
    }

    # Build updated ClaudeStudioControlPlane.exe (now including LivePsecWfpBackend + StudioPsecGuardHost + StudioLabWfp)
    $buildInfo = & (Join-Path $PSScriptRoot 'build.ps1') | ConvertFrom-Json
    $report.build = $buildInfo
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($buildInfo.exePath))

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($buildDir, (New-PrivateAcl $hostSid))
    [void][IO.Directory]::CreateDirectory($n3Dir, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $oOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$ownerExe" `
        (Join-Path $fixtureDir 'Phase1ProxyOwner.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Owner build failed: ' + ($oOut -join '; ')) }

    $builtL1 = Join-Path $buildDir 'StudioLayer1Psec.exe'
    $builtL2 = Join-Path $buildDir 'StudioLiveClient.exe'
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL1 + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $buildDir 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_phase1_client.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $builtL2 + '" kernel32.lib advapi32.lib ws2_32.lib dnsapi.lib secur32.lib crypt32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native build failed: ' + ($clOut -join '; ')) }

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Start shared N3 Target + Upstream(Pu)
    $ports = Get-DistinctHighPorts 3
    $portPa = [uint16]$ports[0]; $portPb = [uint16]$ports[1]; $portPu = [uint16]$ports[2]
    $relayExe = Join-Path $n3Dir 'StudioN3Relay.exe'
    $rOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$relayExe" (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Relay build failed: ' + ($rOut -join '; ')) }

    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $pwsh -NoProfile -NonInteractive -File (Join-Path $mockDesktopDir 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $n3Dir -CertificatePrefix $prefix
    if ($LASTEXITCODE -ne 0) { throw 'Cert gen failed' }

    $topology = @{ upstreamLog = (Join-Path $n3Dir 'upstream.ndjson'); targetLog = (Join-Path $n3Dir 'target.ndjson') }
    [IO.File]::WriteAllText($topology.upstreamLog, ''); [IO.File]::WriteAllText($topology.targetLog, '')
    $targetScript = Join-Path $n3Dir 'n3-target.cjs'
    Copy-Item -LiteralPath (Join-Path $mockDesktopDir 'windows-lab-n3-target.cjs') -Destination $targetScript
    $node = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $certArgs = @('target.crt','target.key','wrong.crt','wrong.key' | ForEach-Object { Join-Path $n3Dir $_ })
    $topology.target = Start-N3Process $node (@($targetScript, $prefix, $topology.targetLog) + $certArgs) $n3Dir
    $tReady = Read-N3Line $topology.target 5000
    $pin = [IO.File]::ReadAllText((Join-Path $n3Dir 'pin.txt')).Trim()

    $setA = Join-Path $n3Dir 'settings-A.json'; $setB = Join-Path $n3Dir 'settings-B.json'
    [IO.File]::WriteAllText($setA, (@{ prefix=$prefix; p=[int]$portPa; u=[int]$portPu; http=$tReady.http; tls=$tReady.tls; half=$tReady.half; wrongCertificate=$tReady.wrongCertificate; pin=$pin } | ConvertTo-Json -Compress))
    [IO.File]::WriteAllText($setB, (@{ prefix=$prefix; p=[int]$portPb; u=[int]$portPu; http=$tReady.http; tls=$tReady.tls; half=$tReady.half; wrongCertificate=$tReady.wrongCertificate; pin=$pin } | ConvertTo-Json -Compress))
    $topology.upstream = Start-N3Process $relayExe @('upstream', $setA, $topology.upstreamLog) $n3Dir
    $null = Read-N3Line $topology.upstream 4500

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # Provision temporary A & B accounts and build LiveSpaceSpec objects for StudioControlPlane
    $liveSpecs = @{}
    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $sp.userName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $k Phase6A"
        $sp.accountCreated = $true; $sp.accountSid = $u.SID.Value
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $sp.origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($sp.userName, $env:COMPUTERNAME, $pw)
        $sp.loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($sp.origToken, $sp.userName)
        $sp.copyToken = [StudioPsecGuardHost]::DuplicateHardened($sp.origToken, $hostSid)

        $sp.workRoot = Join-Path "C:\Users\$($sp.userName)\AppData\Local\Temp" $tag
        $sealed = Join-Path $sp.workRoot 'sealed'; $scratch = Join-Path $sp.workRoot 'scratch'
        $rxAcl = New-PrivateAcl $hostSid; $rwAcl = New-PrivateAcl $hostSid
        foreach ($s in @($sp.accountSid, 'S-1-15-2-1')) {
            $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($sp.workRoot, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)
        [void][IO.Directory]::CreateDirectory($scratch, $rwAcl)

        $l1Exe = Join-Path $sealed "Studio${k}Layer1Psec.exe"
        $l2Exe = Join-Path $sealed "Studio${k}LiveClient.exe"
        $psecBin = Join-Path $sealed 'psec-loopback.bin'
        $cfgPath = Join-Path $sealed 'live-client.cfg'
        Copy-Item -LiteralPath $builtL1 -Destination $l1Exe
        Copy-Item -LiteralPath $builtL2 -Destination $l2Exe
        [IO.File]::WriteAllBytes($psecBin, [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1($scratch, $sealed, $false))
        $myPort = if ($k -eq 'A') { $portPa } else { $portPb }
        $otherPort = if ($k -eq 'A') { $portPb } else { $portPa }
        $cfgTxt = @("prefix=$prefix","host=$prefix-a-window-healthy.test","pin=$pin","workDir=$scratch","coldPhase=$($sp.coldPhase)","p=$myPort","peerPort=$otherPort","u=$portPu","http=$($tReady.http)","tls=$($tReady.tls)","sentinelTcp=$($sentinels.TcpPort)","sentinelUdp=$($sentinels.UdpPort)") -join "`n"
        [IO.File]::WriteAllText($cfgPath, $cfgTxt + "`n", (New-Object Text.UTF8Encoding($false)))

        $spec = New-Object ClaudeStudio.ControlPlane.LiveSpaceSpec
        $spec.Space = if ($k -eq 'A') { [ClaudeStudio.ControlPlane.SpaceId]::A } else { [ClaudeStudio.ControlPlane.SpaceId]::B }
        $spec.AccountName = $sp.userName; $spec.AccountSid = $sp.accountSid; $spec.HostSid = $hostSid
        $spec.Prefix = $prefix; $spec.HostName = "$prefix-a-window-healthy.test"; $spec.Pin = $pin
        $spec.SealedDir = $sealed; $spec.ScratchDir = $scratch; $spec.LauncherExe = $l1Exe; $spec.ClientExe = $l2Exe
        $spec.PsecBin = $psecBin; $spec.ClientCfg = $cfgPath; $spec.ProxyOwnerExe = $ownerExe; $spec.WorkBaseDir = $base
        $spec.RelayExe = $relayExe
        $spec.EntrySettingsPath = if ($k -eq 'A') { $setA } else { $setB }
        $spec.EntryLogPath = Join-Path (Join-Path $n3Dir "entry-$k") "entry-$k.ndjson"
        $spec.ProxyPort = $myPort; $spec.PeerPort = $otherPort
        $spec.OrigToken = $sp.origToken; $spec.CopyToken = $sp.copyToken
        $liveSpecs[$k] = $spec
    }

    # =========================================================================
    # DRIVE REAL DUAL-SPACE LIFECYCLE DIRECTLY THROUGH StudioEngine + LivePsecWfpBackend!
    # =========================================================================
    $liveBackend = New-Object ClaudeStudio.ControlPlane.LivePsecWfpBackend($liveSpecs.A, $liveSpecs.B)
    $engine = New-Object ClaudeStudio.ControlPlane.StudioEngine($liveBackend)
    $errOut = $null
    $null = $engine.ConfigureUpstream('127.0.0.1', [int]$portPu, $false, [ref]$errOut)

    # 1. Put upstream in 'refuse' -> StartSpace(A) MUST stay fail-closed ColdBlocked!
    $null = Invoke-N3Child $topology.upstream 'refuse'
    $coldSnapA = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::A)
    $coldProbeA = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::A, 'fault1')
    $report.checks.liveFailClosedColdStart = ($coldSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ColdBlocked) -and
        $coldSnapA.StaticBlockActive -and (!$coldSnapA.DynamicExceptionOpen) -and
        $coldProbeA.Ok -and (!$coldProbeA.HttpOk) -and (!$coldProbeA.TlsOk)
    $null = Test-HostHealth 'blocked' 51

    # 2. Bring upstream online -> Reconnect A & Start B -> BOTH must be REAL ProxyOnline (HTTP+TLS 200, cross-port 10013)!
    $null = Invoke-N3Child $topology.upstream 'serve'
    $onSnapA = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)
    $onSnapB = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    $probeOnA = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::A, 'healthy1')
    $probeOnB = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::B, 'healthy1')
    $report.liveSnapshots.onlineA = [ordered]@{ state = $onSnapA.State.ToString(); containerSid = $onSnapA.ContainerSid; weight = $onSnapA.WfpSublayerWeight; port = $onSnapA.ProxyPort; ownerPid = $onSnapA.ProxyOwnerPid }
    $report.liveSnapshots.onlineB = [ordered]@{ state = $onSnapB.State.ToString(); containerSid = $onSnapB.ContainerSid; weight = $onSnapB.WfpSublayerWeight; port = $onSnapB.ProxyPort; ownerPid = $onSnapB.ProxyOwnerPid }
    $report.checks.liveDualProxyOnline = ($onSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        ($onSnapB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        ($onSnapA.ContainerSid -cne $onSnapB.ContainerSid) -and ($onSnapA.WfpSublayerWeight -ne $onSnapB.WfpSublayerWeight) -and
        $probeOnA.Ok -and $probeOnA.HttpOk -and $probeOnA.TlsOk -and
        $probeOnB.Ok -and $probeOnB.HttpOk -and $probeOnB.TlsOk
    $null = Test-HostHealth 'healthy1' 61

    # 3. Soft disconnect A ONLY via Control Plane -> A real probe fails, B real probe stays 200!
    $cutSnapA = $engine.DisconnectSpaceNetworkOnly([ClaudeStudio.ControlPlane.SpaceId]::A)
    $probeCutA = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::A, 'fault2')
    $probeStillB = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::B, 'healthy2')
    $report.checks.liveSoftDisconnectIsolatesAOnly = ($cutSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::FaultCutoff) -and
        $probeCutA.Ok -and (!$probeCutA.HttpOk) -and (!$probeCutA.TlsOk) -and
        $probeStillB.Ok -and $probeStillB.HttpOk -and $probeStillB.TlsOk

    # 4. Reconnect A -> returns to 200; export sanitized diagnostics (zero host username PII)
    $recSnapA = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)
    $probeRecA = $engine.ProbeLiveSpace([ClaudeStudio.ControlPlane.SpaceId]::A, 'healthy3')
    $diagJson = $engine.BuildSanitizedDiagnosticJson()
    $report.checks.liveReconnectAndSanitizedDiag = ($recSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        $probeRecA.Ok -and $probeRecA.HttpOk -and $probeRecA.TlsOk -and
        ($diagJson.IndexOf($env:USERNAME, [StringComparison]::OrdinalIgnoreCase) -lt 0) -and
        ($diagJson.Contains($onSnapA.ContainerSid)) -and ($diagJson.Contains($onSnapB.ContainerSid))

    # 5. Emergency Kill-Switch via StudioEngine -> stops BOTH real A & B and removes ALL 10 WFP GUIDs!
    $engine.EmergencyKillSwitchAll()
    $postA = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::A)
    $postB = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::B)
    $resA = [StudioLabWfp]::CountFiltersReferencingPackage($onSnapA.ContainerSid)
    $resB = [StudioLabWfp]::CountFiltersReferencingPackage($onSnapB.ContainerSid)
    $report.checks.liveKillSwitchZeroResidual = ($postA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::Stopped) -and
        ($postB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::Stopped) -and
        ($resA -eq 0) -and ($resB -eq 0) -and $engine.HostContinuous
    $null = Test-HostHealth 'fault2' 71
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($engine) { try { $engine.Dispose() } catch { $report.cleanup.errors += @("engine: $($_.Exception.Message)") } }
    if ($liveBackend) { try { $liveBackend.Dispose() } catch { $report.cleanup.errors += @("backend: $($_.Exception.Message)") } }
    if ($topology) {
        foreach ($role in @('upstream','target')) {
            if ($topology[$role]) { try { Stop-N3Process $topology[$role] } catch { $report.cleanup.errors += @("stop-$role`: $($_.Exception.Message)") } }
        }
    }
    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { } }
    if ($dnsTrace) {
        try {
            $dnsRes = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $psecSR = @($dnsRes.events | Where-Object { $_.role -eq 'psec' -and ($_.event -in 3010,3011) }).Count
            $unkSR = @($dnsRes.events | Where-Object { !$_.role -and ($_.event -in 3010,3011) }).Count
            $hSends = @($dnsRes.events | Where-Object { $_.role -eq 'host' -and $_.event -eq 3010 }).Count
            $lZero = ($null -ne $dnsRes.lossBeforeStop) -and ($dnsRes.lossBeforeStop.eventsLost -eq 0) -and ($dnsRes.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsRes.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{ servicePidStable = ($dnsRes.servicePid -eq $dnsRes.servicePidAfter); lossZero = $lZero; psecSendReplyCount = $psecSR; unknownSendReplyCount = $unkSR; hostSendCount = $hSends }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($psecSR -eq 0) -and ($unkSR -eq 0) -and ($hSends -ge 5)
        } catch { $report.cleanup.errors += @("dns: $($_.Exception.Message)"); $report.checks.dnsZeroLeak = $false }
    }
    if ($sentinels) { try { $sentinels.Dispose() } catch { } }
    if ($hostOld) { try { Close-GatePair $hostOld } catch { } }
    if ($hostListener) { try { $hostListener.Dispose() } catch { } }

    try {
        $report.desktopAfter = [StudioReadDesktop]::Read()
        $report.defaultDesktopAfter = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()
        $report.checks.desktopUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
            ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
            ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
            ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
            ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
    } catch { $report.checks.desktopUnchanged = $false }

    foreach ($k in @('A', 'B')) {
        $sp = $spaces[$k]
        try { [StudioPsecGuardHost]::UnloadLabProfile($sp.origToken, $sp.loadedProfileHandle) } catch { }
        foreach ($tn in @('copyToken','origToken')) { if ($sp[$tn] -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($sp[$tn]) } catch { } } }
        if ($sp.workRoot -and (Test-Path -LiteralPath $sp.workRoot)) { try { Remove-Item -LiteralPath $sp.workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
        if ($sp.accountCreated) {
            try { if ($sp.accountSid) { $pr = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $sp.accountSid + "'") -ErrorAction SilentlyContinue; if ($pr) { Remove-CimInstance -InputObject $pr -ErrorAction Stop } } } catch { $report.cleanup.errors += @("prof-$k`: $($_.Exception.Message)") }
            try { $pd = "C:\Users\$($sp.userName)"; if (Test-Path -LiteralPath $pd) { Remove-Item -LiteralPath $pd -Recurse -Force -ErrorAction Stop } } catch { $report.cleanup.errors += @("pd-$k`: $($_.Exception.Message)") }
            try { Remove-LocalUser -Name $sp.userName -ErrorAction Stop } catch { $report.cleanup.errors += @("user-$k`: $($_.Exception.Message)") }
        }
    }
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.labBProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabB')

    $hOk = $true
    foreach ($st in @('baseline','blocked','healthy1','fault2','restored')) { $h = $report.hostHealth[$st]; if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hOk = $false } }
    $report.checks.hostContinuous = $hOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and $report.cleanup.directoryGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and $report.cleanup.labAProfileDirGone -and $report.cleanup.labBProfileDirGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 9)
    $report.outcome = if ($allOk) { 'passed-phase6a-live-control-plane' } else { 'stopped-phase6a-live-control-plane' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        checks = $report.checks; liveSnapshots = $report.liveSnapshots; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
}
