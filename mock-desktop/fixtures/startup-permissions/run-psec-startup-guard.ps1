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
    $ReportPath = Join-Path $reportDir ('windows-a-psec-startup-guard-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioAPsecGuard-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $outerTimer = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $outerTimer.ElapsedMilliseconds -lt 120000) {
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

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeStudioAPsecGuard-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$aWorkRoot = $null
$sealed = $null
$scratch = $null
$launcherExe = $null
$probeExe = $null
$psecBin = $null
$harnessDll = Join-Path $base 'StudioPsecGuardHarness.dll'
$manifestFile = Join-Path $base 'wfp-recovery-manifest.json'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId
    prefix = $prefix
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-psec-startup-guard'
    nativeIPv6 = 'readback only'
    ipv4Inbound = 'readback only'
    hostSid = $hostSid
    wfpWrites = 0
    sources = [ordered]@{}
    checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$accountCreated = $false
$accountSid = $null
$dirCreated = $false
$assemblyLoaded = $false
$dnsTrace = $null
$sentinels = $null
$hostListener = $null
$hostOld = $null
$origToken = [IntPtr]::Zero
$copyToken = [IntPtr]::Zero
$ordinaryToken = [IntPtr]::Zero
$auditorToken = [IntPtr]::Zero
$loadedProfileHandle = [IntPtr]::Zero
$ordinaryHeld = $null
$posL1 = $null
$blkL1 = $null
$wfpInstalled = $false
$wfpSub = [guid]::Empty
$wfpKeys = $null
$wfpWeight = [uint16]0
$wfpDummyPort = [uint16]49555
$targetContainerSid = $null
$posContainerSid = $null

function Test-HostHealth([string]$Phase, [byte]$Marker) {
    $fresh = Open-GatePair $hostListener
    try {
        $dnsName = $prefix + '-host-' + $Phase + '-dns.test.'
        $answers = @(Resolve-DnsName -Name $dnsName -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue)
        # Note: .test. may return NXDOMAIN (valid DNS round-trip through Dnscache); also verify example.com resolves.
        $publicOk = [Net.Dns]::GetHostAddresses('example.com').Count -gt 0
        return [ordered]@{
            dnsQueryName = $dnsName
            publicDnsOk = $publicOk
            oldTcp = (Send-GateMarker $hostOld $Marker)
            freshTcp = (Send-GateMarker $fresh ($Marker + 1))
        }
    } finally { Close-GatePair $fresh }
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'layer1_psec_launcher.c'),
        (Join-Path $fixtureDir 'layer2_psec_probe.c'),
        (Join-Path $fixtureDir 'PsecStartupGuard.cs'),
        (Join-Path $fixtureDir 'DesktopRead.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-wfp.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs'),
        $PSCommandPath
    )) {
        $report.sources[(Split-Path $src -Leaf)] = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    $existingA = Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue
    $existingB = Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue
    if ($existingA -or $existingB) { throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent before starting' }

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Create temporary standard local user ClaudeStudioLabA
    $password = New-RandomStrongPassword
    $createdUser = New-LocalUser -Name 'ClaudeStudioLabA' -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A PSEC guard test'
    $accountCreated = $true
    $accountSid = $createdUser.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $createdUser
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
    if ($accountSid -in $admins -or $accountSid -notin $users) { throw 'Unexpected group membership for ClaudeStudioLabA' }
    $report.account = [ordered]@{ name = 'ClaudeStudioLabA'; sid = $accountSid; inUsers = $true; inAdmins = $false }

    # Compile host C# harness DLL first (in host-private $base)
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

    $report.qpcFrequency = [StudioPsecGuardHost]::QpcFreq()
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Acquire seclogon session-bound token for A (zero WinSta0/Default DACL writes!) and load A profile
    $origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($origToken, 'ClaudeStudioLabA')
    $copyToken = [StudioPsecGuardHost]::DuplicateHardened($origToken, $hostSid)
    $ordinaryToken = [StudioPsecGuardHost]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $auditorToken = [StudioPsecGuardHost]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)

    $aProfileTemp = 'C:\Users\ClaudeStudioLabA\AppData\Local\Temp'
    if (!(Test-Path -LiteralPath $aProfileTemp)) { throw "Expected ClaudeStudioLabA profile temp directory: $aProfileTemp" }
    $aWorkRoot = Join-Path $aProfileTemp $tag
    $sealed = Join-Path $aWorkRoot 'sealed'
    $scratch = Join-Path $aWorkRoot 'scratch'
    $launcherExe = Join-Path $sealed 'StudioALayer1Psec.exe'
    $probeExe = Join-Path $sealed 'StudioAPsecProbe.exe'
    $psecBin = Join-Path $sealed 'psec-loopback.bin'

    $rxAcl = New-PrivateAcl $hostSid
    $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($accountSid),
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-15-2-1'),
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [void][IO.Directory]::CreateDirectory($aWorkRoot, $rxAcl)
    [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)

    $scratchAcl = New-PrivateAcl $hostSid
    $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($accountSid),
        [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-15-2-1'),
        [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [void][IO.Directory]::CreateDirectory($scratch, $scratchAcl)

    # Compile native Layer-1 PSEC launcher and Layer-2 PSEC probe (zero user32.dll) into $sealed
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    if (!(Test-Path -LiteralPath $vcvars)) { throw 'Missing VS 2022 BuildTools vcvars64.bat' }
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $launcherExe + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2.obj') + '" "' + (Join-Path $fixtureDir 'layer2_psec_probe.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $probeExe + '" kernel32.lib ws2_32.lib dnsapi.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $launcherExe) -or !(Test-Path -LiteralPath $probeExe)) {
        throw ('Native compile failed: ' + ($clOut -join '; '))
    }
    $report.launcherSha256 = (Get-FileHash -LiteralPath $launcherExe -Algorithm SHA256).Hash
    $report.probeSha256 = (Get-FileHash -LiteralPath $probeExe -Algorithm SHA256).Hash

    # Build PSEC v1.0 FlatBuffer (networkLoopback only, egress default deny, MXC-Loopback, disallowWin32k=false matching N3)
    $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1($scratch, $sealed, $false)
    [IO.File]::WriteAllBytes($psecBin, $psecBytes)
    $report.psecSpecBytes = $psecBytes.Length

    # Start host loopback control + TCP/UDP target sentinels + DNS ETW trace
    $hostListener = New-GateSocket
    $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $sentinels = New-Object LoopbackSentinels
    $report.sentinelPorts = [ordered]@{ tcp = $sentinels.TcpPort; udp = $sentinels.UdpPort }

    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $report.hostBefore = Test-HostHealth 'baseline' 41

    # No WinSta0 / WinSta0\Default ACL edits needed: seclogon token carries active session Logon SID natively.
    $report.layer1SessionLogonSid = [StudioPsecGuardHost]::ReadPrimaryLogonSid($origToken)

    # Ordinary A suspended control for handle audit
    $ordinaryHeld = [StudioPsecGuardHost]::StartSuspended($ordinaryToken, $probeExe, 'unused', $false, 'WinSta0\Default')

    # =========================================================================
    # PHASE 1: POSITIVE CONTROL (same PSEC config, NO WFP rules)
    # =========================================================================
    $posMarker = 'POS-' + $RunId + '-0123456789AB'
    $posDnsName = $prefix + '-psec-baseline-dns.test.'
    $posAddrName = $prefix + '-psec-baseline-addr.test.'
    $posReady = Join-Path $scratch 'pos-l1-ready.json'
    $posStop = Join-Path $scratch 'pos-l1-stop'
    $posProbeOut = Join-Path $scratch 'pos-l2-probe.json'
    $posL1Args = "`"$psecBin`" `"$probeExe`" `"$($sentinels.TcpPort) $($sentinels.UdpPort) $posMarker $posDnsName $posAddrName $posProbeOut`" `"$scratch`" `"$hostSid`" `"$posReady`" `"$posStop`""

    $posL1 = [StudioPsecGuardHost]::StartSuspended($copyToken, $launcherExe, $posL1Args, $true, 'WinSta0\Default')
    $report.positiveControlL1Restore = $posL1.RestoreTokenObjectDaclOnly($origToken, $hostSid, $accountSid)
    [void]$posL1.ResumeMainThread()
    $pollTimer = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $posReady) -and $pollTimer.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    if (!(Test-Path -LiteralPath $posReady)) { throw 'Positive control Layer-1 did not write ready receipt' }
    $posL1Receipt = Get-Content -LiteralPath $posReady -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.positiveControlL1 = $posL1Receipt
    if (!$posL1Receipt.psecCreated -or !$posL1Receipt.childCreated -or !$posL1Receipt.childInJob) {
        throw ('Positive control PSEC creation failed: ' + ($posL1Receipt | ConvertTo-Json -Compress))
    }

    $posInspect = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$posL1Receipt.childPid, [int]$posL1Receipt.childTid, $hostSid, $accountSid)
    $report.positiveControlInspect = $posInspect
    $posContainerSid = $posInspect.identity.containerSid
    if (!$posInspect.identity.appContainer -or $posContainerSid -notmatch '^S-1-15-2(-[0-9]+){7}$') {
        throw 'Positive control Layer-2 is not in a valid AppContainer'
    }
    if (@($posInspect.identity.networkCapabilities).Count -ne 1 -or $posInspect.identity.networkCapabilities[0] -cne $loopbackCapSid) {
        throw ('Unexpected positive control network capabilities: ' + ($posInspect.identity.networkCapabilities -join ','))
    }

    $posResume = [StudioPsecGuardHost]::HostResumeChildAndWait([int]$posL1Receipt.childPid, [int]$posL1Receipt.childTid, 8000)
    $report.positiveControlResume = $posResume
    if (!(Test-Path -LiteralPath $posProbeOut)) { throw 'Positive control Layer-2 probe did not write output' }
    $posProbe = Get-Content -LiteralPath $posProbeOut -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.positiveControlProbe = $posProbe
    Start-Sleep -Milliseconds 150
    $report.positiveControlSentinels = $sentinels.DrainMarkers()

    # Stop positive control Layer-1 and verify its PSEC entries clean up
    [IO.File]::WriteAllText($posStop, 'stop')
    $report.positiveControlL1Exit = $posL1.WaitExit(5000)
    $posL1.Dispose(); $posL1 = $null
    Start-Sleep -Milliseconds 150
    $report.positiveControlResidualWfp = [StudioLabWfp]::CountFiltersReferencingPackage($posContainerSid)

    $report.checks.positiveControlReachable = $posProbe.tcpConnected -and ($posProbe.tcpSent -eq $posMarker.Length) -and
        ($posProbe.udpSent -eq $posMarker.Length) -and
        ($report.positiveControlSentinels.tcpCount -eq 1) -and ($report.positiveControlSentinels.tcpMarkers[0] -ceq $posMarker) -and
        ($report.positiveControlSentinels.udpCount -eq 1) -and ($report.positiveControlSentinels.udpMarkers[0] -ceq $posMarker) -and
        ($report.positiveControlResidualWfp -eq 0)
    if (!$report.checks.positiveControlReachable) {
        throw 'Positive control failed: PSEC without WFP did not reach loopback TCP/UDP sentinels'
    }

    # =========================================================================
    # PHASE 2: TARGET PSEC INSTANCE (SUSPENDED -> WFP INSTALL/READBACK -> RESUME)
    # =========================================================================
    $blkMarker = 'BLK-' + $RunId + '-9876543210ZY'
    $blkDnsName = $prefix + '-psec-cold-dns.test.'
    $blkAddrName = $prefix + '-psec-cold-addr.test.'
    $blkReady = Join-Path $scratch 'blk-l1-ready.json'
    $blkStop = Join-Path $scratch 'blk-l1-stop'
    $blkProbeOut = Join-Path $scratch 'blk-l2-probe.json'
    $blkL1Args = "`"$psecBin`" `"$probeExe`" `"$($sentinels.TcpPort) $($sentinels.UdpPort) $blkMarker $blkDnsName $blkAddrName $blkProbeOut`" `"$scratch`" `"$hostSid`" `"$blkReady`" `"$blkStop`""

    $blkL1 = [StudioPsecGuardHost]::StartSuspended($copyToken, $launcherExe, $blkL1Args, $true, 'WinSta0\Default')
    $report.targetL1Restore = $blkL1.RestoreTokenObjectDaclOnly($origToken, $hostSid, $accountSid)
    if (!$report.targetL1Restore.processSecurityAfterRestore.hardenedExpected -or !$report.targetL1Restore.threadSecurityAfterRestore.hardenedExpected) {
        throw 'Layer-1 SD unexpectedly weakened after token object DACL restore'
    }
    [void]$blkL1.ResumeMainThread()
    $pollTimer.Restart()
    while (!(Test-Path -LiteralPath $blkReady) -and $pollTimer.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    if (!(Test-Path -LiteralPath $blkReady)) { throw 'Blocked target Layer-1 did not write ready receipt' }
    $blkL1Receipt = Get-Content -LiteralPath $blkReady -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.targetL1 = $blkL1Receipt
    if (!$blkL1Receipt.psecCreated -or !$blkL1Receipt.childCreated -or !$blkL1Receipt.childInJob) {
        throw ('Blocked target PSEC creation failed: ' + ($blkL1Receipt | ConvertTo-Json -Compress))
    }

    # Inspect suspended Layer-2 before ANY WFP write
    $blkInspect = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, $hostSid, $accountSid)
    $report.targetSuspendedInspect = $blkInspect
    $targetContainerSid = $blkInspect.identity.containerSid
    $report.checks.targetSuspendedIdentity = $blkInspect.identity.userSid -ceq $accountSid -and
        !$blkInspect.identity.admin -and $blkInspect.identity.appContainer -and
        ($targetContainerSid -match '^S-1-15-2(-[0-9]+){7}$') -and ($targetContainerSid -cne $posContainerSid) -and
        (@($blkInspect.identity.networkCapabilities).Count -eq 1) -and ($blkInspect.identity.networkCapabilities[0] -ceq $loopbackCapSid) -and
        $blkInspect.identity.inJob -and ($blkInspect.threadUserTime -eq 0) -and ($blkInspect.threadKernelTime -eq 0) -and
        $blkInspect.processSecurity.hardenedExpected -and $blkInspect.threadSecurity.hardenedExpected
    if (!$report.checks.targetSuspendedIdentity) {
        throw 'Target suspended PSEC Layer-2 failed identity/capability/SD pre-check; aborting with 0 WFP writes'
    }

    # Verify ordinary A (both distinct Logon SID and same Logon SID) cannot touch Layer-1 or suspended Layer-2
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
    if (!$report.checks.handleGatePassed) {
        throw 'Startup handle gate failed before WFP write; aborting with 0 WFP writes'
    }

    # WFP arbitration check + recovery manifest + transactional Static BLOCK install + independent readback
    $wfpSub = [guid]::NewGuid()
    $wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
    $wfpGuard = [StudioLabWfp]::CreateStaticGuard()
    try {
        $wfpWeight = $wfpGuard.PrepareStatic($wfpSub, $wfpKeys, $targetContainerSid, $wfpDummyPort, $probeExe)
        $report.wfpArbitration = [ordered]@{
            chosenSublayerWeight = $wfpWeight
            totalExamined = @($wfpGuard.PriorityEvidence).Count
            excludedByApplication = @($wfpGuard.PriorityEvidence | Where-Object { $_.excludedByApplication })
            requiringHigherPriority = @($wfpGuard.PriorityEvidence | Where-Object { $_.requiresHigherPriority })
        }
        $manifest = [ordered]@{
            runId = $RunId
            containerSid = $targetContainerSid
            sublayer = $wfpSub.ToString()
            keys = @($wfpKeys | ForEach-Object { $_.ToString() })
            dummyPort = $wfpDummyPort
            weight = $wfpWeight
            probeExe = $probeExe
            probeSha256 = $report.probeSha256
        }
        [IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
        $report.wfpManifest = $manifest

        $tWfpCommitStart = [StudioPsecGuardHost]::QpcNow()
        $wfpGuard.InstallStatic($wfpSub, $wfpKeys, $targetContainerSid, $wfpDummyPort, $probeExe, $wfpWeight)
        $tWfpCommitEnd = [StudioPsecGuardHost]::QpcNow()
        $wfpInstalled = $true
        $report.wfpWrites = 4
    } finally { $wfpGuard.Dispose() }

    # Independent WFP session readback (proves Static rules survive installer session exit)
    $tReadbackStart = [StudioPsecGuardHost]::QpcNow()
    $report.wfpReadback = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, $wfpDummyPort, $wfpWeight, $false)
    $tReadbackEnd = [StudioPsecGuardHost]::QpcNow()

    # Host health check while WFP rules are active
    $report.hostDuring = Test-HostHealth 'blocked' 51

    # Confirm Layer-2 STILL suspended right before host calls ResumeThread
    $blkPreResume = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, $hostSid, $accountSid)
    if ($blkPreResume.threadUserTime -ne 0 -or $blkPreResume.threadKernelTime -ne 0) {
        throw 'Layer-2 executed before host ResumeThread'
    }

    # Host directly calls ResumeThread on Layer-2 and waits for completion
    $blkResume = [StudioPsecGuardHost]::HostResumeChildAndWait([int]$blkL1Receipt.childPid, [int]$blkL1Receipt.childTid, 10000)
    $report.targetResume = $blkResume
    if (!(Test-Path -LiteralPath $blkProbeOut)) { throw 'Blocked target Layer-2 probe did not write output' }
    $blkProbe = Get-Content -LiteralPath $blkProbeOut -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.targetProbe = $blkProbe
    Start-Sleep -Milliseconds 200
    $report.targetSentinels = $sentinels.DrainMarkers()

    $report.timingQpc = [ordered]@{
        wfpCommitStart = $tWfpCommitStart
        wfpCommitEnd = $tWfpCommitEnd
        wfpReadbackStart = $tReadbackStart
        wfpReadbackEnd = $tReadbackEnd
        hostResumeBefore = $blkResume.qpcBeforeResume
        hostResumeAfter = $blkResume.qpcAfterResume
        probeEntry = $blkProbe.qpcEntry
        probeFirstSocket = $blkProbe.qpcFirstSocket
        probeDone = $blkProbe.qpcDone
    }

    $report.checks.monotonicOrder = ($tWfpCommitStart -le $tWfpCommitEnd) -and
        ($tWfpCommitEnd -le $tReadbackStart) -and
        ($tReadbackStart -le $tReadbackEnd) -and
        ($tReadbackEnd -le $blkResume.qpcBeforeResume) -and
        ($blkResume.qpcBeforeResume -le $blkProbe.qpcEntry) -and
        ($blkProbe.qpcEntry -le $blkProbe.qpcFirstSocket) -and
        ($blkResume.previousSuspendCount -eq 1)

    # TCP connect() fails synchronously with WSAEACCES (10013); connectionless UDP sendto() queues locally
    # and is dropped in-kernel by WFP ALE_AUTH_CONNECT_V4 (matching N3: positive control udpCount=1 vs blocked udpCount=0).
    $report.checks.targetBlockedZeroHits = !$blkProbe.tcpConnected -and ($blkProbe.tcpSent -eq 0) -and ($blkProbe.tcpErr -eq 10013) -and
        ($blkProbe.dnsQueryStatus -ne 0) -and ($blkProbe.getAddrInfoStatus -ne 0) -and
        ($report.targetSentinels.tcpCount -eq 0) -and ($report.targetSentinels.udpCount -eq 0)
} catch {
    $report.error = Get-ErrDetail $_
} finally {
    # 1. Stop Layer-1/Layer-2/PSEC first
    if ($scratch -and (Test-Path -LiteralPath $scratch)) {
        try {
            if ($posL1) { [IO.File]::WriteAllText((Join-Path $scratch 'pos-l1-stop'), 'stop') }
            if ($blkL1) { [IO.File]::WriteAllText((Join-Path $scratch 'blk-l1-stop'), 'stop') }
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    if ($blkL1) {
        try { $report.cleanup.targetL1Exit = $blkL1.WaitExit(5000) }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { $blkL1.Dispose() }
    }
    if ($posL1) {
        try { $report.cleanup.posL1Exit = $posL1.WaitExit(5000) }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { $posL1.Dispose() }
    }
    if ($ordinaryHeld) {
        try { $report.cleanup.ordinaryExit = $ordinaryHeld.TerminateNow() }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { $ordinaryHeld.Dispose() }
    }
    if ($loadedProfileHandle -ne [IntPtr]::Zero -and $origToken -ne [IntPtr]::Zero) {
        [StudioPsecGuardHost]::UnloadLabProfile($origToken, $loadedProfileHandle)
        $loadedProfileHandle = [IntPtr]::Zero
    }
    if ($copyToken -ne [IntPtr]::Zero) { [StudioPsecGuardHost]::CloseToken($copyToken) }
    if ($origToken -ne [IntPtr]::Zero) { [StudioPsecGuardHost]::CloseToken($origToken) }
    if ($ordinaryToken -ne [IntPtr]::Zero) { [StudioPsecGuardHost]::CloseToken($ordinaryToken) }
    if ($auditorToken -ne [IntPtr]::Zero) { [StudioPsecGuardHost]::CloseToken($auditorToken) }

    # Confirm zero fixture processes remain
    try {
        $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Psec.exe' OR Name = 'StudioAPsecProbe.exe'" | Where-Object {
            $_.ExecutablePath -ieq $launcherExe -or $_.ExecutablePath -ieq $probeExe
        })
        $report.cleanup.remainingPids = @($rem | ForEach-Object { $_.ProcessId })
        if ($rem.Count) { throw 'Fixture processes remain; retaining WFP rules for safety' }
    } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }

    # 2. Remove WFP Static BLOCK rules + sublayer (only after A processes confirmed exited)
    if ($wfpInstalled -and $report.cleanup.remainingPids.Count -eq 0) {
        try {
            [StudioLabWfp]::RemoveStatic($wfpSub, $wfpKeys, $targetContainerSid, $wfpDummyPort, $wfpWeight)
            $report.cleanup.wfpRemovedAndVerifiedAbsent = $true
        } catch {
            $report.cleanup.wfpRemovedAndVerifiedAbsent = $false
            $report.cleanup.errors += @(Get-ErrDetail $_)
        }
    } elseif (!$wfpInstalled) {
        $report.cleanup.wfpRemovedAndVerifiedAbsent = $true
    }

    # Check zero residual WFP entries referencing target container SID (including PSEC own filters)
    if ($targetContainerSid -and $assemblyLoaded) {
        Start-Sleep -Milliseconds 150
        try { $report.cleanup.targetResidualPackageFilters = [StudioLabWfp]::CountFiltersReferencingPackage($targetContainerSid) }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    } else {
        $report.cleanup.targetResidualPackageFilters = 0
    }

    # 3. Host health check after rollback
    if ($hostOld) {
        try { $report.hostAfter = Test-HostHealth 'restored' 61 }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
        finally { Close-GatePair $hostOld }
    }
    if ($hostListener) { $hostListener.Dispose() }
    if ($sentinels) { $sentinels.Dispose() }

    # 4. Stop DNS ETW trace and evaluate DNS zero-send evidence
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
                ($report.dnsSummary.hostSendCount -ge 3)
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }

    # 5. Desktop ACL check
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

    # 6. Delete temp directories ONLY if WFP cleanup succeeded
    if ($aWorkRoot -and (Test-Path -LiteralPath $aWorkRoot) -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.remainingPids.Count -eq 0) {
        try { Remove-Item -LiteralPath $aWorkRoot -Recurse -Force }
        catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    if ($dirCreated -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and $report.cleanup.remainingPids.Count -eq 0) {
        try {
            $item = Get-Item -LiteralPath $base
            if ($item.Name -cne $tag -or $item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                @(Get-ChildItem -LiteralPath $base -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
                throw 'Refusing to delete unexpected or reparse-point directory'
            }
            Remove-Item -LiteralPath $base -Recurse -Force
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)

    # 7. Delete temporary ClaudeStudioLabA account and any created profile
    if ($accountCreated) {
        try {
            Start-Sleep -Milliseconds 400
            $newProfiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
            $report.cleanup.profilesFoundForLabA = @($newProfiles | ForEach-Object { $_.LocalPath })
            foreach ($prof in $newProfiles) {
                try { Remove-CimInstance -InputObject $prof }
                catch {
                    Start-Sleep -Milliseconds 600
                    $retryProf = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid }
                    if ($retryProf) { Remove-CimInstance -InputObject $retryProf }
                }
            }
            Remove-LocalUser -Name 'ClaudeStudioLabA'
        } catch { $report.cleanup.errors += @(Get-ErrDetail $_) }
    }
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $profilesAfter = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
    $report.cleanup.labAProfileRecordGone = ($profilesAfter.Count -eq 0)

    $report.checks.hostContinuous = $report.hostBefore.oldTcp -and $report.hostBefore.freshTcp -and $report.hostBefore.publicDnsOk -and
        $report.hostDuring.oldTcp -and $report.hostDuring.freshTcp -and $report.hostDuring.publicDnsOk -and
        $report.hostAfter.oldTcp -and $report.hostAfter.freshTcp -and $report.hostAfter.publicDnsOk

    $report.checks.desktopUnchanged = ($report.desktopAclUnchanged -eq $true)
    $report.checks.cleanup = $report.cleanup.wfpRemovedAndVerifiedAbsent -and
        ($report.cleanup.targetResidualPackageFilters -eq 0) -and
        ($report.cleanup.remainingPids.Count -eq 0) -and
        $report.cleanup.directoryGone -and $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labAProfileRecordGone -and
        ($report.cleanup.errors.Count -eq 0)

    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    if (!$report.error -and $report.checks.positiveControlReachable -and $report.checks.targetSuspendedIdentity -and
        $report.checks.handleGatePassed -and $report.checks.monotonicOrder -and $report.checks.targetBlockedZeroHits -and
        $report.checks.dnsZeroLeak -and $report.checks.hostContinuous -and $report.checks.desktopUnchanged -and $report.checks.cleanup) {
        $report.outcome = 'passed-a-psec-startup-network-guard'
    } elseif ($report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged) {
        $report.outcome = 'stopped-a-psec-startup-network-guard'
    }

    $json = $report | ConvertTo-Json -Depth 14
    [IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
    $reportSha = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash

    $summary = [ordered]@{
        runId = $RunId
        outcome = $report.outcome
        reportPath = $ReportPath
        reportSha256 = $reportSha
        reportSha256Prefix12 = $reportSha.Substring(0, 12)
        error = $report.error
        wfpWrites = $report.wfpWrites
        checks = $report.checks
        positiveControlProbe = $report.positiveControlProbe
        positiveControlSentinels = $report.positiveControlSentinels
        targetProbe = $report.targetProbe
        targetSentinels = $report.targetSentinels
        timingQpc = $report.timingQpc
        dnsSummary = $report.dnsSummary
        wfpArbitration = if ($report.wfpArbitration) {
            [ordered]@{
                chosenSublayerWeight = $report.wfpArbitration.chosenSublayerWeight
                totalExamined = $report.wfpArbitration.totalExamined
                excludedByApplicationCount = @($report.wfpArbitration.excludedByApplication).Count
                requiringHigherPriorityCount = @($report.wfpArbitration.requiringHigherPriority).Count
            }
        } else { $null }
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
