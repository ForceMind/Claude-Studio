[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$RunId,
    [string]$ReportPath,
    [string]$SummaryPath,
    [string]$PrebuiltLauncherPath,
    [string]$PrebuiltHarnessPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    throw 'Run in x64 Windows PowerShell 5.1'
}

function Get-Win32ErrorDetail($Record) {
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

function Test-RightsAllGranted($Target) {
    $core = @($Target.processRights) + @($Target.threadRights)
    $term = @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' -or $_.right -ceq 'PROCESS_QUERY_LIMITED_INFORMATION' }) +
            @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })
    return @($Target.processRights).Count -eq 9 -and @($Target.threadRights).Count -eq 5 -and
        @($core + $term | Where-Object { !$_.granted -or $_.error -ne 0 }).Count -eq 0
}

function Get-DeniedViolations($Target, [string]$Perspective) {
    $violations = @()
    $all = @()
    foreach ($r in @($Target.processRights)) { $all += [pscustomobject]@{ part = 'process'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.threadRights)) { $all += [pscustomobject]@{ part = 'thread'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraProcessRights | Where-Object { $_.right -ceq 'PROCESS_TERMINATE' })) { $all += [pscustomobject]@{ part = 'processExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($r in @($Target.extraThreadRights | Where-Object { $_.right -ceq 'THREAD_TERMINATE' })) { $all += [pscustomobject]@{ part = 'threadExtra'; right = $r.right; granted = $r.granted; error = $r.error } }
    foreach ($entry in $all) {
        if ($entry.granted -or $entry.error -ne 5) {
            $violations += [ordered]@{
                perspective = $Perspective
                role = $Target.role
                part = $entry.part
                right = $entry.right
                granted = $entry.granted
                error = $entry.error
            }
        }
    }
    return $violations
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    if (!(Test-Path -LiteralPath $reportDir)) { throw "Expected existing report directory: $reportDir" }
    $ReportPath = Join-Path $reportDir ('windows-a-layer1-resumed-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioALayer1-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath `
            -PrebuiltLauncherPath $PrebuiltLauncherPath -PrebuiltHarnessPath $PrebuiltHarnessPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        if ($PrebuiltLauncherPath) { $argLine += ' -PrebuiltLauncherPath "' + $PrebuiltLauncherPath + '"' }
        if ($PrebuiltHarnessPath) { $argLine += ' -PrebuiltHarnessPath "' + $PrebuiltHarnessPath + '"' }
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList $argLine
        if ($proc.ExitCode -ne 0 -and !(Test-Path -LiteralPath $SummaryPath)) {
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

$hostSid = $identity.User.Value
$tag = 'ClaudeStudioALayer1-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$sealed = Join-Path $base 'sealed'
$scratch = Join-Path $base 'scratch'
$launcherExe = Join-Path $sealed 'StudioALayer1Launcher.exe'
$harnessDll = Join-Path $base 'StudioLayer1Harness.dll'
$readyJson = Join-Path $scratch 'layer1-ready.json'
$stopFile = Join-Path $scratch 'stop'
$fixtureDir = $PSScriptRoot
$mockDesktopDir = Split-Path (Split-Path $fixtureDir -Parent) -Parent

$report = [ordered]@{
    runId = $RunId
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-layer1-resumed'
    api = 'CreateProcessWithTokenW -> ResumeThread(layer1) -> CreateProcessW(STARTUPINFOEX+Job+CREATE_SUSPENDED, layer2)'
    psecCreated = $false
    wfpWrites = 0
    layer2ResumeCalls = 0
    hostSid = $hostSid
    sources = [ordered]@{}
    checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingLauncherPids = @() }
}

$accountCreated = $false
$accountSid = $null
$dirCreated = $false
$assemblyLoaded = $false
$origToken = [IntPtr]::Zero
$copyToken = [IntPtr]::Zero
$ordinaryToken = [IntPtr]::Zero
$auditorToken = [IntPtr]::Zero
$ordinaryHeld = $null
$layer1Held = $null
$layer2Pid = 0

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'layer1_launcher.c'),
        (Join-Path $fixtureDir 'DesktopRead.cs'),
        (Join-Path $fixtureDir 'Layer1Resumed.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs'),
        $PSCommandPath
    )) {
        $report.sources[(Split-Path $src -Leaf)] = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    $existingA = Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue
    $existingB = Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue
    $report.accountsBefore = [ordered]@{ labAExists = [bool]$existingA; labBExists = [bool]$existingB }
    if ($existingA -or $existingB) { throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent before starting' }

    if (Test-Path -LiteralPath $base) { throw 'Temporary fixture directory already exists' }
    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Create temporary standard local user ClaudeStudioLabA
    $password = New-RandomStrongPassword
    $createdUser = New-LocalUser -Name 'ClaudeStudioLabA' -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A Layer1 resumed test'
    $accountCreated = $true
    $accountSid = $createdUser.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $createdUser
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
    if ($accountSid -in $admins -or $accountSid -notin $users) { throw 'Unexpected group membership for ClaudeStudioLabA' }
    $report.account = [ordered]@{ name = 'ClaudeStudioLabA'; sid = $accountSid; inUsers = $true; inAdmins = $false }

    # Create sealed (A: ReadAndExecute) and scratch (A: Modify)
    $sealedAcl = New-PrivateAcl $hostSid
    $sealedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($accountSid),
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [void][IO.Directory]::CreateDirectory($sealed, $sealedAcl)

    $scratchAcl = New-PrivateAcl $hostSid
    $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($accountSid),
        [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [void][IO.Directory]::CreateDirectory($scratch, $scratchAcl)

    # Copy or compile native Layer-1 launcher (zero user32.dll)
    if ($PrebuiltLauncherPath -and (Test-Path -LiteralPath $PrebuiltLauncherPath)) {
        Copy-Item -LiteralPath $PrebuiltLauncherPath -Destination $launcherExe
    } else {
        $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
        if (!(Test-Path -LiteralPath $vcvars)) { throw 'Missing VS 2022 BuildTools vcvars64.bat' }
        $srcC = Join-Path $fixtureDir 'layer1_launcher.c'
        $objPath = Join-Path $base 'layer1_launcher.obj'
        $buildCmd = 'call "' + $vcvars + '" >nul && cl /nologo /W4 /O2 /MT /GS /Fo"' + $objPath + '" "' + $srcC + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $launcherExe + '" kernel32.lib'
        $clOut = & cmd.exe /c $buildCmd 2>&1
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $launcherExe)) {
            throw ('Native compile failed: ' + ($clOut -join '; '))
        }
    }
    $report.launcherSha256 = (Get-FileHash -LiteralPath $launcherExe -Algorithm SHA256).Hash

    # Copy or compile C# host harness DLL
    if ($PrebuiltHarnessPath -and (Test-Path -LiteralPath $PrebuiltHarnessPath)) {
        Copy-Item -LiteralPath $PrebuiltHarnessPath -Destination $harnessDll
    } else {
        $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        $cscOut = & $csc /nologo /platform:x64 /target:library /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$harnessDll" `
            (Join-Path $fixtureDir 'DesktopRead.cs') `
            (Join-Path $fixtureDir 'Layer1Resumed.cs') `
            (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('Harness compile failed: ' + ($cscOut -join '; ')) }
    }
    $report.harnessSha256 = (Get-FileHash -LiteralPath $harnessDll -Algorithm SHA256).Hash

    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($harnessDll))
    $assemblyLoaded = $true

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioLayer1Holder]::ReadDefaultDesktopDigest()
    $report.broker = [StudioLayer1Holder]::BrokerIdentity()

    # Logon 3 distinct sessions for A
    $origToken = [StudioLayer1Holder]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $copyToken = [StudioLayer1Holder]::DuplicateWithHardenedDefaultDacl($origToken, $hostSid)
    $report.copyTokenDefaultDaclBeforeCreate = [StudioLayer1Holder]::ReadTokenDefaultDacl($copyToken)
    $ordinaryToken = [StudioLayer1Holder]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $auditorToken = [StudioLayer1Holder]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)

    # 1) Create ordinary A suspended positive control
    $ordinaryHeld = [StudioLayer1Holder]::StartSuspended($ordinaryToken, $launcherExe, 'inert')
    $report.ordinaryBefore = $ordinaryHeld.Snapshot($hostSid, $accountSid)

    # 2) Create hardened Layer-1 launcher suspended
    $layer1Args = 'launch "' + $launcherExe + '" "' + $readyJson + '" "' + $stopFile + '"'
    $layer1Held = [StudioLayer1Holder]::StartSuspended($copyToken, $launcherExe, $layer1Args)
    $report.layer1BeforeResume = $layer1Held.Snapshot($hostSid, $accountSid)

    # 3) Resume Layer-1 and wait for its ready receipt (proving worker thread + suspended Layer-2 child creation)
    $prevSuspend = $layer1Held.ResumeMainThread()
    $report.layer1ResumePrevCount = $prevSuspend

    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $readyJson) -and $watch.ElapsedMilliseconds -lt 10000) {
        if (![StudioLayer1Holder]::IsPidAlive($layer1Held.Pid)) { break }
        Start-Sleep -Milliseconds 25
    }
    if (!(Test-Path -LiteralPath $readyJson)) {
        $exitInfo = $layer1Held.WaitForCleanExit(1000)
        $report.layer1PrematureExit = $exitInfo
        throw ('Layer-1 did not write ready receipt; exitCode=' + $exitInfo.exitCode + ' (0x' + ('{0:X8}' -f $exitInfo.exitCode) + ')')
    }
    $receipt = Get-Content -LiteralPath $readyJson -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.layer1Receipt = $receipt
    if (!$receipt.workerOk -or !$receipt.childCreated -or !$receipt.childInJob -or $receipt.childPid -lt 1 -or $receipt.childTid -lt 1) {
        throw ('Layer-1 receipt reported internal failure: ' + ($receipt | ConvertTo-Json -Compress))
    }
    $layer2Pid = [int]$receipt.childPid

    # 4) Host inspects running Layer-1 and suspended Layer-2 directly
    $report.layer1RunningSnapshot = $layer1Held.Snapshot($hostSid, $accountSid)
    $report.layer2BeforeAudit = [StudioLayer1Holder]::HostInspectChild([int]$receipt.childPid, [int]$receipt.childTid, $hostSid, $accountSid)

    # 5) Dual-perspective A handle audit against all 4 live targets
    $brokerPid = [int]$report.broker.identity.pid
    $brokerTid = [int]$report.broker.tid
    $brokerTicks = [long]$report.broker.identity.startTicks

    $report.auditA1DistinctLogon = [StudioLayer1Holder]::RunImpersonatedAudit4(
        $auditorToken,
        $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $layer1Held.Pid, $layer1Held.Tid, $layer1Held.StartTicks,
        [int]$receipt.childPid, [int]$receipt.childTid, [long]$receipt.childStartTicks,
        $brokerPid, $brokerTid, $brokerTicks)

    $report.auditA2SameLogon = [StudioLayer1Holder]::RunImpersonatedAudit4(
        $origToken,
        $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $layer1Held.Pid, $layer1Held.Tid, $layer1Held.StartTicks,
        [int]$receipt.childPid, [int]$receipt.childTid, [long]$receipt.childStartTicks,
        $brokerPid, $brokerTid, $brokerTicks)

    # 6) Post-audit continuity snapshots
    $report.layer1AfterAudit = $layer1Held.Snapshot($hostSid, $accountSid)
    $report.layer2AfterAudit = [StudioLayer1Holder]::HostInspectChild([int]$receipt.childPid, [int]$receipt.childTid, $hostSid, $accountSid)

    # Evaluate checks
    $l1B = $report.layer1BeforeResume
    $l1R = $report.layer1RunningSnapshot
    $l1A = $report.layer1AfterAudit
    $l2B = $report.layer2BeforeAudit
    $l2A = $report.layer2AfterAudit

    $report.checks.layer1ResumedCleanly = ($prevSuspend -eq 1) -and ($l1R.resumeCalls -eq 1) -and
        $receipt.workerOk -and $receipt.childCreated -and $receipt.childInJob -and ($receipt.layer2ResumeCalls -eq 0)

    $report.checks.layer1SdHardened = $l1B.processSecurity.hardenedExpected -and $l1B.threadSecurity.hardenedExpected -and
        $l1A.processSecurity.hardenedExpected -and $l1A.threadSecurity.hardenedExpected

    $report.checks.layer2IdentityAndSuspended = $l2B.hostOpenedFullAccess -and
        $l2B.identity.userSid -ceq $accountSid -and !$l2B.identity.admin -and !$l2B.identity.appContainer -and
        $l2B.identity.tokenType -eq 1 -and $l2B.identity.integrity -ceq 'S-1-16-8192' -and
        $l2B.identity.inJob -and
        $l2B.pid -eq $l2A.pid -and $l2B.tid -eq $l2A.tid -and
        $l2B.identity.startTicks -eq $l2A.identity.startTicks -and
        $l2B.threadUserTime -eq 0 -and $l2A.threadUserTime -eq 0 -and
        $l2B.threadKernelTime -eq 0 -and $l2A.threadKernelTime -eq 0 -and
        $l2B.resumeCalls -eq 0 -and $l2A.resumeCalls -eq 0

    $report.checks.layer2SdHardened = $l2B.processSecurity.hardenedExpected -and $l2B.threadSecurity.hardenedExpected -and
        $l2A.processSecurity.hardenedExpected -and $l2A.threadSecurity.hardenedExpected -and
        !$l2B.processSecurity.hasAccountAce -and !$l2B.processSecurity.hasLogonSidAce -and $l2B.processSecurity.hasOwnerRightsZeroAce

    $report.checks.distinctLogonSids = $l1B.identity.logonSids[0] -cne $report.ordinaryBefore.identity.logonSids[0] -and
        $l1B.identity.logonSids[0] -cne $report.auditA1DistinctLogon.auditor.logonSids[0] -and
        $l1B.identity.logonSids[0] -ceq $report.auditA2SameLogon.auditor.logonSids[0] -and
        $l1B.identity.logonSids[0] -ceq $l2B.identity.logonSids[0]

    $a1 = @{}; foreach ($t in $report.auditA1DistinctLogon.targets) { $a1[$t.role] = $t }
    $a2 = @{}; foreach ($t in $report.auditA2SameLogon.targets) { $a2[$t.role] = $t }

    $report.checks.a1PositiveControl = Test-RightsAllGranted $a1['ordinary']
    $report.checks.a2PositiveControl = Test-RightsAllGranted $a2['ordinary']

    $violations = @()
    foreach ($role in 'layer1','layer2','broker') {
        $violations += Get-DeniedViolations $a1[$role] 'A1-DistinctLogon'
        $violations += Get-DeniedViolations $a2[$role] 'A2-SameLogon'
    }
    $report.violations = $violations
    $report.checks.allCriticalDenied = ($violations.Count -eq 0)
} catch {
    $report.error = Get-Win32ErrorDetail $_
} finally {
    # Signal Layer-1 to terminate Layer-2 and exit cleanly
    if ($dirCreated -and (Test-Path -LiteralPath $scratch)) {
        try { [IO.File]::WriteAllText($stopFile, 'stop') } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
    }
    if ($layer1Held) {
        try {
            if ($layer1Held.ResumeCalls -gt 0) {
                $report.cleanup.layer1Exit = $layer1Held.WaitForCleanExit(5000)
            } else {
                $report.cleanup.layer1Exit = $layer1Held.TerminateAndWait()
            }
        } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
        finally { $layer1Held.Dispose() }
    }
    if ($layer2Pid -gt 0 -and $assemblyLoaded) {
        $report.cleanup.layer2AliveAfterStop = [StudioLayer1Holder]::IsPidAlive($layer2Pid)
    } else {
        $report.cleanup.layer2AliveAfterStop = $false
    }
    if ($ordinaryHeld) {
        try { $report.cleanup.ordinaryTermination = $ordinaryHeld.TerminateAndWait() }
        catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
        finally { $ordinaryHeld.Dispose() }
    }
    if ($copyToken -ne [IntPtr]::Zero) { [StudioLayer1Holder]::CloseToken($copyToken) }
    if ($origToken -ne [IntPtr]::Zero) { [StudioLayer1Holder]::CloseToken($origToken) }
    if ($ordinaryToken -ne [IntPtr]::Zero) { [StudioLayer1Holder]::CloseToken($ordinaryToken) }
    if ($auditorToken -ne [IntPtr]::Zero) { [StudioLayer1Holder]::CloseToken($auditorToken) }

    try {
        $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioALayer1Launcher.exe'" | Where-Object { $_.ExecutablePath -ieq $launcherExe })
        $report.cleanup.remainingLauncherPids = @($rem | ForEach-Object { $_.ProcessId })
        if ($rem.Count) { throw 'Launcher or child processes remain after cleanup' }
    } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }

    try {
        if ($assemblyLoaded) {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioLayer1Holder]::ReadDefaultDesktopDigest()
            $defaultMatch = ($report.defaultDesktopBefore.readable -eq $report.defaultDesktopAfter.readable) -and
                ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
            $report.desktopAclUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
                $defaultMatch
        }
    } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }

    if ($dirCreated) {
        try {
            $item = Get-Item -LiteralPath $base
            if ($item.Name -cne $tag -or $item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                @(Get-ChildItem -LiteralPath $base -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
                throw 'Refusing to delete unexpected or reparse-point directory'
            }
            Remove-Item -LiteralPath $base -Recurse -Force
        } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
    }
    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)

    if ($accountCreated) {
        try {
            $newProfiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
            $report.cleanup.profilesFoundForLabA = @($newProfiles | ForEach-Object { $_.LocalPath })
            foreach ($prof in $newProfiles) { Remove-CimInstance -InputObject $prof }
            Remove-LocalUser -Name 'ClaudeStudioLabA'
        } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
    }
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $profilesAfter = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
    $report.cleanup.labAProfileRecordGone = ($profilesAfter.Count -eq 0)

    $l1ExitOk = !$layer1Held -or ($report.cleanup.layer1Exit.processSignaled -and $report.cleanup.layer1Exit.threadSignaled -and
        (!$layer1Held.ResumeCalls -or (!$report.cleanup.layer1Exit.timedOut -and $report.cleanup.layer1Exit.exitCode -eq 0)))
    $ordExitOk = !$ordinaryHeld -or ($report.cleanup.ordinaryTermination.processSignaled -and $report.cleanup.ordinaryTermination.threadSignaled -and $report.cleanup.ordinaryTermination.exitCode -eq 20020)

    $report.checks.cleanup = $l1ExitOk -and $ordExitOk -and !$report.cleanup.layer2AliveAfterStop -and
        $report.cleanup.directoryGone -and $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labAProfileRecordGone -and
        ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.remainingLauncherPids.Count -eq 0)

    $report.checks.desktopUnchanged = ($report.desktopAclUnchanged -eq $true)
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    if (!$report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged -and
        $report.checks.layer1ResumedCleanly -and $report.checks.layer1SdHardened -and
        $report.checks.layer2IdentityAndSuspended -and $report.checks.layer2SdHardened -and
        $report.checks.distinctLogonSids -and $report.checks.a1PositiveControl -and $report.checks.a2PositiveControl) {
        if ($report.checks.allCriticalDenied) {
            $report.outcome = 'passed-layer1-resumed-to-layer2-suspended'
        } else {
            $report.outcome = 'stopped-layer1-resumed-rights'
        }
    } elseif ($report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged) {
        $report.outcome = 'stopped-layer1-resumed-error'
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
        layer1ResumePrevCount = $report.layer1ResumePrevCount
        layer1Receipt = $report.layer1Receipt
        checks = $report.checks
        violationCount = if ($null -eq $report.violations) { 0 } else { @($report.violations).Count }
        violations = $report.violations
        layer2ProcessOwner = if ($report.layer2BeforeAudit) { $report.layer2BeforeAudit.processSecurity.owner } else { $null }
        layer2ProcessDacl = if ($report.layer2BeforeAudit) { $report.layer2BeforeAudit.processSecurity.entries } else { $null }
        layer2ThreadDacl = if ($report.layer2BeforeAudit) { $report.layer2BeforeAudit.threadSecurity.entries } else { $null }
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
