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
    $ReportPath = Join-Path $reportDir ('windows-a-token-default-dacl-' + $RunId + '.json')
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioATokenDacl-summary-' + $RunId + '.json')
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
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
$tag = 'ClaudeStudioATokenDacl-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$sealed = Join-Path $base 'sealed'
$scratch = Join-Path $base 'scratch'
$exe = Join-Path $sealed 'StudioAStartupPermission.exe'
$fixtureDir = $PSScriptRoot
$mockDesktopDir = Split-Path (Split-Path $fixtureDir -Parent) -Parent

$report = [ordered]@{
    runId = $RunId
    utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-token-default-dacl'
    api = 'CreateProcessWithTokenW'
    updateTokenDacl = $true
    explicitDesktop = 'WinSta0\Default'
    resumeCalls = 0
    psecCreated = $false
    wfpWrites = 0
    hostSid = $hostSid
    sources = [ordered]@{}
    checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingFixturePids = @() }
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
$suspendedHeld = $null
$profilesBefore = @()

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"

    foreach ($src in @(
        (Join-Path $fixtureDir 'DesktopRead.cs'),
        (Join-Path $fixtureDir 'TokenDefaultDacl.cs'),
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs'),
        $PSCommandPath
    )) {
        $report.sources[(Split-Path $src -Leaf)] = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    # Pre-check: ensure neither test account exists before we begin
    $existingA = Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue
    $existingB = Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue
    $report.accountsBefore = [ordered]@{
        labAExists = [bool]$existingA
        labBExists = [bool]$existingB
    }
    if ($existingA -or $existingB) {
        throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent before starting'
    }

    $profilesBefore = @(Get-CimInstance Win32_UserProfile | ForEach-Object { $_.SID })

    # Check elevated host privileges
    $whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'
    $privRows = @(& $whoami /priv /fo csv /nh | ConvertFrom-Csv -Header name,description,state)
    $report.hostPrivileges = @(foreach ($pName in 'SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeIncreaseQuotaPrivilege') {
        $row = $privRows | Where-Object { $_.name -ceq $pName }
        [ordered]@{ name = $pName; present = [bool]$row; state = if ($row) { $row.state } else { $null } }
    })

    # Create private base directory and compile fixture first (before creating A)
    if (Test-Path -LiteralPath $base) { throw 'Temporary fixture directory already exists' }
    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Create temporary standard local user ClaudeStudioLabA
    $password = New-RandomStrongPassword
    $createdUser = New-LocalUser -Name 'ClaudeStudioLabA' -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A TokenDefaultDacl test'
    $accountCreated = $true
    $accountSid = $createdUser.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $createdUser
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
    if ($accountSid -in $admins -or $accountSid -notin $users) {
        throw 'Created ClaudeStudioLabA has unexpected group membership'
    }
    $report.account = [ordered]@{ name = 'ClaudeStudioLabA'; sid = $accountSid; inUsers = $true; inAdmins = $false }

    # Create sealed (A: ReadAndExecute) and scratch (A: Modify) directories
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

    # Compile x64 synthetic fixture EXE
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $compileOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$exe" `
        (Join-Path $fixtureDir 'DesktopRead.cs') `
        (Join-Path $fixtureDir 'TokenDefaultDacl.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('C# compile failed: ' + ($compileOut -join '; '))
    }
    $report.fixtureSha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash

    # Load compiled assembly into elevated host to access StudioReadDesktop & StudioTokenDaclVerification
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($exe))
    $assemblyLoaded = $true

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioTokenDaclVerification]::ReadDefaultDesktopDigest()
    $report.broker = [StudioTokenDaclVerification]::BrokerIdentity()

    # Logon 3 distinct interactive sessions for A:
    # 1) origToken -> duplicated into hardened copyToken for 'suspended', also used untouched for A2 same-logon-SID probe
    # 2) ordinaryToken -> unmodified default DACL for 'ordinary' positive control
    # 3) auditorToken -> distinct logon session for A1 independent ordinary A probes
    $origToken = [StudioTokenDaclVerification]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $report.origTokenDefaultDacl = [StudioTokenDaclVerification]::ReadTokenDefaultDacl($origToken)

    $copyToken = [StudioTokenDaclVerification]::DuplicateWithHardenedDefaultDacl($origToken, $hostSid)
    $report.copyTokenDefaultDaclBeforeCreate = [StudioTokenDaclVerification]::ReadTokenDefaultDacl($copyToken)

    $ordinaryToken = [StudioTokenDaclVerification]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)
    $auditorToken = [StudioTokenDaclVerification]::LogonInteractive('ClaudeStudioLabA', $env:COMPUTERNAME, $password)

    # Create 'ordinary' suspended positive control with unmodified ordinaryToken
    $ordinaryHeld = [StudioTokenDaclVerification]::StartSuspended($ordinaryToken, $exe)
    $report.ordinaryBefore = $ordinaryHeld.Snapshot($hostSid, $accountSid)

    # Create 'suspended' target with hardened copyToken
    $suspendedHeld = [StudioTokenDaclVerification]::StartSuspended($copyToken, $exe)
    $report.suspendedBefore = $suspendedHeld.Snapshot($hostSid, $accountSid)
    $report.desktopAfterCreate = [StudioReadDesktop]::Read()

    # Perspective A1-Impersonate: distinct Logon SID #3
    $brokerPid = [int]$report.broker.identity.pid
    $brokerTid = [int]$report.broker.tid
    $brokerTicks = [long]$report.broker.identity.startTicks
    $report.auditA1Impersonate = [StudioTokenDaclVerification]::RunImpersonatedAudit(
        $auditorToken,
        $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $suspendedHeld.Pid, $suspendedHeld.Tid, $suspendedHeld.StartTicks,
        $brokerPid, $brokerTid, $brokerTicks)

    # Perspective A1-Process: standalone independent A process with distinct Logon SID #3
    $auditRequestPath = Join-Path $sealed 'audit-request.json'
    $auditOutputPath = Join-Path $scratch 'audit-a1-process.json'
    $auditRequest = [ordered]@{
        outputPath = $auditOutputPath
        targets = @(
            @{ role = 'ordinary'; pid = $ordinaryHeld.Pid; tid = $ordinaryHeld.Tid; startTicks = $ordinaryHeld.StartTicks }
            @{ role = 'suspended'; pid = $suspendedHeld.Pid; tid = $suspendedHeld.Tid; startTicks = $suspendedHeld.StartTicks }
            @{ role = 'broker'; pid = $brokerPid; tid = $brokerTid; startTicks = $brokerTicks }
        )
    }
    [IO.File]::WriteAllText($auditRequestPath, ($auditRequest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    $a1ProcRun = [StudioTokenDaclVerification]::RunStandaloneAuditor($auditorToken, $exe, $auditRequestPath, 10000)
    $a1ProcParsed = $null
    if (Test-Path -LiteralPath $auditOutputPath) {
        $a1ProcParsed = Get-Content -LiteralPath $auditOutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $report.auditA1Process = [ordered]@{
        run = $a1ProcRun
        result = $a1ProcParsed
    }

    # Perspective A2-SameLogon: untouched origToken sharing same Logon SID #1 as suspended
    $report.auditA2SameLogon = [StudioTokenDaclVerification]::RunImpersonatedAudit(
        $origToken,
        $ordinaryHeld.Pid, $ordinaryHeld.Tid, $ordinaryHeld.StartTicks,
        $suspendedHeld.Pid, $suspendedHeld.Tid, $suspendedHeld.StartTicks,
        $brokerPid, $brokerTid, $brokerTicks)

    # Continuity snapshots after all audits
    $report.ordinaryAfter = $ordinaryHeld.Snapshot($hostSid, $accountSid)
    $report.suspendedAfter = $suspendedHeld.Snapshot($hostSid, $accountSid)

    # Evaluate checks
    $suspB = $report.suspendedBefore
    $suspA = $report.suspendedAfter
    $ordB = $report.ordinaryBefore

    $report.checks.tokenCopyReadback = !$report.copyTokenDefaultDaclBeforeCreate.isNull -and
        $report.copyTokenDefaultDaclBeforeCreate.aceCount -eq 3 -and
        @($report.copyTokenDefaultDaclBeforeCreate.entries | Where-Object { $_.sid -ceq $hostSid -and $_.mask -ne 0 }).Count -eq 1 -and
        @($report.copyTokenDefaultDaclBeforeCreate.entries | Where-Object { $_.sid -ceq 'S-1-5-18' -and $_.mask -ne 0 }).Count -eq 1 -and
        @($report.copyTokenDefaultDaclBeforeCreate.entries | Where-Object { $_.sid -ceq 'S-1-3-4' -and $_.mask -eq 0 }).Count -eq 1

    $report.checks.suspendedIdentity = $suspB.identity.userSid -ceq $accountSid -and
        !$suspB.identity.admin -and !$suspB.identity.appContainer -and
        $suspB.identity.tokenType -eq 1 -and $suspB.identity.integrity -ceq 'S-1-16-8192' -and
        $suspB.inCleanupJob -and !$suspB.processInheritable -and !$suspB.threadInheritable

    $report.checks.suspendedInvariant = $suspB.pid -eq $suspA.pid -and $suspB.tid -eq $suspA.tid -and
        $suspB.identity.startTicks -eq $suspA.identity.startTicks -and
        $suspB.threadUserTime -eq 0 -and $suspA.threadUserTime -eq 0 -and
        $suspB.threadKernelTime -eq 0 -and $suspA.threadKernelTime -eq 0 -and
        $suspB.resumeCalls -eq 0 -and $suspA.resumeCalls -eq 0

    $report.checks.distinctLogonSids = @($suspB.identity.logonSids).Count -ge 1 -and
        @($ordB.identity.logonSids).Count -ge 1 -and
        @($report.auditA1Impersonate.auditor.logonSids).Count -ge 1 -and
        $suspB.identity.logonSids[0] -cne $ordB.identity.logonSids[0] -and
        $suspB.identity.logonSids[0] -cne $report.auditA1Impersonate.auditor.logonSids[0] -and
        $suspB.identity.logonSids[0] -ceq $report.auditA2SameLogon.auditor.logonSids[0]

    $report.checks.processSdHardened = $suspB.processSecurity.hardenedExpected -and $suspA.processSecurity.hardenedExpected
    $report.checks.threadSdHardened = $suspB.threadSecurity.hardenedExpected -and $suspA.threadSecurity.hardenedExpected
    $report.checks.noAccountAce = !$suspB.processSecurity.hasAccountAce -and !$suspB.threadSecurity.hasAccountAce
    $report.checks.noLogonSidAce = !$suspB.processSecurity.hasLogonSidAce -and !$suspB.threadSecurity.hasLogonSidAce
    $report.checks.ownerRightsZeroPresent = $suspB.processSecurity.hasOwnerRightsZeroAce -and $suspB.threadSecurity.hasOwnerRightsZeroAce

    $a1ImpTargets = @{}
    foreach ($t in $report.auditA1Impersonate.targets) { $a1ImpTargets[$t.role] = $t }
    $a2Targets = @{}
    foreach ($t in $report.auditA2SameLogon.targets) { $a2Targets[$t.role] = $t }

    $report.checks.a1ImpersonatePositiveControl = Test-RightsAllGranted $a1ImpTargets['ordinary']
    $report.checks.a2SameLogonPositiveControl = Test-RightsAllGranted $a2Targets['ordinary']

    $violations = @()
    $violations += Get-DeniedViolations $a1ImpTargets['suspended'] 'A1-Impersonate'
    $violations += Get-DeniedViolations $a1ImpTargets['broker'] 'A1-Impersonate'
    $violations += Get-DeniedViolations $a2Targets['suspended'] 'A2-SameLogon'
    $violations += Get-DeniedViolations $a2Targets['broker'] 'A2-SameLogon'

    $report.checks.a1ProcessCompleted = $a1ProcRun.exitCode -eq 0 -and !$a1ProcRun.timedOut -and ($null -ne $a1ProcParsed)
    if ($report.checks.a1ProcessCompleted) {
        $a1ProcTargets = @{}
        foreach ($t in $a1ProcParsed.targets) { $a1ProcTargets[$t.role] = $t }
        $report.checks.a1ProcessPositiveControl = Test-RightsAllGranted $a1ProcTargets['ordinary']
        $violations += Get-DeniedViolations $a1ProcTargets['suspended'] 'A1-Process'
        $violations += Get-DeniedViolations $a1ProcTargets['broker'] 'A1-Process'
    }

    $report.violations = $violations
    $report.checks.allCriticalDenied = ($violations.Count -eq 0)
} catch {
    $report.error = Get-Win32ErrorDetail $_
} finally {
    if ($suspendedHeld) {
        try { $report.cleanup.suspendedTermination = $suspendedHeld.TerminateAndWait() }
        catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
        finally { $suspendedHeld.Dispose() }
    }
    if ($ordinaryHeld) {
        try { $report.cleanup.ordinaryTermination = $ordinaryHeld.TerminateAndWait() }
        catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
        finally { $ordinaryHeld.Dispose() }
    }
    if ($copyToken -ne [IntPtr]::Zero) { [StudioTokenDaclVerification]::CloseToken($copyToken) }
    if ($origToken -ne [IntPtr]::Zero) { [StudioTokenDaclVerification]::CloseToken($origToken) }
    if ($ordinaryToken -ne [IntPtr]::Zero) { [StudioTokenDaclVerification]::CloseToken($ordinaryToken) }
    if ($auditorToken -ne [IntPtr]::Zero) { [StudioTokenDaclVerification]::CloseToken($auditorToken) }

    # Check zero remaining fixture processes
    try {
        $rem = @(Get-CimInstance Win32_Process -Filter "Name = 'StudioAStartupPermission.exe'" | Where-Object { $_.ExecutablePath -ieq $exe })
        $report.cleanup.remainingFixturePids = @($rem | ForEach-Object { $_.ProcessId })
        if ($rem.Count) { throw 'Fixture processes remain after cleanup' }
    } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }

    # Desktop ACL after cleanup
    try {
        if ($assemblyLoaded) {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioTokenDaclVerification]::ReadDefaultDesktopDigest()
            $defaultMatch = ($report.defaultDesktopBefore.readable -eq $report.defaultDesktopAfter.readable) -and
                ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
            $report.desktopAclUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
                $defaultMatch
        }
    } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }

    # Remove temporary directory safely
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

    # Remove temporary ClaudeStudioLabA account and any created user profile
    if ($accountCreated) {
        try {
            $newProfiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
            $report.cleanup.profilesFoundForLabA = @($newProfiles | ForEach-Object { $_.LocalPath })
            foreach ($prof in $newProfiles) {
                Remove-CimInstance -InputObject $prof
            }
            Remove-LocalUser -Name 'ClaudeStudioLabA'
        } catch { $report.cleanup.errors += @(Get-Win32ErrorDetail $_) }
    }
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $profilesAfter = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $accountSid })
    $report.cleanup.labAProfileRecordGone = ($profilesAfter.Count -eq 0)

    $termOk = (!$suspendedHeld -or ($report.cleanup.suspendedTermination.processSignaled -and $report.cleanup.suspendedTermination.threadSignaled -and $report.cleanup.suspendedTermination.exitCode -eq 20020)) -and
              (!$ordinaryHeld -or ($report.cleanup.ordinaryTermination.processSignaled -and $report.cleanup.ordinaryTermination.threadSignaled -and $report.cleanup.ordinaryTermination.exitCode -eq 20020))

    $report.checks.cleanup = $termOk -and $report.cleanup.directoryGone -and $report.cleanup.labAGone -and $report.cleanup.labBGone -and
        $report.cleanup.labAProfileDirGone -and $report.cleanup.labAProfileRecordGone -and
        ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.remainingFixturePids.Count -eq 0)

    $report.checks.desktopUnchanged = ($report.desktopAclUnchanged -eq $true)
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    if (!$report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged -and
        $report.checks.tokenCopyReadback -and $report.checks.suspendedIdentity -and $report.checks.suspendedInvariant -and
        $report.checks.distinctLogonSids -and $report.checks.a1ImpersonatePositiveControl -and $report.checks.a2SameLogonPositiveControl) {
        if ($report.checks.allCriticalDenied -and $report.checks.noAccountAce -and $report.checks.ownerRightsZeroPresent) {
            $report.outcome = 'passed-token-default-dacl-gate'
        } else {
            $report.outcome = 'stopped-token-default-dacl-rights'
        }
    } elseif ($report.error -and $report.checks.cleanup -and $report.checks.desktopUnchanged) {
        $report.outcome = 'stopped-token-default-dacl-api-error'
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
        checks = $report.checks
        violationCount = if ($null -eq $report.violations) { 0 } else { @($report.violations).Count }
        violations = $report.violations
        a1ProcessRun = if ($report.auditA1Process) { $report.auditA1Process.run } else { $null }
        suspendedProcessOwner = if ($report.suspendedBefore) { $report.suspendedBefore.processSecurity.owner } else { $null }
        suspendedProcessDacl = if ($report.suspendedBefore) { $report.suspendedBefore.processSecurity.entries } else { $null }
        suspendedThreadDacl = if ($report.suspendedBefore) { $report.suspendedBefore.threadSecurity.entries } else { $null }
        cleanup = $report.cleanup
    }
    [IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
