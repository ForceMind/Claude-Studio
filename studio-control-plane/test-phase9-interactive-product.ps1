[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$RunId,
    [string]$ReportPath,
    [string]$SummaryPath,
    [string]$PkgInstallLocation,
    [string]$PkgVersion,
    [string]$PkgFamilyName
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

function Get-DirMeta([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) { return [ordered]@{ exists = $false } }
    $it = Get-Item -LiteralPath $Path -Force
    $cnt = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count
    return [ordered]@{ exists = $true; lastWriteUtc = $it.LastWriteTimeUtc.ToString('o'); childCount = $cnt }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $pkgLocal = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$pkgLocal -or !(Test-Path -LiteralPath (Join-Path $pkgLocal.InstallLocation 'app\claude.exe'))) {
        throw 'Official Claude MSIX installation not found for current user'
    }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    $ReportPath = Join-Path $reportDir ("windows-ab-phase9-interactive-product-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudePhase9-summary-$RunId.json")
    if ($isAdmin -and [Threading.Thread]::CurrentThread.ApartmentState -eq [Threading.ApartmentState]::STA) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath `
            -PkgInstallLocation $pkgLocal.InstallLocation -PkgVersion $pkgLocal.Version -PkgFamilyName $pkgLocal.PackageFamilyName
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-STA -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '" -PkgInstallLocation "' + $pkgLocal.InstallLocation + '" -PkgVersion "' + $pkgLocal.Version + '" -PkgFamilyName "' + $pkgLocal.PackageFamilyName + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $sw.ElapsedMilliseconds -lt 180000) { Start-Sleep -Milliseconds 100 }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if (!(Test-Path -LiteralPath $SummaryPath)) { throw "Elevated runner exited/timed out without summary (exited=$($proc.HasExited), code=$($proc.ExitCode))" }
    }
    $txt = [IO.File]::ReadAllText($SummaryPath, [Text.Encoding]::UTF8)
    Remove-Item -LiteralPath $SummaryPath -Force
    Write-Output $txt
    return
}

$cpDir = $PSScriptRoot
$binDir = Join-Path $cpDir 'bin'
$repoRoot = Split-Path $cpDir -Parent
$mockDir = Join-Path $repoRoot 'mock-desktop'
. (Join-Path $mockDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDir 'windows-lab-bind-gate.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudePhase9-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$sharedAppStage = Join-Path $env:ProgramData ("ClaudeStudioPhase9App-$RunId")
$sharedRepo = Join-Path $env:ProgramData ("ClaudeStudioPhase9Repo-$RunId")
$srcAppDir = Join-Path $PkgInstallLocation 'app'

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase9-interactive-product'
    officialPackage = [ordered]@{ name = 'Claude'; version = $PkgVersion; packageFamilyName = $PkgFamilyName }
    oauthRouting = [ordered]@{}; liveProjectSync = [ordered]@{}; hostHealth = [ordered]@{}
    checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); residualPackageFilters = 0 }
}

$dirCreated = $false; $sharedAppCreated = $false; $repoCreated = $false; $assemblyLoaded = $false
$users = @{}; $tokens = @{}
$hostListener = $null; $hostOld = $null; $localUpstream = $null
$backend = $null; $engine = $null
$etlName = $prefix; $etlFile = Join-Path $base ($prefix + '.etl'); $etlStarted = $false; $dnsPidBefore = 0
$observedPidSet = New-Object 'System.Collections.Generic.HashSet[int]'

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

    $cpExe = Join-Path $binDir 'ClaudeStudioControlPlane.exe'
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($cpExe))
    $assemblyLoaded = $true

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class Phase9ProcInspect {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int req);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
    public static Dictionary<string, object> ReadPidToken(int pid) {
        var d = new Dictionary<string, object> { { "pid", pid }, { "ok", false } };
        IntPtr p = OpenProcess(0x1000, false, pid); if (p == IntPtr.Zero) return d;
        IntPtr t = IntPtr.Zero;
        try {
            if (!OpenProcessToken(p, 0x0008, out t)) return d;
            int req = 0; GetTokenInformation(t, 1, IntPtr.Zero, 0, out req);
            if (req > 0) { IntPtr b = Marshal.AllocHGlobal(req); try { if (GetTokenInformation(t, 1, b, req, out req)) d["userSid"] = new SecurityIdentifier(Marshal.ReadIntPtr(b)).Value; } finally { Marshal.FreeHGlobal(b); } }
            req = 0; GetTokenInformation(t, 29, IntPtr.Zero, 0, out req);
            if (req >= 4) { IntPtr b = Marshal.AllocHGlobal(req); try { if (GetTokenInformation(t, 29, b, req, out req)) d["isAppContainer"] = (Marshal.ReadInt32(b) != 0); } finally { Marshal.FreeHGlobal(b); } }
            req = 0; GetTokenInformation(t, 31, IntPtr.Zero, 0, out req);
            if (req >= IntPtr.Size) { IntPtr b = Marshal.AllocHGlobal(req); try { if (GetTokenInformation(t, 31, b, req, out req)) { IntPtr s = Marshal.ReadIntPtr(b); d["containerSid"] = (s == IntPtr.Zero) ? null : new SecurityIdentifier(s).Value; } } finally { Marshal.FreeHGlobal(b); } }
            d["ok"] = true; return d;
        } finally { if (t != IntPtr.Zero) CloseHandle(t); CloseHandle(p); }
    }
}
'@

    $coworkBefore = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceBefore = if ($coworkBefore) { [ordered]@{ state = $coworkBefore.State; pid = [int]$coworkBefore.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclBefore = (Get-Acl -LiteralPath $PkgInstallLocation).Sddl
    $cRootAclBefore = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostUserProfile = (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $hostSid + "'") -ErrorAction SilentlyContinue).LocalPath
    $hostRoamingBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    foreach ($sk in @('A','B')) {
        $uName = "ClaudeStudioLab$sk"
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $uName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $sk Phase9"
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $orig = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($uName, $env:COMPUTERNAME, $pw)
        $prof = [StudioPsecGuardHost]::LoadLabProfile($orig, $uName)
        $copy = [StudioPsecGuardHost]::DuplicateHardened($orig, $hostSid)
        $users[$sk] = @{ name = $uName; sid = $u.SID.Value }
        $tokens[$sk] = @{ orig = $orig; copy = $copy; prof = $prof }
    }

    $appAcl = New-PrivateAcl $hostSid
    foreach ($s in @($users['A'].sid, $users['B'].sid, 'S-1-15-2-1')) {
        $appAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($sharedAppStage, $appAcl)
    $sharedAppCreated = $true
    $null = & robocopy.exe $srcAppDir $sharedAppStage /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS
    if ($LASTEXITCODE -ge 8) { throw "robocopy app failed with exit code $LASTEXITCODE" }
    $stagedClaudeExe = Join-Path $sharedAppStage 'claude.exe'

    [void][IO.Directory]::CreateDirectory($sharedRepo, (New-PrivateAcl $hostSid))
    $repoCreated = $true
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'handoff-test.txt'), "phase9\n", (New-Object Text.UTF8Encoding($false)))

    $localUpstream = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $localUpstream.Start()
    [void][Phase9ProcInspect]::SetHandleInformation($localUpstream.Server.Handle, 1, 0)
    $upPort = $localUpstream.LocalEndpoint.Port

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $dnsPidBefore = Get-LabDnsServicePid
    $lmRes = & logman.exe create trace $etlName -o $etlFile -p 'Microsoft-Windows-DNS-Client' 0xffffffffffffffff 4 -ets 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('DNS ETW start failed: ' + ($lmRes -join ' ')) }
    $etlStarted = $true
    $null = Test-HostHealth 'baseline' 41

    $specA = [ClaudeStudio.ControlPlane.RealDesktopSpaceSpec]::new()
    $specA.Space = [ClaudeStudio.ControlPlane.SpaceId]::A; $specA.AccountName = $users['A'].name; $specA.AccountSid = $users['A'].sid; $specA.HostSid = $hostSid
    $specA.UserHomeDir = "C:\Users\$($users['A'].name)"; $specA.WorkRootDir = "C:\Users\$($users['A'].name)\AppData\Local\Temp\$tag"
    $specA.TargetDesktopExe = $stagedClaudeExe; $specA.SharedAppReadOnlyDir = $sharedAppStage
    $specA.UiLanguage = 'zh-CN'; $specA.EnvLang = 'zh_CN.UTF-8'; $specA.EnvTimezone = 'Asia/Shanghai'; $specA.AppendElectronAppContainerFlags = $true
    $specA.OrigToken = $tokens['A'].orig; $specA.CopyToken = $tokens['A'].copy

    $specB = [ClaudeStudio.ControlPlane.RealDesktopSpaceSpec]::new()
    $specB.Space = [ClaudeStudio.ControlPlane.SpaceId]::B; $specB.AccountName = $users['B'].name; $specB.AccountSid = $users['B'].sid; $specB.HostSid = $hostSid
    $specB.UserHomeDir = "C:\Users\$($users['B'].name)"; $specB.WorkRootDir = "C:\Users\$($users['B'].name)\AppData\Local\Temp\$tag"
    $specB.TargetDesktopExe = $stagedClaudeExe; $specB.SharedAppReadOnlyDir = $sharedAppStage
    $specB.UiLanguage = 'en-US'; $specB.EnvLang = 'en_US.UTF-8'; $specB.EnvTimezone = 'America/Los_Angeles'; $specB.AppendElectronAppContainerFlags = $true
    $specB.OrigToken = $tokens['B'].orig; $specB.CopyToken = $tokens['B'].copy

    $backend = [ClaudeStudio.ControlPlane.RealDesktopPsecBackend]::new($specA, $specB, $binDir, '127.0.0.1', $upPort, $true)
    $engine = [ClaudeStudio.ControlPlane.StudioEngine]::new($backend)
    $errUp = ''
    [void]$engine.ConfigureUpstream('127.0.0.1', $upPort, $false, [ref]$errUp)

    # === CHECK 1: Config Persistence Round-Trip & 10810 Guard ===
    $cfgPath = Join-Path $base 'phase9-config.json'
    $cfgErr = ''
    $badCfg = [ClaudeStudio.ControlPlane.StudioUserConfig]::new()
    $badCfg.UpstreamPort = 10810
    $rej10810Save = ![ClaudeStudio.ControlPlane.StudioConfigStore]::Save($badCfg, [ref]$cfgErr, $cfgPath)
    $goodCfg = $engine.ExportUserConfig($false)
    $savedGood = [ClaudeStudio.ControlPlane.StudioConfigStore]::Save($goodCfg, [ref]$cfgErr, $cfgPath)
    $reloaded = [ClaudeStudio.ControlPlane.StudioConfigStore]::Load($cfgPath)
    $cfgRawText = [IO.File]::ReadAllText($cfgPath, [Text.Encoding]::UTF8)
    $report.checks.configPersistenceAndGuard = $rej10810Save -and $savedGood -and ($reloaded.UpstreamPort -eq $upPort) -and
        ($cfgRawText -notmatch [regex]::Escape($env:USERNAME))

    # === CHECK 2: Launch Both Real Official claude.exe Spaces Online ===
    $snapA = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::A)
    $snapB = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::A)) { [void]$observedPidSet.Add($gp) }
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::B)) { [void]$observedPidSet.Add($gp) }
    for ($t = 0; $t -lt 8; $t++) {
        Start-Sleep -Milliseconds 500
        while ($localUpstream.Pending()) { $c = $localUpstream.AcceptTcpClient(); $c.Close() }
    }
    $null = Test-HostHealth 'healthy1' 51

    # Capture live Chromium PIDs for DNS trace accounting
    foreach ($pr in (Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%'" -ErrorAction SilentlyContinue)) {
        $tk = [Phase9ProcInspect]::ReadPidToken([int]$pr.ProcessId)
        if ($tk.ok -and ($tk['userSid'] -ceq $users['A'].sid -or $tk['userSid'] -ceq $users['B'].sid)) {
            [void]$observedPidSet.Add([int]$pr.ProcessId)
        }
    }

    # === CHECK 3: Live In-Container OAuth claude:// Callback Routing (Space A & Space B + Negative Guards + Redaction) ===
    $pidNeg = 0; $msgNeg = ''
    $rejScheme = !$engine.DeliverOAuthCallback([ClaudeStudio.ControlPlane.SpaceId]::A, 'https://evil.invalid/cb?code=1', [ref]$pidNeg, [ref]$msgNeg)
    $rejQuote = !$engine.DeliverOAuthCallback([ClaudeStudio.ControlPlane.SpaceId]::B, 'claude://auth?code=bad"quote', [ref]$pidNeg, [ref]$msgNeg)

    $cbPidA = 0; $cbMsgA = ''
    $okCbA = $engine.DeliverOAuthCallback([ClaudeStudio.ControlPlane.SpaceId]::A, 'claude://studio-phase9/callback?code=SYNTH_SECRET_A_999&state=STATE_A_111', [ref]$cbPidA, [ref]$cbMsgA)
    if ($cbPidA -gt 0) { [void]$observedPidSet.Add($cbPidA) }

    $cbPidB = 0; $cbMsgB = ''
    $okCbB = $engine.DeliverOAuthCallback([ClaudeStudio.ControlPlane.SpaceId]::B, 'claude://studio-phase9/callback?code=SYNTH_SECRET_B_888&state=STATE_B_222', [ref]$cbPidB, [ref]$cbMsgB)
    if ($cbPidB -gt 0) { [void]$observedPidSet.Add($cbPidB) }

    $auditAllText = (($engine.GetAuditLog() | ForEach-Object { $_.Message }) -join "`n")
    $diagJson = $engine.BuildSanitizedDiagnosticJson()
    $noSecretLeak = ($auditAllText -notmatch 'SYNTH_SECRET_A_999') -and ($auditAllText -notmatch 'SYNTH_SECRET_B_888') -and
        ($auditAllText -notmatch 'STATE_A_111') -and ($auditAllText -notmatch 'STATE_B_222') -and
        ($auditAllText -match '\[REDACTED\]') -and ($diagJson -notmatch 'SYNTH_SECRET_')

    $report.oauthRouting = [ordered]@{
        rejectedBadScheme = $rejScheme; rejectedBadQuote = $rejQuote
        spaceADispatched = $okCbA; spaceAHelperPid = $cbPidA
        spaceBDispatched = $okCbB; spaceBHelperPid = $cbPidB
        auditRedactedZeroSecretLeak = $noSecretLeak
    }
    $report.checks.liveOAuthCallbackRoutingAndRedaction = $rejScheme -and $rejQuote -and $okCbA -and $okCbB -and
        ($cbPidA -gt 0) -and ($cbPidB -gt 0) -and ($cbPidA -ne $cbPidB) -and $noSecretLeak

    # === CHECK 4: Live StudioEngine Project NTFS Single-Writer Registration & Controlled Handoff ===
    $aclNoteA = ''; $aclNoteRoB = ''; $aclNoteFail = ''; $aclNoteSwap = ''
    $regA = $engine.RegisterProjectAndSyncAcl([ClaudeStudio.ControlPlane.SpaceId]::A, $sharedRepo, [ClaudeStudio.ControlPlane.ProjectAccessMode]::ReadWrite, [ref]$aclNoteA)
    $regRoB = $engine.RegisterProjectAndSyncAcl([ClaudeStudio.ControlPlane.SpaceId]::B, $sharedRepo, [ClaudeStudio.ControlPlane.ProjectAccessMode]::ReadOnly, [ref]$aclNoteRoB)
    $acl1 = (Get-Acl -LiteralPath $sharedRepo).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $aWrite1 = (@($acl1 | Where-Object { $_.IdentityReference.Value -ceq $users['A'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -ge 1)
    $bNoWrite1 = (@($acl1 | Where-Object { $_.IdentityReference.Value -ceq $users['B'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -eq 0)

    # Handoff MUST be refused while Space A is still running!
    $handoffBlocked = $engine.HandoffProjectWriterAndSyncAcl($sharedRepo, [ClaudeStudio.ControlPlane.SpaceId]::B, [ref]$aclNoteFail)
    # Stop A -> Handoff succeeds & swaps real NTFS ACL + updates specA/specB PSEC mount lists!
    $null = $engine.StopSpaceAndRollback([ClaudeStudio.ControlPlane.SpaceId]::A)
    $handoffOk = $engine.HandoffProjectWriterAndSyncAcl($sharedRepo, [ClaudeStudio.ControlPlane.SpaceId]::B, [ref]$aclNoteSwap)
    $acl2 = (Get-Acl -LiteralPath $sharedRepo).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $bWrite2 = (@($acl2 | Where-Object { $_.IdentityReference.Value -ceq $users['B'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -ge 1)
    $aNoWrite2 = (@($acl2 | Where-Object { $_.IdentityReference.Value -ceq $users['A'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -eq 0)

    $mountsUpdated = ($specB.ExtraReadWriteDirs -contains $regA.CanonicalPath) -and ($specA.ExtraReadOnlyDirs -contains $regA.CanonicalPath)
    $report.liveProjectSync = [ordered]@{
        aWriteBefore = $aWrite1; bReadOnlyBefore = $bNoWrite1
        refusedWhileARunning = (!$handoffBlocked.Ok -and $handoffBlocked.Code -ceq 'WRITER_STILL_RUNNING')
        bWriteAfter = $bWrite2; aReadOnlyAfter = $aNoWrite2; psecSpecsUpdated = $mountsUpdated
    }
    $report.checks.liveNtfsSingleWriterAndMountSync = $regA.Ok -and $regRoB.Ok -and $aWrite1 -and $bNoWrite1 -and
        (!$handoffBlocked.Ok -and $handoffBlocked.Code -ceq 'WRITER_STILL_RUNNING') -and
        $handoffOk.Ok -and $bWrite2 -and $aNoWrite2 -and $mountsUpdated

    # === CHECK 5: Live WPF MainWindow Attached to Live RealDesktopPsecBackend + Clean Exit Rollback ===
    $win = New-Object ClaudeStudio.ControlPlane.MainWindow($engine)
    $win.ShowActivated = $false
    $win.Left = -20000
    $win.Show()
    $win.UpdateLayout()
    $win.RefreshTelemetryOnly()
    $wpfLiveRendered = ($win.ActualWidth -ge 900) -and ($win.ActualHeight -ge 600) -and ($win.Title -match 'Option B')
    $win.ExitCleanly()

    $resTotal = 0
    foreach ($csid in $backend.GetAllObservedContainerSids()) { $resTotal += [StudioLabWfp]::CountFiltersReferencingPackage($csid) }
    $report.cleanup.residualPackageFilters = $resTotal
    $report.checks.liveWpfMainWindowAndExitRollback = $wpfLiveRendered -and ($resTotal -eq 0) -and
        $engine.IsSpaceStopped([ClaudeStudio.ControlPlane.SpaceId]::A) -and $engine.IsSpaceStopped([ClaudeStudio.ControlPlane.SpaceId]::B)

    $coworkAfter = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceAfter = if ($coworkAfter) { [ordered]@{ state = $coworkAfter.State; pid = [int]$coworkAfter.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclAfter = (Get-Acl -LiteralPath $PkgInstallLocation).Sddl
    $cRootAclAfter = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostRoamingAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }
    $report.checks.coworkServiceUntriggered = ($report.coworkServiceBefore.state -ceq $report.coworkServiceAfter.state) -and ($report.coworkServiceBefore.pid -eq $report.coworkServiceAfter.pid)
    $report.checks.hostClaudeAndSystemUnchanged = ($winAppsAclBefore -ceq $winAppsAclAfter) -and ($cRootAclBefore -ceq $cRootAclAfter) -and
        (($hostRoamingBefore | ConvertTo-Json -Compress) -ceq ($hostRoamingAfter | ConvertTo-Json -Compress)) -and
        (($hostLocalDataBefore | ConvertTo-Json -Compress) -ceq ($hostLocalDataAfter | ConvertTo-Json -Compress))
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($engine) { try { $engine.Dispose() } catch { } }
    if ($backend) { try { $backend.Dispose() } catch { } }
    if ($localUpstream) { try { $localUpstream.Stop() } catch { } }
    if ($assemblyLoaded) {
        $sids = @(); foreach ($sk in @('A','B')) { if ($users.ContainsKey($sk)) { $sids += $users[$sk].sid } }
        if ($sids.Count -gt 0) {
            try {
                $rem = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%' OR Name LIKE '%StudioA%' OR Name LIKE '%StudioB%'" -ErrorAction SilentlyContinue
                foreach ($pr in $rem) {
                    $tk = [Phase9ProcInspect]::ReadPidToken([int]$pr.ProcessId)
                    if ($tk.ok -and ($sids -contains $tk['userSid'])) { try { Stop-Process -Id ([int]$pr.ProcessId) -Force -ErrorAction SilentlyContinue } catch { } }
                }
            } catch { }
        }
    }
    Start-Sleep -Milliseconds 300

    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 71 } catch { } }
    if ($etlStarted) {
        try {
            $loss = Get-LabDnsTraceLoss $etlName
            $null = & logman.exe stop $etlName -ets 2>&1
            $dnsPidAfter = Get-LabDnsServicePid
            $hostSends = 0; $labDnsSends = 0; $coworkDnsSends = 0
            $coworkPid = if ($report.coworkServiceAfter -and $report.coworkServiceAfter.pid -gt 0) { [int]$report.coworkServiceAfter.pid } else { -1 }
            foreach ($ev in (Get-WinEvent -FilterHashtable @{ Path = $etlFile; Id = 3006,3010,3011 } -Oldest -ErrorAction SilentlyContinue)) {
                if (!$ev.Properties.Count) { continue }
                $qName = [string]$ev.Properties[0].Value
                $clientPid = -1
                if ($ev.Id -eq 3010 -and $ev.Properties.Count -gt 3) { $clientPid = [int]$ev.Properties[3].Value }
                elseif ($ev.Id -eq 3011 -and $ev.Properties.Count -gt 4) { $clientPid = [int]$ev.Properties[4].Value }
                elseif ($ev.Id -eq 3006) { $clientPid = [int]$ev.ProcessId }
                if ($ev.Id -eq 3010 -and $qName.StartsWith($prefix + '-host-', [StringComparison]::OrdinalIgnoreCase)) { $hostSends++ }
                if ($observedPidSet.Contains($clientPid) -and ($ev.Id -in 3010,3011)) { $labDnsSends++ }
                if ($coworkPid -gt 0 -and $clientPid -eq $coworkPid -and ($ev.Id -in 3010,3011)) { $coworkDnsSends++ }
            }
            if (Test-Path -LiteralPath $etlFile) { Remove-Item -LiteralPath $etlFile -Force }
            $lZero = ($loss.eventsLost -eq 0) -and ($loss.logBuffersLost -eq 0) -and ($loss.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsPidBefore -eq $dnsPidAfter); lossZero = $lZero
                hostCanarySends = $hostSends; observedLabPidCount = $observedPidSet.Count
                labPidDnsWireSendsOrReplies = $labDnsSends; coworkServiceDnsWireSends = $coworkDnsSends
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($labDnsSends -eq 0) -and ($coworkDnsSends -eq 0) -and ($hostSends -ge 8)
        } catch { $report.checks.dnsZeroLeak = $false; $report.cleanup.errors += @("dns: $($_.Exception.Message)") }
    }
    if ($hostOld) { try { Close-GatePair $hostOld } catch { } }
    if ($hostListener) { try { $hostListener.Dispose() } catch { } }

    if ($assemblyLoaded) {
        try {
            $report.desktopAfter = [StudioReadDesktop]::Read()
            $report.defaultDesktopAfter = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()
            $report.checks.desktopUnchanged = ($report.desktopBefore.station -ceq $report.desktopAfter.station) -and
                ($report.desktopBefore.desktop -ceq $report.desktopAfter.desktop) -and
                ($report.desktopBefore.stationOwnerGroupDacl -ceq $report.desktopAfter.stationOwnerGroupDacl) -and
                ($report.desktopBefore.desktopOwnerGroupDacl -ceq $report.desktopAfter.desktopOwnerGroupDacl) -and
                ($report.defaultDesktopBefore.digest -ceq $report.defaultDesktopAfter.digest)
        } catch { $report.checks.desktopUnchanged = $false }
        foreach ($sk in @('A','B')) {
            if ($tokens.ContainsKey($sk)) {
                try { [StudioPsecGuardHost]::UnloadLabProfile($tokens[$sk].orig, $tokens[$sk].prof) } catch { }
                foreach ($tk in @($tokens[$sk].copy, $tokens[$sk].orig)) { if ($tk -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($tk) } catch { } } }
            }
        }
    }

    foreach ($sk in @('A','B')) {
        if ($users.ContainsKey($sk)) {
            $uName = $users[$sk].name; $uSid = $users[$sk].sid
            try { $pr = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $uSid + "'") -ErrorAction SilentlyContinue; if ($pr) { Remove-CimInstance -InputObject $pr -ErrorAction Stop } } catch { $report.cleanup.errors += @("prof$sk`: $($_.Exception.Message)") }
            try { if (Test-Path -LiteralPath "C:\Users\$uName") { Remove-Item -LiteralPath "C:\Users\$uName" -Recurse -Force -ErrorAction Stop } } catch { $report.cleanup.errors += @("profDir$sk`: $($_.Exception.Message)") }
            try { Remove-LocalUser -Name $uName -ErrorAction Stop } catch { $report.cleanup.errors += @("user$sk`: $($_.Exception.Message)") }
        }
    }
    if ($repoCreated -and (Test-Path -LiteralPath $sharedRepo)) { try { Remove-Item -LiteralPath $sharedRepo -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("repo: $($_.Exception.Message)") } }
    if ($sharedAppCreated -and (Test-Path -LiteralPath $sharedAppStage)) { try { Remove-Item -LiteralPath $sharedAppStage -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("sharedApp: $($_.Exception.Message)") } }
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.sharedAppGone = !(Test-Path -LiteralPath $sharedAppStage)
    $report.cleanup.repoGone = !(Test-Path -LiteralPath $sharedRepo)
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labBGone = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
    $report.cleanup.profAGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')
    $report.cleanup.profBGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabB')

    $hOk = $true
    foreach ($st in @('baseline','healthy1','restored')) {
        $h = $report.hostHealth[$st]
        if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hOk = $false }
    }
    $report.checks.hostContinuous = $hOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.residualPackageFilters -eq 0) -and
        $report.cleanup.directoryGone -and $report.cleanup.sharedAppGone -and $report.cleanup.repoGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and $report.cleanup.profAGone -and $report.cleanup.profBGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 10)
    $report.outcome = if ($allOk) { 'passed-ab-phase9-interactive-product' } else { 'stopped-ab-phase9-interactive-product' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        oauthRouting = $report.oauthRouting; liveProjectSync = $report.liveProjectSync
        checks = $report.checks; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
