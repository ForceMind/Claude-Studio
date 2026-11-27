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
    $ReportPath = Join-Path $reportDir ("windows-ab-phase8-control-plane-real-desktop-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudePhase8-summary-$RunId.json")
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath `
            -PkgInstallLocation $pkgLocal.InstallLocation -PkgVersion $pkgLocal.Version -PkgFamilyName $pkgLocal.PackageFamilyName
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '" -PkgInstallLocation "' + $pkgLocal.InstallLocation + '" -PkgVersion "' + $pkgLocal.Version + '" -PkgFamilyName "' + $pkgLocal.PackageFamilyName + '"'
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
$tag = 'ClaudePhase8-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$sharedAppStage = Join-Path $env:ProgramData ("ClaudeStudioPhase8App-$RunId")
$sharedRepo = Join-Path $env:ProgramData ("ClaudeStudioPhase8Repo-$RunId")
$srcAppDir = Join-Path $PkgInstallLocation 'app'

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase8-control-plane-real-desktop'
    officialPackage = [ordered]@{ name = 'Claude'; version = $PkgVersion; packageFamilyName = $PkgFamilyName }
    spaces = [ordered]@{ A = [ordered]@{}; B = [ordered]@{} }
    proxyTelemetry = [ordered]@{}; faultTimingsMs = [ordered]@{}
    hostHealth = [ordered]@{}; checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @(); residualPackageFilters = 0 }
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

    # 1. Load prebuilt ClaudeStudioControlPlane.exe directly (ZERO runtime cl.exe / node.exe!)
    $cpExe = Join-Path $binDir 'ClaudeStudioControlPlane.exe'
    if (!(Test-Path -LiteralPath $cpExe)) { throw 'Missing prebuilt ClaudeStudioControlPlane.exe (run build.ps1 first)' }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($cpExe))
    $assemblyLoaded = $true

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Tiny inspector for verifying real Chromium process tokens & visible windows on WinSta0\Default
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class Phase8ProcInspect {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int req);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
    delegate bool EnumWinProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr OpenDesktopW(string name, uint flags, bool inh, uint acc);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr hDesk);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr hDesk, EnumWinProc cb, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
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
    public static List<int> ListVisibleChromeWindowPids() {
        var list = new List<int>();
        IntPtr hDesk = OpenDesktopW("Default", 0, false, 0x0041);
        try {
            if (hDesk == IntPtr.Zero) return list;
            EnumDesktopWindows(hDesk, (h, lp) => {
                if (!IsWindowVisible(h)) return true;
                var cb = new System.Text.StringBuilder(128); GetClassNameW(h, cb, 128);
                if (cb.ToString() != "Chrome_WidgetWin_1") return true;
                uint p = 0; GetWindowThreadProcessId(h, out p);
                list.Add((int)p);
                return true;
            }, IntPtr.Zero);
        } finally { if (hDesk != IntPtr.Zero) CloseDesktop(hDesk); }
        return list;
    }
}
'@

    # Host baseline snapshots
    $coworkBefore = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceBefore = if ($coworkBefore) { [ordered]@{ state = $coworkBefore.State; pid = [int]$coworkBefore.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclBefore = (Get-Acl -LiteralPath $PkgInstallLocation).Sddl
    $cRootAclBefore = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostUserProfile = (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $hostSid + "'") -ErrorAction SilentlyContinue).LocalPath
    $hostRoamingBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # 2. Create temporary standard users A & B + shared read-only official app\ stage + synthetic repo for NTFS ACL check
    foreach ($sk in @('A','B')) {
        $uName = "ClaudeStudioLab$sk"
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $uName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $sk Phase8 Real Desktop"
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

    # Synthetic repo for NtfsSingleWriterEnforcer verification
    [void][IO.Directory]::CreateDirectory($sharedRepo, (New-PrivateAcl $hostSid))
    $repoCreated = $true
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'sample.txt'), "phase8\n", (New-Object Text.UTF8Encoding($false)))
    [ClaudeStudio.ControlPlane.NtfsSingleWriterEnforcer]::ApplySingleWriterAcl($sharedRepo, $hostSid, $users['A'].sid, $users['B'].sid)
    $repoAclAfterA = (Get-Acl -LiteralPath $sharedRepo).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $ntfsAHasModify = (@($repoAclAfterA | Where-Object { $_.IdentityReference.Value -ceq $users['A'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -ge 1)
    $ntfsBIsReadOnly = (@($repoAclAfterA | Where-Object { $_.IdentityReference.Value -ceq $users['B'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -eq 0) -and
                       (@($repoAclAfterA | Where-Object { $_.IdentityReference.Value -ceq $users['B'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) }).Count -ge 1)

    # 3. Start local zero-egress test upstream TCP listener (NOT listening yet for ColdBlocked test!)
    $localUpstream = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $localUpstream.Start()
    $upPort = $localUpstream.LocalEndpoint.Port
    $localUpstream.Stop() # Offline first!

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $dnsPidBefore = Get-LabDnsServicePid
    $lmRes = & logman.exe create trace $etlName -o $etlFile -p 'Microsoft-Windows-DNS-Client' 0xffffffffffffffff 4 -ets 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('DNS ETW start failed: ' + ($lmRes -join ' ')) }
    $etlStarted = $true
    $null = Test-HostHealth 'baseline' 41

    # 4. Instantiate REAL RealDesktopPsecBackend + StudioEngine directly from ClaudeStudioControlPlane.exe!
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

    # Verify reserved host port 10810 guard
    $err10810 = ''
    $guard10810 = !$engine.ConfigureUpstream('127.0.0.1', 10810, $false, [ref]$err10810)

    # === CHECK 1: Fail-Closed Cold Start (local upstream OFFLINE) ===
    $snapColdA = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::A)
    $snapColdB = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::A)) { [void]$observedPidSet.Add($gp) }
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::B)) { [void]$observedPidSet.Add($gp) }
    $null = Test-HostHealth 'blocked' 51
    Start-Sleep -Milliseconds 1500
    $coldStatsA = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::A)
    $coldStatsB = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::B)
    $report.proxyTelemetry.cold = [ordered]@{ a=$coldStatsA.TotalConnections; b=$coldStatsB.TotalConnections }

    $report.checks.controlPlaneColdStartBlocked = $guard10810 -and
        ($snapColdA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ColdBlocked) -and
        ($snapColdB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ColdBlocked) -and
        ($snapColdA.ContainerSid -cne $snapColdB.ContainerSid) -and
        ($coldStatsA.TotalConnections -eq 0) -and ($coldStatsB.TotalConnections -eq 0)

    # === CHECK 2: Bring Local Zero-Egress Upstream Online (NON-INHERITABLE!) -> Fresh Dual StartSpace -> Both Real claude.exe Hit Embedded Proxy! ===
    $null = $engine.StopSpaceAndRollback([ClaudeStudio.ControlPlane.SpaceId]::A)
    $null = $engine.StopSpaceAndRollback([ClaudeStudio.ControlPlane.SpaceId]::B)
    $localUpstream = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $upPort)
    $localUpstream.Start()
    [void][Phase8ProcInspect]::SetHandleInformation($localUpstream.Server.Handle, 1, 0)
    $snapOnA = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::A)
    $snapOnB = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::A)) { [void]$observedPidSet.Add($gp) }
    foreach ($gp in $backend.GetGuardianPids([ClaudeStudio.ControlPlane.SpaceId]::B)) { [void]$observedPidSet.Add($gp) }

    $seenA = @{}; $seenB = @{}; $bothWins = $false
    for ($tick = 0; $tick -lt 20; $tick++) {
        Start-Sleep -Milliseconds 650
        # Drain any queued test upstream sockets cleanly
        while ($localUpstream.Pending()) { $c = $localUpstream.AcceptTcpClient(); $c.Close() }
        $visPids = [Phase8ProcInspect]::ListVisibleChromeWindowPids()
        $hasWinA = $false; $hasWinB = $false
        $procs = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%'" -ErrorAction SilentlyContinue
        foreach ($pr in $procs) {
            $pidInt = [int]$pr.ProcessId
            $tok = [Phase8ProcInspect]::ReadPidToken($pidInt)
            if (!$tok.ok) { continue }
            if ($tok['userSid'] -ceq $users['A'].sid) {
                [void]$observedPidSet.Add($pidInt)
                $seenA["$pidInt"] = [ordered]@{ pid=$pidInt; ac=$tok['isAppContainer']; sameCid=($tok['containerSid'] -ceq $snapOnA.ContainerSid) }
                if ($visPids.Contains($pidInt)) { $hasWinA = $true }
            } elseif ($tok['userSid'] -ceq $users['B'].sid) {
                [void]$observedPidSet.Add($pidInt)
                $seenB["$pidInt"] = [ordered]@{ pid=$pidInt; ac=$tok['isAppContainer']; sameCid=($tok['containerSid'] -ceq $snapOnB.ContainerSid) }
                if ($visPids.Contains($pidInt)) { $hasWinB = $true }
            }
        }
        if ($hasWinA -and $hasWinB) { $bothWins = $true }
        $stA = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::A)
        $stB = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::B)
        if ($bothWins -and $stA.TotalConnections -ge 1 -and $stB.TotalConnections -ge 1 -and $tick -ge 5) { break }
    }
    $onStatsA = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::A)
    $onStatsB = $engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::B)
    $report.proxyTelemetry.online = [ordered]@{ a=$onStatsA.TotalConnections; aTarget=$onStatsA.LastTarget; b=$onStatsB.TotalConnections; bTarget=$onStatsB.LastTarget }
    $null = Test-HostHealth 'healthy1' 61

    $procsAList = @($seenA.Keys | ForEach-Object { $seenA[$_] })
    $procsBList = @($seenB.Keys | ForEach-Object { $seenB[$_] })
    $report.spaces['A'] = [ordered]@{ procCount=$procsAList.Count; proxyPort=$snapOnA.ProxyPort; wfpWeight=$snapOnA.WfpSublayerWeight }
    $report.spaces['B'] = [ordered]@{ procCount=$procsBList.Count; proxyPort=$snapOnB.ProxyPort; wfpWeight=$snapOnB.WfpSublayerWeight }

    $report.checks.dualRealDesktopContainedAndRouted =
        ($snapOnA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        ($snapOnB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        $bothWins -and ($procsAList.Count -ge 3) -and ($procsBList.Count -ge 3) -and
        (@($procsAList | Where-Object { !$_.ac -or !$_.sameCid }).Count -eq 0) -and
        (@($procsBList | Where-Object { !$_.ac -or !$_.sameCid }).Count -eq 0) -and
        ($onStatsA.TotalConnections -ge 1) -and ($onStatsB.TotalConnections -ge 1)

    # === CHECK 3: Soft Disconnect Space A ONLY via StudioEngine -> B stays ProxyOnline! ===
    $cutA = $engine.DisconnectSpaceNetworkOnly([ClaudeStudio.ControlPlane.SpaceId]::A)
    $stillB = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::B)
    $preCutA = ($engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::A)).TotalConnections
    Start-Sleep -Milliseconds 2500
    $postCutA = ($engine.GetEmbeddedProxyStats([ClaudeStudio.ControlPlane.SpaceId]::A)).TotalConnections
    $recA = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)

    $report.checks.softDisconnectAAndReconnect =
        ($cutA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::FaultCutoff) -and (!$cutA.DynamicExceptionOpen) -and
        ($stillB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and $stillB.DynamicExceptionOpen -and
        ($postCutA -eq $preCutA) -and
        ($recA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and $recA.DynamicExceptionOpen

    # === CHECK 4: Shared Upstream Fault -> Embedded Watchdog AUTOMATICALLY Cuts BOTH A & B < 3000ms! ===
    $swAuto = [Diagnostics.Stopwatch]::StartNew()
    $localUpstream.Stop()
    $autoMs = -1
    while ($swAuto.ElapsedMilliseconds -lt 3000) {
        $fa = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::A)
        $fb = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::B)
        if ($fa.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::FaultCutoff -and
            $fb.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::FaultCutoff -and
            !$fa.DynamicExceptionOpen -and !$fb.DynamicExceptionOpen) {
            $autoMs = [math]::Round($swAuto.Elapsed.TotalMilliseconds, 1)
            break
        }
        Start-Sleep -Milliseconds 60
    }
    $faFinal = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::A)
    $fbFinal = $engine.GetSnapshot([ClaudeStudio.ControlPlane.SpaceId]::B)
    $report.faultTimingsMs.watchdogAutoCutoffBoth = $autoMs
    $report.faultTimingsMs.postFaultStateA = "$($faFinal.State)"
    $report.faultTimingsMs.postFaultStateB = "$($fbFinal.State)"
    $report.faultTimingsMs.relayUpstreamHealthy = $backend.Relay.UpstreamHealthy
    $null = Test-HostHealth 'fault1' 71
    $report.checks.watchdogAutoCutoffOnUpstreamFault = ($autoMs -ge 0 -and $autoMs -lt 3000)

    # === CHECK 5: NTFS Single-Writer ACL Swap + Sanitized Diagnostics Export ===
    $diagJson = $engine.BuildSanitizedDiagnosticJson()
    $diagClean = ($diagJson -match 'claude-studio-sanitized-diagnostics-v1') -and ($diagJson -notmatch [regex]::Escape($env:USERNAME))
    [ClaudeStudio.ControlPlane.NtfsSingleWriterEnforcer]::ApplySingleWriterAcl($sharedRepo, $hostSid, $users['B'].sid, $users['A'].sid)
    $repoAclAfterB = (Get-Acl -LiteralPath $sharedRepo).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $ntfsBHasModify = (@($repoAclAfterB | Where-Object { $_.IdentityReference.Value -ceq $users['B'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -ge 1)
    $ntfsAIsReadOnly = (@($repoAclAfterB | Where-Object { $_.IdentityReference.Value -ceq $users['A'].sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) }).Count -eq 0)
    $report.checks.ntfsSingleWriterAndSanitizedDiag = $ntfsAHasModify -and $ntfsBIsReadOnly -and $ntfsBHasModify -and $ntfsAIsReadOnly -and $diagClean

    # === CHECK 6: Emergency Kill-Switch & Zero Residual WFP ===
    $engine.EmergencyKillSwitchAll()
    $resTotal = 0
    foreach ($csid in $backend.GetAllObservedContainerSids()) { $resTotal += [StudioLabWfp]::CountFiltersReferencingPackage($csid) }
    $report.cleanup.residualPackageFilters = $resTotal
    $report.checks.killSwitchZeroResidual = ($resTotal -eq 0) -and $engine.IsSpaceStopped([ClaudeStudio.ControlPlane.SpaceId]::A) -and $engine.IsSpaceStopped([ClaudeStudio.ControlPlane.SpaceId]::B)

    # Host checks after run
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
                    $tk = [Phase8ProcInspect]::ReadPidToken([int]$pr.ProcessId)
                    if ($tk.ok -and ($sids -contains $tk['userSid'])) { try { Stop-Process -Id ([int]$pr.ProcessId) -Force -ErrorAction SilentlyContinue } catch { } }
                }
            } catch { }
        }
    }
    Start-Sleep -Milliseconds 300

    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { } }
    if ($etlStarted) {
        try {
            $loss = Get-LabDnsTraceLoss $etlName
            $null = & logman.exe stop $etlName -ets 2>&1
            $dnsPidAfter = Get-LabDnsServicePid
            $hostSends = 0; $labDnsSends = 0; $labDnsAttempts = 0; $coworkDnsSends = 0
            $coworkPid = if ($report.coworkServiceAfter -and $report.coworkServiceAfter.pid -gt 0) { [int]$report.coworkServiceAfter.pid } else { -1 }
            foreach ($ev in (Get-WinEvent -FilterHashtable @{ Path = $etlFile; Id = 3006,3010,3011 } -Oldest -ErrorAction SilentlyContinue)) {
                if (!$ev.Properties.Count) { continue }
                $qName = [string]$ev.Properties[0].Value
                $clientPid = -1
                if ($ev.Id -eq 3010 -and $ev.Properties.Count -gt 3) { $clientPid = [int]$ev.Properties[3].Value }
                elseif ($ev.Id -eq 3011 -and $ev.Properties.Count -gt 4) { $clientPid = [int]$ev.Properties[4].Value }
                elseif ($ev.Id -eq 3006) { $clientPid = [int]$ev.ProcessId }
                if ($ev.Id -eq 3010 -and $qName.StartsWith($prefix + '-host-', [StringComparison]::OrdinalIgnoreCase)) { $hostSends++ }
                if ($observedPidSet.Contains($clientPid)) {
                    if ($ev.Id -eq 3006) { $labDnsAttempts++ } elseif ($ev.Id -in 3010,3011) { $labDnsSends++ }
                }
                if ($coworkPid -gt 0 -and $clientPid -eq $coworkPid -and ($ev.Id -in 3010,3011)) { $coworkDnsSends++ }
            }
            if (Test-Path -LiteralPath $etlFile) { Remove-Item -LiteralPath $etlFile -Force }
            $lZero = ($loss.eventsLost -eq 0) -and ($loss.logBuffersLost -eq 0) -and ($loss.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsPidBefore -eq $dnsPidAfter); lossZero = $lZero
                hostCanarySends = $hostSends; observedLabPidCount = $observedPidSet.Count
                labPidDnsApiAttempts = $labDnsAttempts; labPidDnsWireSendsOrReplies = $labDnsSends
                coworkServiceDnsWireSends = $coworkDnsSends
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($labDnsSends -eq 0) -and ($coworkDnsSends -eq 0) -and ($hostSends -ge 12)
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
    foreach ($st in @('baseline','blocked','healthy1','fault1','restored')) {
        $h = $report.hostHealth[$st]
        if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hOk = $false }
    }
    $report.checks.hostContinuous = $hOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and ($report.cleanup.residualPackageFilters -eq 0) -and
        $report.cleanup.directoryGone -and $report.cleanup.sharedAppGone -and $report.cleanup.repoGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and $report.cleanup.profAGone -and $report.cleanup.profBGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 12)
    $report.outcome = if ($allOk) { 'passed-ab-phase8-control-plane-real-desktop' } else { 'stopped-ab-phase8-control-plane-real-desktop' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        officialPackage = $report.officialPackage; spaces = $report.spaces
        proxyTelemetry = $report.proxyTelemetry; faultTimingsMs = $report.faultTimingsMs
        checks = $report.checks; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
