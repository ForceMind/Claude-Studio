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

function Get-UniqueEphemeralPorts([int]$Count) {
    $list = New-Object System.Collections.Generic.List[Net.Sockets.TcpListener]
    $ports = New-Object System.Collections.Generic.List[int]
    try {
        while ($ports.Count -lt $Count) {
            $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $l.ExclusiveAddressUse = $true
            $l.Start()
            $p = $l.LocalEndpoint.Port
            if ($p -ge 45000 -and $p -ne 10810 -and !$ports.Contains($p)) { $list.Add($l); $ports.Add($p) }
            else { $l.Stop() }
        }
        return $ports.ToArray()
    } finally { foreach ($l in $list) { try { $l.Stop() } catch { } } }
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
    $ReportPath = Join-Path $reportDir ("windows-ab-real-claude-dual-space-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeRealDual-summary-$RunId.json")
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

$fixtureDir = $PSScriptRoot
$mockDesktopDir = Split-Path (Split-Path $fixtureDir -Parent) -Parent
. (Join-Path $mockDesktopDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDesktopDir 'windows-lab-bind-gate.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeRealDual-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$sharedAppStage = Join-Path $env:ProgramData ("ClaudeStudioRealApp-$RunId")
$harnessDll = Join-Path $base 'StudioRealDualHarness.dll'
$ownerExe = Join-Path $base 'StudioRealDualProxyOwner.exe'
$srcAppDir = Join-Path $PkgInstallLocation 'app'

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-real-claude-dual-space'
    officialPackage = [ordered]@{ name = 'Claude'; version = $PkgVersion; packageFamilyName = $PkgFamilyName }
    spaces = [ordered]@{ A = [ordered]@{}; B = [ordered]@{} }
    proxyTelemetry = [ordered]@{}
    hostHealth = [ordered]@{}; checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @(); residualPackageFilters = 0 }
}

$dirCreated = $false; $sharedAppCreated = $false; $assemblyLoaded = $false
$users = @{}; $tokens = @{}; $slots = @{}
$hostListener = $null; $hostOld = $null; $proxyProc = $null
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

function Read-ProxyStats([string]$LogPath) {
    $a = 0; $b = 0; $u = 0; $aHosts = New-Object System.Collections.Generic.HashSet[string]; $bHosts = New-Object System.Collections.Generic.HashSet[string]
    if (Test-Path -LiteralPath $LogPath) {
        $lines = [IO.File]::ReadAllLines($LogPath, [Text.Encoding]::UTF8)
        foreach ($ln in $lines) {
            if (!$ln.Trim()) { continue }
            try {
                $o = $ln | ConvertFrom-Json
                if ($o.entry -eq 'A') { $a++; if ($o.target) { [void]$aHosts.Add([string]$o.target) } }
                elseif ($o.entry -eq 'B') { $b++; if ($o.target) { [void]$bHosts.Add([string]$o.target) } }
                elseif ($o.entry -eq 'U') { $u++ }
            } catch { }
        }
    }
    return [ordered]@{ entryA = $a; entryB = $b; upstream = $u; aTargets = @($aHosts); bTargets = @($bHosts) }
}

function Send-OwnerCmd($Proc, [string]$Cmd) {
    $Proc.StandardInput.WriteLine($Cmd)
    $Proc.StandardInput.Flush()
    $t = $Proc.StandardOutput.ReadLineAsync()
    if (!$t.Wait(4000) -or !$t.Result) { throw "ProxyOwner $Cmd timed out" }
    return ($t.Result | ConvertFrom-Json)
}

try {
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"
    if ((Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue) -or (Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)) {
        throw 'Expected ClaudeStudioLabA and ClaudeStudioLabB to be absent'
    }

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Host baseline snapshots (zero user data reads!)
    $coworkBefore = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceBefore = if ($coworkBefore) { [ordered]@{ state = $coworkBefore.State; pid = [int]$coworkBefore.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclBefore = (Get-Acl -LiteralPath $PkgInstallLocation).Sddl
    $cRootAclBefore = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostUserProfile = (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $hostSid + "'") -ErrorAction SilentlyContinue).LocalPath
    $hostRoamingBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }

    # 1. Compile harness + ProxyOwner + native Layer-1 & pure-C Layer-2 host
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $inspCs = Join-Path $base 'DualProcInspect.cs'
    [IO.File]::WriteAllText($inspCs, @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class DualProcInspector {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int req);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    delegate bool EnumWinProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr OpenDesktopW(string name, uint flags, bool inh, uint acc);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr hDesk);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr hDesk, EnumWinProc cb, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hwnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    public static Dictionary<string, object> ReadPidToken(int pid) {
        var d = new Dictionary<string, object> { { "pid", pid }, { "ok", false } };
        IntPtr p = OpenProcess(0x1000, false, pid);
        if (p == IntPtr.Zero) return d;
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
    public static List<Dictionary<string, object>> ListVisibleChromeWindowsOnDefaultDesktop() {
        var list = new List<Dictionary<string, object>>();
        IntPtr hDesk = OpenDesktopW("Default", 0, false, 0x0041);
        try {
            if (hDesk == IntPtr.Zero) return list;
            EnumDesktopWindows(hDesk, (h, lp) => {
                if (!IsWindowVisible(h)) return true;
                var cb = new System.Text.StringBuilder(128); GetClassNameW(h, cb, 128);
                if (cb.ToString() != "Chrome_WidgetWin_1") return true;
                uint p = 0; GetWindowThreadProcessId(h, out p);
                var tb = new System.Text.StringBuilder(256); GetWindowTextW(h, tb, 256);
                list.Add(new Dictionary<string, object> { { "pid", (int)p }, { "hwnd", h.ToInt64() }, { "className", cb.ToString() }, { "title", tb.ToString() } });
                return true;
            }, IntPtr.Zero);
        } finally { if (hDesk != IntPtr.Zero) CloseDesktop(hDesk); }
        return list;
    }
}
'@, (New-Object Text.UTF8Encoding($false)))

    $c1 = & $csc /nologo /platform:x64 /target:library /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$harnessDll" `
        $inspCs (Join-Path $fixtureDir 'DesktopRead.cs') (Join-Path $fixtureDir 'PsecStartupGuard.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Harness compile failed: ' + ($c1 -join '; ')) }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($harnessDll))
    $assemblyLoaded = $true

    $c2 = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$ownerExe" `
        (Join-Path $fixtureDir 'Phase1ProxyOwner.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('ProxyOwner compile failed: ' + ($c2 -join '; ')) }

    $l1Template = Join-Path $base 'StudioLayer1Psec.exe'
    $l2HostC = Join-Path $base 'l2_dual_claude.c'
    $l2Template = Join-Path $base 'StudioLayer2Claude.exe'
    $l2Code = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static void ToWide(const char* s, wchar_t* d, int cap) { MultiByteToWideChar(CP_UTF8, 0, s, -1, d, cap); }
static int ParseArgs(wchar_t a[4][512]) {
    const wchar_t* p = GetCommandLineW(); int idx = 0;
    while (*p && idx < 4) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        int n = 0;
        if (*p == L'"') { p++; while (*p && *p != L'"' && n < 511) a[idx][n++] = *p++; if (*p == L'"') p++; }
        else { while (*p && *p != L' ' && *p != L'\t' && n < 511) a[idx][n++] = *p++; }
        a[idx][n] = L'\0'; idx++;
    }
    return idx;
}
int WINAPI wWinMain(HINSTANCE h1, HINSTANCE h2, PWSTR c, int s) {
    (void)h1; (void)h2; (void)c; (void)s;
    wchar_t a[4][512];
    if (ParseArgs(a) < 2) return 2;
    HANDLE f = CreateFileW(a[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 3;
    char buf[4096]; DWORD got = 0; ReadFile(f, buf, sizeof(buf) - 1, &got, NULL); CloseHandle(f); buf[got] = '\0';
    wchar_t exePath[512] = L"", cmdLine[1536] = L"", stopPath[512] = L"";
    wchar_t homeDir[512] = L"", localDir[512] = L"", roamDir[512] = L"", tmpDir[512] = L"";
    wchar_t userName[128] = L"", proxyUrl[128] = L"", langVal[64] = L"", tzVal[64] = L"";
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        if (line[0] == 'e' && line[1] == '=') ToWide(line + 2, exePath, 512);
        else if (line[0] == 'a' && line[1] == '=') ToWide(line + 2, cmdLine, 1536);
        else if (line[0] == 's' && line[1] == '=') ToWide(line + 2, stopPath, 512);
        else if (line[0] == 'h' && line[1] == '=') ToWide(line + 2, homeDir, 512);
        else if (line[0] == 'L' && line[1] == '=') ToWide(line + 2, localDir, 512);
        else if (line[0] == 'R' && line[1] == '=') ToWide(line + 2, roamDir, 512);
        else if (line[0] == 'T' && line[1] == '=') ToWide(line + 2, tmpDir, 512);
        else if (line[0] == 'u' && line[1] == '=') ToWide(line + 2, userName, 128);
        else if (line[0] == 'p' && line[1] == '=') ToWide(line + 2, proxyUrl, 128);
        else if (line[0] == 'g' && line[1] == '=') ToWide(line + 2, langVal, 64);
        else if (line[0] == 'z' && line[1] == '=') ToWide(line + 2, tzVal, 64);
    }
    if (homeDir[0]) { SetEnvironmentVariableW(L"USERPROFILE", homeDir); SetEnvironmentVariableW(L"HOME", homeDir); }
    if (localDir[0]) SetEnvironmentVariableW(L"LOCALAPPDATA", localDir);
    if (roamDir[0]) SetEnvironmentVariableW(L"APPDATA", roamDir);
    if (tmpDir[0]) { SetEnvironmentVariableW(L"TEMP", tmpDir); SetEnvironmentVariableW(L"TMP", tmpDir); }
    if (userName[0]) SetEnvironmentVariableW(L"USERNAME", userName);
    if (proxyUrl[0]) { SetEnvironmentVariableW(L"HTTP_PROXY", proxyUrl); SetEnvironmentVariableW(L"HTTPS_PROXY", proxyUrl); }
    if (langVal[0]) SetEnvironmentVariableW(L"LANG", langVal);
    if (tzVal[0]) SetEnvironmentVariableW(L"TZ", tzVal);
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exePath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return (int)GetLastError();
    DWORD waited = 0;
    while (waited < 60000) {
        if (GetFileAttributesW(stopPath) != INVALID_FILE_ATTRIBUTES) break;
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) break;
        waited += 200;
    }
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 0;
}
'@
    [IO.File]::WriteAllText($l2HostC, $l2Code, (New-Object Text.UTF8Encoding($false)))
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $clOut = & cmd.exe /c ('call "' + $vcvars + '" >nul && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l1Template + '" kernel32.lib advapi32.lib && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2.obj') + '" "' + $l2HostC + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l2Template + '" kernel32.lib') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native build failed: ' + ($clOut -join '; ')) }

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # 2. Create temporary standard users A & B
    foreach ($sk in @('A','B')) {
        $uName = "ClaudeStudioLab$sk"
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $uName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $sk Real Claude Dual"
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $orig = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($uName, $env:COMPUTERNAME, $pw)
        $prof = [StudioPsecGuardHost]::LoadLabProfile($orig, $uName)
        $copy = [StudioPsecGuardHost]::DuplicateHardened($orig, $hostSid)
        $users[$sk] = @{ name = $uName; sid = $u.SID.Value }
        $tokens[$sk] = @{ orig = $orig; copy = $copy; prof = $prof }
    }

    # 3. Stage ONE shared read-only copy of official app\ (ZERO edits to WindowsApps!)
    $appAcl = New-PrivateAcl $hostSid
    foreach ($s in @($users['A'].sid, $users['B'].sid, 'S-1-15-2-1')) {
        $appAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($sharedAppStage, $appAcl)
    $sharedAppCreated = $true
    $null = & robocopy.exe $srcAppDir $sharedAppStage /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS
    if ($LASTEXITCODE -ge 8) { throw "robocopy app failed with exit code $LASTEXITCODE" }
    $stagedClaudeExe = Join-Path $sharedAppStage 'claude.exe'

    # 4. Start local zero-egress dual-entry + shared-upstream CONNECT proxy (NEVER touches 10810 or internet!)
    $ports = Get-UniqueEphemeralPorts 3
    $portA = [uint16]$ports[0]; $portB = [uint16]$ports[1]; $portU = [uint16]$ports[2]
    $proxyScript = Join-Path $base 'dual-real-proxy.cjs'
    $proxyLog = Join-Path $base 'dual-real-proxy.ndjson'
    [IO.File]::WriteAllText($proxyScript, @'
'use strict';
const net = require('net');
const fs = require('fs');
const [pA, pB, pU, logPath] = [parseInt(process.argv[2],10), parseInt(process.argv[3],10), parseInt(process.argv[4],10), process.argv[5]];
function log(row) { try { fs.appendFileSync(logPath, JSON.stringify({ utc: new Date().toISOString(), ...row }) + '\n', 'utf8'); } catch (_) {} }
// Shared local offline upstream: logs every CONNECT and returns 502 (ZERO outbound internet!)
const upSrv = net.createServer(sock => {
  let buf = '';
  sock.on('data', chunk => {
    buf += chunk.toString('latin1');
    const idx = buf.indexOf('\r\n\r\n');
    if (idx >= 0) {
      const first = buf.slice(0, buf.indexOf('\r\n'));
      const parts = first.split(' ');
      log({ entry: 'U', method: parts[0] || '', target: parts[1] || '' });
      sock.end('HTTP/1.1 502 Local Synthetic Offline Upstream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    }
  });
  sock.on('error', () => {});
});
function makeEntry(label, port) {
  return net.createServer(client => {
    let buf = '';
    client.on('data', chunk => {
      buf += chunk.toString('latin1');
      const idx = buf.indexOf('\r\n\r\n');
      if (idx >= 0) {
        const first = buf.slice(0, buf.indexOf('\r\n'));
        const parts = first.split(' ');
        log({ entry: label, method: parts[0] || '', target: parts[1] || '' });
        const up = net.createConnection({ host: '127.0.0.1', port: pU }, () => { up.write(buf); });
        up.on('data', d => { try { client.write(d); } catch (_) {} });
        up.on('end', () => { try { client.end(); } catch (_) {} });
        up.on('error', () => { try { client.end('HTTP/1.1 503 Upstream Down\r\nContent-Length: 0\r\n\r\n'); } catch (_) {} });
      }
    });
    client.on('error', () => {});
  });
}
const eA = makeEntry('A', pA), eB = makeEntry('B', pB);
upSrv.listen(pU, '127.0.0.1', () => eA.listen(pA, '127.0.0.1', () => eB.listen(pB, '127.0.0.1', () => {
  process.stdout.write(JSON.stringify({ kind: 'ready', pA, pB, pU }) + '\n');
})));
'@, (New-Object Text.UTF8Encoding($false)))

    $nodeExe = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $psiP = [Diagnostics.ProcessStartInfo]::new($nodeExe, "`"$proxyScript`" $portA $portB $portU `"$proxyLog`"")
    $psiP.UseShellExecute = $false; $psiP.CreateNoWindow = $true; $psiP.RedirectStandardOutput = $true; $psiP.RedirectStandardError = $true
    $proxyProc = [Diagnostics.Process]::Start($psiP)
    $pReady = $proxyProc.StandardOutput.ReadLineAsync()
    if (!$pReady.Wait(5000) -or !$pReady.Result) { throw 'Dual proxy failed to start' }

    # 5. Start Host Health + Level-4 DNS ETW
    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $dnsPidBefore = Get-LabDnsServicePid
    $lmRes = & logman.exe create trace $etlName -o $etlFile -p 'Microsoft-Windows-DNS-Client' 0xffffffffffffffff 4 -ets 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('DNS ETW start failed: ' + ($lmRes -join ' ')) }
    $etlStarted = $true
    $null = Test-HostHealth 'baseline' 41

    # 6. Prepare & Cold-Start BOTH Space A (zh-CN / Asia/Shanghai) and Space B (en-US / America/Los_Angeles) in Hardened PSEC 1.1 + 4 Static BLOCK WFP!
    foreach ($sk in @('A','B')) {
        $uName = $users[$sk].name; $uSid = $users[$sk].sid
        $aHome = "C:\Users\$uName"; $aLocal = "$aHome\AppData\Local"; $aRoam = "$aHome\AppData\Roaming"
        $workRoot = Join-Path (Join-Path $aLocal 'Temp') $tag
        $sealed = Join-Path $workRoot 'sealed'
        $scratch = Join-Path $workRoot 'scratch'
        $userData = Join-Path $workRoot 'userdata'
        $cData = Join-Path $aLocal 'Claude-Data'; $c3p = Join-Path $aLocal 'Claude-3p'
        $cLoc = Join-Path $aLocal 'Claude'; $cLogs = Join-Path $cLoc 'logs'; $rClaude = Join-Path $aRoam 'Claude'

        $rxAcl = New-PrivateAcl $hostSid; $rwAcl = New-PrivateAcl $hostSid
        foreach ($s in @($uSid, 'S-1-15-2-1')) {
            $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($workRoot, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)
        foreach ($d in @($scratch, $userData, $cData, $c3p, $cLoc, $cLogs, $rClaude)) { [void][IO.Directory]::CreateDirectory($d, $rwAcl) }

        $l1Exe = Join-Path $sealed "Studio${sk}Layer1.exe"
        $l2Exe = Join-Path $sealed "Studio${sk}Layer2.exe"
        Copy-Item -LiteralPath $l1Template -Destination $l1Exe -Force
        Copy-Item -LiteralPath $l2Template -Destination $l2Exe -Force

        $pPort = if ($sk -eq 'A') { $portA } else { $portB }
        $uiLang = if ($sk -eq 'A') { 'zh-CN' } else { 'en-US' }
        $envLang = if ($sk -eq 'A') { 'zh_CN.UTF-8' } else { 'en_US.UTF-8' }
        $envTz = if ($sk -eq 'A') { 'Asia/Shanghai' } else { 'America/Los_Angeles' }

        $psecBin = Join-Path $sealed "psec-$sk.bin"
        $enumAncestors = [string[]]@('C:\', 'C:\ProgramData', 'C:\Users', $aHome, "$aHome\AppData", $aLocal, "$aLocal\Temp")
        $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Full(
            [string[]]@($scratch, $userData, $cData, $c3p, $cLoc, $cLogs, $rClaude, $aRoam),
            [string[]]@($sealed, $sharedAppStage), $enumAncestors, $false)
        [IO.File]::WriteAllBytes($psecBin, $psecBytes)

        $readyPath = Join-Path $scratch 'l1-ready.json'
        $l1Stop = Join-Path $scratch 'l1-stop'
        $l2Stop = Join-Path $scratch 'l2-stop'
        $claudeCmd = "`"$stagedClaudeExe`" --user-data-dir=`"$userData`" --proxy-server=`"http://127.0.0.1:$pPort`" --lang=$uiLang --no-sandbox --disable-gpu-sandbox"
        $l2Cfg = Join-Path $sealed 'l2-claude.cfg'
        [IO.File]::WriteAllText($l2Cfg, ("e=$stagedClaudeExe`na=$claudeCmd`ns=$l2Stop`nh=$aHome`nL=$aLocal`nR=$aRoam`nT=$scratch`nu=$uName`np=http://127.0.0.1:$pPort`ng=$envLang`nz=$envTz`n"), (New-Object Text.UTF8Encoding($false)))

        $l1Args = "`"$psecBin`" `"$l2Exe`" `"$l2Cfg`" `"$scratch`" `"$hostSid`" `"$readyPath`" `"$l1Stop`""
        $l1 = [StudioPsecGuardHost]::StartSuspended($tokens[$sk].copy, $l1Exe, $l1Args, $true, 'WinSta0\Default')
        $null = $l1.RestoreTokenObjectDaclOnly($tokens[$sk].orig, $hostSid, $uSid)
        [void]$l1.ResumeMainThread()

        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $readyPath) -and $sw.ElapsedMilliseconds -lt 30000) { Start-Sleep -Milliseconds 30 }
        if (!(Test-Path -LiteralPath $readyPath)) { throw "Layer-1 $sk timed out" }
        $l1Rec = [IO.File]::ReadAllText($readyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        if (!$l1Rec.psecCreated -or !$l1Rec.childCreated) { throw "Layer-1 $sk PSEC failed" }
        $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$l1Rec.childPid, [int]$l1Rec.childTid, $hostSid, $uSid)
        $cSid = $insp.identity.containerSid
        [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$l1Rec.childPid, $hostSid, $cSid)
        [void]$observedPidSet.Add([int]$l1Rec.layer1Pid)
        [void]$observedPidSet.Add([int]$l1Rec.childPid)

        # Install 4 Static BLOCK WFP BEFORE ResumeThread!
        $wfpSub = [guid]::NewGuid()
        $wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
        $g = [StudioLabWfp]::CreateStaticGuard()
        try {
            $wfpWeight = $g.PrepareStatic($wfpSub, $wfpKeys, $cSid, $pPort, $l2Exe)
            $g.InstallStatic($wfpSub, $wfpKeys, $cSid, $pPort, $l2Exe, $wfpWeight)
        } finally { $g.Dispose() }
        $null = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $cSid, $pPort, $wfpWeight, $false)

        $slots[$sk] = @{
            l1=$l1; l1Rec=$l1Rec; l1Stop=$l1Stop; l2Stop=$l2Stop; cSid=$cSid; port=$pPort
            wfpSub=$wfpSub; wfpKeys=$wfpKeys; wfpWeight=$wfpWeight; wfpInstalled=$true
            userData=$userData; ownerProc=$null
        }
        $report.spaces[$sk] = [ordered]@{ userSid=$uSid; containerSid=$cSid; wfpWeight=$wfpWeight; proxyPort=$pPort; uiLang=$uiLang; tz=$envTz }
    }

    # Resume BOTH A and B in ColdBlocked state simultaneously!
    $null = [StudioPsecGuardHost]::HostResumeChildOnly([int]$slots['A'].l1Rec.childPid, [int]$slots['A'].l1Rec.childTid)
    $null = [StudioPsecGuardHost]::HostResumeChildOnly([int]$slots['B'].l1Rec.childPid, [int]$slots['B'].l1Rec.childTid)
    $null = Test-HostHealth 'blocked' 51

    # Wait 5s in ColdBlocked -> BOTH windows launch, ZERO proxy hits!
    Start-Sleep -Milliseconds 5000
    $coldProxy = Read-ProxyStats $proxyLog
    $report.proxyTelemetry.afterColdBlocked = $coldProxy

    # 7. Open dynamic single-port exceptions E_A (Pa) and E_B (Pb) via standalone ProxyOwner_A & ProxyOwner_B!
    foreach ($sk in @('A','B')) {
        $sl = $slots[$sk]
        $oArgs = "$($sl.wfpSub) $($sl.wfpKeys[0]) $($sl.wfpKeys[1]) $($sl.wfpKeys[2]) $($sl.wfpKeys[3]) $($sl.wfpKeys[4]) $($sl.cSid) $($sl.port):$($sl.wfpWeight)"
        $psiO = [Diagnostics.ProcessStartInfo]::new($ownerExe, $oArgs)
        $psiO.UseShellExecute = $false; $psiO.CreateNoWindow = $true; $psiO.RedirectStandardInput = $true; $psiO.RedirectStandardOutput = $true; $psiO.RedirectStandardError = $true
        $op = [Diagnostics.Process]::Start($psiO)
        $rdy = $op.StandardOutput.ReadLineAsync(); if (!$rdy.Wait(4000)) { throw "ProxyOwner $sk ready timeout" }
        $resOpen = Send-OwnerCmd $op 'open'
        if (!$resOpen.open) { throw "ProxyOwner $sk open failed" }
        $sl.ownerProc = $op
        $null = [StudioLabWfp]::VerifyStatic($sl.wfpSub, $sl.wfpKeys, $sl.cSid, $sl.port, $sl.wfpWeight, $true)
    }

    # Sample both process trees, visible Chrome windows, and proxy traffic for up to 12 seconds!
    $seenA = @{}; $seenB = @{}
    $bothWinsSimultaneous = $false; $winSnapshotA = @(); $winSnapshotB = @()
    $onlineProxy = $null
    for ($tick = 0; $tick -lt 18; $tick++) {
        Start-Sleep -Milliseconds 650
        $visWins = [DualProcInspector]::ListVisibleChromeWindowsOnDefaultDesktop()
        $curWinA = @(); $curWinB = @()
        $procs = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%'" -ErrorAction SilentlyContinue
        foreach ($pr in $procs) {
            $pidInt = [int]$pr.ProcessId
            $tok = [DualProcInspector]::ReadPidToken($pidInt)
            if (!$tok.ok) { continue }
            $typeArg = ''; if ($pr.CommandLine -match '--type=([a-zA-Z0-9_-]+)') { $typeArg = $Matches[1] }
            $pWins = @($visWins | Where-Object { $_['pid'] -eq $pidInt })
            if ($tok['userSid'] -ceq $users['A'].sid) {
                [void]$observedPidSet.Add($pidInt)
                $seenA["$pidInt"] = [ordered]@{ pid=$pidInt; type=$typeArg; ac=$tok['isAppContainer']; sameCid=($tok['containerSid'] -ceq $slots['A'].cSid); visWinCount=$pWins.Count }
                if ($pWins.Count -gt 0) { $curWinA += $pWins }
            } elseif ($tok['userSid'] -ceq $users['B'].sid) {
                [void]$observedPidSet.Add($pidInt)
                $seenB["$pidInt"] = [ordered]@{ pid=$pidInt; type=$typeArg; ac=$tok['isAppContainer']; sameCid=($tok['containerSid'] -ceq $slots['B'].cSid); visWinCount=$pWins.Count }
                if ($pWins.Count -gt 0) { $curWinB += $pWins }
            }
        }
        if ($curWinA.Count -ge 1 -and $curWinB.Count -ge 1) {
            $bothWinsSimultaneous = $true
            $winSnapshotA = @($curWinA | ForEach-Object { [ordered]@{ pid=$_['pid']; hwnd=$_['hwnd']; title=$_['title'] } })
            $winSnapshotB = @($curWinB | ForEach-Object { [ordered]@{ pid=$_['pid']; hwnd=$_['hwnd']; title=$_['title'] } })
        }
        $onlineProxy = Read-ProxyStats $proxyLog
        if ($bothWinsSimultaneous -and $onlineProxy.entryA -ge 1 -and $onlineProxy.entryB -ge 1 -and $tick -ge 6) { break }
    }
    $report.proxyTelemetry.afterDualOnline = $onlineProxy
    $null = Test-HostHealth 'healthy1' 61

    # 8. Single-Space Fault Cutoff: Exit ProxyOwner_A ONLY (revokes E_A while E_B stays open!)
    $resExitA = Send-OwnerCmd $slots['A'].ownerProc 'exit'
    [void]$slots['A'].ownerProc.WaitForExit(2000); $slots['A'].ownerProc.Dispose(); $slots['A'].ownerProc = $null
    Start-Sleep -Milliseconds 150
    $eAAbsent = ![StudioLabWfp]::StaticExceptionPresent($slots['A'].wfpSub, $slots['A'].wfpKeys, $slots['A'].cSid, $slots['A'].port, $slots['A'].wfpWeight)
    $eBStillPresent = [StudioLabWfp]::StaticExceptionPresent($slots['B'].wfpSub, $slots['B'].wfpKeys, $slots['B'].cSid, $slots['B'].port, $slots['B'].wfpWeight)
    $preCutoffA = (Read-ProxyStats $proxyLog).entryA
    Start-Sleep -Milliseconds 3500
    $postCutoffProxy = Read-ProxyStats $proxyLog
    $report.proxyTelemetry.afterACutoff = $postCutoffProxy
    $null = Test-HostHealth 'fault1' 71

    # Check both windows still coexist cleanly after A cutoff!
    $visAfterCut = [DualProcInspector]::ListVisibleChromeWindowsOnDefaultDesktop()
    $bAliveAfterCut = (@($visAfterCut | Where-Object { $seenB.ContainsKey("$($_['pid'])") }).Count -ge 1)

    $procsAList = @($seenA.Keys | ForEach-Object { $seenA[$_] })
    $procsBList = @($seenB.Keys | ForEach-Object { $seenB[$_] })
    $filesA = @(Get-ChildItem -LiteralPath $slots['A'].userData -Recurse -File -ErrorAction SilentlyContinue).Count
    $filesB = @(Get-ChildItem -LiteralPath $slots['B'].userData -Recurse -File -ErrorAction SilentlyContinue).Count
    $report.spaces['A'].observedProcessCount = $procsAList.Count
    $report.spaces['A'].processes = $procsAList
    $report.spaces['A'].visibleWindows = $winSnapshotA
    $report.spaces['A'].userDataFileCount = $filesA
    $report.spaces['B'].observedProcessCount = $procsBList.Count
    $report.spaces['B'].processes = $procsBList
    $report.spaces['B'].visibleWindows = $winSnapshotB
    $report.spaces['B'].userDataFileCount = $filesB

    # Host checks after run
    $coworkAfter = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceAfter = if ($coworkAfter) { [ordered]@{ state = $coworkAfter.State; pid = [int]$coworkAfter.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclAfter = (Get-Acl -LiteralPath $PkgInstallLocation).Sddl
    $cRootAclAfter = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostRoamingAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }

    $report.checks.dualColdStartZeroProxyHits = ($slots['A'].cSid -cne $slots['B'].cSid) -and ($coldProxy.entryA -eq 0) -and ($coldProxy.entryB -eq 0)
    $report.checks.bothWindowsCoexistSimultaneously = $bothWinsSimultaneous -and ($winSnapshotA.Count -ge 1) -and ($winSnapshotB.Count -ge 1)
    $report.checks.allMultiProcessTreesContained = ($procsAList.Count -ge 3) -and ($procsBList.Count -ge 3) -and
        (@($procsAList | Where-Object { !$_.ac -or !$_.sameCid }).Count -eq 0) -and
        (@($procsBList | Where-Object { !$_.ac -or !$_.sameCid }).Count -eq 0)
    $report.checks.isolatedUserDataCreatedSeparately = ($filesA -ge 10) -and ($filesB -ge 10)
    $report.checks.dualProxyTrafficRoutedToDedicatedPorts = ($onlineProxy.entryA -ge 1) -and ($onlineProxy.entryB -ge 1) -and ($onlineProxy.upstream -ge 2)
    $report.checks.singleSpaceCutoffIsolatesAOnly = $eAAbsent -and $eBStillPresent -and ($postCutoffProxy.entryA -eq $preCutoffA) -and $bAliveAfterCut
    $report.checks.coworkServiceUntriggered = ($report.coworkServiceBefore.state -ceq $report.coworkServiceAfter.state) -and ($report.coworkServiceBefore.pid -eq $report.coworkServiceAfter.pid)
    $report.checks.hostClaudeAndSystemUnchanged = ($winAppsAclBefore -ceq $winAppsAclAfter) -and ($cRootAclBefore -ceq $cRootAclAfter) -and
        (($hostRoamingBefore | ConvertTo-Json -Compress) -ceq ($hostRoamingAfter | ConvertTo-Json -Compress)) -and
        (($hostLocalDataBefore | ConvertTo-Json -Compress) -ceq ($hostLocalDataAfter | ConvertTo-Json -Compress))
} catch {
    $report.error = $_.Exception.Message
} finally {
    foreach ($sk in @('A','B')) {
        if ($slots.ContainsKey($sk)) {
            $sl = $slots[$sk]
            if ($sl.ownerProc) { try { if (!$sl.ownerProc.HasExited) { $sl.ownerProc.Kill(); [void]$sl.ownerProc.WaitForExit(1500) } $sl.ownerProc.Dispose() } catch { } }
            try { [IO.File]::WriteAllText($sl.l2Stop, 'stop') } catch { }
            try { [IO.File]::WriteAllText($sl.l1Stop, 'stop') } catch { }
            if ($sl.l1Rec -and $sl.l1Rec.childPid) { try { [StudioPsecGuardHost]::HostTerminatePid([int]$sl.l1Rec.childPid) } catch { } }
            if ($sl.l1) { try { [StudioPsecGuardHost]::HostTerminatePid($sl.l1.Pid) } catch { } ; try { [void]$sl.l1.WaitExit(2500); $sl.l1.Dispose() } catch { } }
        }
    }
    if ($assemblyLoaded) {
        $sids = @(); foreach ($sk in @('A','B')) { if ($users.ContainsKey($sk)) { $sids += $users[$sk].sid } }
        if ($sids.Count -gt 0) {
            try {
                $rem = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%' OR Name LIKE '%StudioA%' OR Name LIKE '%StudioB%'" -ErrorAction SilentlyContinue
                foreach ($pr in $rem) {
                    $tk = [DualProcInspector]::ReadPidToken([int]$pr.ProcessId)
                    if ($tk.ok -and ($sids -contains $tk['userSid'])) { try { Stop-Process -Id ([int]$pr.ProcessId) -Force -ErrorAction SilentlyContinue } catch { } }
                }
            } catch { }
        }
    }
    if ($proxyProc) { try { if (!$proxyProc.HasExited) { $proxyProc.Kill(); [void]$proxyProc.WaitForExit(1500) } $proxyProc.Dispose() } catch { } }
    Start-Sleep -Milliseconds 350

    $resTotal = 0
    foreach ($sk in @('A','B')) {
        if ($slots.ContainsKey($sk) -and $slots[$sk].wfpInstalled -and $assemblyLoaded) {
            $sl = $slots[$sk]
            try {
                [StudioLabWfp]::RemoveStatic($sl.wfpSub, $sl.wfpKeys, $sl.cSid, $sl.port, $sl.wfpWeight)
                Start-Sleep -Milliseconds 60
                $resTotal += [StudioLabWfp]::CountFiltersReferencingPackage($sl.cSid)
            } catch { $report.cleanup.errors += @("wfp$sk`: $($_.Exception.Message)") }
        }
    }
    $report.cleanup.residualPackageFilters = $resTotal
    $report.cleanup.wfpRemovedAndVerifiedAbsent = ($resTotal -eq 0)

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
    if ($sharedAppCreated -and (Test-Path -LiteralPath $sharedAppStage)) { try { Remove-Item -LiteralPath $sharedAppStage -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("sharedApp: $($_.Exception.Message)") } }
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.sharedAppGone = !(Test-Path -LiteralPath $sharedAppStage)
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
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and
        $report.cleanup.directoryGone -and $report.cleanup.sharedAppGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and $report.cleanup.profAGone -and $report.cleanup.profBGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 11)
    $report.outcome = if ($allOk) { 'passed-ab-real-claude-dual-space' } else { 'stopped-ab-real-claude-dual-space' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        officialPackage = $report.officialPackage
        spaces = [ordered]@{
            A = [ordered]@{ wfpWeight=$report.spaces['A'].wfpWeight; proxyPort=$report.spaces['A'].proxyPort; uiLang=$report.spaces['A'].uiLang; tz=$report.spaces['A'].tz; procCount=$report.spaces['A'].observedProcessCount; visWinCount=@($report.spaces['A'].visibleWindows).Count; dataFiles=$report.spaces['A'].userDataFileCount }
            B = [ordered]@{ wfpWeight=$report.spaces['B'].wfpWeight; proxyPort=$report.spaces['B'].proxyPort; uiLang=$report.spaces['B'].uiLang; tz=$report.spaces['B'].tz; procCount=$report.spaces['B'].observedProcessCount; visWinCount=@($report.spaces['B'].visibleWindows).Count; dataFiles=$report.spaces['B'].userDataFileCount }
        }
        proxyTelemetry = $report.proxyTelemetry
        checks = $report.checks; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
