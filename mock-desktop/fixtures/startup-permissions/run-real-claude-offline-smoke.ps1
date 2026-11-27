[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$RunId,
    [string]$ReportPath,
    [string]$SummaryPath,
    [string]$PkgInstallLocation,
    [string]$PkgVersion,
    [string]$PkgFamilyName,
    [switch]$NoChromiumSandbox
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
    $ReportPath = Join-Path $reportDir ("windows-a-real-claude-offline-smoke-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeRealSmoke-summary-$RunId.json")
    $extraFlag = if ($NoChromiumSandbox) { ' -NoChromiumSandbox' } else { '' }
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath `
            -PkgInstallLocation $pkgLocal.InstallLocation -PkgVersion $pkgLocal.Version -PkgFamilyName $pkgLocal.PackageFamilyName `
            -NoChromiumSandbox:$NoChromiumSandbox
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '" -PkgInstallLocation "' + $pkgLocal.InstallLocation + '" -PkgVersion "' + $pkgLocal.Version + '" -PkgFamilyName "' + $pkgLocal.PackageFamilyName + '"' + $extraFlag
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $sw.ElapsedMilliseconds -lt 180000) { Start-Sleep -Milliseconds 100 }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if (!(Test-Path -LiteralPath $SummaryPath)) {
            $tLog = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeRealSmoke-trace-$RunId.log")
            $tTxt = if (Test-Path -LiteralPath $tLog) { Get-Content -LiteralPath $tLog -Raw -Encoding UTF8 } else { '(no trace)' }
            throw "Elevated runner finished/timed out without summary (exited=$($proc.HasExited), code=$($proc.ExitCode)). Trace:`n$tTxt"
        }
    }
    $txt = Get-Content -LiteralPath $SummaryPath -Raw -Encoding UTF8
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
$tag = 'ClaudeRealSmoke-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$traceLog = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeRealSmoke-trace-$RunId.log")
function Write-Stage([string]$Msg) { try { Add-Content -LiteralPath $traceLog -Value ("[" + [datetime]::UtcNow.ToString('HH:mm:ss.fff') + "] " + $Msg) -Encoding UTF8 } catch { } }
Write-Stage 'elevated-start'
$harnessDll = Join-Path $base 'StudioRealSmokeHarness.dll'

if (!$PkgInstallLocation -or !(Test-Path -LiteralPath (Join-Path $PkgInstallLocation 'app\claude.exe'))) {
    throw 'Official Claude MSIX install path missing'
}
$srcAppDir = Join-Path $PkgInstallLocation 'app'
$pkg = [ordered]@{ Name = 'Claude'; Version = $PkgVersion; PackageFamilyName = $PkgFamilyName; InstallLocation = $PkgInstallLocation }

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-real-claude-offline-smoke'
    noChromiumSandbox = [bool]$NoChromiumSandbox
    officialPackage = [ordered]@{ name = $pkg.Name; version = $pkg.Version; packageFamilyName = $pkg.PackageFamilyName }
    observedProcesses = @(); hostHealth = [ordered]@{}; checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @(); residualPackageFilters = 0 }
}

$dirCreated = $false; $accountCreated = $false; $accountSid = $null
$origToken = [IntPtr]::Zero; $copyToken = [IntPtr]::Zero; $loadedProfileHandle = [IntPtr]::Zero
$aWorkRoot = $null; $hostListener = $null; $hostOld = $null
$etlName = $prefix; $etlFile = Join-Path $base ($prefix + '.etl'); $etlStarted = $false; $dnsPidBefore = 0
$wfpInstalled = $false; $wfpSub = [guid]::Empty; $wfpKeys = $null; $wfpWeight = [uint16]0; $targetContainerSid = $null
$l1 = $null; $l1Receipt = $null; $l1Stop = $null; $assemblyLoaded = $false
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
    if (Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA') {
        Get-Process -Name 'StudioALayer1Psec','StudioALayer2Host' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        Remove-Item -LiteralPath 'C:\Users\ClaudeStudioLabA' -Recurse -Force -ErrorAction SilentlyContinue
    }

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # Capture host baseline metadata (NEVER reads user data contents!)
    $coworkBefore = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceBefore = if ($coworkBefore) { [ordered]@{ state = $coworkBefore.State; pid = [int]$coworkBefore.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclBefore = (Get-Acl -LiteralPath $pkg.InstallLocation).Sddl
    $cRootAclBefore = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostUserProfile = (Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $hostSid + "'") -ErrorAction SilentlyContinue).LocalPath
    $hostRoamingBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataBefore = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }

    # Compile harness + tiny token inspector for observed processes
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $inspCs = Join-Path $base 'ProcTokenInspect.cs'
    [IO.File]::WriteAllText($inspCs, @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Automation;
public static class ProcTokenInspector {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int req);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    delegate bool EnumWinProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWinProc cb, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hwnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr OpenDesktopW(string name, uint flags, bool inh, uint acc);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr hDesk);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr hDesk);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr hDesk, EnumWinProc cb, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr hwndParent, EnumWinProc cb, IntPtr lParam);
    public static List<Dictionary<string, object>> ListPidWindows(int targetPid) {
        var list = new List<Dictionary<string, object>>();
        var th = new System.Threading.Thread(() => {
            IntPtr hDesk = OpenDesktopW("Default", 0, false, 0x0041 | 0x0080 /* DESKTOP_READOBJECTS | ENUMERATE | WRITEOBJECTS */);
            try {
                if (hDesk != IntPtr.Zero) SetThreadDesktop(hDesk);
                EnumWinProc cb = (h, lp) => {
                    uint p = 0; GetWindowThreadProcessId(h, out p);
                    if ((int)p == targetPid) {
                        var tb = new System.Text.StringBuilder(512); GetWindowTextW(h, tb, 512);
                        var cb2 = new System.Text.StringBuilder(128); GetClassNameW(h, cb2, 128);
                        var childTexts = new List<string>();
                        if (cb2.ToString() == "#32770") {
                            try {
                                var ae = AutomationElement.FromHandle(h);
                                if (ae != null) {
                                    var all = ae.FindAll(TreeScope.Descendants, Condition.TrueCondition);
                                    for (int i = 0; i < all.Count; i++) {
                                        string nm = (all[i].Current.Name ?? "").Trim();
                                        if (nm.Length > 0 && !childTexts.Contains(nm)) childTexts.Add(nm);
                                    }
                                }
                            } catch { }
                            EnumChildWindows(h, (ch, clp) => {
                                var ctb = new System.Text.StringBuilder(1024); GetWindowTextW(ch, ctb, 1024);
                                string s = ctb.ToString().Trim();
                                if (s.Length > 0 && !childTexts.Contains(s)) childTexts.Add(s);
                                return true;
                            }, IntPtr.Zero);
                        }
                        list.Add(new Dictionary<string, object> {
                            { "hwnd", h.ToInt64() }, { "visible", IsWindowVisible(h) },
                            { "className", cb2.ToString() }, { "title", tb.ToString() },
                            { "dialogText", string.Join(" | ", childTexts.ToArray()) }
                        });
                    }
                    return true;
                };
                if (hDesk != IntPtr.Zero) EnumDesktopWindows(hDesk, cb, IntPtr.Zero);
                else EnumWindows(cb, IntPtr.Zero);
            } finally { if (hDesk != IntPtr.Zero) CloseDesktop(hDesk); }
        });
        th.SetApartmentState(System.Threading.ApartmentState.STA);
        th.Start();
        th.Join(3000);
        return list;
    }
    public static Dictionary<string, object> ReadPidToken(int pid) {
        var d = new Dictionary<string, object> { { "pid", pid }, { "ok", false } };
        IntPtr p = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (p == IntPtr.Zero) { d["error"] = Marshal.GetLastWin32Error(); return d; }
        IntPtr t = IntPtr.Zero;
        try {
            if (!OpenProcessToken(p, 0x0008 /* TOKEN_QUERY */, out t)) { d["error"] = Marshal.GetLastWin32Error(); return d; }
            int req = 0;
            GetTokenInformation(t, 1 /* TokenUser */, IntPtr.Zero, 0, out req);
            if (req > 0) {
                IntPtr b = Marshal.AllocHGlobal(req);
                try { if (GetTokenInformation(t, 1, b, req, out req)) d["userSid"] = new SecurityIdentifier(Marshal.ReadIntPtr(b)).Value; } finally { Marshal.FreeHGlobal(b); }
            }
            req = 0; GetTokenInformation(t, 29 /* TokenIsAppContainer */, IntPtr.Zero, 0, out req);
            if (req >= 4) {
                IntPtr b = Marshal.AllocHGlobal(req);
                try { if (GetTokenInformation(t, 29, b, req, out req)) d["isAppContainer"] = (Marshal.ReadInt32(b) != 0); } finally { Marshal.FreeHGlobal(b); }
            }
            req = 0; GetTokenInformation(t, 31 /* TokenAppContainerSid */, IntPtr.Zero, 0, out req);
            if (req >= IntPtr.Size) {
                IntPtr b = Marshal.AllocHGlobal(req);
                try {
                    if (GetTokenInformation(t, 31, b, req, out req)) {
                        IntPtr s = Marshal.ReadIntPtr(b);
                        d["containerSid"] = (s == IntPtr.Zero) ? null : new SecurityIdentifier(s).Value;
                    }
                } finally { Marshal.FreeHGlobal(b); }
            }
            d["ok"] = true;
            return d;
        } finally {
            if (t != IntPtr.Zero) CloseHandle(t);
            CloseHandle(p);
        }
    }
}
'@, (New-Object Text.UTF8Encoding($false)))

    $wpfDir = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\WPF'
    $cOut = & $csc /nologo /platform:x64 /target:library /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/reference:$(Join-Path $wpfDir 'UIAutomationClient.dll')" "/reference:$(Join-Path $wpfDir 'UIAutomationTypes.dll')" "/out:$harnessDll" `
        $inspCs (Join-Path $fixtureDir 'DesktopRead.cs') (Join-Path $fixtureDir 'PsecStartupGuard.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Harness compile failed: ' + ($cOut -join '; ')) }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($harnessDll))
    $assemblyLoaded = $true

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # Create temporary standard user ClaudeStudioLabA
    $pw = New-RandomStrongPassword
    $u = New-LocalUser -Name 'ClaudeStudioLabA' -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A Real Claude Offline Smoke'
    $accountCreated = $true; $accountSid = $u.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
    $origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken('ClaudeStudioLabA', $env:COMPUTERNAME, $pw)
    $loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($origToken, 'ClaudeStudioLabA')
    $copyToken = [StudioPsecGuardHost]::DuplicateHardened($origToken, $hostSid)

    $aHome = 'C:\Users\ClaudeStudioLabA'
    $aLocal = 'C:\Users\ClaudeStudioLabA\AppData\Local'
    $aRoam = 'C:\Users\ClaudeStudioLabA\AppData\Roaming'
    $aWorkRoot = Join-Path (Join-Path $aLocal 'Temp') $tag
    $sealed = Join-Path $aWorkRoot 'sealed'
    $stagedApp = Join-Path $sealed 'claude-app'
    $scratch = Join-Path $aWorkRoot 'scratch'
    $userDataDir = Join-Path $aWorkRoot 'userdata'
    $claudeDataDir = Join-Path $aLocal 'Claude-Data'
    $claude3pDir = Join-Path $aLocal 'Claude-3p'
    $claudeLocalDir = Join-Path $aLocal 'Claude'
    $claudeLogsDir = Join-Path $claudeLocalDir 'logs'
    $roamingClaudeDir = Join-Path $aRoam 'Claude'

    $rxAcl = New-PrivateAcl $hostSid; $rwAcl = New-PrivateAcl $hostSid
    foreach ($s in @($accountSid, 'S-1-15-2-1')) {
        $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($aWorkRoot, $rxAcl)
    [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)
    [void][IO.Directory]::CreateDirectory($stagedApp, $rxAcl)
    foreach ($d in @($scratch, $userDataDir, $claudeDataDir, $claude3pDir, $claudeLocalDir, $claudeLogsDir, $roamingClaudeDir)) { [void][IO.Directory]::CreateDirectory($d, $rwAcl) }

    # Copy official app\ read-only into temp stagedApp (ZERO changes to WindowsApps!)
    Write-Stage 'robocopy-start'
    $null = & robocopy.exe $srcAppDir $stagedApp /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS
    if ($LASTEXITCODE -ge 8) { throw "robocopy app failed with exit code $LASTEXITCODE" }
    Write-Stage 'robocopy-done'
    $stagedClaudeExe = Join-Path $stagedApp 'claude.exe'
    if (!(Test-Path -LiteralPath $stagedClaudeExe)) { throw 'Missing staged claude.exe' }

    # Compile Layer-1 + pure-C Layer-2 host (captures stdout/stderr + exit code of real claude.exe)
    $l1Exe = Join-Path $sealed 'StudioALayer1Psec.exe'
    $l2HostC = Join-Path $base 'l2_claude_host.c'
    $l2Exe = Join-Path $sealed 'StudioALayer2Host.exe'
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
    wchar_t exePath[512] = L"", cmdLine[1536] = L"", logPath[512] = L"", statusPath[512] = L"", stopPath[512] = L"";
    wchar_t homeDir[512] = L"", localDir[512] = L"", roamDir[512] = L"", tmpDir[512] = L"";
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        if (line[0] == 'e' && line[1] == '=') ToWide(line + 2, exePath, 512);
        else if (line[0] == 'a' && line[1] == '=') ToWide(line + 2, cmdLine, 1536);
        else if (line[0] == 'l' && line[1] == '=') ToWide(line + 2, logPath, 512);
        else if (line[0] == 'r' && line[1] == '=') ToWide(line + 2, statusPath, 512);
        else if (line[0] == 's' && line[1] == '=') ToWide(line + 2, stopPath, 512);
        else if (line[0] == 'h' && line[1] == '=') ToWide(line + 2, homeDir, 512);
        else if (line[0] == 'L' && line[1] == '=') ToWide(line + 2, localDir, 512);
        else if (line[0] == 'R' && line[1] == '=') ToWide(line + 2, roamDir, 512);
        else if (line[0] == 'T' && line[1] == '=') ToWide(line + 2, tmpDir, 512);
    }
    if (homeDir[0]) { SetEnvironmentVariableW(L"USERPROFILE", homeDir); SetEnvironmentVariableW(L"HOME", homeDir); }
    if (localDir[0]) SetEnvironmentVariableW(L"LOCALAPPDATA", localDir);
    if (roamDir[0]) SetEnvironmentVariableW(L"APPDATA", roamDir);
    if (tmpDir[0]) { SetEnvironmentVariableW(L"TEMP", tmpDir); SetEnvironmentVariableW(L"TMP", tmpDir); }
    SetEnvironmentVariableW(L"USERNAME", L"ClaudeStudioLabA");
    SetEnvironmentVariableW(L"ELECTRON_ENABLE_LOGGING", L"1");
    SetEnvironmentVariableW(L"ELECTRON_ENABLE_STACK_DUMPING", L"1");
    SetEnvironmentVariableW(L"HTTP_PROXY", L"http://127.0.0.1:59999");
    SetEnvironmentVariableW(L"HTTPS_PROXY", L"http://127.0.0.1:59999");
    SetEnvironmentVariableW(L"LANG", L"zh_CN.UTF-8");
    SetEnvironmentVariableW(L"TZ", L"Asia/Shanghai");
    SECURITY_ATTRIBUTES sa; sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    HANDLE hLog = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (hLog != INVALID_HANDLE_VALUE) { si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = hLog; si.hStdError = hLog; }
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    DWORD err = 0;
    BOOL ok = CreateProcessW(exePath, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!ok) err = GetLastError();
    if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);

    DWORD waitedMs = 0;
    BOOL exitedEarly = FALSE;
    DWORD exitCode = 0xFFFFFFFF;
    if (ok) {
        while (waitedMs < 20000) {
            if (GetFileAttributesW(stopPath) != INVALID_FILE_ATTRIBUTES) break;
            if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) {
                exitedEarly = TRUE;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                break;
            }
            waitedMs += 200;
        }
        if (!exitedEarly) {
            GetExitCodeProcess(pi.hProcess, &exitCode);
            TerminateProcess(pi.hProcess, 0);
            WaitForSingleObject(pi.hProcess, 3000);
        }
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    char out[512]; int opos = 0;
    const char* s1 = "{\"launched\":"; while (*s1) out[opos++] = *s1++;
    const char* sb1 = ok ? "true" : "false"; while (*sb1) out[opos++] = *sb1++;
    const char* s2 = ",\"createErr\":"; while (*s2) out[opos++] = *s2++;
    { char t[16]; int n = 0; unsigned long v = (unsigned long)err; if (!v) t[n++] = '0'; else while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (n) out[opos++] = t[--n]; }
    const char* s3 = ",\"claudePid\":"; while (*s3) out[opos++] = *s3++;
    { char t[16]; int n = 0; unsigned long v = (unsigned long)pi.dwProcessId; if (!v) t[n++] = '0'; else while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (n) out[opos++] = t[--n]; }
    const char* s4 = ",\"exitedEarly\":"; while (*s4) out[opos++] = *s4++;
    const char* sb2 = exitedEarly ? "true" : "false"; while (*sb2) out[opos++] = *sb2++;
    const char* s5 = ",\"exitCode\":"; while (*s5) out[opos++] = *s5++;
    { char t[16]; int n = 0; unsigned long v = (unsigned long)exitCode; if (!v) t[n++] = '0'; else while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (n) out[opos++] = t[--n]; }
    const char* s6 = ",\"waitedMs\":"; while (*s6) out[opos++] = *s6++;
    { char t[16]; int n = 0; unsigned long v = (unsigned long)waitedMs; if (!v) t[n++] = '0'; else while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (n) out[opos++] = t[--n]; }
    out[opos++] = '}'; out[opos] = '\0';
    HANDLE sf = CreateFileW(statusPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (sf != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(sf, out, (DWORD)opos, &w, NULL); CloseHandle(sf); }
    return 0;
}
'@
    [IO.File]::WriteAllText($l2HostC, $l2Code, (New-Object Text.UTF8Encoding($false)))
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $clOut = & cmd.exe /c ('call "' + $vcvars + '" >nul && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l1Exe + '" kernel32.lib advapi32.lib && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2.obj') + '" "' + $l2HostC + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l2Exe + '" kernel32.lib') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native build failed: ' + ($clOut -join '; ')) }

    # Grant LabA's own AppData RW + PSEC in-kernel fs_enumerate on ancestor path components for Node.js fs.realpathSync(lstat 'C:\') (zero disk ACL change!)
    $psecBin = Join-Path $sealed 'psec-real-claude.bin'
    $enumAncestors = [string[]]@('C:\', 'C:\Users', 'C:\Users\ClaudeStudioLabA', 'C:\Users\ClaudeStudioLabA\AppData', 'C:\Users\ClaudeStudioLabA\AppData\Local', 'C:\Users\ClaudeStudioLabA\AppData\Local\Temp')
    $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Full(
        [string[]]@($scratch, $userDataDir, $claudeDataDir, $claude3pDir, $claudeLocalDir, $claudeLogsDir, $roamingClaudeDir, $aRoam),
        [string[]]@($sealed), $enumAncestors, $false)
    [IO.File]::WriteAllBytes($psecBin, $psecBytes)

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener

    # Start DNS ETW trace at level 4 (Informational — captures all 3006/3010/3011 without level-5 verbose flood)
    $dnsPidBefore = Get-LabDnsServicePid
    $lmRes = & logman.exe create trace $etlName -o $etlFile -p 'Microsoft-Windows-DNS-Client' 0xffffffffffffffff 4 -ets 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('DNS ETW start failed: ' + ($lmRes -join ' ')) }
    $etlStarted = $true
    $null = Test-HostHealth 'baseline' 41

    # Prepare Layer-2 bridge config for real claude.exe (offline proxy 127.0.0.1:59999, isolated user-data-dir, zh-CN)
    $readyPath = Join-Path $scratch 'l1-ready.json'
    $l1Stop = Join-Path $scratch 'l1-stop'
    $l2Stop = Join-Path $scratch 'l2-stop'
    $l2StatusPath = Join-Path $scratch 'l2-status.json'
    $claudeOutLog = Join-Path $scratch 'claude-stdio.log'
    $claudeChromeLog = Join-Path $scratch 'chrome-debug.log'
    $sandboxArg = if ($NoChromiumSandbox) { " --no-sandbox --disable-gpu-sandbox --disable-gpu --enable-logging --log-file=`"$claudeChromeLog`" --v=1" } else { " --enable-logging --log-file=`"$claudeChromeLog`" --v=1" }
    $claudeCmdLine = "`"$stagedClaudeExe`" --user-data-dir=`"$userDataDir`" --proxy-server=`"http://127.0.0.1:59999`" --lang=zh-CN$sandboxArg"
    $l2CfgPath = Join-Path $sealed 'l2-claude.cfg'
    [IO.File]::WriteAllText($l2CfgPath, ("e=$stagedClaudeExe`na=$claudeCmdLine`nl=$claudeOutLog`nr=$l2StatusPath`ns=$l2Stop`nh=$aHome`nL=$aLocal`nR=$aRoam`nT=$scratch`n"), (New-Object Text.UTF8Encoding($false)))

    $l1Args = "`"$psecBin`" `"$l2Exe`" `"$l2CfgPath`" `"$scratch`" `"$hostSid`" `"$readyPath`" `"$l1Stop`""
    $l1 = [StudioPsecGuardHost]::StartSuspended($copyToken, $l1Exe, $l1Args, $true, 'WinSta0\Default')
    $null = $l1.RestoreTokenObjectDaclOnly($origToken, $hostSid, $accountSid)
    Write-Stage 'l1-resume'
    [void]$l1.ResumeMainThread()

    # Wait up to 45s because CreateProcessSecurityEnvironment recursively stamps container SID on staged Electron app files
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $readyPath) -and $sw.ElapsedMilliseconds -lt 45000) { Start-Sleep -Milliseconds 50 }
    if (!(Test-Path -LiteralPath $readyPath)) { throw 'Layer-1 did not write ready receipt within 45s' }
    Write-Stage 'l1-ready'
    $l1Receipt = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.l1Receipt = $l1Receipt
    if (!$l1Receipt.psecCreated -or !$l1Receipt.childCreated) { throw ("Layer-1 PSEC/child failed: " + ($l1Receipt | ConvertTo-Json -Compress)) }
    $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$l1Receipt.childPid, [int]$l1Receipt.childTid, $hostSid, $accountSid)
    $targetContainerSid = $insp.identity.containerSid
    [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$l1Receipt.childPid, $hostSid, $targetContainerSid)
    [void]$observedPidSet.Add([int]$l1Receipt.layer1Pid)
    [void]$observedPidSet.Add([int]$l1Receipt.childPid)

    # Install 4 Static BLOCK WFP BEFORE ResumeThread (ZERO proxy exception!)
    $wfpSub = [guid]::NewGuid()
    $wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
    $g = [StudioLabWfp]::CreateStaticGuard()
    try {
        $wfpWeight = $g.PrepareStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $l2Exe)
        $g.InstallStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $l2Exe, $wfpWeight)
        $wfpInstalled = $true
    } finally { $g.Dispose() }
    $null = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $wfpWeight, $false)

    Write-Stage 'l2-resume-and-sample'
    $null = [StudioPsecGuardHost]::HostResumeChildOnly([int]$l1Receipt.childPid, [int]$l1Receipt.childTid)
    $null = Test-HostHealth 'blocked' 51

    # Sample running Claude processes under ClaudeStudioLabA for 10 seconds
    $seenMap = @{}
    for ($tick = 0; $tick -lt 20; $tick++) {
        Start-Sleep -Milliseconds 500
        $procs = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%' OR Name LIKE '%StudioA%'" -ErrorAction SilentlyContinue
        foreach ($pr in $procs) {
            $pidInt = [int]$pr.ProcessId
            $tok = [ProcTokenInspector]::ReadPidToken($pidInt)
            if ($tok.ok -and $tok['userSid'] -ceq $accountSid) {
                [void]$observedPidSet.Add($pidInt)
                $gp = Get-Process -Id $pidInt -ErrorAction SilentlyContinue
                $title = if ($gp) { $gp.MainWindowTitle } else { '' }
                $hwnd = if ($gp) { [int64]$gp.MainWindowHandle } else { 0 }
                $wsMb = if ($gp) { [math]::Round($gp.WorkingSet64 / 1MB, 1) } else { 0 }
                $cpuMs = if ($gp) { try { [math]::Round($gp.TotalProcessorTime.TotalMilliseconds, 0) } catch { -1 } } else { -1 }
                $thCnt = if ($gp) { $gp.Threads.Count } else { 0 }
                $waitReasons = if ($gp) { try { @($gp.Threads | Where-Object { $_.ThreadState -eq 'Wait' } | Group-Object WaitReason | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ',' } catch { '' } } else { '' }
                $wins = [ProcTokenInspector]::ListPidWindows($pidInt)
                $typeArg = ''
                if ($pr.CommandLine -match '--type=([a-zA-Z0-9_-]+)') { $typeArg = $Matches[1] }
                $seenMap["$pidInt"] = [ordered]@{
                    pid = $pidInt; name = $pr.Name; chromiumType = $typeArg
                    isAppContainer = $tok['isAppContainer']; sameContainerSid = ($tok['containerSid'] -ceq $targetContainerSid)
                    windowHandle = $hwnd; windowTitle = $title; allWindows = $wins
                    workingSetMB = $wsMb; cpuMs = $cpuMs; threads = $thCnt; waitReasons = $waitReasons
                }
            }
        }
        if (Test-Path -LiteralPath $l2StatusPath) { break }
    }

    Write-Stage ("sampling-done seen=" + $seenMap.Count)
    # Signal clean stop & wait for Layer-2 status
    [IO.File]::WriteAllText($l2Stop, 'stop')
    $sw.Restart()
    while (!(Test-Path -LiteralPath $l2StatusPath) -and $sw.ElapsedMilliseconds -lt 6000) { Start-Sleep -Milliseconds 50 }
    Write-Stage ("l2-status-exists=" + (Test-Path -LiteralPath $l2StatusPath))
    if (Test-Path -LiteralPath $l2StatusPath) {
        $report.l2Status = Get-Content -LiteralPath $l2StatusPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    if (Test-Path -LiteralPath $claudeOutLog) {
        $rawLog = [IO.File]::ReadAllText($claudeOutLog, [Text.Encoding]::UTF8)
        if ($rawLog -and $rawLog.Length -gt 3000) { $rawLog = $rawLog.Substring(0, 3000) + '...(truncated)' }
        $report.claudeStdioSnippet = [string]$rawLog
    }
    if (Test-Path -LiteralPath $claudeChromeLog) {
        $rawChrome = [IO.File]::ReadAllText($claudeChromeLog, [Text.Encoding]::UTF8)
        if ($rawChrome -and $rawChrome.Length -gt 3500) { $rawChrome = $rawChrome.Substring(0, 3500) + '...(truncated)' }
        $report.claudeChromeLogSnippet = [string]$rawChrome
    }
    $report.observedProcesses = @($seenMap.Keys | ForEach-Object { $seenMap[$_] })
    $report.claudeDataFilesCreated = @(Get-ChildItem -LiteralPath $userDataDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 25 | ForEach-Object { $_.FullName.Replace($userDataDir, '<userData>') })
    $report.claudeAnyProfileFilesCreated = @(Get-ChildItem -LiteralPath $aLocal -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "$sealed*" -and $_.FullName -notlike "$scratch*" } | Select-Object -First 25 | ForEach-Object { $_.FullName.Replace($aLocal, '<LocalAppData>') })
    $report.claudeLogFilesCreated = @(Get-ChildItem -LiteralPath $claudeLogsDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { $_.Name })

    # Check CoworkVMService & host folders after run
    $coworkAfter = Get-CimInstance Win32_Service -Filter "Name='CoworkVMService'" -ErrorAction SilentlyContinue
    $report.coworkServiceAfter = if ($coworkAfter) { [ordered]@{ state = $coworkAfter.State; pid = [int]$coworkAfter.ProcessId } } else { [ordered]@{ state = 'Absent'; pid = 0 } }
    $winAppsAclAfter = (Get-Acl -LiteralPath $pkg.InstallLocation).Sddl
    $cRootAclAfter = (Get-Acl -LiteralPath 'C:\').Sddl
    $hostRoamingAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Roaming\Claude') } else { $null }
    $hostLocalDataAfter = if ($hostUserProfile) { Get-DirMeta (Join-Path $hostUserProfile 'AppData\Local\Claude-Data') } else { $null }

    $claudeProcs = @($report.observedProcesses | Where-Object { $_.name -imatch 'claude' })
    $allClaudeInSamePsec = ($claudeProcs.Count -ge 1) -and (@($claudeProcs | Where-Object { !$_.isAppContainer -or !$_.sameContainerSid }).Count -eq 0)
    $anyWindowVisible = (@($claudeProcs | Where-Object { (@($_.allWindows | Where-Object { $_.visible -and $_.className -cne '#32770' }).Count -gt 0) }).Count -ge 1)

    $report.checks.claudeLaunchedAndContained = $allClaudeInSamePsec
    $report.checks.claudeWindowCreated = $anyWindowVisible
    $report.checks.coworkServiceUntriggered = ($report.coworkServiceBefore.state -ceq $report.coworkServiceAfter.state) -and ($report.coworkServiceBefore.pid -eq $report.coworkServiceAfter.pid)
    $report.checks.hostClaudeUnchanged = ($winAppsAclBefore -ceq $winAppsAclAfter) -and ($cRootAclBefore -ceq $cRootAclAfter) -and
        (($hostRoamingBefore | ConvertTo-Json -Compress) -ceq ($hostRoamingAfter | ConvertTo-Json -Compress)) -and
        (($hostLocalDataBefore | ConvertTo-Json -Compress) -ceq ($hostLocalDataAfter | ConvertTo-Json -Compress))
} catch {
    $report.error = $_.Exception.Message
    Write-Stage ("try-catch-err=" + $_.Exception.Message)
} finally {
    Write-Stage 'finally-start'
    if ($l1Stop -and $scratch -and (Test-Path -LiteralPath $scratch)) { try { [IO.File]::WriteAllText($l1Stop, 'stop') } catch { } }
    if ($l1Receipt -and $l1Receipt.childPid) { try { [StudioPsecGuardHost]::HostTerminatePid([int]$l1Receipt.childPid) } catch { } }
    if ($l1) { try { [StudioPsecGuardHost]::HostTerminatePid($l1.Pid) } catch { } ; try { [void]$l1.WaitExit(2500); $l1.Dispose() } catch { } }
    # Terminate any remaining LabA processes cleanly (including Layer-1/Layer-2/Claude children)
    if ($accountSid -and $assemblyLoaded) {
        try {
            $rem = Get-CimInstance Win32_Process -Filter "Name LIKE '%claude%' OR Name LIKE '%StudioA%'" -ErrorAction SilentlyContinue
            foreach ($pr in $rem) {
                $tk = [ProcTokenInspector]::ReadPidToken([int]$pr.ProcessId)
                if ($tk.ok -and $tk['userSid'] -ceq $accountSid) {
                    try { Stop-Process -Id ([int]$pr.ProcessId) -Force -ErrorAction SilentlyContinue } catch { }
                }
            }
        } catch { }
    }
    Start-Sleep -Milliseconds 400

    if ($wfpInstalled -and $assemblyLoaded) {
        try {
            [StudioLabWfp]::RemoveStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $wfpWeight)
            Start-Sleep -Milliseconds 80
            $res = [StudioLabWfp]::CountFiltersReferencingPackage($targetContainerSid)
            $report.cleanup.residualPackageFilters = $res
            $report.cleanup.wfpRemovedAndVerifiedAbsent = ($res -eq 0)
        } catch { $report.cleanup.errors += @("wfp: $($_.Exception.Message)"); $report.cleanup.wfpRemovedAndVerifiedAbsent = $false }
    } else { $report.cleanup.wfpRemovedAndVerifiedAbsent = $true }

    Write-Stage 'wfp-done'
    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { } }
    Write-Stage 'dns-stop-start'

    # Stop DNS ETW & inspect BOTH canary events AND any real-domain DNS wire send from observed ClaudeStudioLabA PIDs!
    if ($etlStarted) {
        try {
            $loss = Get-LabDnsTraceLoss $etlName
            $null = & logman.exe stop $etlName -ets 2>&1
            $dnsPidAfter = Get-LabDnsServicePid
            $hostSends = 0; $labPidDnsSends = 0; $labPidDnsAttempts = 0; $coworkDnsSends = 0
            $coworkPid = if ($report.coworkServiceAfter -and $report.coworkServiceAfter.pid -gt 0) { [int]$report.coworkServiceAfter.pid } else { -1 }
            foreach ($ev in (Get-WinEvent -FilterHashtable @{ Path = $etlFile; Id = 3006,3010,3011 } -Oldest -ErrorAction SilentlyContinue)) {
                if ($ev.Id -notin 3006,3010,3011 -or !$ev.Properties.Count) { continue }
                $qName = [string]$ev.Properties[0].Value
                $clientPid = -1
                if ($ev.Id -eq 3010 -and $ev.Properties.Count -gt 3) { $clientPid = [int]$ev.Properties[3].Value }
                elseif ($ev.Id -eq 3011 -and $ev.Properties.Count -gt 4) { $clientPid = [int]$ev.Properties[4].Value }
                elseif ($ev.Id -eq 3006) { $clientPid = [int]$ev.ProcessId }

                if ($ev.Id -eq 3010 -and $qName.StartsWith($prefix + '-host-', [StringComparison]::OrdinalIgnoreCase)) { $hostSends++ }
                if ($observedPidSet.Contains($clientPid)) {
                    if ($ev.Id -eq 3006) { $labPidDnsAttempts++ }
                    elseif ($ev.Id -in 3010,3011) { $labPidDnsSends++ }
                }
                if ($coworkPid -gt 0 -and $clientPid -eq $coworkPid -and ($ev.Id -in 3010,3011)) { $coworkDnsSends++ }
            }
            if (Test-Path -LiteralPath $etlFile) { Remove-Item -LiteralPath $etlFile -Force }
            $lZero = ($loss.eventsLost -eq 0) -and ($loss.logBuffersLost -eq 0) -and ($loss.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{
                servicePidStable = ($dnsPidBefore -eq $dnsPidAfter); lossZero = $lZero
                hostCanarySends = $hostSends; observedLabPidCount = $observedPidSet.Count
                labPidDnsApiAttempts = $labPidDnsAttempts; labPidDnsWireSendsOrReplies = $labPidDnsSends
                coworkServiceDnsWireSends = $coworkDnsSends
            }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($labPidDnsSends -eq 0) -and ($coworkDnsSends -eq 0) -and ($hostSends -ge 3)
        } catch { $report.checks.dnsZeroLeak = $false; $report.cleanup.errors += @("dns: $($_.Exception.Message)") }
    }
    Write-Stage 'dns-done'
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
        try { [StudioPsecGuardHost]::UnloadLabProfile($origToken, $loadedProfileHandle) } catch { }
        foreach ($tk in @($copyToken, $origToken)) { if ($tk -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($tk) } catch { } } }
    }

    if ($accountCreated) {
        try { if ($accountSid) { $pr = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $accountSid + "'") -ErrorAction SilentlyContinue; if ($pr) { Remove-CimInstance -InputObject $pr -ErrorAction Stop } } } catch { $report.cleanup.errors += @("prof: $($_.Exception.Message)") }
        try { if (Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA') { Remove-Item -LiteralPath 'C:\Users\ClaudeStudioLabA' -Recurse -Force -ErrorAction Stop } } catch { $report.cleanup.errors += @("profDir: $($_.Exception.Message)") }
        try { Remove-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction Stop } catch { $report.cleanup.errors += @("user: $($_.Exception.Message)") }
    }
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    Write-Stage 'cleanup-done-writing-report'
    try {
        $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
        $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
        $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')

        $hOk = $true
        foreach ($st in @('baseline','blocked','restored')) { $h = $report.hostHealth[$st]; if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hOk = $false } }
        $report.checks.hostContinuous = $hOk
        $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and
            $report.cleanup.directoryGone -and $report.cleanup.labAGone -and $report.cleanup.labAProfileDirGone

        $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 8)
        $report.outcome = if ($allOk) { 'passed-a-real-claude-offline-smoke' } else { 'diagnostic-a-real-claude-offline-smoke' }
        $report.utcFinished = [datetime]::UtcNow.ToString('o')

        [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
        $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
        [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
            runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
            noChromiumSandbox = $report.noChromiumSandbox; officialPackage = $report.officialPackage
            l2Status = $report.l2Status; observedProcesses = $report.observedProcesses
            claudeDataFileCount = @($report.claudeDataFilesCreated).Count; claudeLogFilesCreated = $report.claudeLogFilesCreated
            claudeAnyProfileFilesCreated = $report.claudeAnyProfileFilesCreated
            claudeStdioSnippet = $report.claudeStdioSnippet; claudeChromeLogSnippet = $report.claudeChromeLogSnippet
            coworkServiceBefore = $report.coworkServiceBefore; coworkServiceAfter = $report.coworkServiceAfter
            checks = $report.checks; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
        } | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
        Write-Stage 'summary-written'
        try { if (Test-Path -LiteralPath $traceLog) { Remove-Item -LiteralPath $traceLog -Force } } catch { }
    } catch {
        Write-Stage ("FINAL_WRITE_ERR: " + $_.Exception.ToString())
    }
}
