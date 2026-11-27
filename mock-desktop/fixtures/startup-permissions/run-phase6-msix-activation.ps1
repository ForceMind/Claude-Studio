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

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    $ReportPath = Join-Path $reportDir ("windows-a-phase6b-msix-activation-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeStudioPhase6B-summary-$RunId.json")
    if ($isAdmin) {
        & $PSCommandPath -Elevated -RunId $RunId -ReportPath $ReportPath -SummaryPath $SummaryPath
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -RunId "' + $RunId + '" -ReportPath "' + $ReportPath + '" -SummaryPath "' + $SummaryPath + '"'
        $proc = Start-Process -FilePath $psExe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argLine
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (!(Test-Path -LiteralPath $SummaryPath) -and !$proc.HasExited -and $sw.ElapsedMilliseconds -lt 180000) { Start-Sleep -Milliseconds 100 }
        if (!$proc.HasExited) { [void]$proc.WaitForExit(3000) }
        if ($proc.HasExited -and $proc.ExitCode -ne 0 -and !(Test-Path -LiteralPath $SummaryPath)) { throw "Elevated runner exited $($proc.ExitCode)" }
    }
    $txt = Get-Content -LiteralPath $SummaryPath -Raw -Encoding UTF8
    Remove-Item -LiteralPath $SummaryPath -Force
    Write-Output $txt
    return
}

$fixtureDir = $PSScriptRoot
$mockDesktopDir = Split-Path (Split-Path $fixtureDir -Parent) -Parent
$repoRoot = Split-Path $mockDesktopDir -Parent
. (Join-Path $mockDesktopDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDesktopDir 'windows-lab-bind-gate.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeStudioPhase6B-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$harnessDll = Join-Path $base 'StudioPhase6BHarness.dll'
$loopbackCapSid = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-a-phase6b-msix-activation'
    msixBuild = $null; receipts = @(); hostHealth = [ordered]@{}; checks = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @() }
}

$dirCreated = $false; $msixBuildDir = $null; $accountCreated = $false; $accountSid = $null
$origToken = [IntPtr]::Zero; $copyToken = [IntPtr]::Zero; $loadedProfileHandle = [IntPtr]::Zero
$aWorkRoot = $null; $hostListener = $null; $hostOld = $null; $dnsTrace = $null
$wfpInstalled = $false; $wfpSub = [guid]::Empty; $wfpKeys = $null; $wfpWeight = [uint16]0; $targetContainerSid = $null
$l1 = $null; $l1Receipt = $null; $l1Stop = $null; $assemblyLoaded = $false

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

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true

    # 1. Build & offline-sign synthetic MSIX (ZERO trust-store / package-registry modifications!)
    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $msixBuildScript = Join-Path $mockDesktopDir 'n4-activation-mock\build.ps1'
    $msixJson = & $pwsh -NoProfile -NonInteractive -Command "& '$msixBuildScript' -SignForTest | ConvertTo-Json -Compress"
    if ($LASTEXITCODE -ne 0) { throw "Signed MSIX build failed: $msixJson" }
    $msixInfo = $msixJson | ConvertFrom-Json
    $msixBuildDir = Split-Path $msixInfo.path -Parent
    $sig = Get-AuthenticodeSignature -LiteralPath $msixInfo.path
    $report.msixBuild = [ordered]@{
        name = $msixInfo.name; version = $msixInfo.packageVersion; sha256Prefix12 = $msixInfo.sha256.Substring(0, 12)
        thumbprint = $msixInfo.thumbprint; signerMatches = ($sig.SignerCertificate.Thumbprint -ceq $msixInfo.thumbprint)
        trustStoreModified = $false; globalAppxRegistered = $false
    }
    $report.checks.signedMsixBuiltOffline = (Test-Path -LiteralPath $msixInfo.path) -and $report.msixBuild.signerMatches

    # 2. Compile harness DLL + native Layer-1 PSEC launcher + small native MSIX runner inside Layer-2
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $cOut = & $csc /nologo /platform:x64 /target:library /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$harnessDll" `
        (Join-Path $fixtureDir 'DesktopRead.cs') (Join-Path $fixtureDir 'PsecStartupGuard.cs') `
        (Join-Path $mockDesktopDir 'windows-lab-n4-preflight.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp.cs') (Join-Path $mockDesktopDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Harness compile failed: ' + ($cOut -join '; ')) }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($harnessDll))
    $assemblyLoaded = $true

    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # 3. Create temporary standard user ClaudeStudioLabA & stage unpacked MSIX binaries into A's sealed dir
    $pw = New-RandomStrongPassword
    $u = New-LocalUser -Name 'ClaudeStudioLabA' -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description 'Temp A Phase6B MSIX'
    $accountCreated = $true; $accountSid = $u.SID.Value
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
    $origToken = [StudioPsecGuardHost]::AcquireSeclogonSeedToken('ClaudeStudioLabA', $env:COMPUTERNAME, $pw)
    $loadedProfileHandle = [StudioPsecGuardHost]::LoadLabProfile($origToken, 'ClaudeStudioLabA')
    $copyToken = [StudioPsecGuardHost]::DuplicateHardened($origToken, $hostSid)

    $aLocalApp = 'C:\Users\ClaudeStudioLabA\AppData\Local'
    $aWorkRoot = Join-Path (Join-Path $aLocalApp 'Temp') $tag
    $sealed = Join-Path $aWorkRoot 'sealed'
    $scratch = Join-Path $aWorkRoot 'scratch'
    $msixUnpacked = Join-Path $sealed 'msix-layout'
    $mockOutDir = Join-Path $aLocalApp 'StudioN4ActivationMock'

    $rxAcl = New-PrivateAcl $hostSid; $rwAcl = New-PrivateAcl $hostSid
    foreach ($s in @($accountSid, 'S-1-15-2-1')) {
        $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($aWorkRoot, $rxAcl)
    [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)
    [void][IO.Directory]::CreateDirectory($scratch, $rwAcl)
    [void][IO.Directory]::CreateDirectory($mockOutDir, $rwAcl)

    $makeappx = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe'
    $null = & $makeappx unpack /p $msixInfo.path /d $msixUnpacked /o 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'makeappx unpack failed' }
    $msixAppDir = Join-Path $msixUnpacked 'app'
    $winExe = Join-Path $msixAppDir 'StudioActivationWindow.exe'
    if (!(Test-Path -LiteralPath $winExe)) { throw 'Missing unpacked StudioActivationWindow.exe' }

    # Compile native Layer-1 launcher + tiny native Layer-2 MSIX orchestrator (spawns Window + warm Window + 3 Helpers inside same PSEC!)
    $l1Exe = Join-Path $sealed 'StudioALayer1Psec.exe'
    $l2RunnerC = Join-Path $base 'l2_msix_runner.c'
    $l2Exe = Join-Path $sealed 'StudioAMsixRunner.exe'
    $runnerCode = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void ToWide(const char* s, wchar_t* d, int cap) { MultiByteToWideChar(CP_UTF8, 0, s, -1, d, cap); }
static int ParseArgs(wchar_t a[4][512]) {
    const wchar_t* p = GetCommandLineW(); int idx = 0;
    while (*p && idx < 5) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        int n = 0;
        if (*p == L'"') { p++; while (*p && *p != L'"' && n < 511) a[idx][n++] = *p++; if (*p == L'"') p++; }
        else { while (*p && *p != L' ' && *p != L'\t' && n < 511) a[idx][n++] = *p++; }
        a[idx][n] = L'\0'; idx++;
    }
    return idx;
}
static void JoinPathW(wchar_t* dst, int cap, const wchar_t* dir, const wchar_t* leaf) {
    int i = 0; while (dir[i] && i < cap - 2) { dst[i] = dir[i]; i++; }
    dst[i++] = L'\\';
    int j = 0; while (leaf[j] && i < cap - 1) { dst[i++] = leaf[j++]; }
    dst[i] = L'\0';
}
static void AppendStr(char* dst, int cap, const char* s) {
    int i = 0; while (dst[i] && i < cap - 1) i++;
    int j = 0; while (s[j] && i < cap - 1) dst[i++] = s[j++];
    dst[i] = '\0';
}
static void AppendHex(char* dst, int cap, DWORD v) {
    static const char hx[] = "0123456789ABCDEF";
    char b[11] = "0x00000000";
    for (int i = 9; i >= 2; i--) { b[i] = hx[v & 0xF]; v >>= 4; }
    AppendStr(dst, cap, b);
}
static PROCESS_INFORMATION LaunchExe(const wchar_t* path, DWORD* outErr) {
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) *outErr = GetLastError();
    else *outErr = 0;
    return pi;
}
static int ReadRunnerCfg(const wchar_t* cfgPath, wchar_t appDir[512], wchar_t doneFile[512]) {
    appDir[0] = L'\0'; doneFile[0] = L'\0';
    HANDLE f = CreateFileW(cfgPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    char buf[2048]; DWORD got = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &got, NULL);
    CloseHandle(f);
    buf[got] = '\0';
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        if (line[0] == 'a' && line[1] == '=') ToWide(line + 2, appDir, 512);
        else if (line[0] == 'd' && line[1] == '=') ToWide(line + 2, doneFile, 512);
    }
    return appDir[0] != L'\0' && doneFile[0] != L'\0';
}
int WINAPI wWinMain(HINSTANCE h1, HINSTANCE h2, PWSTR c, int s) {
    (void)h1; (void)h2; (void)c; (void)s;
    wchar_t a[4][512];
    if (ParseArgs(a) < 2) return 2;
    wchar_t appDir[512], doneFile[512];
    if (!ReadRunnerCfg(a[1], appDir, doneFile)) return 3;
    wchar_t wWin[600], wH1[600], wH2[600], wHm[600];
    JoinPathW(wWin, 600, appDir, L"StudioActivationWindow.exe");
    JoinPathW(wH1, 600, appDir, L"StudioActivationHelperOne.exe");
    JoinPathW(wH2, 600, appDir, L"StudioActivationHelperTwo.exe");
    JoinPathW(wHm, 600, appDir, L"StudioActivationMediumHelper.exe");

    char log[2048]; log[0] = '\0';
    DWORD eWin = 0, eWarm = 0, e1 = 0, e2 = 0, em = 0;
    // 1. Launch primary MSIX window (holds single-instance mutex!)
    PROCESS_INFORMATION pWin = LaunchExe(wWin, &eWin);
    Sleep(1800);
    // 2. Launch warm second window + all 3 MSIX helpers inside the SAME hardened PSEC container!
    PROCESS_INFORMATION pWarm = LaunchExe(wWin, &eWarm);
    PROCESS_INFORMATION p1 = LaunchExe(wH1, &e1);
    PROCESS_INFORMATION p2 = LaunchExe(wH2, &e2);
    PROCESS_INFORMATION pm = LaunchExe(wHm, &em);

    const char* names[4] = { "warm", "h1", "h2", "hm" };
    DWORD errs[4] = { eWarm, e1, e2, em };
    HANDLE waits[4] = { pWarm.hProcess, p1.hProcess, p2.hProcess, pm.hProcess };
    for (int i = 0; i < 4; i++) {
        DWORD ec = 0xFFFFFFFF;
        if (waits[i]) { WaitForSingleObject(waits[i], 10000); GetExitCodeProcess(waits[i], &ec); CloseHandle(waits[i]); }
        AppendStr(log, sizeof(log), names[i]); AppendStr(log, sizeof(log), ":err="); AppendHex(log, sizeof(log), errs[i]);
        AppendStr(log, sizeof(log), ",rc="); AppendHex(log, sizeof(log), ec); AppendStr(log, sizeof(log), ";");
    }
    if (pWarm.hThread) CloseHandle(pWarm.hThread);
    if (p1.hThread) CloseHandle(p1.hThread);
    if (p2.hThread) CloseHandle(p2.hThread);
    if (pm.hThread) CloseHandle(pm.hThread);

    DWORD winEc = 0xFFFFFFFF;
    if (pWin.hProcess) {
        if (WaitForSingleObject(pWin.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(pWin.hProcess, 0);
            WaitForSingleObject(pWin.hProcess, 3000);
            winEc = 0;
        } else {
            GetExitCodeProcess(pWin.hProcess, &winEc);
        }
        CloseHandle(pWin.hProcess);
    }
    if (pWin.hThread) CloseHandle(pWin.hThread);
    AppendStr(log, sizeof(log), "win:err="); AppendHex(log, sizeof(log), eWin);
    AppendStr(log, sizeof(log), ",rc="); AppendHex(log, sizeof(log), winEc);

    HANDLE f = CreateFileW(doneFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, log, (DWORD)lstrlenA(log), &w, NULL); CloseHandle(f); }
    return 0;
}
'@
    [IO.File]::WriteAllText($l2RunnerC, $runnerCode, (New-Object Text.UTF8Encoding($false)))

    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $buildCmd = 'call "' + $vcvars + '" >nul && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l1Exe + '" kernel32.lib advapi32.lib && ' +
        'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2.obj') + '" "' + $l2RunnerC + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l2Exe + '" kernel32.lib'
    $clOut = & cmd.exe /c $buildCmd 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native build failed: ' + ($clOut -join '; ')) }

    $psecBin = Join-Path $sealed 'psec-msix.bin'
    $psecBytes = [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Multi([string[]]@($scratch, $mockOutDir), [string[]]@($sealed), $false)
    [IO.File]::WriteAllBytes($psecBin, $psecBytes)

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # 4. Launch hardened Layer-1 -> suspended Layer-2 -> inspect -> 4 Static BLOCK WFP -> ResumeThread!
    $readyPath = Join-Path $scratch 'l1-ready.json'
    $l1Stop = Join-Path $scratch 'l1-stop'
    $doneFile = Join-Path $scratch 'msix-done.txt'
    $runnerCfgPath = Join-Path $sealed 'msix-runner.cfg'
    [IO.File]::WriteAllText($runnerCfgPath, ("a=$msixAppDir`nd=$doneFile`n"), (New-Object Text.UTF8Encoding($false)))
    $l1Args = "`"$psecBin`" `"$l2Exe`" `"$runnerCfgPath`" `"$scratch`" `"$hostSid`" `"$readyPath`" `"$l1Stop`""

    $l1 = [StudioPsecGuardHost]::StartSuspended($copyToken, $l1Exe, $l1Args, $true, 'WinSta0\Default')
    $null = $l1.RestoreTokenObjectDaclOnly($origToken, $hostSid, $accountSid)
    [void]$l1.ResumeMainThread()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $readyPath) -and $sw.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 25 }
    $l1Receipt = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $insp = [StudioPsecGuardHost]::InspectSuspendedPsecChild([int]$l1Receipt.childPid, [int]$l1Receipt.childTid, $hostSid, $accountSid)
    $targetContainerSid = $insp.identity.containerSid
    [StudioPsecGuardHost]::AllowSelfContainerDefaultDacl([int]$l1Receipt.childPid, $hostSid, $targetContainerSid)

    # Install 4 Static BLOCK WFP BEFORE ResumeThread
    $wfpSub = [guid]::NewGuid()
    $wfpKeys = @([guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid(), [guid]::NewGuid())
    $g = [StudioLabWfp]::CreateStaticGuard()
    try {
        $wfpWeight = $g.PrepareStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $l2Exe)
        $g.InstallStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $l2Exe, $wfpWeight)
        $wfpInstalled = $true
    } finally { $g.Dispose() }
    $null = [StudioLabWfp]::VerifyStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $wfpWeight, $false)

    $null = [StudioPsecGuardHost]::HostResumeChildOnly([int]$l1Receipt.childPid, [int]$l1Receipt.childTid)
    $null = Test-HostHealth 'blocked' 51

    $sw.Restart()
    while (!(Test-Path -LiteralPath $doneFile) -and $sw.ElapsedMilliseconds -lt 25000) { Start-Sleep -Milliseconds 50 }
    if (!(Test-Path -LiteralPath $doneFile)) { throw 'MSIX runner did not finish within 25s' }

    $report.runnerLog = [IO.File]::ReadAllText($doneFile)
    # 5. Collect and validate ALL 5 activation receipts (check mockOutDir AND AppContainer redirected LocalAppData)
    $files = @(Get-ChildItem -LiteralPath $aLocalApp -Recurse -Filter 'activation-*.json' -ErrorAction SilentlyContinue)
    foreach ($f in $files) {
        $obj = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $report.receipts += @($obj)
    }

    $rolesSeen = @($report.receipts | ForEach-Object { $_.role })
    $allSameUserAndContainer = ($report.receipts.Count -eq 5) -and
        (@($report.receipts | Where-Object { $_.userSid -cne $accountSid -or $_.containerSid -cne $targetContainerSid }).Count -eq 0)
    $coldWin = @($report.receipts | Where-Object { $_.role -ceq 'StudioActivationWindow' -and $_.warm -eq $false }).Count
    $warmWin = @($report.receipts | Where-Object { $_.role -ceq 'StudioActivationWindow' -and $_.warm -eq $true }).Count
    $hasH1 = ($rolesSeen -contains 'StudioActivationHelperOne')
    $hasH2 = ($rolesSeen -contains 'StudioActivationHelperTwo')
    $hasHm = ($rolesSeen -contains 'StudioActivationMediumHelper')

    $report.checks.allFiveMsixBinariesContainedInPsec = $allSameUserAndContainer -and ($coldWin -eq 1) -and ($warmWin -eq 1) -and $hasH1 -and $hasH2 -and $hasHm
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($l1Stop -and $scratch -and (Test-Path -LiteralPath $scratch)) { try { [IO.File]::WriteAllText($l1Stop, 'stop') } catch { } }
    if ($l1Receipt -and $l1Receipt.childPid) { try { [StudioPsecGuardHost]::HostTerminatePid([int]$l1Receipt.childPid) } catch { } }
    if ($l1) { try { [void]$l1.WaitExit(4000); $l1.Dispose() } catch { } }
    Start-Sleep -Milliseconds 180

    if ($wfpInstalled -and $assemblyLoaded) {
        try {
            [StudioLabWfp]::RemoveStatic($wfpSub, $wfpKeys, $targetContainerSid, [uint16]59999, $wfpWeight)
            Start-Sleep -Milliseconds 80
            $res = [StudioLabWfp]::CountFiltersReferencingPackage($targetContainerSid)
            $report.cleanup.residualPackageFilters = $res
            $report.cleanup.wfpRemovedAndVerifiedAbsent = ($res -eq 0)
        } catch { $report.cleanup.errors += @("wfp: $($_.Exception.Message)"); $report.cleanup.wfpRemovedAndVerifiedAbsent = $false }
    } else { $report.cleanup.wfpRemovedAndVerifiedAbsent = $true }

    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { } }
    if ($dnsTrace) {
        try {
            $dnsRes = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $psecSR = @($dnsRes.events | Where-Object { $_.role -eq 'psec' -and ($_.event -in 3010,3011) }).Count
            $unkSR = @($dnsRes.events | Where-Object { !$_.role -and ($_.event -in 3010,3011) }).Count
            $hSends = @($dnsRes.events | Where-Object { $_.role -eq 'host' -and $_.event -eq 3010 }).Count
            $lZero = ($null -ne $dnsRes.lossBeforeStop) -and ($dnsRes.lossBeforeStop.eventsLost -eq 0) -and ($dnsRes.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsRes.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{ servicePidStable = ($dnsRes.servicePid -eq $dnsRes.servicePidAfter); lossZero = $lZero; psecSendReplyCount = $psecSR; unknownSendReplyCount = $unkSR; hostSendCount = $hSends }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($psecSR -eq 0) -and ($unkSR -eq 0) -and ($hSends -ge 3)
        } catch { $report.checks.dnsZeroLeak = $false }
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
        try { [StudioPsecGuardHost]::UnloadLabProfile($origToken, $loadedProfileHandle) } catch { }
        foreach ($tk in @($copyToken, $origToken)) { if ($tk -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($tk) } catch { } } }
    }

    if ($msixBuildDir -and (Test-Path -LiteralPath $msixBuildDir)) { try { Remove-Item -LiteralPath $msixBuildDir -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("msixDir: $($_.Exception.Message)") } }
    if ($accountCreated) {
        try { if ($accountSid) { $pr = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $accountSid + "'") -ErrorAction SilentlyContinue; if ($pr) { Remove-CimInstance -InputObject $pr -ErrorAction Stop } } } catch { $report.cleanup.errors += @("prof: $($_.Exception.Message)") }
        try { if (Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA') { Remove-Item -LiteralPath 'C:\Users\ClaudeStudioLabA' -Recurse -Force -ErrorAction Stop } } catch { $report.cleanup.errors += @("profDir: $($_.Exception.Message)") }
        try { Remove-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction Stop } catch { $report.cleanup.errors += @("user: $($_.Exception.Message)") }
    }
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
    $report.cleanup.msixBuildDirGone = !($msixBuildDir -and (Test-Path -LiteralPath $msixBuildDir))
    $report.cleanup.labAGone = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
    $report.cleanup.labAProfileDirGone = !(Test-Path -LiteralPath 'C:\Users\ClaudeStudioLabA')

    $hOk = $true
    foreach ($st in @('baseline','blocked','restored')) { $h = $report.hostHealth[$st]; if (!$h -or !$h.publicDnsOk -or !$h.oldTcp -or !$h.freshTcp) { $hOk = $false } }
    $report.checks.hostContinuous = $hOk
    $report.checks.cleanup = ($report.cleanup.errors.Count -eq 0) -and $report.cleanup.wfpRemovedAndVerifiedAbsent -and
        $report.cleanup.directoryGone -and $report.cleanup.msixBuildDirGone -and $report.cleanup.labAGone -and $report.cleanup.labAProfileDirGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 6)
    $report.outcome = if ($allOk) { 'passed-a-phase6b-msix-activation' } else { 'stopped-a-phase6b-msix-activation' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        msixBuild = $report.msixBuild; runnerLog = $report.runnerLog; receiptCount = $report.receipts.Count
        receiptRoles = @($report.receipts | ForEach-Object { "$($_.role):warm=$($_.warm),sameContainer=$($_.containerSid -ceq $targetContainerSid)" })
        checks = $report.checks; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
}
