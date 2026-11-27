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

function Set-RepoAcl([string]$RepoPath, [string]$HostSid, [string]$WriterSid, [string]$ReaderSid) {
    $acl = New-PrivateAcl $HostSid
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($WriterSid), [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($ReaderSid), [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-15-2-1'), [Security.AccessControl.FileSystemRights]::Modify,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $RepoPath -AclObject $acl
    Get-ChildItem -LiteralPath $RepoPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $fa = Get-Acl -LiteralPath $_.FullName
            $fa.SetAccessRuleProtection($false, $false)
            Set-Acl -LiteralPath $_.FullName -AclObject $fa
        } catch { }
    }
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

function Get-UniqueEphemeralPorts([int]$Count) {
    $list = New-Object System.Collections.Generic.List[Net.Sockets.TcpListener]
    $ports = New-Object System.Collections.Generic.List[int]
    try {
        while ($ports.Count -lt $Count) {
            $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $l.ExclusiveAddressUse = $true
            $l.Start()
            $p = $l.LocalEndpoint.Port
            if ($p -ge 45000 -and $p -ne 10810 -and !$ports.Contains($p)) {
                $list.Add($l); $ports.Add($p)
            } else { $l.Stop() }
        }
        return $ports.ToArray()
    } finally { foreach ($l in $list) { try { $l.Stop() } catch { } } }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    if (!$RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 16) }
    $reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
    $ReportPath = Join-Path $reportDir ("windows-ab-phase7-realistic-twins-$RunId.json")
    $SummaryPath = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeStudioPhase7-summary-$RunId.json")
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

$twinDir = $PSScriptRoot
$repoRoot = Split-Path $twinDir -Parent
$cpDir = Join-Path $repoRoot 'studio-control-plane'
$mockDir = Join-Path $repoRoot 'mock-desktop'
$fixtureDir = Join-Path $mockDir 'fixtures\startup-permissions'
. (Join-Path $mockDir 'windows-lab-dns-trace.ps1')
. (Join-Path $mockDir 'windows-lab-bind-gate.ps1') -FunctionsOnly
. (Join-Path $mockDir 'windows-lab-n3-protocol.ps1') -FunctionsOnly

$hostSid = $identity.User.Value
$prefix = 'studio-' + $RunId
$tag = 'ClaudeStudioPhase7-' + $RunId
$base = Join-Path ([IO.Path]::GetTempPath()) $tag
$n3Dir = Join-Path $base 'n3'
$sharedRepo = Join-Path $env:ProgramData ("ClaudeStudioPhase7Repo-$RunId")

$report = [ordered]@{
    runId = $RunId; prefix = $prefix; utcStarted = [datetime]::UtcNow.ToString('o')
    outcome = 'inconclusive-ab-phase7-realistic-twins'
    checks = [ordered]@{}; hostHealth = [ordered]@{}; details = [ordered]@{}
    cleanup = [ordered]@{ errors = @(); remainingPids = @(); residualPackageFilters = 0 }
}

$dirCreated = $false; $repoCreated = $false; $assemblyLoaded = $false
$users = @{}; $tokens = @{}
$hostListener = $null; $hostOld = $null; $dnsTrace = $null
$sentinelTcpListener = $null; $sentinelUdpSocket = $null; $sentinelTcpHits = 0; $sentinelUdpHits = 0
$apiProc = $null; $upstreamEntry = $null; $engine = $null; $liveBackend = $null
$retiredContainerSids = New-Object System.Collections.Generic.List[string]
$cmdSeq = @{ A = 0; B = 0 }
$autoDirs = @{}

function Send-TwinCmd([string]$SpaceKey, [hashtable]$Payload, [int]$TimeoutMs = 15000) {
    $cmdSeq[$SpaceKey] = $cmdSeq[$SpaceKey] + 1
    $n = $cmdSeq[$SpaceKey]
    $dir = $autoDirs[$SpaceKey]
    $cmdPath = Join-Path $dir ("cmd-$n.json")
    $resPath = Join-Path $dir ("res-$n.json")
    $tmp = $cmdPath + '.tmp'
    [IO.File]::WriteAllText($tmp, ($Payload | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $cmdPath -Force
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $resPath) -and $sw.ElapsedMilliseconds -lt $TimeoutMs) { Start-Sleep -Milliseconds 20 }
    if (!(Test-Path -LiteralPath $resPath)) { throw "Twin $SpaceKey command #$n ($($Payload.action)) timed out" }
    return (Get-Content -LiteralPath $resPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Invoke-MockApiIssueCode([int]$TlsPort, [string]$HostName, [string]$Pin, [hashtable]$Body) {
    $tcp = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $tcp.Connect([Net.IPAddress]::Loopback, $TlsPort)
        $pinClean = $Pin.ToUpperInvariant()
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, {
            param($s,$c,$ch,$e)
            $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new($c)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $h = ([BitConverter]::ToString($sha.ComputeHash($x.RawData)) -replace '-','').ToUpperInvariant(); return ($h -eq $pinClean) } finally { $sha.Dispose() }
        })
        try {
            $ssl.AuthenticateAsClient($HostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
            $jb = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
            $req = "POST /oauth/issue-code HTTP/1.1`r`nHost: $HostName`r`nContent-Type: application/json`r`nContent-Length: $($jb.Length)`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($req)
            $ssl.Write($hb, 0, $hb.Length); $ssl.Write($jb, 0, $jb.Length); $ssl.Flush()
            $sr = [IO.StreamReader]::new($ssl, [Text.Encoding]::UTF8)
            $raw = $sr.ReadToEnd()
            $idx = $raw.IndexOf("`r`n`r`n")
            if ($idx -lt 0) { throw "Bad API response: $raw" }
            return ($raw.Substring($idx + 4) | ConvertFrom-Json)
        } finally { $ssl.Dispose() }
    } finally { $tcp.Close() }
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

    # 1. Ensure fresh builds of Twin binaries & Control Plane EXE
    $null = & (Join-Path $twinDir 'build.ps1')
    $null = & (Join-Path $cpDir 'build.ps1')
    $cliBin = Join-Path $twinDir 'bin\ClaudeCliTwin.exe'
    $deskBin = Join-Path $twinDir 'bin\ClaudeDesktopTwin.exe'
    $cpExe = Join-Path $cpDir 'bin\ClaudeStudioControlPlane.exe'
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($cpExe))
    $assemblyLoaded = $true

    [void][IO.Directory]::CreateDirectory($base, (New-PrivateAcl $hostSid))
    $dirCreated = $true
    [void][IO.Directory]::CreateDirectory($n3Dir, (New-PrivateAcl $hostSid))
    $report.desktopBefore = [StudioReadDesktop]::Read()
    $report.defaultDesktopBefore = [StudioPsecGuardHost]::ReadDefaultDesktopDigest()

    # 2. Generate ephemeral TLS cert/key/pin (zero trust-store edits) + compile N3 Relay + ProxyOwner + Layer-1 Launcher
    $pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $null = & $pwsh -NoProfile -NonInteractive -File (Join-Path $mockDir 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $n3Dir -CertificatePrefix $prefix
    if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed' }
    $pin = (Get-Content -LiteralPath (Join-Path $n3Dir 'pin.txt') -Raw).Trim()
    $hostName = $prefix + '-a-window-healthy.test'

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $relayExe = Join-Path $n3Dir 'StudioN3Relay.exe'
    $ownerExe = Join-Path $base 'StudioPhase7ProxyOwner.exe'
    $oR = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$relayExe" (Join-Path $mockDir 'windows-lab-n3-protocol.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Relay compile failed: ' + ($oR -join '; ')) }
    $oO = & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$ownerExe" `
        (Join-Path $fixtureDir 'Phase1ProxyOwner.cs') (Join-Path $mockDir 'windows-lab-wfp.cs') (Join-Path $mockDir 'windows-lab-wfp-container.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('ProxyOwner compile failed: ' + ($oO -join '; ')) }

    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $l1Template = Join-Path $base 'StudioLayer1Psec.exe'
    $l2HostC = Join-Path $base 'l2_twin_host.c'
    $l2HostTemplate = Join-Path $base 'StudioLayer2TwinHost.exe'
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
    char buf[2048]; DWORD got = 0; ReadFile(f, buf, sizeof(buf) - 1, &got, NULL); CloseHandle(f); buf[got] = '\0';
    wchar_t exePath[512] = L"", cfgPath[512] = L"";
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        if (line[0] == 'e' && line[1] == '=') ToWide(line + 2, exePath, 512);
        else if (line[0] == 'c' && line[1] == '=') ToWide(line + 2, cfgPath, 512);
    }
    if (!exePath[0] || !cfgPath[0]) return 4;
    wchar_t cmd[1200];
    int pos = 0;
    cmd[pos++] = L'"';
    for (int i = 0; exePath[i] && pos < 1180; i++) cmd[pos++] = exePath[i];
    cmd[pos++] = L'"'; cmd[pos++] = L' '; cmd[pos++] = L'"';
    for (int i = 0; cfgPath[i] && pos < 1195; i++) cmd[pos++] = cfgPath[i];
    cmd[pos++] = L'"'; cmd[pos] = L'\0';
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exePath, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return (int)GetLastError();
    WaitForSingleObject(pi.hProcess, 140000);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)ec;
}
'@
    [IO.File]::WriteAllText($l2HostC, $l2Code, (New-Object Text.UTF8Encoding($false)))
    $clOut = & cmd.exe /c ('call "' + $vcvars + '" >nul && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l1.obj') + '" "' + (Join-Path $fixtureDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l1Template + '" kernel32.lib advapi32.lib && cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $base 'l2h.obj') + '" "' + $l2HostC + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l2HostTemplate + '" kernel32.lib') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native Layer-1/Layer-2 build failed: ' + ($clOut -join '; ')) }

    # 3. Allocate ephemeral ports & start Mock Claude API + Sentinels + Host Health + DNS ETW
    $ports = Get-UniqueEphemeralPorts 9
    $portA = [uint16]$ports[0]; $portB = [uint16]$ports[1]; $portU = [uint16]$ports[2]
    $portHttpDummy = [uint16]$ports[3]; $portTlsApi = [uint16]$ports[4]; $portHalfDummy = [uint16]$ports[5]; $portWrongDummy = [uint16]$ports[6]
    $portSentTcp = [uint16]$ports[7]; $portSentUdp = [uint16]$ports[8]

    $sentinelTcpListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $portSentTcp)
    $sentinelTcpListener.Start()
    $sentinelUdpSocket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    $sentinelUdpSocket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $portSentUdp))
    $sentinelUdpSocket.Blocking = $false

    $nodeExe = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $apiLog = Join-Path $n3Dir 'mock-claude-api.ndjson'
    $apiProc = Start-N3Process -Executable $nodeExe -Arguments @(
        (Join-Path $twinDir 'mock-claude-api.cjs'), "$portTlsApi", (Join-Path $n3Dir 'target.crt'), (Join-Path $n3Dir 'target.key'), $apiLog, "$portHttpDummy"
    ) -Directory $n3Dir
    $apiReady = Read-N3Line $apiProc 5000
    if ($apiReady.kind -cne 'ready') { throw 'Mock Claude API did not start' }

    foreach ($sk in @('A','B')) {
        $pPort = if ($sk -eq 'A') { $portA } else { $portB }
        $eDir = Join-Path $n3Dir ("entry-$sk")
        [void][IO.Directory]::CreateDirectory($eDir, (New-PrivateAcl $hostSid))
        $setObj = [ordered]@{ Prefix=$prefix; P=[int]$pPort; U=[int]$portU; Http=[int]$portHttpDummy; Tls=[int]$portTlsApi; Half=[int]$portHalfDummy; WrongCertificate=[int]$portWrongDummy; Pin=$pin }
        [IO.File]::WriteAllText((Join-Path $eDir 'settings.json'), ($setObj | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
    }
    $upSettings = Join-Path $n3Dir 'upstream-settings.json'
    $upLog = Join-Path $n3Dir 'upstream.ndjson'
    [IO.File]::WriteAllText($upSettings, ([ordered]@{ Prefix=$prefix; P=[int]$portA; U=[int]$portU; Http=[int]$portHttpDummy; Tls=[int]$portTlsApi; Half=[int]$portHalfDummy; WrongCertificate=[int]$portWrongDummy; Pin=$pin } | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))

    # 4. Create temporary standard users A & B + shared synthetic Git repo
    foreach ($sk in @('A','B')) {
        $uName = "ClaudeStudioLab$sk"
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $uName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Temp $sk Phase7 Twin"
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $u
        $orig = [StudioPsecGuardHost]::AcquireSeclogonSeedToken($uName, $env:COMPUTERNAME, $pw)
        $prof = [StudioPsecGuardHost]::LoadLabProfile($orig, $uName)
        $copy = [StudioPsecGuardHost]::DuplicateHardened($orig, $hostSid)
        $users[$sk] = @{ name = $uName; sid = $u.SID.Value }
        $tokens[$sk] = @{ orig = $orig; copy = $copy; prof = $prof }
    }

    [void][IO.Directory]::CreateDirectory($sharedRepo, (New-PrivateAcl $hostSid))
    $repoCreated = $true
    $gitExe = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $null = & $gitExe -C $sharedRepo init -q
    $null = & $gitExe -C $sharedRepo config user.name 'Synthetic Twin Tester'
    $null = & $gitExe -C $sharedRepo config user.email 'twin@example.invalid'
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'app.txt'), "initial-baseline`n", (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'README.md'), "# Synthetic Shared Project`n", (New-Object Text.UTF8Encoding($false)))
    $null = & $gitExe -C $sharedRepo add .
    $null = & $gitExe -C $sharedRepo commit -q -m 'initial commit'
    Set-RepoAcl -RepoPath $sharedRepo -HostSid $hostSid -WriterSid $users['A'].sid -ReaderSid $users['B'].sid

    # 5. Stage per-space sealed binaries, isolated profiles, PSEC manifests & LiveSpaceSpecs
    $specs = @{}; $spaceDirs = @{}
    foreach ($sk in @('A','B')) {
        $uName = $users[$sk].name; $uSid = $users[$sk].sid
        $root = Join-Path "C:\Users\$uName\AppData\Local\Temp" $tag
        $sealed = Join-Path $root 'sealed'
        $scratch = Join-Path $root 'scratch'
        $userData = Join-Path $root 'desktop-userdata'
        $cliCfg = Join-Path $root 'cli-config'
        $autoDir = Join-Path $root 'automation'
        $autoDirs[$sk] = $autoDir
        $spaceDirs[$sk] = @{ root=$root; sealed=$sealed; scratch=$scratch; userData=$userData; cliCfg=$cliCfg; autoDir=$autoDir }

        $rxAcl = New-PrivateAcl $hostSid; $rwAcl = New-PrivateAcl $hostSid
        foreach ($s in @($uSid, 'S-1-15-2-1')) {
            $rxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::ReadAndExecute, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            $rwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s), [Security.AccessControl.FileSystemRights]::Modify, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($root, $rxAcl)
        [void][IO.Directory]::CreateDirectory($sealed, $rxAcl)
        foreach ($d in @($scratch, $userData, $cliCfg, $autoDir)) { [void][IO.Directory]::CreateDirectory($d, $rwAcl) }

        $l1SpaceExe = Join-Path $sealed "Studio${sk}Layer1.exe"
        $l2HostSpaceExe = Join-Path $sealed "Studio${sk}Layer2Host.exe"
        $deskSpaceExe = Join-Path $sealed "ClaudeDesktopTwin.exe"
        $cliSpaceExe = Join-Path $sealed "ClaudeCliTwin.exe"
        Copy-Item -LiteralPath $l1Template -Destination $l1SpaceExe -Force
        Copy-Item -LiteralPath $l2HostTemplate -Destination $l2HostSpaceExe -Force
        Copy-Item -LiteralPath $deskBin -Destination $deskSpaceExe -Force
        Copy-Item -LiteralPath $cliBin -Destination $cliSpaceExe -Force

        $pPort = if ($sk -eq 'A') { $portA } else { $portB }
        $peerP = if ($sk -eq 'A') { $portB } else { $portA }
        $lang = if ($sk -eq 'A') { 'zh-CN' } else { 'en-US' }
        $tz = if ($sk -eq 'A') { 'Asia/Shanghai' } else { 'America/Los_Angeles' }

        $cfgPath = Join-Path $sealed 'desktop-twin.json'
        $cfgObj = [ordered]@{
            space = $sk; userDataDir = $userData; proxyServer = "http://127.0.0.1:$pPort"
            lang = $lang; tz = $tz; projectDir = $sharedRepo; cliExe = $cliSpaceExe; cliConfigDir = $cliCfg
            apiHost = $hostName; tlsPin = $pin; automationDir = $autoDir
            sentinelTcp = [int]$portSentTcp; sentinelUdp = [int]$portSentUdp; peerProxy = [int]$peerP
            dnsName = "$prefix-psec-healthy1-dns.test."
        }
        [IO.File]::WriteAllText($cfgPath, ($cfgObj | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
        $l2BridgeCfg = Join-Path $sealed 'l2-bridge.cfg'
        [IO.File]::WriteAllText($l2BridgeCfg, ("e=$deskSpaceExe`nc=$cfgPath`n"), (New-Object Text.UTF8Encoding($false)))

        $psecPath = Join-Path $sealed 'psec-twin.bin'
        $rwList = if ($sk -eq 'A') { [string[]]@($scratch, $userData, $cliCfg, $autoDir, $sharedRepo) } else { [string[]]@($scratch, $userData, $cliCfg, $autoDir) }
        $roList = if ($sk -eq 'A') { [string[]]@($sealed) } else { [string[]]@($sealed, $sharedRepo) }
        [IO.File]::WriteAllBytes($psecPath, [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Multi($rwList, $roList, $false))

        $sp = [ClaudeStudio.ControlPlane.LiveSpaceSpec]::new()
        $sp.Space = if ($sk -eq 'A') { [ClaudeStudio.ControlPlane.SpaceId]::A } else { [ClaudeStudio.ControlPlane.SpaceId]::B }
        $sp.AccountName = $uName; $sp.AccountSid = $uSid; $sp.HostSid = $hostSid
        $sp.Prefix = $prefix; $sp.HostName = $hostName; $sp.Pin = $pin
        $sp.SealedDir = $sealed; $sp.ScratchDir = $scratch
        $sp.LauncherExe = $l1SpaceExe; $sp.ClientExe = $l2HostSpaceExe; $sp.PsecBin = $psecPath; $sp.ClientCfg = $l2BridgeCfg
        $sp.ProxyOwnerExe = $ownerExe; $sp.WorkBaseDir = $base; $sp.RelayExe = $relayExe
        $sp.EntrySettingsPath = Join-Path $n3Dir ("entry-$sk\settings.json")
        $sp.EntryLogPath = Join-Path $n3Dir ("entry-$sk\entry.ndjson")
        $sp.ProxyPort = $pPort; $sp.PeerPort = $peerP
        $sp.OrigToken = $tokens[$sk].orig; $sp.CopyToken = $tokens[$sk].copy
        $sp.SkipNativeColdProbeWait = $true
        $sp.TwinReadyPath = Join-Path $autoDir 'ready.json'
        $specs[$sk] = $sp
    }

    $hostListener = New-GateSocket; $hostListener.ExclusiveAddressUse = $true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)); $hostListener.Listen(4)
    $hostOld = Open-GatePair $hostListener
    $dnsTrace = Start-LabDnsTrace -RunDirectory $base -Prefix $prefix -AccountMatch
    $null = Test-HostHealth 'baseline' 41

    # 6. Initialize REAL StudioEngine + LivePsecWfpBackend!
    $liveBackend = [ClaudeStudio.ControlPlane.LivePsecWfpBackend]::new($specs['A'], $specs['B'])
    $engine = [ClaudeStudio.ControlPlane.StudioEngine]::new($liveBackend)

    # === CHECK 1: Fail-Closed Cold Start (Upstream NOT running yet) ===
    $snapColdA = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::A)
    $snapColdB = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    $retiredContainerSids.Add($snapColdA.ContainerSid)
    $retiredContainerSids.Add($snapColdB.ContainerSid)

    $readyA = Get-Content -LiteralPath (Join-Path $autoDirs['A'] 'ready.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $readyB = Get-Content -LiteralPath (Join-Path $autoDirs['B'] 'ready.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $coldDeskA = Send-TwinCmd 'A' @{ action = 'bypass-check'; dnsName = "$prefix-psec-cold1-dns.test." }
    $coldDeskB = Send-TwinCmd 'B' @{ action = 'bypass-check'; dnsName = "$prefix-psec-cold2-dns.test." }
    $coldCliA = Send-TwinCmd 'A' @{ action = 'run-cli'; cliArgs = "doctor --sentinel-tcp $portSentTcp --sentinel-udp $portSentUdp --peer-proxy $portB --dns-name $prefix-psec-cold3-dns.test." }
    $coldCliB = Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = "doctor --sentinel-tcp $portSentTcp --sentinel-udp $portSentUdp --peer-proxy $portA --dns-name $prefix-psec-cold4-dns.test." }
    $null = Test-HostHealth 'blocked' 51

    $report.checks.desktopAndCliColdBlocked =
        ($snapColdA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ColdBlocked) -and
        ($snapColdB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ColdBlocked) -and
        $readyA.visible -and $readyB.visible -and
        ($snapColdA.ContainerSid -cne $snapColdB.ContainerSid) -and
        (!$coldDeskA.apiViaProxyOk) -and (!$coldDeskB.apiViaProxyOk) -and
        (!$coldDeskA.directSentinelTcp.connected) -and ($coldDeskA.directSentinelTcp.wsaError -eq 10013) -and
        (!$coldDeskB.directSentinelTcp.connected) -and ($coldDeskB.directSentinelTcp.wsaError -eq 10013) -and
        (!$coldDeskA.peerProxyTcp.connected) -and (!$coldDeskB.peerProxyTcp.connected) -and
        ($coldDeskA.dnsQueryRc -eq 5) -and ($coldDeskB.dnsQueryRc -eq 5) -and
        (!$coldCliA.parsed.apiReachableViaProxy) -and (!$coldCliB.parsed.apiReachableViaProxy) -and
        ($coldCliA.parsed.dnsQueryRc -eq 5) -and ($coldCliB.parsed.dnsQueryRc -eq 5)

    # === CHECK 2: Bring Upstream Online -> Interleaved OAuth PKCE & Account/Org UUID Physical Isolation ===
    $upstreamEntry = Start-N3Process -Executable $relayExe -Arguments @('upstream', $upSettings, $upLog) -Directory $n3Dir
    $upReady = Read-N3Line $upstreamEntry 4000
    if ($upReady.kind -cne 'ready') { throw 'Upstream did not start' }

    $snapOnA = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)
    $snapOnB = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::B)

    $acctA = 'acct-aaaa-1111'; $orgA = 'org-aaaa-1111'; $emailA = 'alice-a@example.invalid'
    $acctB = 'acct-bbbb-2222'; $orgB = 'org-bbbb-2222'; $emailB = 'bob-b@example.invalid'

    # Interleaved: B initiates -> A initiates -> cross-deliver A's state to B (reject!) -> B completes -> replay B (reject!) -> A completes
    $oStartB = Send-TwinCmd 'B' @{ action = 'oauth-start' }
    $oStartA = Send-TwinCmd 'A' @{ action = 'oauth-start' }
    $codeB = (Invoke-MockApiIssueCode $portTlsApi $hostName $pin @{ state = $oStartB.state; code_challenge = $oStartB.codeChallenge; email = $emailB; account_uuid = $acctB; org_uuid = $orgB }).code
    $codeA = (Invoke-MockApiIssueCode $portTlsApi $hostName $pin @{ state = $oStartA.state; code_challenge = $oStartA.codeChallenge; email = $emailA; account_uuid = $acctA; org_uuid = $orgA }).code

    $crossDeliverB = Send-TwinCmd 'B' @{ action = 'oauth-complete'; state = $oStartA.state; code = $codeA }
    $oDoneB = Send-TwinCmd 'B' @{ action = 'oauth-complete'; state = $oStartB.state; code = $codeB }
    $replayB = Send-TwinCmd 'B' @{ action = 'oauth-complete'; state = $oStartB.state; code = $codeB }
    $oDoneA = Send-TwinCmd 'A' @{ action = 'oauth-complete'; state = $oStartA.state; code = $codeA }

    # CLI OAuth inside Space A & B (isolated CLAUDE_CONFIG_DIR)
    $cliStartA = (Send-TwinCmd 'A' @{ action = 'run-cli'; cliArgs = 'auth start-oauth' }).parsed
    $cliStartB = (Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = 'auth start-oauth' }).parsed
    $cliCodeA = (Invoke-MockApiIssueCode $portTlsApi $hostName $pin @{ state = $cliStartA.state; code_challenge = $cliStartA.codeChallenge; email = $emailA; account_uuid = $acctA; org_uuid = $orgA }).code
    $cliCodeB = (Invoke-MockApiIssueCode $portTlsApi $hostName $pin @{ state = $cliStartB.state; code_challenge = $cliStartB.codeChallenge; email = $emailB; account_uuid = $acctB; org_uuid = $orgB }).code
    $cliDoneA = (Send-TwinCmd 'A' @{ action = 'run-cli'; cliArgs = "auth complete-oauth --state $($cliStartA.state) --code $cliCodeA" }).parsed
    $cliDoneB = (Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = "auth complete-oauth --state $($cliStartB.state) --code $cliCodeB" }).parsed

    # Cross-space file read MUST be denied by OS ACL
    $aReadsBDesk = Send-TwinCmd 'A' @{ action = 'cross-read'; path = (Join-Path $spaceDirs['B'].userData 'account-session.json') }
    $bReadsADesk = Send-TwinCmd 'B' @{ action = 'cross-read'; path = (Join-Path $spaceDirs['A'].userData 'account-session.json') }
    $aReadsBCli = Send-TwinCmd 'A' @{ action = 'cross-read'; path = (Join-Path $spaceDirs['B'].cliCfg '.credentials.json') }
    # Identity spoofing test: A tries sending B's accountUuid with A's Bearer token -> 403 IDENTITY_MISMATCH!
    $spoofResp = Send-TwinCmd 'A' @{ action = 'chat'; prompt = 'spoof check'; spoofAccountUuid = $acctB; spoofOrgUuid = $orgB }

    $report.checks.oauthPkceAndUuidIsolation =
        ($snapOnA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        ($snapOnB.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        (!$crossDeliverB.ok -and $crossDeliverB.code -ceq 'STATE_MISMATCH') -and
        ($oDoneB.ok -and $oDoneB.accountUuid -ceq $acctB -and $oDoneB.desktopSessionFile -like "*claude-code-sessions\$acctB\$orgB\local_*.json") -and
        (!$replayB.ok) -and
        ($oDoneA.ok -and $oDoneA.accountUuid -ceq $acctA -and $oDoneA.desktopSessionFile -like "*claude-code-sessions\$acctA\$orgA\local_*.json") -and
        ($cliDoneA.ok -and $cliDoneA.accountUuid -ceq $acctA) -and
        ($cliDoneB.ok -and $cliDoneB.accountUuid -ceq $acctB) -and
        (!$aReadsBDesk.readable) -and (!$bReadsADesk.readable) -and (!$aReadsBCli.readable) -and
        (!$spoofResp.ok -and $spoofResp.statusCode -eq 403)

    # === CHECK 3: Multi-Process Tree Containment (Desktop + MCP Helper + CLI Twin inside SAME PSEC!) ===
    $mcpA = Send-TwinCmd 'A' @{ action = 'spawn-mcp-helper' }
    $mcpB = Send-TwinCmd 'B' @{ action = 'spawn-mcp-helper' }
    $cliStA = (Send-TwinCmd 'A' @{ action = 'run-cli'; cliArgs = 'auth status' }).parsed
    $cliStB = (Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = 'auth status' }).parsed

    $report.checks.multiProcessTreeContained =
        $mcpA.ok -and $mcpA.apiViaProxyOk -and (!$mcpA.directSentinelTcp.connected) -and ($mcpA.dnsQueryRc -eq 5) -and
        ($mcpA.identity.userSid -ceq $users['A'].sid) -and ($mcpA.identity.containerSid -ceq $snapColdA.ContainerSid) -and
        $mcpB.ok -and $mcpB.apiViaProxyOk -and (!$mcpB.directSentinelTcp.connected) -and ($mcpB.dnsQueryRc -eq 5) -and
        ($mcpB.identity.userSid -ceq $users['B'].sid) -and ($mcpB.identity.containerSid -ceq $snapColdB.ContainerSid) -and
        $cliStA.ok -and $cliStA.symlinkCheckPassed -and ($cliStA.identity.userSid -ceq $users['A'].sid) -and ($cliStA.identity.containerSid -ceq $snapColdA.ContainerSid) -and
        $cliStB.ok -and $cliStB.symlinkCheckPassed -and ($cliStB.identity.userSid -ceq $users['B'].sid) -and ($cliStB.identity.containerSid -ceq $snapColdB.ContainerSid)

    # === CHECK 4: Dual Proxy API & Live SSE Streaming ===
    $chatA = Send-TwinCmd 'A' @{ action = 'chat'; prompt = 'Hello from Space A' }
    $chatB = Send-TwinCmd 'B' @{ action = 'chat'; prompt = 'Hello from Space B' }
    $chatBodyA = $chatA.body | ConvertFrom-Json
    $chatBodyB = $chatB.body | ConvertFrom-Json

    $null = Test-HostHealth 'healthy1' 61
    $sStartA = Send-TwinCmd 'A' @{ action = 'stream-start' }
    $sStartB = Send-TwinCmd 'B' @{ action = 'stream-start' }
    Start-Sleep -Milliseconds 600
    $sPreA = Send-TwinCmd 'A' @{ action = 'stream-status' }
    $sPreB = Send-TwinCmd 'B' @{ action = 'stream-status' }

    $report.checks.dualProxyApiAndStreaming =
        $chatA.ok -and $chatB.ok -and
        ($chatBodyA.account_uuid -ceq $acctA) -and ($chatBodyA.accept_language_seen -ceq 'zh-CN,zh;q=0.9') -and
        ($chatBodyB.account_uuid -ceq $acctB) -and ($chatBodyB.accept_language_seen -ceq 'en-US,en;q=0.9') -and
        $sStartA.ok -and $sStartB.ok -and
        (!$sPreA.ended) -and ($sPreA.chunkCount -ge 2) -and
        (!$sPreB.ended) -and ($sPreB.chunkCount -ge 2)

    # === CHECK 5: Soft Disconnect A Only (<3s drop, B uninterrupted!) + Shared Upstream Kill (<3s both drop!) ===
    $swCutA = [Diagnostics.Stopwatch]::StartNew()
    $cutSnapA = $engine.DisconnectSpaceNetworkOnly([ClaudeStudio.ControlPlane.SpaceId]::A)
    $aDropMs = -1
    while ($swCutA.ElapsedMilliseconds -lt 3000) {
        $sPostA = Send-TwinCmd 'A' @{ action = 'stream-status' }
        if ($sPostA.ended) { $aDropMs = [math]::Round($swCutA.Elapsed.TotalMilliseconds, 1); break }
        Start-Sleep -Milliseconds 60
    }
    Start-Sleep -Milliseconds 450
    $sMidB = Send-TwinCmd 'B' @{ action = 'stream-status' }
    $chatAOffline = Send-TwinCmd 'A' @{ action = 'chat'; prompt = 'should fail offline' }
    $chatBStillOk = Send-TwinCmd 'B' @{ action = 'chat'; prompt = 'B stays online while A is cut' }

    # Reconnect A, open fresh streams on A & B, then kill shared Upstream -> BOTH A & B drop < 3000ms!
    $recSnapA = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)
    $chatARecovered = Send-TwinCmd 'A' @{ action = 'chat'; prompt = 'A recovered' }
    $null = Send-TwinCmd 'A' @{ action = 'stream-start' }
    $null = Send-TwinCmd 'B' @{ action = 'stream-start' }
    Start-Sleep -Milliseconds 500

    $swUpKill = [Diagnostics.Stopwatch]::StartNew()
    try { $upstreamEntry.process.Kill(); [void]$upstreamEntry.process.WaitForExit(1500) } catch { }
    $upDropA = -1; $upDropB = -1
    while ($swUpKill.ElapsedMilliseconds -lt 3000 -and ($upDropA -lt 0 -or $upDropB -lt 0)) {
        if ($upDropA -lt 0) { $sa = Send-TwinCmd 'A' @{ action = 'stream-status' }; if ($sa.ended) { $upDropA = [math]::Round($swUpKill.Elapsed.TotalMilliseconds, 1) } }
        if ($upDropB -lt 0) { $sb = Send-TwinCmd 'B' @{ action = 'stream-status' }; if ($sb.ended) { $upDropB = [math]::Round($swUpKill.Elapsed.TotalMilliseconds, 1) } }
        Start-Sleep -Milliseconds 60
    }
    $null = Test-HostHealth 'fault1' 71
    $report.details.faultTimingsMs = [ordered]@{ softDisconnectA = $aDropMs; sharedUpstreamKillA = $upDropA; sharedUpstreamKillB = $upDropB }

    $report.details.check5Sub = [ordered]@{
        cutState = "$($cutSnapA.State)"; aDropMs = $aDropMs; chatAOfflineOk = $chatAOffline.ok
        sPreBChunks = $sPreB.chunkCount; sMidBEnded = $sMidB.ended; sMidBReason = $sMidB.endReason; sMidBChunks = $sMidB.chunkCount
        chatBStillOk = $chatBStillOk.ok; recState = "$($recSnapA.State)"; chatARecoveredOk = $chatARecovered.ok
        upDropA = $upDropA; upDropB = $upDropB
    }
    $report.checks.faultCutoffAndSingleSpaceIsolation =
        ($cutSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::FaultCutoff) -and
        ($aDropMs -ge 0 -and $aDropMs -lt 3000) -and
        (!$chatAOffline.ok) -and
        (!$sMidB.ended) -and ($sMidB.chunkCount -gt $sPreB.chunkCount) -and $chatBStillOk.ok -and
        ($recSnapA.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and $chatARecovered.ok -and
        ($upDropA -ge 0 -and $upDropA -lt 3000) -and ($upDropB -ge 0 -and $upDropB -lt 3000)

    # Restart Upstream & Reconnect A & B for Step 6 (Shared Repo Single-Writer + Controlled Handoff)
    $upstreamEntry = Start-N3Process -Executable $relayExe -Arguments @('upstream', $upSettings, $upLog) -Directory $n3Dir
    $null = Read-N3Line $upstreamEntry 4000
    $null = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::A)
    $null = $engine.ReconnectSpaceNetwork([ClaudeStudio.ControlPlane.SpaceId]::B)

    # === CHECK 6: Shared Synthetic Git Repo Single-Writer + Controlled Handoff + HANDOFF.md ===
    $leaseA = $engine.Leases.RequestMount([ClaudeStudio.ControlPlane.SpaceId]::A, $sharedRepo, [ClaudeStudio.ControlPlane.ProjectAccessMode]::ReadWrite)
    $leaseBRo = $engine.Leases.RequestMount([ClaudeStudio.ControlPlane.SpaceId]::B, $sharedRepo, [ClaudeStudio.ControlPlane.ProjectAccessMode]::ReadOnly)
    $leaseBConflict = $engine.Leases.RequestMount([ClaudeStudio.ControlPlane.SpaceId]::B, $sharedRepo, [ClaudeStudio.ControlPlane.ProjectAccessMode]::ReadWrite)

    $cliEditA = (Send-TwinCmd 'A' @{ action = 'run-cli'; cliArgs = "-p `"Edit app.txt from A`" --cwd `"$sharedRepo`" --write-file app.txt --content `"updated-by-space-a`"" }).parsed
    $cliReadWriteB = (Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = "-p `"Read and attempt write from B`" --cwd `"$sharedRepo`" --read-file app.txt --write-file app.txt --content `"unauthorized-b`"" }).parsed
    $diffAfterA = (& $gitExe -C $sharedRepo diff -- app.txt) -join "`n"

    # Generate sanitized HANDOFF.md via real Control Plane HandoffGenerator!
    $brief = [ClaudeStudio.ControlPlane.HandoffGenerator]::BuildSanitizedBrief($sharedRepo, [ClaudeStudio.ControlPlane.SpaceId]::A, [ClaudeStudio.ControlPlane.SpaceId]::B, 'Space A updated app.txt cleanly', 'Space B continue after handoff')
    $briefClean = ($brief -notmatch [regex]::Escape($acctA)) -and ($brief -notmatch 'sk-twin-') -and ($brief -notmatch [regex]::Escape($env:USERNAME))
    [IO.File]::WriteAllText((Join-Path $sharedRepo 'HANDOFF.md'), $brief, (New-Object Text.UTF8Encoding($false)))

    # Attempt handoff while A still running -> MUST fail WRITER_STILL_RUNNING!
    $handoffBlocked = $engine.Leases.ControlledHandoffWriter($sharedRepo, [ClaudeStudio.ControlPlane.SpaceId]::B, [Func[ClaudeStudio.ControlPlane.SpaceId,bool]]{ param($x) $engine.IsSpaceStopped($x) })

    # Stop A cleanly -> Controlled handoff to B -> swap NTFS ACL & restart B with RW PSEC!
    $null = Send-TwinCmd 'A' @{ action = 'finish' }
    $null = $engine.StopSpaceAndRollback([ClaudeStudio.ControlPlane.SpaceId]::A)
    $handoffOk = $engine.Leases.ControlledHandoffWriter($sharedRepo, [ClaudeStudio.ControlPlane.SpaceId]::B, [Func[ClaudeStudio.ControlPlane.SpaceId,bool]]{ param($x) $engine.IsSpaceStopped($x) })

    $null = Send-TwinCmd 'B' @{ action = 'finish' }
    $null = $engine.StopSpaceAndRollback([ClaudeStudio.ControlPlane.SpaceId]::B)
    Set-RepoAcl -RepoPath $sharedRepo -HostSid $hostSid -WriterSid $users['B'].sid -ReaderSid $users['A'].sid

    # Rebuild B's PSEC with $sharedRepo in fs_read_write & reset B automation dir
    Get-ChildItem -LiteralPath $autoDirs['B'] -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $cmdSeq['B'] = 0
    [IO.File]::WriteAllBytes($specs['B'].PsecBin, [PsecFlatBufferBuilder]::BuildLoopbackOnlyPsecV1Multi(
        [string[]]@($spaceDirs['B'].scratch, $spaceDirs['B'].userData, $spaceDirs['B'].cliCfg, $spaceDirs['B'].autoDir, $sharedRepo),
        [string[]]@($spaceDirs['B'].sealed), $false))
    $snapB2 = $engine.StartSpace([ClaudeStudio.ControlPlane.SpaceId]::B)
    $retiredContainerSids.Add($snapB2.ContainerSid)

    $cliEditB = (Send-TwinCmd 'B' @{ action = 'run-cli'; cliArgs = "-p `"Read HANDOFF.md and edit app.txt from B`" --cwd `"$sharedRepo`" --read-file HANDOFF.md --write-file app.txt --content `"updated-by-space-b-after-handoff`"" }).parsed
    $diffAfterB = (& $gitExe -C $sharedRepo diff -- app.txt) -join "`n"

    $report.details.check6Sub = [ordered]@{
        leaseA = $leaseA.Ok; leaseBRo = $leaseBRo.Ok; leaseBConflict = $leaseBConflict.Code
        cliEditAOk = $cliEditA.ok; cliEditAWrite = $cliEditA.writeOk; cliEditAErr = $cliEditA.writeError; cliEditAApiErr = $cliEditA.apiError; diffAMatch = ($diffAfterA -match 'updated-by-space-a')
        cliRWBOk = $cliReadWriteB.ok; cliRWBReadMatch = ($cliReadWriteB.readResult -match 'updated-by-space-a'); cliRWBWriteOk = $cliReadWriteB.writeOk
        briefClean = $briefClean; handoffBlockedCode = $handoffBlocked.Code; handoffOk = $handoffOk.Ok
        snapB2State = "$($snapB2.State)"; cliEditBOk = $cliEditB.ok; cliEditBReadMatch = ($cliEditB.readResult -match 'Cross-Space Task Handoff Brief'); cliEditBWrite = $cliEditB.writeOk; cliEditBErr = $cliEditB.writeError; diffBMatch = ($diffAfterB -match 'updated-by-space-b-after-handoff')
    }
    $report.checks.sharedRepoSingleWriterAndHandoff =
        $leaseA.Ok -and $leaseBRo.Ok -and (!$leaseBConflict.Ok -and $leaseBConflict.Code -ceq 'WRITE_CONFLICT') -and
        $cliEditA.ok -and $cliEditA.writeOk -and $cliEditA.jsonlExists -and ($diffAfterA -match 'updated-by-space-a') -and
        $cliReadWriteB.ok -and ($cliReadWriteB.readResult -match 'updated-by-space-a') -and (!$cliReadWriteB.writeOk) -and
        $briefClean -and (!$handoffBlocked.Ok -and $handoffBlocked.Code -ceq 'WRITER_STILL_RUNNING') -and
        $handoffOk.Ok -and ($handoffOk.Holder -eq [ClaudeStudio.ControlPlane.SpaceId]::B) -and
        ($snapB2.State -eq [ClaudeStudio.ControlPlane.SpaceNetworkState]::ProxyOnline) -and
        $cliEditB.ok -and ($cliEditB.readResult -match 'Cross-Space Task Handoff Brief') -and $cliEditB.writeOk -and $cliEditB.jsonlExists -and
        ($diffAfterB -match 'updated-by-space-b-after-handoff')

    # === CHECK 7: All 5 AGENTS.md Locale & Timezone Readings Honestly Recorded ===
    $hostBias = -[int][TimeZoneInfo]::Local.BaseUtcOffset.TotalMinutes
    $report.details.localeMatrix = [ordered]@{
        spaceA = [ordered]@{
            windowLang = $readyA.windowLanguage; rendererTz = $readyA.rendererTimezone; rendererFormatted = $readyA.rendererRefUtcFormatted
            requestAcceptLang = $chatBodyA.accept_language_seen; childLang = $mcpA.langEnv; childTz = $mcpA.tzEnv
            winNativeBias = $readyA.nativeTimezone.biasMinutes; winNativeStd = $readyA.nativeTimezone.standardName
        }
        spaceB = [ordered]@{
            windowLang = $readyB.windowLanguage; rendererTz = $readyB.rendererTimezone; rendererFormatted = $readyB.rendererRefUtcFormatted
            requestAcceptLang = $chatBodyB.accept_language_seen; childLang = $mcpB.langEnv; childTz = $mcpB.tzEnv
            winNativeBias = $readyB.nativeTimezone.biasMinutes; winNativeStd = $readyB.nativeTimezone.standardName
        }
    }
    $report.checks.localeFiveReadingsHonest =
        ($readyA.windowLanguage -ceq 'zh-CN') -and ($readyB.windowLanguage -ceq 'en-US') -and
        ($readyA.rendererTimezone -ceq 'Asia/Shanghai') -and ($readyB.rendererTimezone -ceq 'America/Los_Angeles') -and
        ($readyA.rendererRefUtcFormatted -ceq '2026-07-01T20:00:00+08:00') -and ($readyB.rendererRefUtcFormatted -ceq '2026-07-01T05:00:00-07:00') -and
        ($chatBodyA.accept_language_seen -ceq 'zh-CN,zh;q=0.9') -and ($chatBodyB.accept_language_seen -ceq 'en-US,en;q=0.9') -and
        ($mcpA.langEnv -ceq 'zh_CN.UTF-8') -and ($mcpA.tzEnv -ceq 'Asia/Shanghai') -and
        ($mcpB.langEnv -ceq 'en_US.UTF-8') -and ($mcpB.tzEnv -ceq 'America/Los_Angeles') -and
        ($readyA.nativeTimezone.biasMinutes -eq $hostBias) -and ($readyB.nativeTimezone.biasMinutes -eq $hostBias)

    # Check sentinel zero-hits
    while ($sentinelTcpListener.Pending()) { $c = $sentinelTcpListener.AcceptTcpClient(); $c.Close(); $sentinelTcpHits++ }
    $udpBuf = New-Object byte[] 256
    while ($sentinelUdpSocket.Available -gt 0) { $null = $sentinelUdpSocket.Receive($udpBuf); $sentinelUdpHits++ }
    $report.details.sentinelHits = [ordered]@{ tcp = $sentinelTcpHits; udp = $sentinelUdpHits }

    # === CHECK 8: Emergency Kill-Switch & Zero Residual WFP ===
    $null = Send-TwinCmd 'B' @{ action = 'finish' }
    $engine.EmergencyKillSwitchAll()
    $resTotal = 0
    foreach ($csid in $retiredContainerSids) { $resTotal += [StudioLabWfp]::CountFiltersReferencingPackage($csid) }
    $report.cleanup.residualPackageFilters = $resTotal
    $report.checks.killSwitchAndZeroBypass = ($resTotal -eq 0) -and ($sentinelTcpHits -eq 0) -and ($sentinelUdpHits -eq 0)
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($engine) { try { $engine.Dispose() } catch { } }
    if ($liveBackend) { try { $liveBackend.Dispose() } catch { } }
    if ($upstreamEntry) { try { Stop-N3Process $upstreamEntry } catch { } }
    if ($apiProc) { try { if (!$apiProc.process.HasExited) { $apiProc.process.Kill(); [void]$apiProc.process.WaitForExit(2000) } $apiProc.process.Dispose() } catch { } }
    if ($sentinelTcpListener) { try { $sentinelTcpListener.Stop() } catch { } }
    if ($sentinelUdpSocket) { try { $sentinelUdpSocket.Dispose() } catch { } }
    Start-Sleep -Milliseconds 180

    if ($hostListener -and $hostOld) { try { $null = Test-HostHealth 'restored' 81 } catch { } }
    if ($dnsTrace) {
        try {
            $dnsRes = Stop-LabDnsTrace -Trace $dnsTrace -MeasureLoss
            $psecSR = @($dnsRes.events | Where-Object { $_.role -eq 'psec' -and ($_.event -in 3010,3011) }).Count
            $unkSR = @($dnsRes.events | Where-Object { !$_.role -and ($_.event -in 3010,3011) }).Count
            $hSends = @($dnsRes.events | Where-Object { $_.role -eq 'host' -and $_.event -eq 3010 }).Count
            $lZero = ($null -ne $dnsRes.lossBeforeStop) -and ($dnsRes.lossBeforeStop.eventsLost -eq 0) -and ($dnsRes.lossBeforeStop.logBuffersLost -eq 0) -and ($dnsRes.lossBeforeStop.realtimeBuffersLost -eq 0)
            $report.dnsSummary = [ordered]@{ servicePidStable = ($dnsRes.servicePid -eq $dnsRes.servicePidAfter); lossZero = $lZero; psecSendReplyCount = $psecSR; unknownSendReplyCount = $unkSR; hostSendCount = $hSends }
            $report.checks.dnsZeroLeak = $report.dnsSummary.servicePidStable -and $lZero -and ($psecSR -eq 0) -and ($unkSR -eq 0) -and ($hSends -ge 4)
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
    if ($dirCreated -and (Test-Path -LiteralPath $base)) { try { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop } catch { $report.cleanup.errors += @("base: $($_.Exception.Message)") } }

    $report.cleanup.directoryGone = !(Test-Path -LiteralPath $base)
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
        $report.cleanup.directoryGone -and $report.cleanup.repoGone -and
        $report.cleanup.labAGone -and $report.cleanup.labBGone -and $report.cleanup.profAGone -and $report.cleanup.profBGone

    $allOk = (!$report.error) -and ($report.checks.Values -notcontains $false) -and ($report.checks.Count -ge 11)
    $report.outcome = if ($allOk) { 'passed-ab-phase7-realistic-twins' } else { 'stopped-ab-phase7-realistic-twins' }
    $report.utcFinished = [datetime]::UtcNow.ToString('o')

    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
    $sha12 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.Substring(0, 12)
    [IO.File]::WriteAllText($SummaryPath, ([ordered]@{
        runId = $RunId; outcome = $report.outcome; reportPath = $ReportPath; reportSha256Prefix12 = $sha12; error = $report.error
        checks = $report.checks; details = $report.details; dnsSummary = $report.dnsSummary; cleanup = $report.cleanup
    } | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
}
