[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$UpstreamHost = '127.0.0.1',
    [int]$UpstreamPort = 0,
    [switch]$LiveForwardUpstream,
    [string]$PkgInstallLocation,
    [string]$PkgVersion,
    [string]$PkgFamilyName
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) { throw 'Run in x64 Windows PowerShell 5.1' }

if ($UpstreamPort -eq 10810) {
    throw 'Port 10810 is the host reserved proxy port and is blocked by default. Specify an independent upstream port.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$Elevated) {
    $pkgLocal = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$pkgLocal -or !(Test-Path -LiteralPath (Join-Path $pkgLocal.InstallLocation 'app\claude.exe'))) {
        throw 'Official Claude Desktop MSIX installation not found for current user.'
    }
    if ($isAdmin) {
        & $PSCommandPath -Elevated -UpstreamHost $UpstreamHost -UpstreamPort $UpstreamPort -LiveForwardUpstream:$LiveForwardUpstream `
            -PkgInstallLocation $pkgLocal.InstallLocation -PkgVersion $pkgLocal.Version -PkgFamilyName $pkgLocal.PackageFamilyName
    } else {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $fwdFlag = if ($LiveForwardUpstream) { ' -LiveForwardUpstream' } else { '' }
        $argLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated -UpstreamHost "' + $UpstreamHost + '" -UpstreamPort ' + $UpstreamPort + $fwdFlag +
            ' -PkgInstallLocation "' + $pkgLocal.InstallLocation + '" -PkgVersion "' + $pkgLocal.Version + '" -PkgFamilyName "' + $pkgLocal.PackageFamilyName + '"'
        Start-Process -FilePath $psExe -Verb RunAs -ArgumentList $argLine
    }
    return
}

# Interactive STA WPF host inside elevated session with guaranteed 100% rollback on window close!
if ([Threading.Thread]::CurrentThread.ApartmentState -ne [Threading.ApartmentState]::STA) {
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $fwdFlag = if ($LiveForwardUpstream) { ' -LiveForwardUpstream' } else { '' }
    & $psExe -STA -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Elevated -UpstreamHost $UpstreamHost -UpstreamPort $UpstreamPort -LiveForwardUpstream:$LiveForwardUpstream `
        -PkgInstallLocation $PkgInstallLocation -PkgVersion $PkgVersion -PkgFamilyName $PkgFamilyName
    return
}

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

$binDir = Join-Path $PSScriptRoot 'bin'
$cpExe = Join-Path $binDir 'ClaudeStudioControlPlane.exe'
if (!(Test-Path -LiteralPath $cpExe)) {
    & (Join-Path $PSScriptRoot 'build.ps1') | Out-Null
}
[void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($cpExe))

$runId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$hostSid = $identity.User.Value
$tag = "ClaudeStudioGuiLab-$runId"
$sharedAppStage = Join-Path $env:ProgramData ("ClaudeStudioGuiApp-$runId")
$srcAppDir = Join-Path $PkgInstallLocation 'app'
$users = @{}; $tokens = @{}
$sharedAppCreated = $false; $localTestUpstream = $null; $backend = $null; $engine = $null

try {
    if ((Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue) -or (Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)) {
        throw 'Existing ClaudeStudioLabA or ClaudeStudioLabB account detected; refusing to overwrite.'
    }

    Write-Host "[Claude Studio Lab] Creating ephemeral standard users A/B and read-only official app staging copy..." -ForegroundColor Cyan
    foreach ($sk in @('A','B')) {
        $uName = "ClaudeStudioLab$sk"
        $pw = New-RandomStrongPassword
        $u = New-LocalUser -Name $uName -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description "Ephemeral GUI Lab $sk"
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

    $zeroEgress = !$LiveForwardUpstream
    $effPort = $UpstreamPort
    if ($effPort -le 0) {
        $localTestUpstream = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $localTestUpstream.Start()
        $effPort = $localTestUpstream.LocalEndpoint.Port
        $zeroEgress = $true
    }

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

    $backend = [ClaudeStudio.ControlPlane.RealDesktopPsecBackend]::new($specA, $specB, $binDir, $UpstreamHost, $effPort, $zeroEgress)
    $engine = [ClaudeStudio.ControlPlane.StudioEngine]::new($backend)
    $errUp = ''
    [void]$engine.ConfigureUpstream($UpstreamHost, $effPort, $false, [ref]$errUp)

    Write-Host "[Claude Studio Lab] Ready! Opening interactive WPF Control Plane (zeroEgress=$zeroEgress, upstream=$($UpstreamHost):$effPort). Close window for 100% automatic rollback." -ForegroundColor Green
    $app = [System.Windows.Application]::Current
    if (!$app) { $app = New-Object System.Windows.Application }
    $win = New-Object ClaudeStudio.ControlPlane.MainWindow($engine)
    [void]$app.Run($win)
} finally {
    Write-Host "[Claude Studio Lab] Rolling back WFP filters, processes, staged app copy, and ephemeral accounts..." -ForegroundColor Yellow
    if ($engine) { try { $engine.Dispose() } catch { } }
    if ($backend) { try { $backend.Dispose() } catch { } }
    if ($localTestUpstream) { try { $localTestUpstream.Stop() } catch { } }
    Start-Sleep -Milliseconds 400
    foreach ($sk in @('A','B')) {
        if ($tokens.ContainsKey($sk)) {
            try { [StudioPsecGuardHost]::UnloadLabProfile($tokens[$sk].orig, $tokens[$sk].prof) } catch { }
            foreach ($tk in @($tokens[$sk].copy, $tokens[$sk].orig)) { if ($tk -ne [IntPtr]::Zero) { try { [StudioPsecGuardHost]::CloseToken($tk) } catch { } } }
        }
        if ($users.ContainsKey($sk)) {
            $uName = $users[$sk].name; $uSid = $users[$sk].sid
            try { $pr = Get-CimInstance Win32_UserProfile -Filter ("SID = '" + $uSid + "'") -ErrorAction SilentlyContinue; if ($pr) { Remove-CimInstance -InputObject $pr -ErrorAction SilentlyContinue } } catch { }
            try { if (Test-Path -LiteralPath "C:\Users\$uName") { Remove-Item -LiteralPath "C:\Users\$uName" -Recurse -Force -ErrorAction SilentlyContinue } } catch { }
            try { Remove-LocalUser -Name $uName -ErrorAction SilentlyContinue } catch { }
        }
    }
    if ($sharedAppCreated -and (Test-Path -LiteralPath $sharedAppStage)) { try { Remove-Item -LiteralPath $sharedAppStage -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
    Write-Host "[Claude Studio Lab] Rollback complete." -ForegroundColor Green
}
