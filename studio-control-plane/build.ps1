[CmdletBinding()]
param(
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
if (!$OutDir) { $OutDir = Join-Path $PSScriptRoot 'bin' }

$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$wpfDir = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\WPF'
if (!(Test-Path -LiteralPath $csc) -or !(Test-Path -LiteralPath (Join-Path $wpfDir 'PresentationFramework.dll'))) {
    throw 'Expected x64 .NET Framework 4.x csc.exe and WPF assemblies'
}

if (!(Test-Path -LiteralPath $OutDir)) { [void][IO.Directory]::CreateDirectory($OutDir) }
$outExe = Join-Path $OutDir 'ClaudeStudioControlPlane.exe'
$repoRoot = Split-Path $PSScriptRoot -Parent
$fixturesDir = Join-Path $repoRoot 'mock-desktop\fixtures\startup-permissions'
$mockDir = Join-Path $repoRoot 'mock-desktop'

$srcDir = Join-Path $PSScriptRoot 'src'
$nativeDir = Join-Path $PSScriptRoot 'native'
$sources = @(
    (Join-Path $srcDir 'ControlPlaneModels.cs'),
    (Join-Path $srcDir 'ProjectLeaseManager.cs'),
    (Join-Path $srcDir 'HandoffGenerator.cs'),
    (Join-Path $srcDir 'OAuthCallbackRouter.cs'),
    (Join-Path $srcDir 'StudioConfig.cs'),
    (Join-Path $srcDir 'ClientAdapter.cs'),
    (Join-Path $srcDir 'EmbeddedProxyRelay.cs'),
    (Join-Path $srcDir 'NtfsSingleWriterEnforcer.cs'),
    (Join-Path $srcDir 'LivePsecBackend.cs'),
    (Join-Path $srcDir 'RealDesktopPsecBackend.cs'),
    (Join-Path $srcDir 'StudioEngine.cs'),
    (Join-Path $srcDir 'MainWindow.cs'),
    (Join-Path $srcDir 'Program.cs'),
    (Join-Path $fixturesDir 'DesktopRead.cs'),
    (Join-Path $fixturesDir 'PsecStartupGuard.cs'),
    (Join-Path $mockDir 'windows-lab-n4-preflight.cs'),
    (Join-Path $mockDir 'windows-lab-wfp.cs'),
    (Join-Path $mockDir 'windows-lab-wfp-container.cs')
)

$args = @(
    '/nologo',
    '/platform:x64',
    '/target:winexe',
    '/main:ClaudeStudio.ControlPlane.Program',
    '/optimize+',
    '/define:N4_HOST_CREATE',
    '/warn:4',
    "/out:$outExe",
    "/reference:$(Join-Path $wpfDir 'PresentationFramework.dll')",
    "/reference:$(Join-Path $wpfDir 'PresentationCore.dll')",
    "/reference:$(Join-Path $wpfDir 'WindowsBase.dll')",
    '/reference:System.Xaml.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Web.Extensions.dll'
) + $sources

$output = & $csc @args 2>&1
if ($LASTEXITCODE -ne 0) {
    throw ("Build failed:`n" + ($output -join "`n"))
}

# Build standalone ProxyOwner helper (holds ONLY FWPM_SESSION_FLAG_DYNAMIC exception E)
$ownerExe = Join-Path $OutDir 'StudioProxyOwner.exe'
$oOut = & $csc /nologo /platform:x64 /target:exe /optimize+ /warn:4 /reference:System.Web.Extensions.dll "/out:$ownerExe" `
    (Join-Path $fixturesDir 'Phase1ProxyOwner.cs') (Join-Path $mockDir 'windows-lab-wfp.cs') (Join-Path $mockDir 'windows-lab-wfp-container.cs') 2>&1
if ($LASTEXITCODE -ne 0) {
    throw ("StudioProxyOwner build failed:`n" + ($oOut -join "`n"))
}

# Build pure-C native Layer-1 PSEC Creator & Layer-2 Container Guardian helpers (zero runtime MSVC needed!)
$l1Exe = Join-Path $OutDir 'StudioLayer1Psec.exe'
$l2Exe = Join-Path $OutDir 'StudioLayer2DesktopHost.exe'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (Test-Path -LiteralPath $vcvars) {
    $objDir = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioCpBuild-' + [guid]::NewGuid().ToString('N').Substring(0,8))
    [void][IO.Directory]::CreateDirectory($objDir)
    try {
        $clCmd = 'call "' + $vcvars + '" >nul && ' +
            'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $objDir 'l1.obj') + '" "' + (Join-Path $fixturesDir 'layer1_psec_launcher.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l1Exe + '" kernel32.lib advapi32.lib && ' +
            'cl /nologo /W4 /O2 /MT /GS /Fo"' + (Join-Path $objDir 'l2.obj') + '" "' + (Join-Path $nativeDir 'l2_desktop_host.c') + '" /link /SUBSYSTEM:WINDOWS /OUT:"' + $l2Exe + '" kernel32.lib'
        $clOut = & cmd.exe /c $clCmd 2>&1
        if ($LASTEXITCODE -ne 0) { throw ("Native helpers build failed:`n" + ($clOut -join "`n")) }
    } finally {
        if (Test-Path -LiteralPath $objDir) { Remove-Item -LiteralPath $objDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

$hash = (Get-FileHash -LiteralPath $outExe -Algorithm SHA256).Hash
[pscustomobject]@{
    built = $true
    exePath = $outExe
    sizeBytes = (Get-Item -LiteralPath $outExe).Length
    sha256Prefix12 = $hash.Substring(0, 12)
    helpers = [ordered]@{
        proxyOwner = (Test-Path -LiteralPath $ownerExe)
        layer1 = (Test-Path -LiteralPath $l1Exe)
        layer2 = (Test-Path -LiteralPath $l2Exe)
    }
} | ConvertTo-Json -Compress
