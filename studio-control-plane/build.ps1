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
$sources = @(
    (Join-Path $srcDir 'ControlPlaneModels.cs'),
    (Join-Path $srcDir 'ProjectLeaseManager.cs'),
    (Join-Path $srcDir 'HandoffGenerator.cs'),
    (Join-Path $srcDir 'ClientAdapter.cs'),
    (Join-Path $srcDir 'LivePsecBackend.cs'),
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

$hash = (Get-FileHash -LiteralPath $outExe -Algorithm SHA256).Hash
[pscustomobject]@{
    built = $true
    exePath = $outExe
    sizeBytes = (Get-Item -LiteralPath $outExe).Length
    sha256Prefix12 = $hash.Substring(0, 12)
} | ConvertTo-Json -Compress
