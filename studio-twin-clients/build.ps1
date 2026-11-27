[CmdletBinding()]
param(
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
if (!$OutDir) { $OutDir = Join-Path $PSScriptRoot 'bin' }

$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $csc)) { throw 'Expected x64 .NET Framework 4.x csc.exe' }
if (!(Test-Path -LiteralPath $OutDir)) { [void][IO.Directory]::CreateDirectory($OutDir) }

$srcDir = Join-Path $PSScriptRoot 'src'
$shared = Join-Path $srcDir 'TwinShared.cs'
$cliExe = Join-Path $OutDir 'ClaudeCliTwin.exe'
$deskExe = Join-Path $OutDir 'ClaudeDesktopTwin.exe'

$o1 = & $csc /nologo /platform:x64 /target:exe /optimize+ /warn:4 /reference:System.Web.Extensions.dll "/out:$cliExe" $shared (Join-Path $srcDir 'ClaudeCliTwin.cs') 2>&1
if ($LASTEXITCODE -ne 0) { throw ("ClaudeCliTwin build failed:`n" + ($o1 -join "`n")) }

$o2 = & $csc /nologo /platform:x64 /target:winexe /optimize+ /warn:4 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$deskExe" $shared (Join-Path $srcDir 'ClaudeDesktopTwin.cs') 2>&1
if ($LASTEXITCODE -ne 0) { throw ("ClaudeDesktopTwin build failed:`n" + ($o2 -join "`n")) }

[pscustomobject]@{
    built = $true
    cliExe = $cliExe
    cliBytes = (Get-Item -LiteralPath $cliExe).Length
    cliSha12 = (Get-FileHash -LiteralPath $cliExe -Algorithm SHA256).Hash.Substring(0, 12)
    desktopExe = $deskExe
    desktopBytes = (Get-Item -LiteralPath $deskExe).Length
    desktopSha12 = (Get-FileHash -LiteralPath $deskExe -Algorithm SHA256).Hash.Substring(0, 12)
} | ConvertTo-Json -Compress
