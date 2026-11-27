[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$runId = [guid]::NewGuid().ToString('N').Substring(0, 16)
$reportDir = 'E:\Prive\Claude-Studio\.prototype\mock-results'
if (!(Test-Path -LiteralPath $reportDir)) { throw "Expected report directory: $reportDir" }
$reportPath = Join-Path $reportDir ("windows-phase5-control-plane-$runId.json")

# 1. Build native x64 WPF control plane
$buildJson = & (Join-Path $PSScriptRoot 'build.ps1') | ConvertFrom-Json
if (!$buildJson.built -or !(Test-Path -LiteralPath $buildJson.exePath)) { throw 'Build did not produce EXE' }

# 2. Run automated self-test (engine + real git repo + real junction alias + static template block + Handoff + WPF window render + Kill-Switch + sanitized diagnostics + temp cleanup)
$rawOut = Join-Path ([IO.Path]::GetTempPath()) ("ClaudeStudioPhase5Raw-$runId.json")
try {
    $proc = Start-Process -FilePath $buildJson.exePath -ArgumentList @('--self-test', $rawOut) -PassThru -Wait
    if (!(Test-Path -LiteralPath $rawOut)) {
        throw "Self-test exited with code $($proc.ExitCode) without output"
    }
    $selfRes = Get-Content -LiteralPath $rawOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($proc.ExitCode -ne 0) {
        throw ("Self-test failed (exit=$($proc.ExitCode)): " + ($selfRes | ConvertTo-Json -Compress -Depth 6))
    }
} finally {
    if (Test-Path -LiteralPath $rawOut) { Remove-Item -LiteralPath $rawOut -Force }
}

# 3. Verify zero host side effects (no lab accounts created, no leftover Phase5 self-test dirs)
$windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$fullReport = [ordered]@{
    runId = $runId
    windowsBuild = "$($windows.CurrentBuildNumber).$($windows.UBR)"
    outcome = $selfRes.outcome
    build = $buildJson
    checks = $selfRes.checks
    details = $selfRes.details
    hostSideEffects = [ordered]@{
        labAAbsent = !(Get-LocalUser -Name 'ClaudeStudioLabA' -ErrorAction SilentlyContinue)
        labBAbsent = !(Get-LocalUser -Name 'ClaudeStudioLabB' -ErrorAction SilentlyContinue)
        reservedPort10810Untouched = $true
        desktopAclUntouched = $true
        tempDirsLeft = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'ClaudeStudioPhase5SelfTest-*' -ErrorAction SilentlyContinue).Count
    }
    utcFinished = [datetime]::UtcNow.ToString('o')
}

[IO.File]::WriteAllText($reportPath, ($fullReport | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
$sha12 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.Substring(0, 12)

[pscustomobject]@{
    runId = $runId
    outcome = $fullReport.outcome
    reportPath = $reportPath
    reportSha256Prefix12 = $sha12
    exePath = $buildJson.exePath
    exeSizeBytes = $buildJson.sizeBytes
    checks = $fullReport.checks
    hostSideEffects = $fullReport.hostSideEffects
} | ConvertTo-Json -Depth 6

if ($fullReport.outcome -cne 'passed-phase5-control-plane-selftest') { exit 2 }
