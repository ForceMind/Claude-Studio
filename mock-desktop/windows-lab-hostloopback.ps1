param([switch]$PortGuard,[switch]$FlowChecks,[switch]$StaticGuard,[switch]$BindGuard)
if($BindGuard){$StaticGuard=$true}
if($StaticGuard){$FlowChecks=$true}
if($FlowChecks){$PortGuard=$true}
# Runs the approved A-only healthy gate. Later phases require this gate to pass.
# The official ZIP entry is downloaded separately without using the host proxy.
$ErrorActionPreference = 'Stop'
$lab=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
$reportPath=Join-Path $lab '..\mock-results\windows-psec-hostloopback.json'
if($PortGuard) {$reportPath=Join-Path $lab '..\mock-results\windows-psec-hostloopback-portguard.json'}
if($FlowChecks) {$reportPath=Join-Path $lab '..\mock-results\windows-psec-hostloopback-portguard-flows.json'}
if($StaticGuard) {$reportPath=Join-Path $lab '..\mock-results\windows-psec-static-guard.json'}
if($BindGuard) {$reportPath=Join-Path $lab '..\mock-results\windows-psec-bind-guard.json'}
if (Test-Path -LiteralPath $reportPath) { throw 'Preserve the previous report before rerunning' }
$stage=Join-Path $lab ('psec-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
$entry=Join-Path $lab 'mxc-x64-entry.bin'
$cleanup=[ordered]@{}
$testExit=1
try {
    $bytes=[IO.File]::ReadAllBytes($entry)
    if ([BitConverter]::ToUInt32($bytes,0) -ne 0x04034b50 -or [BitConverter]::ToUInt16($bytes,8) -ne 8) { throw 'Unexpected ZIP entry' }
    $nameLength=[BitConverter]::ToUInt16($bytes,26)
    $extraLength=[BitConverter]::ToUInt16($bytes,28)
    if ([Text.Encoding]::UTF8.GetString($bytes,30,$nameLength) -cne 'x64/wxc-exec.exe') { throw 'Wrong executor entry' }
    $compressedStream=[IO.MemoryStream]::new($bytes,30+$nameLength+$extraLength,4514455)
    $inflate=[IO.Compression.DeflateStream]::new($compressedStream,[IO.Compression.CompressionMode]::Decompress)
    $executor=Join-Path $stage 'wxc-exec.exe'
    $output=[IO.File]::Create($executor)
    try { $inflate.CopyTo($output) } finally { $output.Dispose(); $inflate.Dispose(); $compressedStream.Dispose() }
    if ((Get-FileHash -LiteralPath $executor -Algorithm SHA256).Hash -cne 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D') { throw 'Executor SHA-256 mismatch' }
    if(!$PortGuard) {
    $baselinePath=Join-Path $lab '..\mock-results\windows-psec-hostloopback-baseline.json'
    if (Test-Path -LiteralPath $baselinePath) { throw 'Preserve the previous baseline before rerunning' }
    & (Join-Path $PSScriptRoot 'windows-lab-psec-stopped.ps1') -Stage $stage -Networkless -ReferenceRun
    $baseline=Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($baseline.assessment.outcome -cne 'no-leak-observed-without-network-capabilities') { throw 'The same-binary zero-network control did not pass' }
    }
    & (Join-Path $PSScriptRoot 'windows-lab-psec-stopped.ps1') -Stage $stage -HostLoopback -PortGuard:$PortGuard -FlowChecks:$FlowChecks -StaticGuard:$StaticGuard -BindGuard:$BindGuard
    $testExit=$LASTEXITCODE
} finally {
    # Restrict cleanup to this newly-created, resolved stage and its own binaries.
    $resolved=(Resolve-Path -LiteralPath $stage).Path
    if ((Split-Path $resolved -Parent) -ne $lab -or (Split-Path $resolved -Leaf) -notmatch '^psec-[a-f0-9]{32}$') { throw 'Cleanup path mismatch' }
    $owned=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($resolved+'\',[StringComparison]::OrdinalIgnoreCase) })
    $cleanup.forcedPids=@()
    foreach ($item in $owned) {
        $process=Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if(!$process){continue}
        try {
            [void]$process.Handle
            if($process.HasExited){continue}
            if($process.MainModule.FileName -ine $item.ExecutablePath -or
                [Math]::Abs(($process.StartTime.ToUniversalTime()-$item.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 1){continue}
            $cleanup.forcedPids+=@($process.Id);$process.Kill()
            if(!$process.WaitForExit(2000)){throw 'Stage process failed to exit'}
        }finally{$process.Dispose()}
    }
    $cleanup.remainingStagePids=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($resolved+'\',[StringComparison]::OrdinalIgnoreCase) } | ForEach-Object ProcessId)
    if ($cleanup.remainingStagePids.Count) { throw 'Stage process cleanup failed' }
    if (@(Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Unexpected reparse point in stage' }
    if($StaticGuard){
        if(!(Test-Path -LiteralPath $reportPath)){throw ('N1 evidence missing; retain rollback binaries at '+$resolved)}
        $lastReport=Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8|ConvertFrom-Json
        $verifiedAbsence=$lastReport.observer.staticGuardCleanup.absent -and (!$BindGuard -or $lastReport.observer.staticGuardCleanup.bindAbsent)
        $preWriteFailure=$BindGuard -and (!$lastReport.observer -and !$lastReport.windowReady -and
            ($lastReport.bindGuard.noObserverNoRuleWrite -or !$lastReport.bindGuard.privateAclProtected))
        if(!$verifiedAbsence -and !$preWriteFailure){throw ('Guard cleanup unverified; retain rollback binaries at '+$resolved)}
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $cleanup.stageGone=!(Test-Path -LiteralPath $resolved)
    if (Test-Path -LiteralPath $reportPath) {
        $report=Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $report | Add-Member -NotePropertyName stageCleanup -NotePropertyValue $cleanup -Force
        if($BindGuard){
            $report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-bind-result.ps1') $report
            $testExit=if($report.assessment.outcome -eq 'passed-bind-guard-n2'){0}else{2}
        }elseif($StaticGuard){
            $report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-static-guard-result.ps1') $report
            $testExit=if($report.assessment.outcome -eq 'passed-static-guard-n1'){0}elseif($report.assessment.outcome -like 'failed-*'){2}else{1}
        }
        [IO.File]::WriteAllText($reportPath,($report | ConvertTo-Json -Depth 16))
        if($StaticGuard){$report.assessment|ConvertTo-Json -Depth 5}
    }
    $cleanup | ConvertTo-Json -Compress
}
exit $testExit
