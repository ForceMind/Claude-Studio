# This body is passed by value to a short-lived elevated observer. Its input,
# ETL and control files live in a new private directory owned by the host user.
$ErrorActionPreference = 'Stop'
function Get-PsecFilterSnapshot([string]$ContainerSid) {
    if ($ContainerSid -notmatch '^S-1-15-2(-[0-9]+){7}$') { throw 'Invalid test AppContainer SID' }
    $xmlFile = Join-Path $privateDir 'filters.xml'
    try {
        $start=[Diagnostics.ProcessStartInfo]::new('netsh.exe',('wfp show filters file="'+$xmlFile+'" verbose=on'))
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($start)
        try {
            $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
            if(!$process.WaitForExit(10000)){$process.Kill();[void]$process.WaitForExit(1500);throw 'WFP snapshot timed out'}
            if($process.ExitCode -ne 0){throw ('WFP snapshot failed: '+$process.ExitCode)}
        } finally {$process.Dispose()}
        $xml = [xml]([IO.File]::ReadAllText($xmlFile))
        $filters = @($xml.SelectNodes("//*[local-name()='filterKey']/.."))
        if (!$filters.Count) { throw 'Empty WFP filter inventory' }
        $owned = @($filters | Where-Object { $_.InnerText.Contains($ContainerSid) } | ForEach-Object {
            [pscustomobject]@{key=[string]$_.filterKey; layer=[string]$_.layerKey; sublayer=[string]$_.subLayerKey}
        })
        return @{matched=$owned; inspected=$filters.Count}
    } finally { if (Test-Path -LiteralPath $xmlFile) { Remove-Item -LiteralPath $xmlFile } }
}
$trace = $null
$evidence = [ordered]@{}
$clientSid = $null
try {
    if ($guardControlSource) { . $guardControlSource }
    $trace = Start-LabDnsTrace $privateDir $prefix
    [IO.File]::WriteAllText((Join-Path $privateDir 'ready'),'1')
    $end = [datetime]::UtcNow.AddSeconds($(if($n2GuardMode){150}elseif($staticGuardMode){120}elseif($guardControlSource){195}else{115}))
    $capture = Join-Path $privateDir 'sample'
    while (!(Test-Path -LiteralPath (Join-Path $privateDir 'stop'))) {
        if (!$clientSid -and (Test-Path -LiteralPath $capture)) {
            $clientSid = [IO.File]::ReadAllText($capture).Trim()
            try { $evidence.live = Get-PsecFilterSnapshot $clientSid }
            catch { $evidence.liveError=$_.Exception.Message }
            [IO.File]::WriteAllText((Join-Path $privateDir 'sampled'),'1')
        }
        if ([datetime]::UtcNow -gt $end) { throw 'Observer timed out' }
        if ($guardControlSource -and ($clientSid -or $n2GuardMode)) { Invoke-GuardMailbox }
        Start-Sleep -Milliseconds 100
    }
} catch { $evidence.error = $_.Exception.Message }
finally {
    if ($guardControlSource -and (Get-Command Close-GuardOwner -ErrorAction SilentlyContinue)) { Close-GuardOwner }
    if ($trace) {
        try { $evidence.dns = Stop-LabDnsTrace $trace -MeasureLoss }
        catch { $evidence.traceError=$_.Exception.Message }
        # In case of an interrupted stop, clean up only our random session.
        $null = & logman.exe query $prefix -ets 2>&1
        if ($LASTEXITCODE -eq 0) { $null = & logman.exe stop $prefix -ets }
        $null = & logman.exe query $prefix -ets 2>&1
        $evidence.sessionGone = $LASTEXITCODE -ne 0
        if (Test-Path -LiteralPath $trace.file) { Remove-Item -LiteralPath $trace.file }
        $evidence.rawTraceGone = !(Test-Path -LiteralPath $trace.file)
    }
    if ($clientSid) {
        try {
            $evidence.after = Get-PsecFilterSnapshot $clientSid
            if ($evidence.after.matched.Count) {
                Start-Sleep -Seconds 3
                $evidence.after = Get-PsecFilterSnapshot $clientSid
            }
        } catch { $evidence.readbackError=$_.Exception.Message }
    }
    [IO.File]::WriteAllText((Join-Path $privateDir 'result.json'), ($evidence | ConvertTo-Json -Depth 10))
}
