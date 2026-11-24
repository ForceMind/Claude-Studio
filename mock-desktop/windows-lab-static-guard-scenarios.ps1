# N1 reuses protocol helpers only; it never runs the earlier proxy-fault matrix.
. (Join-Path $PSScriptRoot 'windows-lab-portguard-scenarios.ps1') -FunctionsOnly
function Invoke-StaticControl([string]$Command){
    $path=Join-Path $privateDir ('guard-'+$Command)
    [IO.File]::WriteAllText($path,'1');Wait-GuardFile ($path+'-done')
    return (Get-Content -LiteralPath ($path+'-done') -Raw -Encoding UTF8|ConvertFrom-Json)
}
$null=Check-Phase 'healthy1' $true -Native
$stream=Invoke-Flow 'start-stream' 'healthy1'
$report.staticGuard.initialFlow=$stream.flow
$crash=Invoke-StaticControl 'crash'
$report.staticGuard.managerCrash=$crash
$report.staticGuard.afterCrashReadback=$crash.readback
$deadline=[datetimeoffset]::Parse($crash.exitSignalUtc).UtcDateTime.AddSeconds(3)
do {
    $snapshot=Invoke-Flow 'snapshot' 'crash'
    if([datetime]::UtcNow -gt $deadline){throw 'N1 old-flow offline deadline exceeded'}
    if(!$snapshot.flow.socketInvalid){Start-Sleep -Milliseconds 30}
} while(!$snapshot.flow.socketInvalid)
$command=Invoke-Flow 'probe' 'crash'
$hits=Get-DirectHits
if($command.probe.windowHttp -ne 'ConnectFailure' -or $command.probe.system.dnsQueryStatus -ne 5 -or
    $command.probe.system.getAddrInfoStatus -ne 11001 -or @($hits.Values|Where-Object {$_ -ne 0}).Count){throw 'N1 new requests not blocked after owner exit'}
$crash|Add-Member offlineUtc ([datetime]::UtcNow.ToString('o'))
$crash|Add-Member windowProbe $command.probe
if([datetimeoffset]::Parse($crash.offlineUtc).UtcDateTime -gt $deadline){throw 'N1 offline verification deadline exceeded'}
$alive=@{}
foreach($item in @(@{key='window';pid=$report.windowReady.pid},@{key='listener';pid=$report.windowReady.listenerReady.pid},@{key='proxy';pid=$report.proxyReady.pid})){
    $process=Get-Process -Id $item.pid -ErrorAction Stop
    try {$alive[$item.key]=!$process.HasExited}finally{$process.Dispose()}
}
$crash|Add-Member othersAlive $alive
if(@($alive.Values|Where-Object {!$_}).Count){throw 'N1 control killed a protected peer'}
Start-Sleep -Milliseconds 350
$snapshot=Invoke-Flow 'snapshot' 'crash'
$crash|Add-Member flowSnapshot $snapshot.flow
Assert-OfflineFlow $snapshot $crash.offlineUtc
$hostCheck=Test-Host 'crash' 76
$crash|Add-Member host $hostCheck
$report.phaseChecks+=@{phase='crash';online=$false;command=$command.number;hits=$hits;host=$hostCheck}
if(!$hostCheck.old -or !$hostCheck.fresh -or $hostCheck.dns -ne 'answered'){throw 'N1 host failed after owner exit'}
$report.staticGuard.proxyAfterCrash=Invoke-GuardProxy 'state'
# Recovery leaves the old stream closed; the same ordinary host proxy survives.
$health=Test-ProxyHealth 'recovered1'
$report.staticGuard.recoveryHealth=$health
if(!$health.matched){throw 'N1 surviving proxy health failed'}
$report.staticGuard.recoveryReadback=Invoke-StaticControl 'recover'
$null=Check-Phase 'recovered1' $true
$null=Check-Phase 'recovered2' $true -Native
$snapshot=Invoke-Flow 'snapshot' 'recovered2'
$report.staticGuard.oldFlowAfterRecovery=$snapshot.flow
Assert-OfflineFlow $snapshot $crash.offlineUtc
$null=Invoke-Flow 'stop-stream' 'recovered2'
$report.finalFlow=Invoke-Flow 'finish' 'recovered2'
$report.finalProxy=Invoke-GuardProxy 'state'
