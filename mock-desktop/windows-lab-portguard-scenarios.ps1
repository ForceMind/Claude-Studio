param([switch]$FunctionsOnly)
# Dot-sourced only after the same-container baseline and healthy gate pass.
$report.flowCommands=@(); $report.proxyCommands=@(); $report.proxySegments=@($report.proxyReady)
$report.faults=@(); $report.phaseChecks=@(); $script:flowNumber=0
function Invoke-Flow([string]$Action,[string]$Phase,[int]$Port=0) {
    $script:flowNumber++
    $path=Join-Path $run.FullName ('flow-command-'+$script:flowNumber+'.json')
    $json=@{action=$Action;phase=$Phase;port=$Port}|ConvertTo-Json -Compress
    [IO.File]::WriteAllText(($path+'.tmp'),$json); [IO.File]::Move(($path+'.tmp'),$path)
    $resultPath=Join-Path $run.FullName ('flow-result-'+$script:flowNumber+'.json')
    Wait-GuardFile $resultPath
    $value=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $report.flowCommands+=@($value)
    if(!$value.ok -or $value.number -ne $script:flowNumber -or $value.action -ne $Action -or $value.phase -ne $Phase){throw 'Flow command failed or mismatched'}
    Verify-Scope $value.identity
    if($value.identity.containerSid -ne $report.windowReady.containerSid){throw 'Flow container changed'}
    if($Action -eq 'start-stream' -and !$value.initialMatched){throw 'Continuous stream positive control failed'}
    return $value
}
function Invoke-GuardProxy([string]$Action) {
    if(!$proxyProcess -or $proxyProcess.HasExited){throw 'No active synthetic proxy'}
    $proxyProcess.StandardInput.WriteLine((@{action=$Action}|ConvertTo-Json -Compress)); $proxyProcess.StandardInput.Flush()
    $line=$proxyProcess.StandardOutput.ReadLineAsync()
    if(!$line.Wait(3000) -or !$line.Result){throw 'Synthetic proxy command timed out'}
    $value=$line.Result|ConvertFrom-Json
    $report.proxyCommands+=@{pid=$proxyProcess.Id;result=$value}
    if(!$value.ok -or $value.action -ne $Action -or $value.droppedEvents){throw 'Synthetic proxy command failed'}
    return $value
}
function Set-GuardGate([bool]$Closed) {
    $action=if($Closed){'close'}else{'open'}
    $path=Join-Path $privateDir ('guard-'+$action)
    foreach($item in @($path,($path+'-done'))){if(Test-Path -LiteralPath $item){Remove-Item -LiteralPath $item}}
    [IO.File]::WriteAllText($path,'1'); Wait-GuardFile ($path+'-done')
    $value=Get-Content -LiteralPath ($path+'-done') -Raw|ConvertFrom-Json
    if($value.gateClosed -ne $Closed -or $value.rules.Count -ne $(if($Closed){7}else{6})){throw 'Gate readback mismatch'}
    return [datetime]::UtcNow.ToString('o')
}
function Close-ScenarioProxy {
    if(!$proxyProcess){return}
    if(!$proxyProcess.HasExited){$null=Invoke-GuardProxy 'exit'}
    if(!$proxyProcess.WaitForExit(3000)){throw 'Synthetic proxy did not exit'}
    if($proxyErrors.Wait(1000) -and $proxyErrors.Result){throw $proxyErrors.Result}
    $proxyProcess.Dispose(); $script:proxyProcess=$null
}
function Start-ScenarioProxy([string]$Executable=$exe) {
    if($proxyProcess){throw 'Previous proxy still owned'}
    $start=[Diagnostics.ProcessStartInfo]::new($Executable,('guardproxy '+$prefix+' a healthy '+$ports.proxy+' '+$ports.tcp+' '+$ports.udp+' portguardflow'))
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $script:proxyProcess=[Diagnostics.Process]::Start($start)
    $script:proxyErrors=$proxyProcess.StandardError.ReadToEndAsync()
    $line=$proxyProcess.StandardOutput.ReadLineAsync()
    if(!$line.Wait(3000) -or !$line.Result){throw 'Replacement proxy did not start'}
    $ready=$line.Result|ConvertFrom-Json; $report.proxySegments+=@($ready)
    if(!$ready.listening -or $ready.container -or $ready.port -ne $ports.proxy -or $ready.pid -ne $proxyProcess.Id){throw 'Replacement proxy identity mismatch'}
}
function Test-ProxyHealth([string]$Phase,[int]$Timeout=1400) {
    $result=@{startedUtc=[datetime]::UtcNow.ToString('o');matched=$false}
    $request=[Net.HttpWebRequest]::Create('http://'+$prefix+'-a-window-'+$Phase+'.test/studio-probe?'+$Phase)
    $request.Proxy=[Net.WebProxy]::new(('http://127.0.0.1:'+$ports.proxy),$false)
    $request.Timeout=$Timeout; $request.ReadWriteTimeout=$Timeout; $request.KeepAlive=$false; $request.AllowAutoRedirect=$false
    try {$response=$request.GetResponse();try{$reader=[IO.StreamReader]::new($response.GetResponseStream());try{$result.matched=$reader.ReadToEnd() -ceq $prefix}finally{$reader.Dispose()}}finally{$response.Dispose()}}
    catch{$result.error=$_.Exception.Message}
    finally{$request.Abort();$result.finishedUtc=[datetime]::UtcNow.ToString('o')}
    return $result
}
function Check-Phase([string]$Phase,[bool]$Online,[switch]$Native) {
    $action=if($Native){'native-probe'}else{'probe'}
    $value=Invoke-Flow $action $Phase
    $hits=Get-DirectHits; $hostCheck=Test-Host $Phase 74
    $record=@{phase=$Phase;online=$Online;command=$value.number;hits=$hits;host=$hostCheck}
    $report.phaseChecks+=@($record)
    if(@($hits.Values|Where-Object {$_ -ne 0}).Count){throw ('Direct path reached during '+$Phase)}
    if(($value.probe.windowHttp -eq 'matched') -ne $Online){throw ('Unexpected proxy result during '+$Phase)}
    if(!$Online -and $value.probe.windowHttp -eq 'unexpected-response'){throw 'Offline request reached an untrusted same-port listener'}
    if($value.probe.system.dnsQueryStatus -ne 5 -or $value.probe.system.getAddrInfoStatus -ne 11001){throw ('Unexpected DNS status during '+$Phase)}
    Verify-Scope $value.probe.identity
    if($value.probe.identity.containerSid -ne $report.windowReady.containerSid){throw 'Probe container changed'}
    if(!$hostCheck.old -or !$hostCheck.fresh -or $hostCheck.dns -ne 'answered'){throw 'Host control failed'}
    return $value
}
function Assert-OfflineFlow($Value,[string]$OfflineUtc) {
    $events=@($Value.flow.events)
    $after=@($events|Where-Object {[datetime]$_.attemptUtc -ge [datetime]$OfflineUtc})
    if(!$after.Count){throw 'Old flow lacks post-offline attempts; evidence incomplete'}
    if(@($after|Where-Object {$_.status -in 'matched','unexpected-response'}).Count -or
        @($events|Where-Object {$_.completedUtc -and [datetime]$_.completedUtc -ge [datetime]$OfflineUtc -and $_.status -in 'matched','unexpected-response'}).Count){throw 'Old flow delivered after offline confirmation or lacks post-offline attempts'}
    if($Value.flow.reconnects -ne 0 -or $Value.flow.droppedEvents){throw 'Invalid continuous-flow evidence'}
}
function Restore-Scenario([string]$Phase) {
    Close-ScenarioProxy; Start-ScenarioProxy
    $health=Test-ProxyHealth $Phase
    if(!$health.matched){throw 'Replacement proxy health check failed'}
    $null=Set-GuardGate $false
    $null=Check-Phase $Phase $true
}

if($FunctionsOnly){return}
$null=Invoke-Flow 'start-stream' 'healthy1'
$stopListen=Invoke-GuardProxy 'stop-listening'
Start-Sleep -Milliseconds 500
$still=Invoke-Flow 'snapshot' 'outage'
$afterStop=@($still.flow.events|Where-Object {$_.status -eq 'matched' -and [datetime]$_.attemptUtc -gt [datetime]$stopListen.utc})
$report.stopListeningControl=@{proxy=$stopListen;command=$still.number;oldResponsesAfterStop=$afterStop.Count}
if(!$afterStop.Count){throw 'Stopped-listener old-connection control missing'}
$fault=@{kind='controlled';injectedUtc=[datetime]::UtcNow.ToString('o')}
$fault.gateUtc=Set-GuardGate $true
$closed=Invoke-GuardProxy 'stop-all'; $fault.closedUtc=$closed.utc; $fault.activeConnections=$closed.activeConnections
$fault.offlineUtc=[datetime]::UtcNow.ToString('o')
$null=Check-Phase 'stopped1' $false
Start-Sleep -Milliseconds 350
$probe=Invoke-Flow 'snapshot' 'stopped1'
$fault.command=$probe.number; $report.faults+=@($fault)
Assert-OfflineFlow $probe $fault.offlineUtc
$null=Invoke-Flow 'stop-stream' 'stopped1'
Close-ScenarioProxy
$null=Check-Phase 'cold' $false -Native
Start-ScenarioProxy; $null=Invoke-GuardProxy 'fake'
$null=Check-Phase 'fake' $false
$fake=Invoke-GuardProxy 'state'; $report.fakeState=$fake
if($fake.requests -ne 0){throw 'Same-port fake proxy was reached while offline'}
Restore-Scenario 'recovered1'

$null=Invoke-Flow 'start-stream' 'recovered1'
$report.preCrash=Invoke-GuardProxy 'state'
$fault=@{kind='crash';injectedUtc=[datetime]::UtcNow.ToString('o');pid=$proxyProcess.Id}
$proxyProcess.Kill()
if(!$proxyProcess.WaitForExit(2000)){throw 'Synthetic crash did not exit'}
$fault.detectedUtc=[datetime]::UtcNow.ToString('o');$fault.exitUtc=$proxyProcess.ExitTime.ToUniversalTime().ToString('o')
$proxyProcess.Dispose(); $proxyProcess=$null
$fault.gateUtc=Set-GuardGate $true; $fault.offlineUtc=[datetime]::UtcNow.ToString('o')
$null=Check-Phase 'crash' $false
Start-Sleep -Milliseconds 350
$probe=Invoke-Flow 'snapshot' 'crash'
$fault.command=$probe.number;$report.faults+=@($fault)
Assert-OfflineFlow $probe $fault.offlineUtc
$null=Invoke-Flow 'stop-stream' 'crash'
Restore-Scenario 'recovered2'

$null=Invoke-Flow 'start-stream' 'recovered2'
$silent=Invoke-GuardProxy 'silent'
$fault=@{kind='silent';injectedUtc=$silent.utc;activeAtInjection=$silent.activeConnections}
$health=Test-ProxyHealth 'silent' 1700; $fault.health=$health; $fault.detectedUtc=$health.finishedUtc
if($health.matched){throw 'Silent proxy unexpectedly responded'}
$fault.gateUtc=Set-GuardGate $true
$closed=Invoke-GuardProxy 'stop-all';$fault.closedUtc=$closed.utc;$fault.activeConnections=$closed.activeConnections
$fault.offlineUtc=[datetime]::UtcNow.ToString('o')
$fault.offlineMilliseconds=([datetime]$fault.offlineUtc-[datetime]$fault.injectedUtc).TotalMilliseconds
$null=Check-Phase 'silent' $false
Start-Sleep -Milliseconds 350
$probe=Invoke-Flow 'snapshot' 'silent'
$fault.command=$probe.number;$report.faults+=@($fault)
Assert-OfflineFlow $probe $fault.offlineUtc
if($fault.offlineMilliseconds -gt 3000){throw 'Silent proxy offline deadline exceeded 3 seconds'}
$null=Invoke-Flow 'stop-stream' 'silent'
Restore-Scenario 'recovered3'
$report.finalFlow=Invoke-Flow 'finish' 'recovered3'
$report.finalProxy=Invoke-GuardProxy 'state'
