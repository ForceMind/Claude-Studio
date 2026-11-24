param([Parameter(Mandatory)]$Report)
$regular=& (Join-Path $PSScriptRoot 'windows-lab-psec-result.ps1') $Report
$gate=& (Join-Path $PSScriptRoot 'windows-lab-portguard-result.ps1') $Report
$checks=[ordered]@{}
$checks.initialGate=$gate.sameContainerScopeVerified -and $gate.baselineVerified -and $gate.outsideIdentityControl -and $gate.gateBlocked -and $gate.exactReadback -and $gate.dnsGateChecks
$checks.scope=$regular.scopeVerified
$checks.trace=$regular.traceComplete
$checks.initialHost=$regular.positiveControls -and $gate.hostGateControl
$checks.cleanup=$gate.systemCleanupVerified -and !$Report.observer.error -and !$Report.proxyError
$checks.reverse=$Report.hostReverseBaseline.connected -and !$Report.hostReverseGate.connected
$checks.expandedCanaries=$true
$canaries=@('tcp','udp','udpProxy','alternate')
if($Report.extraCanaries.localAddress){$canaries+=@('local')}
foreach($name in $canaries){
    if($Report.outsideGateHits[$name] -ne 1 -or $Report.guardGateHits[$name] -ne 0 -or $Report.healthyCheckpointHits[$name] -ne 0){$checks.expandedCanaries=$false}
}
$checks.healthy=$Report.healthyCheckpoint.windowHttp -eq 'matched' -and $Report.healthyCheckpoint.native.proxyHttp -eq 'matched'
$commands=@($Report.observer.guard.commands)
$checks.ruleReadbacks=$commands.Count -ge 8
foreach($command in $commands){
    $closed=$command.command -ne 'open'
    if($command.readback.gateClosed -ne $closed -or $command.readback.rules.Count -ne $(if($closed){7}else{6})){$checks.ruleReadbacks=$false}
}
$checks.phases=$Report.phaseChecks.Count -eq 8
$checks.phaseHost=$true; $checks.phaseDns=$true; $checks.phaseResults=$true
foreach($phase in @('stopped1','cold','fake','recovered1','crash','recovered2','silent','recovered3')){
    $entry=@($Report.phaseChecks|Where-Object {$_.phase -eq $phase})
    if($entry.Count -ne 1){$checks.phases=$false;continue}
    $entry=$entry[0]
    $command=@($Report.flowCommands|Where-Object {$_.number -eq $entry.command})[0]
    $probe=$command.probe
    if(!$command.ok -or !$probe -or $probe.identity.containerSid -ne $Report.windowReady.containerSid -or
        $probe.identity.userSid -ne $Report.accountSid -or !$probe.identity.container -or !$probe.identity.inJob -or
        $probe.identity.networkCapabilities.Count -ne 1 -or $probe.identity.networkCapabilities[0] -ne $Report.windowReady.networkCapabilities[0]){$checks.scope=$false}
    if(($probe.windowHttp -eq 'matched') -ne $entry.online -or (!$entry.online -and $probe.windowHttp -notin 'ConnectFailure','Timeout') -or
        @($entry.hits.Values|Where-Object {$_ -ne 0}).Count){$checks.phaseResults=$false}
    $events=@($Report.observer.dns.events|Where-Object {$_.profile -eq 'A' -and $_.phase -eq $phase -and $_.clientPid -eq $probe.identity.pid -and $_.event -in 3010,3011})
    if($events.Count -or $probe.system.dnsQueryStatus -ne 5 -or $probe.system.getAddrInfoStatus -ne 11001){$checks.phaseDns=$false}
    $hostEvents=@($Report.observer.dns.events|Where-Object {$_.profile -eq 'H' -and $_.phase -eq $phase -and $_.clientPid -eq $entry.host.pid -and $_.emitterPid -eq $Report.observer.dns.servicePid})
    if(!$entry.host.old -or !$entry.host.fresh -or $entry.host.dns -ne 'answered' -or 3010 -notin $hostEvents.event -or 3011 -notin $hostEvents.event){$checks.phaseHost=$false}
}
$checks.coldChild=$false
$cold=@($Report.flowCommands|Where-Object {$_.action -eq 'native-probe' -and $_.phase -eq 'cold'})
if($cold.Count -eq 1){$checks.coldChild=$cold[0].probe.ok -and $cold[0].probe.sameContainer -and !$cold[0].probe.freshContainer -and $cold[0].probe.exitCode -eq 0 -and $cold[0].probe.childPid -ne $Report.windowReady.pid}
$checks.stopListening=$Report.stopListeningControl.oldResponsesAfterStop -gt 0
$checks.fakeBlocked=$Report.fakeState.fake -and $Report.fakeState.listening -and $Report.fakeState.requests -eq 0
$checks.faults=$Report.faults.Count -eq 3
foreach($kind in @('controlled','crash','silent')){
    $fault=@($Report.faults|Where-Object {$_.kind -eq $kind})
    if($fault.Count -ne 1){$checks.faults=$false;continue}
    $fault=$fault[0];$command=@($Report.flowCommands|Where-Object {$_.number -eq $fault.command})[0]
    $after=@($command.flow.events|Where-Object {[datetime]$_.attemptUtc -ge [datetime]$fault.offlineUtc})
    $delivered=@($command.flow.events|Where-Object {$_.completedUtc -and [datetime]$_.completedUtc -ge [datetime]$fault.offlineUtc -and $_.status -in 'matched','unexpected-response'})
    if(!$after.Count -or $delivered.Count -or $command.flow.reconnects -ne 0 -or $command.flow.droppedEvents){$checks.faults=$false}
    if($kind -in 'controlled','silent' -and $fault.activeConnections -ne 0){$checks.faults=$false}
    if($kind -eq 'silent' -and ($fault.offlineMilliseconds -gt 3000 -or $fault.activeAtInjection -lt 1)){$checks.faults=$false}
}
$checks.streams=$Report.finalFlow.archives.Count -eq 2 -and $Report.finalFlow.flow.streamId -eq 3
foreach($stream in @($Report.finalFlow.archives)+@($Report.finalFlow.flow)){
    if(!$stream -or !$stream.started -or !$stream.stopped -or $stream.reconnects -ne 0 -or $stream.droppedEvents -or
        @($stream.events|Where-Object {$_.status -eq 'matched'}).Count -eq 0){$checks.streams=$false}
}
$checks.noErrors=!$Report.error -and !$Report.workerError -and !$Report.observerError -and !$Report.observer.guard.error
$failed=@($checks.Keys|Where-Object {!$checks[$_]})
$outcome=if(!$failed.Count){'passed-container-portguard-fault-matrix'}else{'inconclusive-portguard-fault-matrix'}
if($Report.error -match 'Direct path reached|Old flow delivered|Unexpected proxy result|Host control failed|deadline exceeded|guard failed|inbound guard failed'){$outcome='failed-container-portguard-fault-matrix'}
[pscustomobject]@{outcome=$outcome;checks=$checks;missingOrFailed=$failed;systemCleanupVerified=$checks.cleanup;directHitEventsAvailable=$false;freshContainerColdStartVerified=$false;hostTcpScope='controlled loopback connections';nativeIPv6Verified=$false}
