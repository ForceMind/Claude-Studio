param([Parameter(Mandatory)]$Report,[switch]$FunctionsOnly)
# Pure report evaluation: no process, socket, WFP or filesystem mutation.
function Has-N1($Value,[string[]]$Names) {
    if($null -eq $Value){return $false}
    foreach($name in $Names){
        if($Value -is [Collections.IDictionary]){if(!$Value.Contains($name)){return $false}}
        elseif($null -eq $Value.PSObject.Properties[$name]){return $false}
    }
    return $true
}
function Empty-N1($Value,[string]$Name){return (Has-N1 $Value @($Name)) -and $null -ne $Value.$Name -and @($Value.$Name).Count -eq 0}
function Time-N1($Value){
    try{
        if(!$Value){return $null}
        if($Value -is [datetime]){return $Value.ToUniversalTime()}
        if($Value -is [datetimeoffset]){return $Value.UtcDateTime}
        return [datetimeoffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
    }catch{return $null}
}
function Scope-N1($Value){
    return (Has-N1 $Value @('pid','container','inJob','userSid','containerSid','session','networkCapabilities')) -and
        $Value.pid -gt 0 -and $Value.container -eq $true -and $Value.inJob -eq $true -and
        $Value.userSid -eq $Report.accountSid -and $Value.containerSid -eq $Report.windowReady.containerSid -and
        $Value.session -eq $Report.session -and @($Value.networkCapabilities).Count -eq 1 -and
        $Value.networkCapabilities[0] -eq 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
}
function Hits-N1($Value,[string[]]$Names,[int]$Expected){
    if(!(Has-N1 $Value $Names)){return $false}
    foreach($name in $Names){if($null -eq $Value.$name -or $Value.$name -ne $Expected){return $false}}
    return $true
}
function Host-N1($Value,[string]$Phase){
    if(!(Has-N1 $Value @('pid','old','fresh','dns')) -or $Value.pid -le 0 -or $Value.old -ne $true -or $Value.fresh -ne $true -or $Value.dns -ne 'answered'){return $false}
    $events=@($Report.observer.dns.events|Where-Object {$_.profile -eq 'H' -and $_.phase -eq $Phase -and $_.clientPid -eq $Value.pid -and $_.emitterPid -eq $Report.observer.dns.servicePid})
    return 3010 -in $events.event -and 3011 -in $events.event
}
function Dns-N1($Native,[string]$Phase,[int[]]$Pids){
    if(!(Has-N1 $Native @('dnsQueryStatus','getAddrInfoStatus')) -or $Native.dnsQueryStatus -ne 5 -or $Native.getAddrInfoStatus -ne 11001){return $false}
    # Only the recorded ordinary A controls may emit DNS in baseline/stopped.
    # A claimed outside PID that is also a known container PID cannot exempt it.
    $containerPids=@($Report.windowReady.pid,$Report.windowReady.listenerReady.pid,$Report.simulation.pid,$Report.simulation.native.pid,
        $Report.guardBaseline.pid,$Report.guardBaseline.native.pid,$Report.guardGate.pid,$Report.guardGate.native.pid,
        $Report.healthyCheckpoint.pid,$Report.healthyCheckpoint.native.pid)+@($Report.flowCommands|ForEach-Object {$_.probe.identity.pid})
    $outsideDns=$checks.outsideControl -and $Report.outsideGate.pid -notin $containerPids
    return @($Report.observer.dns.events|Where-Object {$_.profile -eq 'A' -and $_.phase -eq $Phase -and $_.event -in 3010,3011 -and
        !(($_.probe -in 'dns','addr') -and (($Phase -eq 'baseline' -and $_.clientPid -eq $Report.baseline.pid) -or
            ($Phase -eq 'stopped' -and $outsideDns -and $_.clientPid -eq $Report.outsideGate.pid)))}).Count -eq 0
}
function Readback-N1($Value,[bool]$Permit,[int]$Port=0){
    $manifest=$Report.observer.guard.manifest
    if(!(Has-N1 $Value @('sublayer','sublayerPresent','sublayerFlags','weight','exceptionPresent','rules')) -or
        $Value.sublayer -ne $manifest.sublayer -or $Value.sublayerPresent -ne $true -or $Value.sublayerFlags -ne 0 -or
        $Value.weight -ne $manifest.weight -or $Value.exceptionPresent -ne $Permit -or @($Value.rules).Count -ne 5){return $false}
    $names=@('D4','D6','I4','I6','E')
    $layers=@('c38d57d1-05a7-4c33-904f-7fbceee60e82','4a72393b-319f-44bc-84c3-ba54dcb3b6b4','e1cd9fe7-f4b5-4273-96c0-592e487b8650','a3b42c97-9f04-4672-b87e-cee9c483257f','c38d57d1-05a7-4c33-904f-7fbceee60e82')
    $fields=@('71bc78fa-f17c-4997-a602-6abb261f351c','3971ef2b-623e-4f9a-8cb1-6e79b806b9a7','b235ae9a-1d64-49b8-a44c-5ff3d9095045','c35a604d-d22b-4e1a-91b4-68f674ee674b')
    $types=@(13,1,3,2);$values=@($Report.windowReady.containerSid,6,2130706433,$(if($Port){$Port}else{$manifest.port}))
    for($i=0;$i -lt 5;$i++){
        $rows=@($Value.rules|Where-Object {$_.rule -eq $names[$i]});if($rows.Count -ne 1){return $false};$rule=$rows[0]
        $present=$i -lt 4 -or $Permit
        if(!(Has-N1 $rule @('key','present')) -or $rule.key -ne $manifest.keys[$i] -or $rule.present -ne $present){return $false}
        if(!$present){continue}
        $weight=if($i -eq 4){[uint64]2305843009213693952}else{[uint64]1152921504606846976}
        $action=if($i -eq 4){4098}else{4097};$count=if($i -eq 4){4}else{1}
        if(!(Has-N1 $rule @('id','layer','sublayer','action','flags','weightType','weight','effectiveWeightType','effectiveWeight','conditions')) -or
            $rule.id -le 0 -or $rule.layer -ne $layers[$i] -or $rule.sublayer -ne $manifest.sublayer -or $rule.action -ne $action -or
            $rule.flags -notin 0,64 -or $rule.weightType -ne 4 -or $rule.effectiveWeightType -ne 4 -or $rule.weight -ne $weight -or
            $rule.effectiveWeight -ne $weight -or @($rule.conditions).Count -ne $count){return $false}
        for($j=0;$j -lt $count;$j++){
            $condition=$rule.conditions[$j]
            if(!(Has-N1 $condition @('field','match','type','value')) -or $condition.field -ne $fields[$j] -or
                $condition.match -ne 0 -or $condition.type -ne $types[$j] -or $condition.value -ne $values[$j]){return $false}
        }
    }
    return $true
}
function Offline-Flow-N1($Value,$Initial,$Offline){
    if($null -eq $Offline -or !(Has-N1 $Value @('streamId','connectionId','started','sameSocket','socketInvalid','reconnects','droppedEvents','events')) -or
        $Value.started -ne $true -or $Value.sameSocket -ne $true -or $Value.socketInvalid -ne $true -or $Value.reconnects -ne 0 -or $Value.droppedEvents -ne 0 -or
        $Value.streamId -ne $Initial.streamId -or $Value.connectionId -ne $Initial.connectionId -or !$Value.connectionId){return $false}
    $after=@($Value.events|Where-Object {(Time-N1 $_.attemptUtc) -ge $Offline})
    $late=@($Value.events|Where-Object {$_.status -in 'matched','unexpected-response' -and (Time-N1 $_.completedUtc) -ge $Offline})
    $malformed=@($Value.events|Where-Object {!(Time-N1 $_.attemptUtc) -or !$_.status -or ($_.status -in 'matched','unexpected-response' -and !(Time-N1 $_.completedUtc))})
    return $after.Count -gt 0 -and $late.Count -eq 0 -and $malformed.Count -eq 0 -and
        @($after|Where-Object {$_.status -notin 'failed','socket-invalid','stopped'}).Count -eq 0
}
if($FunctionsOnly){return}
$checks=[ordered]@{}
$regular=& (Join-Path $PSScriptRoot 'windows-lab-psec-result.ps1') $Report
$checks.scope=(Has-N1 $Report @('accountSid','session','windowReady','simulation')) -and $Report.accountSid -match '^S-1-5-' -and
    $Report.windowReady.containerSid -match '^S-1-15-2-' -and (Scope-N1 $Report.windowReady) -and $Report.windowReady.visible -eq $true -and
    $Report.windowReady.windowHandle -gt 0 -and $regular.scopeVerified
foreach($item in @($Report.guardBaseline,$Report.guardBaseline.native,$Report.guardGate,$Report.guardGate.native,$Report.healthyCheckpoint,$Report.healthyCheckpoint.native,$Report.simulation,$Report.simulation.native,$Report.windowReady.listenerReady)){
    if(!(Scope-N1 $item)){$checks.scope=$false}
}
$checks.baseline=$Report.guardBaseline.windowHttp -eq 'matched' -and $Report.guardBaseline.native.proxyHttp -eq 'matched' -and
    (Hits-N1 $Report.guardBaselineHits @('tcp','udp') 1) -and (Hits-N1 $Report.baselineHits @('tcp','udp') 1)
$checks.outsideControl=(Has-N1 $Report.outsideGate @('container','userSid','pid','proxyHttp')) -and $Report.outsideGate.container -eq $false -and
    $Report.outsideGate.userSid -eq $Report.accountSid -and $Report.outsideGate.pid -gt 0 -and $Report.outsideGate.proxyHttp -eq 'matched' -and
    (Hits-N1 $Report.outsideGateHits @('tcp','udp') 1)
$checks.closedGate=$Report.guardGate.windowHttp -in 'ConnectFailure','Timeout' -and $Report.guardGate.native.proxyHttp -in 'ConnectFailure','Timeout'
$canaries=@('tcp','udp','udpProxy','alternate');if($Report.extraCanaries.localAddress){$canaries+=@('local')}
$checks.canaries=(Hits-N1 $Report.outsideGateHits $canaries 1) -and (Hits-N1 $Report.guardGateHits $canaries 0) -and
    (Hits-N1 $Report.healthyCheckpointHits $canaries 0) -and (Hits-N1 $Report.containerHits @('tcp','udp') 0)
$checks.healthy=$Report.healthyCheckpoint.windowHttp -eq 'matched' -and $Report.healthyCheckpoint.native.proxyHttp -eq 'matched' -and
    $Report.simulation.windowHttp -eq 'matched' -and $Report.simulation.native.proxyHttp -eq 'matched'
$checks.reverse=$Report.hostReverseBaseline.attempted -eq $true -and $Report.hostReverseBaseline.connected -eq $true -and
    $Report.hostReverseGate.attempted -eq $true -and $Report.hostReverseGate.connected -eq $false
$manifest=$Report.observer.guard.manifest
$checks.manifest=(Has-N1 $manifest @('mode','containerSid','port','weight','sublayer','keys')) -and $manifest.mode -ceq 'static-a-only' -and
    $manifest.containerSid -eq $Report.windowReady.containerSid -and $manifest.port -ge 49152 -and $manifest.port -le 65535 -and
    $manifest.port -eq $Report.proxyReady.port -and $manifest.weight -gt 0 -and $manifest.weight -le 65535 -and @($manifest.keys).Count -eq 5
try{
    $keys=@([string]$manifest.sublayer)+@($manifest.keys)
    if(@($keys|Select-Object -Unique).Count -ne 6){$checks.manifest=$false}
    foreach($key in $keys){if([guid]$key -eq [guid]::Empty){$checks.manifest=$false}}
}catch{$checks.manifest=$false}
foreach($pair in @(@('installClosedReadback',$false),@('initialPermitReadback',$true),@('afterCrashReadback',$false),@('recoveryReadback',$true))){
    $checks[$pair[0]]=$checks.manifest -and (Readback-N1 $Report.staticGuard.($pair[0]) $pair[1])
}
$checks.installationClosed=$Report.staticGuard.installationSessionClosed -eq $true -and $Report.observer.installationSessionClosed -eq $true -and
    $null -ne (Time-N1 $Report.staticGuard.installClosedUtc) -and $Report.staticGuard.installClosedUtc -eq $Report.observer.installClosedUtc
$dns=$Report.observer.dns;$loss=$dns.lossBeforeStop
$checks.trace=$regular.traceComplete -and (Has-N1 $dns @('events','servicePid','servicePidAfter','lossBeforeStop')) -and
    (Has-N1 $loss @('eventsLost','logBuffersLost','realtimeBuffersLost')) -and $null -ne $dns.events
$checks.initialDns=(Dns-N1 $Report.guardBaseline.native 'baseline' @()) -and (Dns-N1 $Report.guardGate.native 'stopped' @()) -and
    (Dns-N1 $Report.healthyCheckpoint.native 'healthy' @()) -and (Dns-N1 $Report.simulation.native $Report.policy.phase @())
$checks.initialHost=$regular.positiveControls -and (Host-N1 $Report.hostGate 'stopped')
$checks.phases=@($Report.phaseChecks).Count -eq 4;$checks.phaseScope=$true;$checks.phaseResults=$true;$checks.phaseDns=$true;$checks.phaseHost=$true;$checks.nativeChildren=$true
foreach($phase in @('healthy1','crash','recovered1','recovered2')){
    $entries=@($Report.phaseChecks|Where-Object {$_.phase -eq $phase})
    if($entries.Count -ne 1){$checks.phases=$false;continue};$entry=$entries[0];$online=$phase -ne 'crash'
    $commands=@($Report.flowCommands|Where-Object {$_.number -eq $entry.command})
    if(!(Has-N1 $entry @('online','command','hits','host')) -or $entry.online -ne $online -or $commands.Count -ne 1){$checks.phases=$false;continue}
    $command=$commands[0];$probe=$command.probe;$native=$phase -in 'healthy1','recovered2'
    if(!$command.ok -or $command.phase -ne $phase -or $command.action -ne $(if($native){'native-probe'}else{'probe'}) -or !(Scope-N1 $command.identity) -or !(Scope-N1 $probe.identity)){$checks.phaseScope=$false}
    if($native -and (!(Has-N1 $probe @('ok','sameContainer','freshContainer','exitCode','childPid')) -or !$probe.ok -or !$probe.sameContainer -or $probe.freshContainer -ne $false -or
        $probe.exitCode -ne 0 -or $probe.childPid -ne $probe.identity.pid -or $probe.childPid -eq $Report.windowReady.pid)){$checks.nativeChildren=$false}
    if(!$native -and $probe.identity.pid -ne $Report.windowReady.pid){$checks.phaseScope=$false}
    if(($online -and $probe.windowHttp -ne 'matched') -or (!$online -and $probe.windowHttp -notin 'ConnectFailure','Timeout') -or !(Hits-N1 $entry.hits $canaries 0)){$checks.phaseResults=$false}
    if(!(Dns-N1 $probe.system $phase @())){$checks.phaseDns=$false}
    if(!(Host-N1 $entry.host $phase)){$checks.phaseHost=$false}
}
$crash=$Report.staticGuard.managerCrash;$exit=Time-N1 $crash.exitUtc;$absent=Time-N1 $crash.permitAbsentUtc;$offline=Time-N1 $crash.offlineUtc;$signal=Time-N1 $crash.exitSignalUtc
$checks.managerCrash=(Has-N1 $crash @('managerPid','managerWasOnlyKilled','othersAlive','windowProbe','flowSnapshot','host')) -and
    $crash.managerPid -gt 0 -and $crash.managerWasOnlyKilled -eq $true -and $crash.managerPid -notin @($Report.windowReady.pid,$Report.windowReady.listenerReady.pid,$Report.proxyReady.pid) -and
    (Has-N1 $crash.othersAlive @('window','proxy','listener')) -and $crash.othersAlive.window -eq $true -and $crash.othersAlive.proxy -eq $true -and $crash.othersAlive.listener -eq $true
$checks.deadline=$null -ne $exit -and $null -ne $absent -and $null -ne $offline -and $null -ne $signal -and
    $signal -ge $exit -and $absent -ge $signal -and $offline -ge $absent -and ($absent-$signal).TotalMilliseconds -le 3000 -and ($offline-$signal).TotalMilliseconds -le 3000
$checks.crashProbe=(Scope-N1 $crash.windowProbe.identity) -and $crash.windowProbe.identity.pid -eq $Report.windowReady.pid -and
    $crash.windowProbe.windowHttp -in 'ConnectFailure','Timeout' -and (Dns-N1 $crash.windowProbe.system 'crash' @()) -and (Host-N1 $crash.host 'crash') -and
    (Has-N1 $crash.windowProbe @('startedUtc','finishedUtc')) -and $null -ne $absent -and $null -ne $offline -and
    (Time-N1 $crash.windowProbe.startedUtc) -ge $absent -and (Time-N1 $crash.windowProbe.finishedUtc) -ge (Time-N1 $crash.windowProbe.startedUtc) -and
    (Time-N1 $crash.windowProbe.finishedUtc) -le $offline
$starts=@($Report.flowCommands|Where-Object {$_.action -eq 'start-stream'});$flow=$crash.flowSnapshot;$initial=$Report.staticGuard.initialFlow;$final=$Report.finalFlow.flow
$checks.oldFlow=$starts.Count -eq 1 -and $starts[0].ok -and $starts[0].initialMatched -eq $true -and $starts[0].phase -eq 'healthy1' -and (Scope-N1 $starts[0].identity) -and
    (Has-N1 $initial @('streamId','connectionId','started','sameSocket','reconnects','droppedEvents','events')) -and
    $initial.started -eq $true -and $initial.sameSocket -eq $true -and $initial.reconnects -eq 0 -and $initial.droppedEvents -eq 0 -and $initial.streamId -gt 0 -and
    (Offline-Flow-N1 $flow $initial $offline) -and
    $flow.connectionId -eq $starts[0].flow.connectionId -and $flow.streamId -eq $starts[0].flow.streamId
$checks.oldFlowAfterRecovery=Offline-Flow-N1 $Report.staticGuard.oldFlowAfterRecovery $initial $offline
$checks.finalFlow=$Report.finalFlow.ok -eq $true -and $Report.finalFlow.action -eq 'finish' -and
    (Has-N1 $Report.finalFlow @('archives')) -and
    (Has-N1 $final @('started','stopped','sameSocket','reconnects','droppedEvents','streamId','connectionId','events')) -and
    $final.started -eq $true -and $final.stopped -eq $true -and $final.sameSocket -eq $true -and $final.reconnects -eq 0 -and $final.droppedEvents -eq 0 -and
    $final.streamId -eq $flow.streamId -and $final.connectionId -eq $flow.connectionId -and @($Report.finalFlow.archives).Count -eq 0 -and
    @($initial.events|Where-Object {$_.status -eq 'matched'}).Count -gt 0 -and (Offline-Flow-N1 $final $initial $offline)
$cleanup=$Report.observer.staticGuardCleanup;$removed=Time-N1 $cleanup.removedUtc;$post=$Report.postRollbackHost
$checks.staticCleanup=(Has-N1 $cleanup @('absent','removedUtc','emergencyStoppedPids','errors')) -and $cleanup.absent -eq $true -and $null -ne $removed -and
    (Empty-N1 $cleanup 'emergencyStoppedPids') -and (Empty-N1 $cleanup 'errors')
$checks.postRollbackHost=(Host-N1 $post 'recovered9') -and (Has-N1 $post @('phase','startedUtc','finishedUtc')) -and $post.phase -eq 'recovered9' -and
    $null -ne $removed -and (Time-N1 $post.startedUtc) -gt $removed -and (Time-N1 $post.finishedUtc) -ge (Time-N1 $post.startedUtc)
$checks.cleanup=$regular.systemCleanupVerified -and (Empty-N1 $Report 'remainingProbePids') -and
    (Empty-N1 $Report 'remainingTcpListeners') -and (Empty-N1 $Report 'remainingUdpListeners') -and
    (Empty-N1 $Report.execution 'addedProfileDirs') -and (Empty-N1 $Report.observer.after 'matched')
$checks.stageCleanup=$Report.stageCleanup.stageGone -eq $true -and (Empty-N1 $Report.stageCleanup 'remainingStagePids') -and (Empty-N1 $Report.stageCleanup 'forcedPids')
$checks.noErrors=!$Report.error -and !$Report.workerError -and !$Report.observerError -and !$Report.proxyError -and !$Report.hostError -and
    !$Report.staticCleanupError -and !$Report.observer.error -and !$Report.observer.guard.error -and !$Report.observer.guard.cleanupError -and !$Report.observer.guard.removeError
$failed=@($checks.Keys|Where-Object {!$checks[$_]})
[pscustomobject]@{outcome=$(if(!$failed.Count){'passed-static-guard-n1'}else{'inconclusive-static-guard-n1'});checks=$checks;
    missingOrFailed=$failed;systemCleanupVerified=[bool]($checks.cleanup -and $checks.staticCleanup -and $checks.stageCleanup);hostTcpScope='controlled loopback connections';
    realUpstreamVerified=$false;spaceBVerified=$false;nativeIPv6Verified=$false;browserVerified=$false}
