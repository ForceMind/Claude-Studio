param([Parameter(Mandatory)]$Report)
. (Join-Path $PSScriptRoot 'windows-lab-static-guard-result.ps1') -Report $Report -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.ps1') -FunctionsOnly
if($Report.error -or !$Report.observer.guard.manifest){
    return @{outcome='failed-n3-a';checks=@{execution=$false};error=$Report.error}
}
$checks=[ordered]@{}
$m=$Report.observer.guard.manifest
$p,$u=$Report.ports

function Confirm-N3ScopeReadback($Value,[bool]$Expected) {
    $scope=@{sublayer=$m.scope.sub;keys=$m.scope.keys;weight=$m.scope.weight;port=$p}
    $Report=@{windowReady=$Report.windowReady;observer=@{guard=@{manifest=$scope}}}
    return (Readback-N1 $Value $Expected $p)
}

function Confirm-N3Bindings($Snapshot) {
    $layers=@('1247d66d-0b60-4a15-8d44-7155d0f53a0c','55a650e1-5f0a-4eca-a653-88f53b26aa8c')
    if($Snapshot.sublayer -ne $m.bind.sub -or $Snapshot.weight -ne $m.bind.weight -or
        $Snapshot.weight -le 0 -or @($Snapshot.rules).Count -ne 4){return $false}
    for($i=0;$i -lt 4;$i++){
        $rule=$Snapshot.rules[$i];$port=$Report.ports[[int][math]::Floor($i/2)]
        if($rule.key -ne $m.bind.keys[$i] -or $rule.layer -ne $layers[$i%2] -or $rule.flags -notin 0,64 -or
            $rule.action -ne 4097 -or $rule.id -le 0 -or $rule.port -ne $port -or $rule.protocol -ne 6 -or
            $rule.filterWeight -ne 1152921504606846976){return $false}
    }
    return $true
}

$keys=@($m.bind.sub,$m.scope.sub)+@($m.bind.keys)+@($m.scope.keys)
$checks.scope=$m.mode -ceq 'n3-synthetic-a' -and $m.scope.sid -ceq $Report.windowReady.containerSid -and
    (Scope-N1 $Report.windowReady) -and (Scope-N1 $Report.simulation) -and $Report.windowReady.visible -eq $true -and
    $Report.simulation.pid -eq $Report.windowReady.pid -and $Report.finishSequence -gt 0 -and
    $Report.simulation.finishSequence -eq $Report.finishSequence -and $Report.simulation.finishPhase -ceq 'crash1' -and
    $Report.windowReady.windowHandle -gt 0 -and $Report.execution.callerSid -eq $Report.accountSid -and $Report.execution.runExit -eq 0 -and
    $Report.execution.probeExit -eq 0 -and $Report.execution.tier -eq 'base-container' -and @($Report.execution.addedProfileDirs).Count -eq 0 -and
    $Report.policy.egress.default -eq 'deny' -and $Report.policy.ingress.default -eq 'deny' -and $Report.policy.ingress.hostLoopback -eq 'allow'
$checks.portScope=@($Report.ports).Count -eq 2 -and $p -ge 40000 -and $p -lt 49152 -and $u -ge 40000 -and $u -lt 49152 -and
    $p -ne $u -and $m.bind.ports[0] -eq $p -and $m.bind.ports[1] -eq $u -and @($keys|Sort-Object -Unique).Count -eq 11 -and
    (Confirm-N3Bindings $Report.bindings) -and @($Report.initialPortControl|Where-Object {$_.stage -eq 'listening' -and $_.nativeError -eq 0}).Count -eq 2
$checks.privacy=$Report.privateAclProtected -eq $true -and $Report.privateAccess.userSid -eq $Report.accountSid -and
    $Report.privateAccess.readConfig -eq 'denied' -and $Report.privateAccess.replaceConfig -eq 'denied' -and $Report.privateAccess.writeProxy -eq 'denied'
$checks.initialGate=(Confirm-N3ScopeReadback $Report.closedScope $false) -and
    (Confirm-N3ScopeReadback $Report.firstOpen.scope $true) -and $Report.coldUpstream.mode -eq 'refuse' -and
    $Report.firstOpen.health.lastProbe.http.ok -eq $true -and $Report.firstOpen.health.lastProbe.tls.ok -eq $true
$checks.outsideControl=$Report.outsideA.system.container -eq $false -and $Report.outsideA.system.userSid -eq $Report.accountSid -and
    $Report.outsideA.system.pid -gt 0 -and $Report.outsideA.system.pid -ne $Report.windowReady.pid -and
    $Report.outsideHits.tcp -eq 1 -and $Report.outsideHits.udp -eq 1 -and $Report.outsideA.directTargets.u -eq 'sent' -and
    $Report.outsideA.directTargets.http -eq 'sent' -and $Report.outsideA.directTargets.tls -eq 'sent'

$checks.phasePaths=@($Report.phases).Count -eq 8
$checks.phaseHost=$true;$checks.phaseIsolation=$true;$checks.noFailedDelivery=$true
$paths=@()
foreach($phase in 'cold1','healthy1','healthy2','outage1','recovered1','silent1','recovered2','crash1'){
    $items=@($Report.phases|Where-Object phase -eq $phase)
    if($items.Count -ne 1){$checks.phasePaths=$false;continue}
    $item=$items[0];$probe=$item.probe
    $online=$phase -in 'healthy1','healthy2','recovered1','recovered2'
    $native=$phase -in 'cold1','healthy2'
    if($item.online -ne $online -or $item.native -ne $native -or $probe.http.ok -ne $online -or $probe.tls.ok -ne $online -or
        (!$online -and ($probe.http.status -notin 'ConnectFailure','Timeout' -or $probe.tls.status -notin 'ConnectFailure','Timeout')) -or
        $probe.http.marker -cnotmatch '^[a-f0-9]{16}$' -or $probe.tls.marker -cnotmatch '^[a-f0-9]{16}$'){$checks.phasePaths=$false}
    if(!(Scope-N1 $probe.system) -or $probe.system.dnsQueryStatus -ne 5 -or $probe.system.getAddrInfoStatus -ne 11001 -or
        $null -eq $item.hits.tcp -or $item.hits.tcp -ne 0 -or $null -eq $item.hits.udp -or $item.hits.udp -ne 0 -or
        !$probe.directTargets.u -or !$probe.directTargets.http -or !$probe.directTargets.tls -or
        'sent' -in @($probe.directTargets.u,$probe.directTargets.http,$probe.directTargets.tls) -or
        ($native -and ($probe.launchedPid -ne $probe.system.pid -or $probe.system.pid -eq $Report.windowReady.pid)) -or
        (!$native -and $probe.system.pid -ne $Report.windowReady.pid)){$checks.phaseIsolation=$false}
    if(!(Host-N1 $item.host $phase)){$checks.phaseHost=$false}
    foreach($protocol in 'http','tls'){
        $reading=$probe.$protocol
        if($online){
            $path=Find-N3Path $Report.events $reading $protocol $Report.run
            if(!$path -or $path.entry.pid -ne $m.entry.pid -or $path.upstream.pid -ne $m.upstream.pid -or
                $path.target.pid -ne $m.target.pid){$checks.phasePaths=$false}
            else{$paths+=@{phase=$phase;protocol=$protocol;path=$path}}
        }elseif(@($Report.events.target|Where-Object {$_.marker -ceq $reading.marker}).Count){$checks.noFailedDelivery=$false}
    }
}
$newMarkers=@($Report.phases|ForEach-Object {$_.probe.http.marker;$_.probe.tls.marker})
$checks.uniqueRequests=$newMarkers.Count -eq 16 -and @($newMarkers|Sort-Object -Unique).Count -eq 16
$checks.faults=@($Report.faults).Count -eq 3;$checks.noReplay=$true;$checks.noOldReceiptAfterCutoff=$true
foreach($kind in 'refuse','silent','exit'){
    $items=@($Report.faults|Where-Object fault -eq $kind)
    if($items.Count -ne 1){$checks.faults=$false;continue}
    $fault=$items[0]
    if($fault.closedMilliseconds -le 0 -or $fault.closedMilliseconds -gt 3000 -or
        $fault.entry.admitting -ne $false -or $fault.entry.active -ne 0 -or $fault.entry.closedTick -lt $fault.injectedTick -or
        $fault.guard.open -ne $false -or $fault.guard.shutdown.reason -ne 'entry-unhealthy' -or
        $fault.guard.shutdown.tick -lt $fault.entry.closedTick -or $fault.closedTick -lt $fault.guard.shutdown.tick -or
        !(Confirm-N3ScopeReadback $fault.guard.shutdown.scope $false)){
        $checks.faults=$false
    }
    if($kind -eq 'exit'){
        $connection=$fault.upstreamSocketResult
        $unreachable=($connection.status -eq 'timeout' -and $connection.deadlineMs -eq 1200 -and $null -eq $connection.nativeError) -or
            ($connection.status -eq 'ConnectionRefused' -and $connection.nativeError -eq 10061) -or
            ($connection.status -eq 'TimedOut' -and $connection.nativeError -eq 10060)
        if($fault.upstreamExited -ne $true -or $fault.rebindU.stage -ne 'bind' -or $fault.rebindU.nativeError -ne 10013 -or
            !$unreachable -or !(Confirm-N3Bindings $fault.bindings)){$checks.faults=$false}
    }elseif($fault.injection.mode -ne $kind -or !(Confirm-N3ScopeReadback $fault.reopen.scope $true) -or
        $fault.reopen.health.lastProbe.http.ok -ne $true -or $fault.reopen.health.lastProbe.tls.ok -ne $true){$checks.faults=$false}
    foreach($protocol in 'http','tls'){
        $old=$fault.before.$protocol;$after=$fault.after.$protocol
        $target=@($Report.events.target|Where-Object {$_.kind -eq 'target' -and $_.action -eq 'hold' -and $_.marker -ceq $old.marker -and $_.protocol -eq $protocol})
        if($old.state -ne 'active' -or $old.marks.Count -lt 2 -or $after.state -in 'active','starting' -or !$after.state -or
            $after.marker -cne $old.marker -or $target.Count -ne 1){$checks.noReplay=$false}
        if(!$fault.closedTick -or @($after.receivedTicks).Count -ne @($after.marks).Count -or
            @($after.receivedTicks|Where-Object {$_ -le 0 -or $_ -gt $fault.closedTick}).Count){$checks.noOldReceiptAfterCutoff=$false}
        if($kind -ne 'exit'){
            $recovered=$fault.oldAfterRecovery.$protocol
            if($recovered.marker -cne $after.marker -or $recovered.state -in 'active','starting' -or !$recovered.state -or
                ($recovered.marks -join ',') -cne ($after.marks -join ',')){$checks.noReplay=$false}
        }
    }
}

$dns=$Report.observer.dns;$loss=$dns.lossBeforeStop
$checks.trace=$null -ne $dns.events -and $dns.servicePid -gt 0 -and $dns.servicePid -eq $dns.servicePidAfter -and
    (Has-N1 $loss @('eventsLost','logBuffersLost','realtimeBuffersLost')) -and $loss.eventsLost -eq 0 -and
    $loss.logBuffersLost -eq 0 -and $loss.realtimeBuffersLost -eq 0 -and $Report.observer.sessionGone -eq $true
$knownPids=@($Report.windowReady.pid)+@($Report.phases|ForEach-Object {$_.probe.system.pid})+@($m.entry.pid,$m.upstream.pid,$m.target.pid)
$ordinary=$Report.outsideA.system.pid
$calls=@($dns.events|Where-Object {$_.profile -eq 'A' -and $_.event -in 3010,3011})
$unattributed=@($calls|Where-Object { !($checks.outsideControl -and $_.clientPid -eq $ordinary -and $ordinary -notin $knownPids -and
    $_.phase -eq 'baseline' -and $_.probe -in 'dns','addr' -and $_.emitterPid -eq $dns.servicePid)})
$checks.dnsAttribution=$unattributed.Count -eq 0 -and 3010 -in $calls.event -and 3011 -in $calls.event
$checks.hostBaseline=(Host-N1 $Report.hostBaseline 'baseline')
$checks.hostRollback=(Host-N1 $Report.hostAfter 'recovered9') -and
    (Time-N1 $Report.hostAfter.startedUtc) -ge (Time-N1 $Report.observer.staticGuardCleanup.removedUtc)
$checks.rollback=$Report.cleanup.control.absent -eq $true -and $Report.cleanup.control.bindAbsent -eq $true -and
    $Report.observer.staticGuardCleanup.absent -eq $true -and $Report.observer.staticGuardCleanup.bindAbsent -eq $true -and
    (Empty-N1 $Report.observer.staticGuardCleanup 'forced') -and (Empty-N1 $Report.observer.staticGuardCleanup 'errors') -and
    (Empty-N1 $Report.cleanup 'errors') -and (Empty-N1 $Report.observer.after 'matched') -and $Report.observer.rawTraceGone -eq $true -and
    !$Report.observer.error -and $Report.cleanup.stageGone -eq $true -and $Report.cleanup.directoryGone -eq $true -and
    @($Report.cleanup.rebind|Where-Object {$_.stage -eq 'listening' -and $_.nativeError -eq 0}).Count -eq 2
$failed=@($checks.Keys|Where-Object {$checks[$_] -ne $true})
return @{outcome=$(if(!$failed.Count){'passed-n3-a'}else{'failed-n3-a'});checks=$checks;failed=$failed;paths=$paths}
