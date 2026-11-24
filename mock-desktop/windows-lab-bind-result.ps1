param([Parameter(Mandatory)]$Report)
. (Join-Path $PSScriptRoot 'windows-lab-static-guard-result.ps1') -Report $Report -FunctionsOnly
$checks=[ordered]@{}
if($Report.error -or !$Report.observer.guard.manifest){
    return @{outcome='failed-bind-guard-n2';checks=@{execution=$false};error=$Report.error}
}
$n2=$Report.bindGuard
$manifest=$Report.observer.guard.manifest
$p,$q=$n2.ports
$regular=& (Join-Path $PSScriptRoot 'windows-lab-psec-result.ps1') $Report
$canaries=@('tcp','udp','udpProxy','alternate')
if($Report.extraCanaries.localAddress){$canaries+=@('local')}

function Confirm-BindRows($Readback,[int]$Count) {
    if($Readback.sublayer -ne $manifest.bind.sub -or $Readback.weight -ne $manifest.bind.weight -or
        $Readback.weight -le 0 -or @($Readback.rules).Count -ne 2*$Count){return $false}
    $layers=@('1247d66d-0b60-4a15-8d44-7155d0f53a0c','55a650e1-5f0a-4eca-a653-88f53b26aa8c')
    for($i=0;$i -lt 2*$Count;$i++){
        $row=$Readback.rules[$i]
        if($row.key -ne $manifest.bind.keys[$i] -or $row.layer -ne $layers[$i%2] -or
            $row.port -ne $n2.ports[[int][math]::Floor($i/2)] -or $row.protocol -ne 6 -or
            $row.flags -notin 0,64 -or $row.action -ne 4097 -or $row.id -le 0 -or $row.filterWeight -ne 1152921504606846976){return $false}
    }
    return $true
}

function Confirm-BindMatrix($Rows,[int]$Port,[bool]$Baseline,[bool]$Live=$false) {
    $addresses=if($Baseline){'0.0.0.0'}else{'0.0.0.0','127.0.0.1'}
    $options=if($Baseline){'exclusive'}else{'default','reuse','exclusive'}
    $errorCodes=if($Baseline){0}elseif($Live){10013,10048}else{10013}
    $stage=if($Baseline){'listening'}else{'bind'}
    if(@($Rows).Count -ne (@($addresses).Count*@($options).Count)){return $false}
    foreach($address in $addresses){
        foreach($option in $options){
            $row=@($Rows|Where-Object {$_.address -eq $address -and $_.option -eq $option})
            if($row.Count -ne 1 -or $row[0].port -ne $Port -or $row[0].outsideA.userSid -ne $Report.accountSid -or
                $row[0].outsideA.container -ne $false -or $row[0].sameExecutable.container -ne $false -or
                $row[0].sameExecutable.userSid -ne $Report.proxyReady.userSid){return $false}
            foreach($reading in $row[0].outsideA,$row[0].sameExecutable,$row[0].host){
                if($reading.stage -ne $stage -or $null -eq $reading.nativeError -or $reading.nativeError -notin $errorCodes -or
                    $reading.address -ne $address -or $reading.option -ne $option){return $false}
            }
        }
    }
    return $true
}

$keys=@($manifest.sublayer,$manifest.bind.sub)+@($manifest.keys)+@($manifest.bind.keys)
$checks.scope=$regular.scopeVerified -and $Report.windowReady.visible -eq $true -and (Scope-N1 $Report.windowReady) -and
    (Scope-N1 $Report.windowReady.listenerReady) -and (Scope-N1 $Report.simulation) -and (Scope-N1 $Report.simulation.native)
$checks.temporaryScope=$manifest.mode -ceq 'bind-guard-a-only' -and $manifest.containerSid -eq $Report.windowReady.containerSid -and
    $manifest.port -eq $q -and $manifest.bind.ports[0] -eq $p -and $manifest.bind.ports[1] -eq $q -and
    @($n2.ports).Count -eq 2 -and $p -ge 40000 -and $p -lt 49152 -and $q -ge 40000 -and $q -lt 49152 -and $p -ne $q -and
    @($keys|Sort-Object -Unique).Count -eq 11 -and @($keys|Where-Object {!$_ -or $_ -eq [guid]::Empty.ToString()}).Count -eq 0
$checks.privateAcl=$n2.privateAclProtected -eq $true -and $n2.aclControl.userSid -eq $Report.accountSid -and
    $n2.aclControl.readConfig -eq 'denied' -and $n2.aclControl.writeProxy -eq 'denied' -and $n2.aclControl.replaceConfig -eq 'denied'
$checks.proxyIdentity=@($manifest.bind.owners).Count -eq 2 -and @($Report.proxySegments).Count -eq 2 -and
    $manifest.bind.owners[0].port -eq $p -and $manifest.bind.owners[1].port -eq $q -and
    $manifest.bind.owners[0].sha256 -match '^[A-F0-9]{64}$' -and $manifest.bind.owners[0].sha256 -eq $n2.proxySha256 -and
    $manifest.bind.owners[1].sha256 -eq $n2.proxySha256 -and $manifest.bind.owners[0].pid -eq $Report.proxyReady.pid -and
    $manifest.bind.owners[1].pid -eq $Report.proxySegments[1].pid -and $manifest.bind.owners[0].pid -ne $manifest.bind.owners[1].pid -and
    $manifest.bind.owners[0].userSid -eq $Report.proxyReady.userSid -and $manifest.bind.owners[1].userSid -eq $Report.proxyReady.userSid -and
    $Report.proxyReady.container -eq $false -and $Report.proxySegments[1].container -eq $false
$checks.bindBefore=(Confirm-BindMatrix $n2.preBind $p $true) -and (Confirm-BindMatrix $n2.preQ $q $true)
$checks.pBinding=(Confirm-BindRows $n2.pReadback 1) -and (Confirm-BindMatrix $n2.liveBind $p $false $true) -and $n2.pHealthBeforeA -eq $true
$checks.qBinding=(Confirm-BindRows $n2.qReadback 2) -and $n2.qHealth -eq $true -and (Confirm-BindMatrix $n2.oldPStillSealed $p $false)
$checks.defaultDeny=$Report.staticGuard.installationSessionClosed -eq $true -and
    (Readback-N1 $Report.staticGuard.installClosedReadback $false $p) -and
    (Readback-N1 $Report.staticGuard.initialPermitReadback $true $p) -and (Readback-N1 $n2.qPermit $true $q)
$checks.outsideControl=$Report.outsideGate.container -eq $false -and $Report.outsideGate.userSid -eq $Report.accountSid -and
    $Report.outsideGate.proxyHttp -eq 'matched' -and (Hits-N1 $Report.outsideGateHits $canaries 1)
$checks.baselines=$Report.guardBaseline.windowHttp -eq 'matched' -and $Report.guardBaseline.native.proxyHttp -eq 'matched' -and
    (Hits-N1 $Report.guardBaselineHits @('tcp','udp') 1) -and $Report.hostReverseBaseline.connected -eq $true -and
    $Report.hostReverseGate.connected -eq $false -and (Hits-N1 $Report.guardGateHits $canaries 0) -and
    (Hits-N1 $Report.healthyCheckpointHits $canaries 0) -and $Report.healthyCheckpoint.windowHttp -eq 'matched'
$checks.outages=(Confirm-BindRows $n2.proxyOnly.readback.bind 1) -and (Readback-N1 $n2.proxyOnly.readback.scope $true $p) -and
    $n2.proxyOnly.readback.ownerPid -eq $n2.both.owner.managerPid -and $n2.proxyOnly.pid -eq $Report.proxyReady.pid -and
    (Readback-N1 $n2.both.owner.readback $false $p) -and (Readback-N1 $n2.ownerOnly.owner.readback $false $q) -and
    $n2.both.owner.managerWasOnlyKilled -eq $true -and $n2.ownerOnly.owner.managerWasOnlyKilled -eq $true -and
    $n2.ownerOnly.owner.managerPid -ne $n2.both.owner.managerPid -and $n2.ownerOnly.proxyPid -eq $Report.proxySegments[1].pid -and
    (Confirm-BindRows $n2.ownerOnly.readback 2) -and $n2.ownerOnly.proxyHealthyAfter -eq $true -and
    (Confirm-BindMatrix $n2.proxyOnly.bind $p $false) -and (Confirm-BindMatrix $n2.both.bind $p $false)
$checks.oldFlows=(Offline-Flow-N1 $n2.proxyOnly.flow $n2.oldP (Time-N1 $n2.proxyOnly.offlineUtc)) -and
    (Offline-Flow-N1 $n2.both.flow $n2.oldP (Time-N1 $n2.both.offlineUtc)) -and
    (Offline-Flow-N1 $n2.oldPAfterQ $n2.oldP (Time-N1 $n2.proxyOnly.offlineUtc)) -and
    (Offline-Flow-N1 $n2.ownerOnly.flow $n2.oldQ (Time-N1 $n2.ownerOnly.offlineUtc)) -and
    @($n2.oldP.events|Where-Object {$_.status -eq 'matched'}).Count -gt 0 -and
    @($n2.oldQ.events|Where-Object {$_.status -eq 'matched'}).Count -gt 0
foreach($fault in $n2.proxyOnly,$n2.both,$n2.ownerOnly){
    $start=Time-N1 $(if($fault.owner){$fault.owner.exitSignalUtc}else{$fault.exitedUtc})
    $end=Time-N1 $fault.offlineUtc
    if(!$start -or !$end -or $end -lt $start -or ($end-$start).TotalSeconds -gt 4){$checks.oldFlows=$false}
}
$checks.rotation=$n2.clientRotation.ok -eq $true -and $n2.clientRotation.port -eq $q -and
    (Scope-N1 $n2.clientRotation.identity) -and $n2.clientRotation.flow.socketInvalid -eq $true -and $Report.finalFlow.action -eq 'finish'
$checks.phaseResults=@($Report.phaseChecks).Count -eq 7
foreach($phase in 'healthy1','outage1','crash1','stopped2','recovered1','recovered2','crash2'){
    $online=$phase -in 'healthy1','recovered1','recovered2'
    $entry=@($Report.phaseChecks|Where-Object {$_.phase -eq $phase})
    $command=@($Report.flowCommands|Where-Object {$_.number -eq $entry[0].command -and $_.phase -eq $phase})
    if($entry.Count -ne 1 -or $command.Count -ne 1){$checks.phaseResults=$false;continue}
    $entry=$entry[0];$command=$command[0];$probe=$command.probe
    $expectedPort=if($phase -in 'healthy1','outage1','crash1'){$p}else{$q}
    $expectedStatus=if($online){'matched'}else{'ConnectFailure','Timeout'}
    if($entry.online -ne $online -or $command.ok -ne $true -or $command.port -ne $expectedPort -or $probe.windowHttp -notin $expectedStatus -or
        !(Scope-N1 $command.identity) -or !(Scope-N1 $probe.identity) -or !(Hits-N1 $entry.hits $canaries 0) -or
        !(Dns-N1 $probe.system $phase @()) -or !(Host-N1 $entry.host $phase)){$checks.phaseResults=$false}
    if($phase -in 'healthy1','recovered2' -and ($command.action -ne 'native-probe' -or $probe.sameContainer -ne $true -or
        $probe.identity.pid -ne $probe.childPid -or $probe.childPid -eq $Report.windowReady.pid)){$checks.phaseResults=$false}
}
$dns=$Report.observer.dns
$loss=$dns.lossBeforeStop
$checks.trace=$regular.traceComplete -and $null -ne $loss.eventsLost -and $loss.eventsLost -eq 0 -and
    $loss.logBuffersLost -eq 0 -and $loss.realtimeBuffersLost -eq 0 -and $dns.servicePid -gt 0 -and $dns.servicePid -eq $dns.servicePidAfter
$checks.initialDns=(Dns-N1 $Report.guardBaseline.native 'baseline' @()) -and (Dns-N1 $Report.guardGate.native 'stopped' @()) -and
    (Dns-N1 $Report.healthyCheckpoint.native 'healthy' @()) -and (Dns-N1 $Report.simulation.native 'healthy' @())
$testedPhases=@('baseline','stopped','healthy','healthy1','outage1','crash1','stopped2','recovered1','recovered2','crash2')
$checks.noOtherDns=@($dns.events|Where-Object {$_.profile -eq 'A' -and $_.event -in 3010,3011 -and $_.phase -notin $testedPhases}).Count -eq 0
$checks.initialHost=(Host-N1 $Report.hostBefore 'baseline') -and (Host-N1 $Report.hostGate 'stopped') -and (Host-N1 $Report.hostDuring 'healthy')
$cleanup=$Report.observer.staticGuardCleanup
$checks.rollback=$cleanup.absent -eq $true -and $cleanup.bindAbsent -eq $true -and (Empty-N1 $cleanup 'errors') -and
    (Empty-N1 $cleanup 'emergencyStoppedPids') -and (Empty-N1 $Report.observer.after 'matched') -and
    (Empty-N1 $Report 'remainingTcpListeners') -and (Empty-N1 $Report 'remainingUdpListeners') -and (Empty-N1 $Report 'remainingProbePids') -and
    $Report.observer.sessionGone -eq $true -and $Report.observer.rawTraceGone -eq $true -and $Report.privateDirectoryGone -eq $true -and
    !$Report.staticCleanupError -and !$Report.proxyError -and !$Report.observer.error
$checks.rebind=@($n2.rebind).Count -eq 2 -and @($n2.rebind|Where-Object {$_.stage -eq 'listening' -and $_.nativeError -eq 0}).Count -eq 2
$checks.postRollbackHost=(Host-N1 $Report.postRollbackHost 'recovered9') -and (Time-N1 $Report.postRollbackHost.startedUtc) -ge (Time-N1 $cleanup.removedUtc)
$checks.stageCleanup=$Report.stageCleanup.stageGone -eq $true -and (Empty-N1 $Report.stageCleanup 'remainingStagePids') -and
    (Empty-N1 $Report.stageCleanup 'forcedPids')
$failed=@($checks.Keys|Where-Object {$checks[$_] -ne $true})
$outcome=if(!$failed.Count){'passed-bind-guard-n2'}elseif($failed.Count -eq 1 -and $failed[0] -eq 'stageCleanup' -and !$Report.stageCleanup){'pending-stage-cleanup'}else{'failed-bind-guard-n2'}
return @{outcome=$outcome;checks=$checks;failed=$failed;scope='IPv4 synthetic HTTP, IPv6 bind-rule readback only'}
