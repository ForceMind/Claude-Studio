$ErrorActionPreference='Stop'
# Synthetic report only. This script never launches the lab or changes Windows.
$cap='S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
$sid='S-1-15-2-1-2-3-4-5-6-7';$user='S-1-5-21-1-2-3-1001'
function Identity([int]$Id){return @{pid=$Id;container=$true;inJob=$true;userSid=$user;containerSid=$sid;session=1;networkCapabilities=@($cap)}}
function Native([int]$Id){$v=Identity $Id;$v.dnsQueryStatus=5;$v.getAddrInfoStatus=11001;$v.proxyHttp='matched';return $v}
function Window([int]$Id,[int]$Child){$v=Identity $Id;$v.native=Native $Child;$v.windowHttp='matched';return $v}
function Hits([int]$Count){return @{tcp=$Count;udp=$Count;udpProxy=$Count;alternate=$Count}}
function Host([string]$Phase){return @{pid=90;old=$true;fresh=$true;dns='answered';phase=$Phase;startedUtc='2026-11-22T00:00:10.100Z';finishedUtc='2026-11-22T00:00:10.200Z'}}
$keys=@(1..5|ForEach-Object {('00000000-0000-0000-0000-{0:d12}' -f $_)})
$manifest=@{mode='static-a-only';containerSid=$sid;port=55000;weight=100;sublayer='00000000-0000-0000-0000-000000000006';keys=$keys}
function Readback([bool]$Permit){
    $names=@('D4','D6','I4','I6','E');$layers=@('c38d57d1-05a7-4c33-904f-7fbceee60e82','4a72393b-319f-44bc-84c3-ba54dcb3b6b4','e1cd9fe7-f4b5-4273-96c0-592e487b8650','a3b42c97-9f04-4672-b87e-cee9c483257f','c38d57d1-05a7-4c33-904f-7fbceee60e82')
    $rules=@();for($i=0;$i -lt 5;$i++){
        $v=@{rule=$names[$i];key=$keys[$i];present=($i -lt 4 -or $Permit)}
        if($v.present){
            $weight=if($i -eq 4){2305843009213693952}else{1152921504606846976}
            $v.id=$i+1;$v.layer=$layers[$i];$v.sublayer=$manifest.sublayer;$v.action=if($i -eq 4){4098}else{4097}
            $v.flags=0;$v.weightType=4;$v.weight=$weight;$v.effectiveWeightType=4;$v.effectiveWeight=$weight
            $v.conditions=@(@{field='71bc78fa-f17c-4997-a602-6abb261f351c';match=0;type=13;value=$sid})
            if($i -eq 4){$v.conditions+=@(@{field='3971ef2b-623e-4f9a-8cb1-6e79b806b9a7';match=0;type=1;value=6},@{field='b235ae9a-1d64-49b8-a44c-5ff3d9095045';match=0;type=3;value=2130706433},@{field='c35a604d-d22b-4e1a-91b4-68f674ee674b';match=0;type=2;value=55000})}
        };$rules+=@($v)
    }
    return @{sublayer=$manifest.sublayer;sublayerPresent=$true;sublayerFlags=0;weight=100;exceptionPresent=$Permit;rules=$rules}
}
$ready=Window 10 11;$ready.visible=$true;$ready.windowHandle=100;$ready.listenerReady=Identity 12
$simulation=Window 10 11;$simulation.visible=$true
$baseline=Window 10 13;$gate=Window 10 14;$gate.windowHttp='ConnectFailure';$gate.native.proxyHttp='ConnectFailure'
$initial=@{streamId=1;connectionId='synthetic-connection';started=$true;sameSocket=$true;socketInvalid=$false;reconnects=0;droppedEvents=0;events=@(@{attemptUtc='2026-11-22T00:00:02Z';completedUtc='2026-11-22T00:00:02.100Z';status='matched'})}
$offline=@{streamId=1;connectionId='synthetic-connection';started=$true;sameSocket=$true;socketInvalid=$true;reconnects=0;droppedEvents=0;events=@($initial.events)+@(@{attemptUtc='2026-11-22T00:00:05Z';completedUtc='2026-11-22T00:00:05.001Z';status='socket-invalid'})}
$final=@{};foreach($key in $offline.Keys){$final[$key]=$offline[$key]};$final.stopped=$true
$report=@{accountSid=$user;session=1;windowReady=$ready;simulation=$simulation;guardBaseline=$baseline;guardGate=$gate;healthyCheckpoint=(Window 10 15);
    baseline=@{pid=80};baselineHits=(Hits 1);guardBaselineHits=(Hits 1);guardGateHits=(Hits 0);healthyCheckpointHits=(Hits 0);outsideGateHits=(Hits 1);containerHits=(Hits 0);
    outsideGate=@{container=$false;pid=81;userSid=$user;proxyHttp='matched'};hostReverseBaseline=@{attempted=$true;connected=$true};hostReverseGate=@{attempted=$true;connected=$false};
    policy=@{phase='healthy';hostLoopbackExperiment=$true;hostLoopback='allow';ingress='deny';egress='deny';runtimeProxy=$null};
    proxyReady=@{pid=50;port=55000};hostBefore=(Host 'baseline');hostDuring=(Host 'healthy');hostAfter=(Host 'recovered');hostGate=(Host 'stopped');postRollbackHost=(Host 'recovered9');
    observer=@{sessionGone=$true;rawTraceGone=$true;live=@{inspected=10;matched=@(1)};after=@{inspected=10;matched=@()};installationSessionClosed=$true;installClosedUtc='2026-11-22T00:00:01Z';
        guard=@{manifest=$manifest};staticGuardCleanup=@{absent=$true;removedUtc='2026-11-22T00:00:10Z';emergencyStoppedPids=@();errors=@()};
        dns=@{events=@();servicePid=99;servicePidAfter=99;lossBeforeStop=@{eventsLost=0;logBuffersLost=0;realtimeBuffersLost=0}}};
    privateDirectoryGone=$true;remainingTcpListeners=@();remainingUdpListeners=@();remainingProbePids=@();execution=@{runExit=0;addedProfileDirs=@()};
    stageCleanup=@{stageGone=$true;remainingStagePids=@();forcedPids=@()};
    staticGuard=@{installationSessionClosed=$true;installClosedUtc='2026-11-22T00:00:01Z';installClosedReadback=(Readback $false);initialPermitReadback=(Readback $true);afterCrashReadback=(Readback $false);recoveryReadback=(Readback $true);initialFlow=$initial;oldFlowAfterRecovery=$offline};
    flowCommands=@(@{number=1;action='start-stream';phase='healthy1';identity=(Identity 10);ok=$true;initialMatched=$true;flow=$initial});phaseChecks=@();
    finalFlow=@{ok=$true;action='finish';flow=$final;archives=@()}}
foreach($phase in @('baseline','healthy','recovered','stopped','healthy1','crash','recovered1','recovered2','recovered9')){
    foreach($event in @(3010,3011)){$report.observer.dns.events+=@{profile='H';phase=$phase;event=$event;clientPid=90;emitterPid=99}}
}
foreach($api in @('dns','addr')){foreach($event in @(3010,3011)){$report.observer.dns.events+=@{profile='A';phase='baseline';probe=$api;event=$event;clientPid=80;emitterPid=99}}}
foreach($api in @('dns','addr')){foreach($event in @(3010,3011)){$report.observer.dns.events+=@{profile='A';phase='stopped';probe=$api;event=$event;clientPid=81;emitterPid=99}}}
$number=1
foreach($phase in @('healthy1','crash','recovered1','recovered2')){
    $number++;$native=$phase -in 'healthy1','recovered2';$id=if($native){20+$number}else{10}
    $probe=@{identity=(Identity $id);system=(Native $id);windowHttp=$(if($phase -eq 'crash'){'ConnectFailure'}else{'matched'});startedUtc='2026-11-22T00:00:03.100Z';finishedUtc='2026-11-22T00:00:03.900Z'}
    if($native){$probe.ok=$true;$probe.sameContainer=$true;$probe.freshContainer=$false;$probe.exitCode=0;$probe.childPid=$id}
    $report.flowCommands+=@{number=$number;phase=$phase;action=$(if($native){'native-probe'}else{'probe'});identity=(Identity 10);ok=$true;probe=$probe}
    $report.phaseChecks+=@{phase=$phase;online=($phase -ne 'crash');command=$number;hits=(Hits 0);host=(Host $phase)}
    if($phase -eq 'crash'){$report.staticGuard.managerCrash=@{managerPid=60;managerWasOnlyKilled=$true;exitUtc='2026-11-22T00:00:03Z';exitSignalUtc='2026-11-22T00:00:03.010Z';permitAbsentUtc='2026-11-22T00:00:03.050Z';offlineUtc='2026-11-22T00:00:04Z';othersAlive=@{window=$true;proxy=$true;listener=$true};windowProbe=$probe;host=(Host 'crash');flowSnapshot=$offline}}
}
$json=$report|ConvertTo-Json -Depth 30
$evaluator=Join-Path $PSScriptRoot 'windows-lab-static-guard-result.ps1'
function Evaluate($Value){return & $evaluator $Value}
$positive=Evaluate ($json|ConvertFrom-Json)
if($positive.outcome -ne 'passed-static-guard-n1'){throw ('Synthetic valid JSON report rejected: '+($positive.missingOrFailed -join ', '))}
$cases=[ordered]@{
    wrongSID={param($r)$r.staticGuard.initialPermitReadback.rules[4].conditions[0].value='S-1-15-2-9'}
    missingStatic={param($r)$r.staticGuard.afterCrashReadback.rules[0].present=$false}
    permitRemains={param($r)$r.staticGuard.afterCrashReadback.rules[4].present=$true}
    timeout={param($r)$r.staticGuard.managerCrash.offlineUtc='2026-11-22T00:00:07Z'}
    oldFlowLate={param($r)$r.staticGuard.managerCrash.flowSnapshot.events[1].status='matched'}
    proxyKilled={param($r)$r.staticGuard.managerCrash.othersAlive.proxy=$false}
    hostFail={param($r)$r.postRollbackHost.fresh=$false}
    DNSsend={param($r)$r.observer.dns.events+=@{profile='A';phase='crash';event=3010;clientPid=10;emitterPid=99}}
    residue={param($r)$r.observer.staticGuardCleanup.absent=$false}
    missingCleanup={param($r)$r.PSObject.Properties.Remove('stageCleanup')}
    missingReconnectCount={param($r)$r.staticGuard.managerCrash.flowSnapshot.PSObject.Properties.Remove('reconnects')}
    rollbackHostTooEarly={param($r)$r.postRollbackHost.startedUtc='2026-11-22T00:00:09Z'}
    wrongPermitPort={param($r)$r.staticGuard.initialPermitReadback.rules[4].conditions[3].value=55001}
    wrongWeight={param($r)$r.staticGuard.initialPermitReadback.rules[4].weight=1}
    missingPhase={param($r)$r.phaseChecks=@($r.phaseChecks|Where-Object {$_.phase -ne 'crash'})}
    recoveredOldFlowLate={param($r)$r.staticGuard.oldFlowAfterRecovery.events[1].status='matched'}
    finalFlowLate={param($r)$r.finalFlow.flow.events[1].status='matched'}
    missingFlowAfterRecovery={param($r)$r.staticGuard.PSObject.Properties.Remove('oldFlowAfterRecovery')}
    stoppedContainerDNS={param($r)$r.observer.dns.events+=@{profile='A';phase='stopped';probe='dns';event=3010;clientPid=$r.guardGate.native.pid;emitterPid=99}}
    stoppedUnknownDNS={param($r)$r.observer.dns.events+=@{profile='A';phase='stopped';probe='dns';event=3010;clientPid=777;emitterPid=99}}
    forgedOutsideContainerPID={param($r)
        $r.outsideGate.pid=$r.guardGate.native.pid
        foreach($event in @($r.observer.dns.events|Where-Object {$_.profile -eq 'A' -and $_.phase -eq 'stopped'})){$event.clientPid=$r.guardGate.native.pid}
    }
}
$results=@()
foreach($name in $cases.Keys){
    $candidate=$json|ConvertFrom-Json;& $cases[$name] $candidate
    $result=Evaluate $candidate
    if($result.outcome -eq 'passed-static-guard-n1' -or !$result.missingOrFailed.Count){throw ('Synthetic negative incorrectly passed: '+$name)}
    $results+=@{case=$name;rejected=$true;missingOrFailed=$result.missingOrFailed}
}
$empty=Evaluate ([pscustomobject]@{})
if($empty.outcome -eq 'passed-static-guard-n1'){throw 'Empty report incorrectly passed'}
[pscustomobject]@{syntheticOnly=$true;positivePassed=$true;negativeCases=$results.Count;emptyReportRejected=$true;results=$results}|ConvertTo-Json -Depth 6
