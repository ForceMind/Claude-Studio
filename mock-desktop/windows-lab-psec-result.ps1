param([Parameter(Mandatory)]$Report)
$dns=$Report.observer.dns
$window=$Report.simulation
$native=$window.native
$phase=if ($Report.policy.phase) { $Report.policy.phase } else { 'stopped' }
$loopback=[bool]$Report.policy.loopback
$hostLoopback=[bool]$Report.policy.hostLoopbackExperiment
$sent=@($dns.events | Where-Object { $_.phase -eq $phase -and $_.profile -eq 'A' -and
    $_.event -eq 3010 -and $_.emitterPid -eq $dns.servicePid })
$attributed=@($sent | Where-Object { ($_.probe -in 'dns','addr' -and $_.clientPid -eq $native.pid) -or
    ($_.probe -eq 'window' -and $_.clientPid -eq $window.pid) })
$phaseLabel='cold-start with reserved, non-listening proxy port'
$noNetwork=[bool]$Report.policy.networkless
$modeVerified=[bool]$window.configuredProxyMatches
$httpExpected='ConnectFailure'
if ($noNetwork) {
    $phaseLabel='no proxy and no AppContainer network capabilities'
    $httpExpected='not-configured'
    $modeVerified=$Report.policy.ingress -eq 'deny' -and !$Report.policy.runtimeProxy -and
        $null -ne $window.networkCapabilities -and $null -ne $native.networkCapabilities -and
        $window.networkCapabilities.Count -eq 0 -and $native.networkCapabilities.Count -eq 0
}
if ($hostLoopback) {
    $phaseLabel='only networkLoopback capability, synthetic host HTTP proxy'
    $httpExpected='matched'
    $loopbackSid='S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
    $modeVerified=$Report.policy.ingress -eq 'deny' -and $Report.policy.egress -eq 'deny' -and
        $Report.policy.hostLoopback -eq 'allow' -and !$Report.policy.runtimeProxy -and
        $window.networkCapabilities.Count -eq 1 -and $native.networkCapabilities.Count -eq 1 -and
        $window.networkCapabilities[0] -eq $loopbackSid -and $native.networkCapabilities[0] -eq $loopbackSid
}
$scope=$null -ne $window -and $window.container -and $native.container -and $window.inJob -and $native.inJob -and
    $window.visible -and $modeVerified -and $window.containerSid -eq $native.containerSid -and
    $window.userSid -eq $Report.accountSid -and $native.userSid -eq $Report.accountSid -and
    $window.session -eq $Report.session -and $native.session -eq $Report.session
if ($loopback) {
    $phaseLabel='same-container HTTP proxy without AppContainer network capabilities'
    $listener=$window.listenerReady
    $scope=$scope -and $listener.container -and $listener.inJob -and $listener.userSid -eq $Report.accountSid -and
        $listener.session -eq $Report.session -and $listener.containerSid -eq $window.containerSid -and
        $listener.pid -gt 0 -and $listener.pid -ne $window.pid -and $listener.pid -ne $native.pid -and $window.pid -ne $native.pid -and
        $window.windowHandle -gt 0 -and $Report.windowReady.listenerReady.pid -eq $listener.pid -and
        $null -ne $listener.networkCapabilities -and $listener.networkCapabilities.Count -eq 0
}
$loss=$dns.lossBeforeStop
$traceComplete=$null -ne $loss -and !$dns.lossError -and $loss.eventsLost -eq 0 -and $loss.logBuffersLost -eq 0 -and
    $loss.realtimeBuffersLost -eq 0 -and $dns.servicePid -gt 0 -and $dns.servicePid -eq $dns.servicePidAfter
$positiveControls=$true
foreach ($hostPhase in 'baseline',$phase,'recovered') {
    $hostResult=switch ($hostPhase) { baseline {$Report.hostBefore} recovered {$Report.hostAfter} default {$Report.hostDuring} }
    $ctrl=@($dns.events | Where-Object { $_.profile -eq 'H' -and $_.phase -eq $hostPhase -and
        $_.emitterPid -eq $dns.servicePid -and $_.clientPid -eq $hostResult.pid })
    if (!$hostResult.old -or !$hostResult.fresh -or $hostResult.dns -ne 'answered' -or
        3010 -notin $ctrl.event -or 3011 -notin $ctrl.event) { $positiveControls=$false }
}
foreach ($api in 'addr','dns') {
    $ctrl=@($dns.events | Where-Object { $_.profile -eq 'A' -and $_.phase -eq 'baseline' -and $_.probe -eq $api -and
        $_.emitterPid -eq $dns.servicePid -and $_.clientPid -eq $Report.baseline.pid })
    if (3010 -notin $ctrl.event -or 3011 -notin $ctrl.event) { $positiveControls=$false }
}
$cleanup=$Report.observer.sessionGone -and $Report.observer.rawTraceGone -and $Report.privateDirectoryGone -and
    $Report.observer.live.inspected -gt 0 -and ($noNetwork -or $Report.observer.live.matched.Count -gt 0) -and
    $Report.observer.after.inspected -gt 0 -and $Report.observer.after.matched.Count -eq 0 -and
    $Report.remainingTcpListeners.Count -eq 0 -and $Report.remainingUdpListeners.Count -eq 0 -and
    $Report.execution.addedProfileDirs.Count -eq 0
$outcome='inconclusive'
if ($scope -and $attributed.Count) { $outcome='failed-system-dns' }
elseif ($scope -and ($Report.containerHits.tcp -gt 0 -or $Report.containerHits.udp -gt 0 -or (!$loopback -and !$hostLoopback -and $window.windowHttp -eq 'matched'))) {
    $outcome=if ($hostLoopback) { 'failed-nonproxy-host-loopback-isolation' } else { 'failed-direct-or-proxy-access' }
} elseif (!$hostLoopback -and $scope -and !$Report.error -and $Report.execution.runExit -eq 0 -and $traceComplete -and
    $positiveControls -and $cleanup -and !$sent.Count -and $Report.baselineHits.tcp -gt 0 -and
    $Report.baselineHits.udp -gt 0 -and $window.windowHttp -eq $httpExpected -and
    $native.dnsQueryStatus -ne 0 -and $native.getAddrInfoStatus -ne 0) {
    $outcome=if ($noNetwork) { 'no-leak-observed-without-network-capabilities' } else { 'no-leak-observed-in-stopped-phase' }
}
if ($hostLoopback) {
    $cleanup=$cleanup -and $null -ne $Report.remainingProbePids -and $Report.remainingProbePids.Count -eq 0 -and !$Report.proxyError
    $networkEvents=@($dns.events | Where-Object { $_.profile -eq 'A' -and $_.phase -eq $phase -and $_.event -in 3010,3011 })
    if ($scope -and !$Report.error -and $Report.execution.runExit -eq 0 -and $traceComplete -and $positiveControls -and $cleanup -and !$networkEvents.Count -and
        $Report.containerHits.tcp -eq 0 -and $Report.containerHits.udp -eq 0 -and
        $native.dnsQueryStatus -ne 0 -and $native.getAddrInfoStatus -ne 0) {
        if ($window.windowHttp -ne 'matched') { $outcome='failed-host-loopback-proxy' }
        elseif ($Report.proxyResult.windowRequests -eq 1 -and $Report.proxyResult.markerSent -eq 1 -and
            $Report.proxyResult.stoppedByParent -and $Report.proxyResult.readErrors -eq 0) { $outcome='passed-host-loopback-healthy' }
    }
}
if ($loopback) {
    $cleanup=$cleanup -and $null -ne $Report.remainingProbePids -and $Report.remainingProbePids.Count -eq 0
    $networkEvents=@($dns.events | Where-Object { $_.profile -eq 'A' -and $_.phase -eq $phase -and $_.event -in 3010,3011 })
    if ($scope -and ($Report.hostReverse.connected -or $window.listener.hostRequests -gt 0)) {
        $outcome='failed-host-to-container-loopback'
    } elseif ($outcome -eq 'inconclusive' -and $scope -and !$Report.error -and $Report.execution.runExit -eq 0 -and
        $traceComplete -and $positiveControls -and $cleanup -and !$networkEvents.Count -and
        $Report.containerHits.tcp -eq 0 -and $Report.containerHits.udp -eq 0 -and
        $Report.baselineHits.tcp -eq 1 -and $Report.baselineHits.udp -eq 1 -and
        $native.dnsQueryStatus -ne 0 -and $native.getAddrInfoStatus -ne 0) {
        if (!$listener.listening -and $listener.nativeError -gt 0) {
            $outcome='failed-container-loopback-listener'
        } elseif ($listener.listening -and $Report.hostReverse.attempted -and !$Report.hostReverse.connected -and
            $window.listener.stoppedByParent -and $window.listener.readErrors -eq 0) {
            if ($window.windowHttp -ne 'matched') {
                $outcome='failed-container-loopback-http'
            } elseif ($window.displayedMarker -and $window.listener.windowRequests -eq 1 -and
                $window.listener.markerSent -eq 1 -and $window.listener.accepted -eq 1 -and $window.listener.hostRequests -eq 0) {
                $outcome='passed-container-loopback'
            }
        }
    }
}
[pscustomobject]@{outcome=$outcome; scopeVerified=[bool]$scope; traceComplete=[bool]$traceComplete
    positiveControls=[bool]$positiveControls; attributedServiceSends=$attributed.Count
    systemCleanupVerified=[bool]$cleanup; phase=$phaseLabel}
