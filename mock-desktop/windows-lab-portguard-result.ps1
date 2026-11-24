param([Parameter(Mandatory)]$Report)
$regular=& (Join-Path $PSScriptRoot 'windows-lab-psec-result.ps1') $Report
$guard=$Report.observer.guard
$baseline=$Report.guardBaseline
$gate=$Report.guardGate
$native=$Report.simulation.native
$same=$Report.windowReady.containerSid
$scope=$same -and $baseline.containerSid -eq $same -and $baseline.native.containerSid -eq $same -and
    $gate.containerSid -eq $same -and $gate.native.containerSid -eq $same
foreach($item in @($baseline,$baseline.native,$gate,$gate.native)) {
    if(!$item.container -or !$item.inJob -or $item.userSid -ne $Report.accountSid -or $item.session -ne $Report.session -or
        $item.networkCapabilities.Count -ne 1 -or
        $item.networkCapabilities[0] -ne 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225') {$scope=$false}
}
$baselineOk=$baseline.windowHttp -eq 'matched' -and $baseline.native.proxyHttp -eq 'matched' -and
    $Report.guardBaselineHits.tcp -eq 1 -and $Report.guardBaselineHits.udp -eq 1
$outsideOk=!$Report.outsideGate.container -and $Report.outsideGate.userSid -eq $Report.accountSid -and
    $Report.outsideGate.proxyHttp -eq 'matched' -and $Report.outsideGateHits.tcp -eq 1 -and $Report.outsideGateHits.udp -eq 1
$gateOk=$gate.windowHttp -eq 'ConnectFailure' -and $gate.native.proxyHttp -eq 'ConnectFailure' -and
    $Report.guardGateHits.tcp -eq 0 -and $Report.guardGateHits.udp -eq 0
$dns=$Report.observer.dns
$extraDnsOk=$true
foreach($item in @(@{phase='baseline';value=$baseline},@{phase='stopped';value=$gate})) {
    $events=@($dns.events | Where-Object {$_.profile -eq 'A' -and $_.phase -eq $item.phase -and $_.event -in 3010,3011 -and
        $_.clientPid -in @($item.value.pid,$item.value.native.pid)})
    if($events.Count -or $item.value.native.dnsQueryStatus -ne 5 -or $item.value.native.getAddrInfoStatus -ne 11001) {$extraDnsOk=$false}
}
$hostGateEvents=@($dns.events|Where-Object {$_.profile -eq 'H' -and $_.phase -eq 'stopped' -and $_.clientPid -eq $Report.hostGate.pid -and $_.emitterPid -eq $dns.servicePid})
$hostGateOk=$Report.hostGate.old -and $Report.hostGate.fresh -and $Report.hostGate.dns -eq 'answered' -and
    3010 -in $hostGateEvents.event -and 3011 -in $hostGateEvents.event
$clean=$regular.systemCleanupVerified -and $guard.absent -and !$guard.cleanupError -and !$guard.removeError -and
    @($guard.emergencyStoppedPids).Count -eq 0
$installed=@($guard.commands|Where-Object {$_.command -eq 'install'})
$opened=@($guard.commands|Where-Object {$_.command -eq 'open'})
$readbackOk=$installed.Count -eq 1 -and $installed[0].readback.rules.Count -eq 7 -and $installed[0].readback.gateClosed
$outcome='inconclusive-portguard'
if($scope -and $baselineOk -and $outsideOk -and $readbackOk -and !$gateOk) {$outcome='failed-container-gate'}
elseif($scope -and $baselineOk -and $outsideOk -and $gateOk -and $readbackOk -and !$Report.error -and !$guard.error -and
    $regular.scopeVerified -and $regular.traceComplete -and $regular.positiveControls -and $hostGateOk -and $extraDnsOk -and $clean -and
    $opened.Count -eq 1 -and $opened[0].readback.rules.Count -eq 6 -and !$opened[0].readback.gateClosed) {
    if($Report.containerHits.tcp -or $Report.containerHits.udp) {$outcome='failed-container-portguard'}
    elseif($Report.simulation.windowHttp -ne 'matched' -or $native.proxyHttp -ne 'matched') {$outcome='failed-guarded-proxy'}
    elseif($Report.proxyResult.windowRequests -eq 5 -and $Report.proxyResult.markerSent -eq 5 -and
        $regular.attributedServiceSends -eq 0 -and $native.dnsQueryStatus -eq 5 -and $native.getAddrInfoStatus -eq 11001) {
        $outcome='passed-container-portguard-healthy-gate'
    }
}
[pscustomobject]@{outcome=$outcome;sameContainerScopeVerified=[bool]$scope;baselineVerified=[bool]$baselineOk;outsideIdentityControl=[bool]$outsideOk;
    gateBlocked=[bool]$gateOk;exactReadback=[bool]$readbackOk;traceComplete=$regular.traceComplete;dnsGateChecks=[bool]$extraDnsOk;
    hostGateControl=[bool]$hostGateOk;systemCleanupVerified=[bool]$clean;directHitEventsAvailable=$false}
