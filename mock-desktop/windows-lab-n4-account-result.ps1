[CmdletBinding(DefaultParameterSetName='Report')]
param(
    [Parameter(Mandatory,ParameterSetName='Library')][switch]$FunctionsOnly,
    [Parameter(Mandatory,ParameterSetName='Report')][object]$Report,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest
)
$ErrorActionPreference = 'Stop'

function Test-AccountIdentity($Identity, [string]$UserSid, [bool]$Container) {
    if (!$Identity -or $Identity.userSid -cne $UserSid -or $Identity.pid -le 0 -or
        $Identity.startTicks -le 0 -or $Identity.session -le 0 -or
        $Identity.container -isnot [bool] -or $Identity.container -ne $Container) { return $false }
    if (!$Container) { return !$Identity.containerSid }
    return $Identity.containerSid -cmatch '^S-1-15-2(-[0-9]+){7}$' -and
        @($Identity.networkCapabilities).Count -eq 1 -and
        $Identity.networkCapabilities[0] -ceq 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
}

function Test-AccountPath($Probe, $Endpoint, [bool]$ExpectedReachable) {
    return $Probe -and $Probe.endpoint -ceq $Endpoint -and (Test-Count $Probe.sent) -and
        $Probe.sent -gt 0 -and (Test-Count $Probe.hits) -and (Test-True $Probe.completed) -and
        $(if ($ExpectedReachable) { $Probe.hits -eq $Probe.sent } else { $Probe.hits -eq 0 })
}

function Test-Count($Value) { return ($Value -is [int] -or $Value -is [long]) -and $Value -ge 0 }
function Test-True($Value) { return $Value -is [bool] -and $Value }

function Get-AccountResult($Data) {
    $checks = [ordered]@{ accountMatch = $false; coldStart = $false; dns = $false; host = $false; cleanup = $false }
    if (!$Data -or $Data.schema -cne 'studio-n4-account-match-v1' -or
        $Data.accountSid -cnotmatch '^S-1-5-21(-[0-9]+){4}$' -or $Data.hostSid -ceq $Data.accountSid -or
        $Data.hostSid -cnotmatch '^S-1-5-21(-[0-9]+){4}$' -or !$Data.endpoints.tcp -or !$Data.endpoints.udp) {
        return [ordered]@{ outcome = 'invalid-evidence'; checks = $checks }
    }
    $sid = $Data.accountSid
    $phases = @($Data.phases)
    if (($phases.name -join ',') -cne 'baseline,blocked,cold,restored') {
        return [ordered]@{ outcome = 'invalid-evidence'; checks = $checks }
    }
    $checks.accountMatch = $true
    $checks.host = $true
    $oldFlow = $phases[0].host.oldConnection
    foreach ($phase in $phases) {
        $reachable = $phase.name -in 'baseline','restored'
        if (!(Test-AccountIdentity $phase.psec.identity $sid $true)) { $checks.accountMatch = $false }
        if ($phase.name -ne 'cold' -and !(Test-AccountIdentity $phase.ordinary.identity $sid $false)) {
            $checks.accountMatch = $false
        }
        foreach ($protocol in 'tcp','udp') {
            if (!(Test-AccountPath $phase.psec.$protocol $Data.endpoints.$protocol $reachable) -or
                ($phase.name -ne 'cold' -and !(Test-AccountPath $phase.ordinary.$protocol $Data.endpoints.$protocol $reachable))) {
                $checks.accountMatch = $false
            }
        }
        if (!$oldFlow -or $phase.host.oldConnection -cne $oldFlow -or $phase.host.sid -cne $Data.hostSid -or
            !(Test-True $phase.host.dns) -or !(Test-True $phase.host.oldMarker) -or !(Test-True $phase.host.newMarker)) {
            $checks.host = $false
        }
    }
    $cold = $phases[2]
    $t = $cold.timeline
    $checks.coldStart = ($t.observerReady -gt 0 -and $t.observerReady -lt $t.commit -and
        $t.commit -lt $t.independentReadback -and $t.independentReadback -lt $t.startRequest -and
        $t.startRequest -le $t.launchTick -and $t.launchTick -le $t.firstProbe -and $t.firstProbe -le $t.observedTick -and
        $t.startRequestUtcTicks -gt 0 -and $t.startRequestUtcTicks -le $t.processCreationUtcTicks -and
        $t.processCreationUtcTicks -le $t.observedUtcTicks -and $t.processCreationUtcTicks -eq $cold.psec.identity.startTicks -and
        (Test-True $t.readbackExact) -and (Test-True $t.firstProbeObserved) -and (Test-True $t.lineageVerified) -and
        $cold.psec.identity.containerSid -cne $phases[1].psec.identity.containerSid -and
        $cold.psec.identity.startTicks -gt $phases[1].psec.identity.startTicks -and
        $cold.psec.identity.pid -gt 0 -and $t.observedPid -eq $cold.psec.identity.pid)
    $dns = $cold.dns
    $queries = @($dns.queries)
    $checks.dns = ($dns.servicePid -gt 0 -and (Test-True $dns.lossCountsVerified) -and (Test-Count $dns.lostEvents) -and $dns.lostEvents -eq 0 -and
        (Test-Count $dns.unknownAttributions) -and $dns.unknownAttributions -eq 0 -and
        (Test-Count $dns.otherPsecTraffic) -and $dns.otherPsecTraffic -eq 0 -and (Test-True $dns.coveredFirstProbe) -and
        (Test-True $dns.hostPositive) -and (Test-True $dns.ordinaryPositive) -and ($queries.api -join ',') -ceq 'DnsQuery_W,GetAddrInfoW' -and
        $queries[0].name -and $queries[1].name -and $queries[0].name -ine $queries[1].name)
    foreach ($query in $queries) {
        if ($query.callerPid -ne $cold.psec.identity.pid -or !(Test-Count $query.sends) -or
            !(Test-Count $query.replies) -or $query.sends -ne 0 -or $query.replies -ne 0) { $checks.dns = $false }
    }
    $checks.cleanup = ((Test-True $Data.cleanup.workloadsExited) -and (Test-True $Data.cleanup.rulesAbsent) -and
        (Test-True $Data.cleanup.sublayersAbsent) -and (Test-True $Data.cleanup.traceStoppedAfterControls))
    $all = $false -notin $checks.Values
    return [ordered]@{ outcome = $(if ($all) { 'passed-account-match-m' } else { 'failed-or-incomplete-account-match-m' });
        checks = $checks; ingress = 'not-assessed'; ipv6 = 'not-assessed'; product = 'not-assessed' }
}

function New-SyntheticAccountReport {
    $cap = 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
    $sid = 'S-1-5-21-1-2-3-1001'
    $hostSid = 'S-1-5-21-1-2-3-1002'
    $phases = @(foreach ($name in 'baseline','blocked','cold','restored') {
        $count = if ($name -in 'baseline','restored') { 2 } else { 0 }
        $pkg = if ($name -eq 'cold') { 'S-1-15-2-2-3-4-5-6-7-8' } else { 'S-1-15-2-1-2-3-4-5-6-7' }
        $psec = @{ pid=11; startTicks=$(if ($name -eq 'cold') { 300 } else { 200 }); session=1;
            userSid=$sid; container=$true; containerSid=$pkg; networkCapabilities=@($cap) }
        $ordinary = @{ pid=12; startTicks=100; session=1; userSid=$sid; container=$false }
        $phase = @{ name=$name; psec=@{identity=$psec}; ordinary=@{identity=$ordinary};
            host=@{sid=$hostSid; oldConnection='fixed'; dns=$true; oldMarker=$true; newMarker=$true} }
        foreach ($role in 'psec','ordinary') {
            foreach ($protocol in 'tcp','udp') { $phase[$role][$protocol] = @{endpoint="$protocol-target"; sent=2; hits=$count; completed=$true} }
        }
        $phase
    })
    $phases[2].timeline = @{observerReady=1; commit=2; independentReadback=3; startRequest=4; launchTick=5;
        firstProbe=6;observedTick=7;startRequestUtcTicks=250;processCreationUtcTicks=300;observedUtcTicks=350;
        readbackExact=$true; firstProbeObserved=$true; lineageVerified=$true; observedPid=11}
    $phases[2].dns = @{servicePid=13; lossCountsVerified=$true; lostEvents=0; unknownAttributions=0;otherPsecTraffic=0;
        coveredFirstProbe=$true; hostPositive=$true; ordinaryPositive=$true;
        queries=@(@{api='DnsQuery_W'; name='sample-w.test.'; callerPid=11; sends=0; replies=0},
            @{api='GetAddrInfoW'; name='sample-g.test.'; callerPid=11; sends=0; replies=0})}
    return @{schema='studio-n4-account-match-v1'; accountSid=$sid; hostSid=$hostSid;
        endpoints=@{tcp='tcp-target'; udp='udp-target'}; phases=$phases;
        cleanup=@{workloadsExited=$true; rulesAbsent=$true; sublayersAbsent=$true; traceStoppedAfterControls=$true}}
}

if ($FunctionsOnly) { return }
if (!$SelfTest) { return Get-AccountResult $Report }

$positive = New-SyntheticAccountReport | ConvertTo-Json -Depth 10 | ConvertFrom-Json
if ((Get-AccountResult $positive).outcome -cne 'passed-account-match-m') {
    throw 'N4 result judge rejected its synthetic positive control'
}
$negative = @(
    { param($r) $r.phases[0].psec.udp.hits=0 },
    { param($r) $r.phases[1].psec.tcp.hits=1 },
    { param($r) $r.phases[2].timeline.independentReadback=5 },
    { param($r) $r.phases[2].timeline.lineageVerified=$false },
    { param($r) $r.phases[2].timeline.processCreationUtcTicks=249 },
    { param($r) $r.phases[2].psec.identity.userSid=$r.hostSid },
    { param($r) $r.phases[2].dns.lostEvents=1 },
    { param($r) $r.phases[2].dns.queries[0].sends=1 },
    { param($r) $r.phases[2].dns.queries[0].Remove('replies') },
    { param($r) $r.phases[2].dns.queries[0].callerPid=12 },
    { param($r) $r.phases[3].host.oldConnection='reopened' },
    { param($r) $r.cleanup.rulesAbsent=$false }
)
foreach ($change in $negative) {
    $fixture = New-SyntheticAccountReport
    & $change $fixture
    if ((Get-AccountResult $fixture).outcome -ceq 'passed-account-match-m') {
        throw ('N4 result judge accepted a synthetic regression: ' + $change.ToString())
    }
}
[ordered]@{ mode='offline-result-selftest'; positive=1; rejected=$negative.Count; systemWrites=0 }
