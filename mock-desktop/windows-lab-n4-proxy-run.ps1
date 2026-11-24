[CmdletBinding(DefaultParameterSetName='Test')]
param(
    [Parameter(Mandatory,ParameterSetName='Library')][switch]$FunctionsOnly,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$loadN4ProxyOnly = [bool]$FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n4-account-host.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.ps1') -FunctionsOnly

function Assert-N4ProxyHost($Value,[string]$OldConnection) {
    if (!$OldConnection -or $Value.oldConnection -cne $OldConnection -or
        !(Test-True $Value.dns) -or !(Test-True $Value.oldMarker) -or !(Test-True $Value.newMarker)) {
        throw 'Host control failed or the old host flow changed'
    }
}

function Assert-N4ProxyScope($Value, $State) {
    $dnsReady=if ($State.proxyContext) { $null -ne $Value.dnsReceipt } else { Test-True $Value.systemDnsClean }
    if (!(Test-True $Value.directClean) -or !$dnsReady -or
        $Value.containerSid -cne $State.containerSid) { throw 'A proxy stage lost direct-network or DNS isolation evidence' }
    Assert-N4ProxyHost $Value.host $State.oldConnection
}

function Start-N4RelayOwnerWatch($Topology,[Diagnostics.Process]$Owner) {
    if (!$Owner -or $Owner.Handle -eq [IntPtr]::Zero -or $Owner.HasExited) {
        throw 'N4 exception owner is unavailable before entry arm'
    }
    $ownerPid=$Owner.Id
    $ownerStartTicks=$Owner.StartTime.ToUniversalTime().Ticks
    $reply=Invoke-N3Child $Topology.entry ('arm-owner {0} {1}' -f $ownerPid,$ownerStartTicks)
    if (!(Test-True $reply.admitting) -or !(Test-True $reply.watching) -or
        !(Test-True $reply.lastProbe.ok) -or $reply.exceptionOwnerPid -ne $ownerPid -or
        $reply.exceptionOwnerStartTicks -ne $ownerStartTicks -or $reply.closeReason -or $Owner.HasExited) {
        throw 'N4 entry did not arm against the exact exception owner'
    }
    return $reply
}

function Start-N4ReviewedProxyException($Context,$Topology,[Diagnostics.Process]$Probe,
    [string]$ContainerSid,[string]$Segment,[int]$Generation) {
    $digest=$Context.reviewedJournalHash
    $scope=Get-N4ReviewedHostScope $Context $digest $true $Segment
    Assert-N4WatchActive $Context
    if ($Segment -cnotin 'F','X' -or $Generation -lt 1 -or $Generation -gt $scope.plan.exceptionKeys.Count -or
        $Topology.directory -ine (Join-Path $scope.root ('proxy-'+$Segment)) -or
        ($Topology.ports -join ',') -cne ($scope.plan.ports -join ',') -or $Context.proxyOwner) {
        throw 'N4 proxy exception is outside the staged topology or an owner is already registered'
    }
    $launcher=[Diagnostics.Process]::GetCurrentProcess()
    try {
        $request=@{run=$scope.reviewed.run;segment=$Segment;generation=$Generation;
            journalSha256=$digest;containerSid=$ContainerSid}
        $processes=@{launcher=$launcher;entry=$Topology.entry.process;upstream=$Topology.upstream.process;probe=$Probe}
        foreach ($role in 'launcher','entry','upstream','probe') {
            $process=$processes[$role]
            if (!$process -or $process.HasExited) { throw 'N4 exception process already exited' }
            $request[$role]=@{pid=$process.Id;startTicks=$process.StartTime.ToUniversalTime().Ticks}
        }
    } finally { $launcher.Dispose() }
    $requestPath=Join-Path $scope.root ('proxy-owner-'+$Segment+'-'+$Generation+'.json')
    $requestBytes=[Text.UTF8Encoding]::new($false).GetBytes(($request | ConvertTo-Json -Compress))
    $file=[IO.File]::Open($requestPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($requestBytes,0,$requestBytes.Length); $file.Flush($true) }
    finally { $file.Dispose() }
    $requestDigest=(Get-FileHash -LiteralPath $requestPath).Hash
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $controller="'"+$scope.controller.Replace("'","''")+"'"
    $directory="'"+$scope.root.Replace("'","''")+"'"
    $command="& $controller -ProxyOwner -Directory $directory -Generation $Generation -ManifestSha256 $digest -RequestSha256 $requestDigest -Confirm:`$false"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $child=Start-N3Process $shell @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) $scope.root
    $Context.proxyOwner=$child
    $key=$scope.plan.exceptionKeys[$Generation-1]
    $child.generation=$Generation
    $child.containerSid=$ContainerSid
    $child.requestSha256=$requestDigest
    $child.ruleKey=$key
    try {
        foreach ($eventName in 'ready','opened') {
            $read=$child.process.StandardOutput.ReadLineAsync()
            if (!$read.Wait(9000) -or !$read.Result -or !$read.Result.StartsWith('N4-EXCEPTION:',[StringComparison]::Ordinal) -or
                $child.process.HasExited) { throw "N4 exception worker did not report $eventName" }
            $receipt=$read.Result.Substring(13) | ConvertFrom-Json
            if ($receipt.event -cne $eventName -or $receipt.run -cne $request.run -or $receipt.segment -cne $Segment -or
                $receipt.generation -ne $Generation -or [guid]$receipt.key -ne $key -or
                $receipt.pid -ne $child.process.Id -or $receipt.startTicks -ne $child.startTicks -or
                $receipt.journalSha256 -cne $digest -or $receipt.requestSha256 -cne $requestDigest) {
                throw 'N4 exception worker acknowledged a different process, generation or journal'
            }
            if ($eventName -ceq 'ready') {
                $arm=Start-N4RelayOwnerWatch $Topology $child.process
                $child.process.StandardInput.WriteLine('open')
                $child.process.StandardInput.Flush()
            }
        }
        return @{exactReadback=$true;key=$key;port=$scope.plan.ports[0];containerSid=$ContainerSid;
            ownerPid=$child.process.Id;ownerStartTicks=$child.startTicks;arm=$arm;receipt=$receipt}
    } catch {
        if (!$child.process.HasExited) {
            $child.process.Kill()
            [void]$child.process.WaitForExit(2000)
        }
        throw
    }
}

function Complete-N4ReviewedProxyException($Context,[string]$Segment) {
    $child=$Context.proxyOwner
    if (!$child) { return }
    if (!$child.process.HasExited) {
        try {
            $child.process.StandardInput.WriteLine('close')
            $child.process.StandardInput.Flush()
        } catch [IO.IOException] {}
        if (!$child.process.WaitForExit(1200)) {
            $child.process.Kill()
            if (!$child.process.WaitForExit(1500)) { throw 'N4 exception owner is still active' }
        }
    }
    $scope=Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash $true $Segment
    if (!('StudioLabWfp' -as [type])) { Add-Type -Path $scope.library }
    if ([StudioLabWfp].Assembly.Location -ine $scope.library) { throw 'N4 exception readback DLL differs from review' }
    $key=$scope.plan.exceptionKeys[$child.generation-1]
    $spec=[StudioLabWfp+AccountGuardSpec]::new($scope.plan.userSid,$child.containerSid,$scope.plan.accountLayer,
        [guid[]]($scope.plan.accountKeys+@($key)),$scope.plan.accountWeight,$scope.plan.ports[0])
    [StudioLabWfp]::VerifyBoundAccountProxy($spec,$scope.plan.bindLayer,$scope.plan.bindKeys,$scope.plan.ports,$scope.plan.bindWeight,$false)
    $child.process.Dispose()
    $Context.proxyOwner=$null
}

function Invoke-N4ReviewedProxyFault($State,[string]$Segment,[string]$Fault) {
    $context=$State.proxyContext
    $null=Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true $Segment
    $actor=switch -CaseSensitive ($Fault) {
        'upstream-refuse' { $State.topology.upstream }
        'upstream-silent' { $State.topology.upstream }
        'upstream-exit' { $State.topology.upstream }
        'exception-owner-exit' { $context.proxyOwner }
        'entry-exit' { $State.topology.entry }
        default { throw 'Unknown N4 fault' }
    }
    if (!$actor -or $actor.process.Handle -eq [IntPtr]::Zero -or $actor.process.HasExited -or
        $actor.process.StartTime.ToUniversalTime().Ticks -ne $actor.startTicks -or
        $actor.process.MainModule.FileName -ine $actor.file) { throw 'N4 fault actor no longer matches the retained handle' }
    $record=@{pid=$actor.process.Id;startTicks=$actor.startTicks;fault=$Fault}
    if ($Fault -cin 'upstream-refuse','upstream-silent') {
        $mode=$Fault.Substring('upstream-'.Length)
        $ack=Invoke-N3Child $actor $mode
        if ($ack.mode -cne $mode -or $actor.process.HasExited) { throw 'N4 upstream fault did not reach the original relay' }
        $record.mode=$ack.mode
    } else {
        $actor.process.Kill()
        if (!$actor.process.WaitForExit(700)) { throw 'N4 fault actor did not exit' }
        $record.exitObserved=$true
    }
    $record.observedTick=[Diagnostics.Stopwatch]::GetTimestamp()
    return $record
}

function Measure-N4ReviewedProxyPolicies($State,[string]$Segment,[string]$Fault,[long]$Injected) {
    $context=$State.proxyContext
    $scope=Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true $Segment
    $child=$context.proxyOwner
    if (!$child) { throw 'N4 fault was not associated with a recorded exception owner' }
    if (!('StudioLabWfp' -as [type])) { Add-Type -Path $scope.library }
    if ([StudioLabWfp].Assembly.Location -ine $scope.library) { throw 'N4 fault observation DLL differs from review' }
    $spec=[StudioLabWfp+AccountGuardSpec]::new($scope.plan.userSid,$child.containerSid,$scope.plan.accountLayer,
        [guid[]]($scope.plan.accountKeys+@($child.ruleKey)),$scope.plan.accountWeight,$scope.plan.ports[0])
    $deadline=$Injected+3*[Diagnostics.Stopwatch]::Frequency
    do {
        if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'N4 exception stayed open past the fault deadline' }
        $present=[StudioLabWfp]::ReadBoundAccountProxy($spec,$scope.plan.bindLayer,$scope.plan.bindKeys,$scope.plan.ports,$scope.plan.bindWeight)
        if ($present) { Start-Sleep -Milliseconds 25 }
    } while ($present)
    $wfpTick=[Diagnostics.Stopwatch]::GetTimestamp()
    if ($wfpTick -gt $deadline) { throw 'N4 WFP readback exceeded the fault deadline' }
    $evidence=@{readbackTick=$wfpTick;probeAlive=(!$State.probe.HasExited);entryAlive=(!$State.topology.entry.process.HasExited);
        upstreamAlive=(!$State.topology.upstream.process.HasExited);managerAlive=(!$child.process.HasExited)}
    if ($Fault -ceq 'exception-owner-exit') {
        $evidence.entryClosure=Invoke-N3Child $State.topology.entry 'status' 500
    }
    if ($Fault -ceq 'entry-exit') {
        $remaining=[int](($deadline-[Diagnostics.Stopwatch]::GetTimestamp())*1000.0/[Diagnostics.Stopwatch]::Frequency)
        $read=$child.process.StandardOutput.ReadLineAsync()
        if ($remaining -le 0 -or !$read.Wait($remaining) -or !$read.Result -or
            !$read.Result.StartsWith('N4-EXCEPTION:',[StringComparison]::Ordinal)) { throw 'N4 X did not receive a manager release receipt' }
        $receipt=$read.Result.Substring(13) | ConvertFrom-Json
        if ($receipt.event -cne 'process-exit' -or $receipt.run -cne $scope.reviewed.run -or $receipt.segment -cne $Segment -or
            $receipt.pid -ne $child.process.Id -or $receipt.startTicks -ne $child.startTicks -or
            $receipt.generation -ne $child.generation -or [guid]$receipt.key -ne $child.ruleKey -or
            $receipt.journalSha256 -cne $context.reviewedJournalHash -or $receipt.requestSha256 -cne $child.requestSha256 -or
            $child.process.HasExited -or $State.probe.HasExited -or $State.topology.upstream.process.HasExited -or
            !$State.topology.entry.process.HasExited) {
            throw 'N4 X did not prove release by the surviving manager for the exact generation'
        }
        $evidence.releaseReceipt=$receipt
    }
    if ($Fault -cin 'entry-exit','upstream-exit') {
        $port=$scope.plan.ports[[int]($Fault -ceq 'upstream-exit')]
        $bind=Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'
        if ($bind.stage -cne 'bind' -or $bind.nativeError -ne 10013) {
            throw 'N4 host could rebind the exited relay port or denial was inconclusive'
        }
        $evidence.hostRebind=$bind
    }
    $evidence.observedTick=[Diagnostics.Stopwatch]::GetTimestamp()
    if ($evidence.observedTick -gt $deadline) { throw 'N4 fault policy observation exceeded the deadline' }
    return $evidence
}

function Read-N4ProxyLogWindow($Logs, $Start) {
    $events=@{}
    $boundary=@{}
    $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        foreach ($part in 'entry','upstream','target') {
            $log=$Logs.$part
            if (!(Test-Count $log.pid) -or $log.pid -lt 1 -or ![IO.Path]::IsPathRooted($log.path)) {
                throw "Missing $part proxy log identity"
            }
            $file=Get-Item -LiteralPath $log.path
            if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                !$paths.Add($file.FullName)) { throw "Invalid or shared $part proxy log" }
            $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            try {
                $length=$stream.Length
                if ($length -gt 4000000) { throw "N4 $part proxy log limit exceeded" }
                $bytes=[byte[]]::new([int]$length)
                $offset=0
                while ($offset -lt $length) {
                    $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
                    if (!$read) { throw "N4 $part proxy log shortened during read" }
                    $offset+=$read
                }
            } finally { $stream.Dispose() }
            if ($bytes.Length -and $bytes[-1] -ne 10) { throw "N4 $part proxy log has a partial record at the boundary" }
            $boundary[$part]=@{path=$file.FullName;pid=$log.pid;length=$bytes.Length;
                sha256=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}
            if (!$Start) { continue }
            $prior=$Start.$part
            if (!$prior -or $prior.path -ine $file.FullName -or $prior.pid -ne $log.pid -or
                !(Test-Count $prior.length) -or $prior.length -lt 0 -or $prior.length -gt $bytes.Length -or
                $prior.sha256 -cne ([BitConverter]::ToString($sha.ComputeHash($bytes,0,$prior.length))).Replace('-','')) {
                throw "N4 $part proxy log changed before the generation boundary"
            }
            $events[$part]=@(foreach ($line in ($utf8.GetString($bytes,$prior.length,$bytes.Length-$prior.length) -split "`r?`n")) {
                if (!$line) { continue }
                if (!$line.StartsWith('{')) { throw "N4 $part proxy log contains an invalid record" }
                $row=$line | ConvertFrom-Json -ErrorAction Stop
                if (!(Test-Count $row.pid) -or $row.pid -ne $log.pid -or $row.kind -isnot [string] -or !$row.kind) {
                    throw "N4 $part proxy log contains an event of unknown origin"
                }
                $row
            })
        }
    } finally { $sha.Dispose() }
    return @{boundary=$boundary;events=$events}
}

function Measure-N4ProxyRoutes($Protocols, $Events, [string]$Prefix) {
    if ($Prefix -cnotmatch '^studio-[a-f0-9]{16}$' -or
        !@($Events.entry).Count -or !@($Events.upstream).Count -or !@($Events.target).Count) {
        throw 'N4 proxy protocol proof requires the run prefix and all three event streams'
    }
    $markers = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $paths = [ordered]@{}
    foreach ($role in 'primary','auxiliary') {
        foreach ($protocol in 'http','tls') {
            $probe = $Protocols.$role.$protocol
            if (!(Test-True $probe.ok) -or !(Test-Count $probe.status) -or $probe.status -ne 200 -or
                $probe.marker -cnotmatch '^[a-f0-9]{16}$' -or !$markers.Add($probe.marker)) {
                throw "N4 proxy $role $protocol has no distinct successful receipt"
            }
            $path = Find-N3Path $Events $probe $protocol $Prefix
            if (!$path) { throw "N4 proxy $role $protocol lacks one entry, upstream and target path" }
            $paths["$role-$protocol"] = $path
        }
    }
    $trustCases = @{wrongCertificate=@{test='wrong-cert';authority=$Prefix+'-a-window-healthy.test:9443'};
        wrongHost=@{test='wrong-host';authority=$Prefix+'-a-window-fake.test:443'}}
    foreach ($test in 'wrongCertificate','wrongHost') {
        $probe = $Protocols.$test
        $expected = $trustCases[$test]
        if ($probe.test -cne $expected.test -or $probe.ok -isnot [bool] -or $probe.ok -or $probe.status -cne 'TrustFailure' -or
            $probe.marker -cnotmatch '^[a-f0-9]{16}$' -or !$markers.Add($probe.marker) -or
            @($Events.target | Where-Object { $_.marker -ceq $probe.marker }).Count) {
            throw "N4 proxy $test has no clean TLS trust rejection"
        }
        $upstream = @($Events.upstream | Where-Object { $_.kind -ceq 'routed' -and
            $_.method -ceq 'CONNECT' -and $_.authority -ceq $expected.authority })
        $entry = @($Events.entry | Where-Object { $_.kind -ceq 'routed' -and
            $_.method -ceq 'CONNECT' -and $_.authority -ceq $expected.authority })
        if ($upstream.Count -ne 1 -or $entry.Count -ne 1 -or
            !(Test-Count $upstream[0].peer) -or $upstream[0].peer -lt 1 -or $upstream[0].peer -gt 65535 -or
            $entry[0].outbound -ne $upstream[0].peer) {
            throw "N4 proxy $test lacks one generation-local CONNECT through both relays"
        }
    }
    return $paths
}

function Assert-N4StreamSnapshot($Stream,[bool]$Active) {
    $validState=if ($Active) { $Stream.state -ceq 'active' } else {
        $Stream.state -is [string] -and $Stream.state -and $Stream.state -cnotin 'active','starting'
    }
    if (!$validState -or $Stream.marker -cnotmatch '^[a-f0-9]{16}$' -or @($Stream.marks).Count -lt 2 -or
        @($Stream.marks).Count -ne @($Stream.receivedTicks).Count) { throw 'N4 old stream snapshot is incomplete' }
    $prior=0
    for ($i=0;$i -lt $Stream.marks.Count;$i++) {
        $tick=$Stream.receivedTicks[$i]
        if ($Stream.marks[$i] -cne ('{0}:{1}' -f $Stream.marker,($i+1)) -or !(Test-Count $tick) -or $tick -le 0 -or $tick -lt $prior) {
            throw 'N4 old stream has an unverified marker sequence or timestamp'
        }
        $prior=$tick
    }
}

function Confirm-N4ProxyFaultFlows($Before,$After,$Fresh,$Events,[long]$Injected,[long]$Closed) {
    $deadline=$Injected+3*[Diagnostics.Stopwatch]::Frequency
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($protocol in 'http','tls') {
        $old=$Before.$protocol
        $end=$After.$protocol
        Assert-N4StreamSnapshot $old $true
        Assert-N4StreamSnapshot $end $false
        if (!$seen.Add($old.marker) -or $end.marker -cne $old.marker -or $old.receivedTicks[-1] -gt $Injected -or
            $end.receivedTicks[-1] -gt [Math]::Min($deadline,$Closed) -or $end.marks.Count -lt $old.marks.Count) {
            throw 'N4 old stream identity or closure timestamp differs'
        }
        for ($i=0;$i -lt $old.marks.Count;$i++) {
            if ($old.marks[$i] -cne $end.marks[$i] -or $old.receivedTicks[$i] -ne $end.receivedTicks[$i]) {
                throw 'N4 old stream rewrote markers observed before fault'
            }
        }
        $match=@($Events.target | Where-Object { $_.kind -ceq 'target' -and $_.action -ceq 'hold' -and
            $_.protocol -ceq $protocol -and $_.marker -ceq $old.marker })
        if ($match.Count -ne 1) { throw 'N4 old stream has no unique pre-fault target request' }
        $probe=$Fresh.$protocol
        if ($probe.test -cne $protocol -or $probe.ok -isnot [bool] -or $probe.ok -or
            $probe.marker -cnotmatch '^[a-f0-9]{16}$' -or !$seen.Add($probe.marker) -or
            $probe.status -cnotin 'ConnectFailure','Timeout','ProtocolError','ReceiveFailure','ConnectionClosed','SendFailure' -or
            @($Events.target | Where-Object { $_.marker -ceq $probe.marker }).Count) {
            throw 'N4 fresh request lacks a clean fault rejection'
        }
    }
    return @($seen)
}

function Open-N4ProxyGeneration($Plan, $State, [hashtable]$Ops, [int]$Generation) {
    if ($State.exceptionActive -or $Generation -ne $State.generationsOpened+1 -or $Generation -gt $Plan.exceptionKeys.Count) {
        throw 'N4 proxy generation is still open or outside the reviewed sequence'
    }
    $key=$Plan.exceptionKeys[$Generation-1]
    $State.exceptionActive=$true # The permit can commit even if its receipt is lost.
    $opened=if ($State.proxyContext) {
        Start-N4ReviewedProxyException $State.proxyContext $State.topology $State.probe $State.containerSid $Plan.segment $Generation
    } else { & $Ops.OpenReviewedException $Plan $State $key }
    if (!(Test-True $opened.exactReadback) -or $opened.key -cne $key -or
        $opened.port -ne $Plan.ports[0] -or $opened.containerSid -cne $State.containerSid -or
        !(Test-Count $opened.ownerPid) -or $opened.ownerPid -lt 1 -or
        !(Test-Count $opened.ownerStartTicks) -or $opened.ownerStartTicks -le 0) { throw 'Dynamic exception does not match review' }
    $State.generationsOpened=$Generation
    if ($State.lastFaultBoundary) {
        $gap=Read-N4ProxyLogWindow $State.logs $State.lastFaultBoundary
        foreach ($target in $gap.events.target) {
            if ($target.kind -ceq 'target' -and $target.marker -and $State.deliveredMarkers.Contains($target.marker)) {
                throw 'N4 proxy replayed a previous request before the new generation'
            }
        }
        $start=$gap.boundary
    } else {
        $start=(Read-N4ProxyLogWindow $State.logs $null).boundary
    }
    $live=& $Ops.MeasureHealthy $Plan $State
    $window=Read-N4ProxyLogWindow $State.logs $start
    Assert-N4ProxyScope $live $State
    foreach ($target in $window.events.target) {
        if ($target.marker -and $State.deliveredMarkers.Contains($target.marker)) {
            throw 'N4 proxy replayed a delivered marker from an earlier generation'
        }
    }
    $routes=Measure-N4ProxyRoutes $live.protocols $window.events $State.prefix
    if ($State.proxyContext) {
        $ordinaryMarkers=@($live.ordinaryProxy.frame.data.http.marker,$live.ordinaryProxy.frame.data.tls.marker)
        if (@($window.events.target | Where-Object {$_.marker -cin $ordinaryMarkers}).Count) {
            throw 'Ordinary A reached the target while the container exception was active'
        }
    }
    foreach ($path in $routes.Values) {
        $null=$State.deliveredMarkers.Add($path.target.marker)
    }
    if (!(Test-True $live.ordinaryADenied) -or
        !(Test-Count $live.replayed) -or $live.replayed -ne 0) { throw 'A healthy proxy protocol or replay check failed' }
    return @{generation=$Generation;key=$key;healthy=$live;routes=$routes;
        ownerPid=$opened.ownerPid;ownerStartTicks=$opened.ownerStartTicks;
        logWindow=@{start=$start;end=$window.boundary;events=$window.events}}
}

function Invoke-N4ProxyFaultSchedule($Manifest, $Previous, [hashtable]$Ops) {
    $plan=Read-RecoveryPlan $Manifest $Manifest.run
    $required='PrepareClosed','OpenReviewedException','MeasureHealthy','HoldOldFlows','InjectFault',
        'MeasureFailure','RestoreProxyHealth','RevokeAndDrain','RollbackAndMeasure'
    foreach ($name in $required) { if ($Ops[$name] -isnot [scriptblock]) { throw ('Missing N4 proxy operation '+$name) } }
    if ($plan.segment -cnotin 'F','X' -or $Previous.run -cne $Manifest.run -or
        $Previous.accountSid -cne $plan.userSid -or !(Test-True $Previous.cleanupVerified) -or
        ($plan.segment -ceq 'F' -and $Previous.outcome -cne 'passed-account-match-m') -or
        ($plan.segment -ceq 'X' -and $Previous.outcome -cne 'passed-account-proxy-f')) { throw 'Previous stage did not pass and roll back for this N4 batch' }
    if ($plan.segment -ceq 'X' -and (@($Previous.ports).Count -ne 2 -or @($plan.ports | Where-Object {$_ -in $Previous.ports}).Count)) {
        throw 'N4 X cannot reuse the F relay ports'
    }

    $state=@{exceptionActive=$false;generationsOpened=0;containerSid=$null;oldConnection=$null;prefix=$null;logs=$null;lastFaultBoundary=$null;
        deliveredMarkers=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);proxyContext=$null;topology=$null;probe=$null}
    $output=[ordered]@{run=$Manifest.run;accountSid=$plan.userSid;segment=$plan.segment;ports=@($plan.ports);outcome='failed-or-incomplete';
        cleanupVerified=$false;generations=@();faults=@();restoration=$null;errors=@()}
    $schedule = @(if ($plan.segment -ceq 'F') { 'upstream-refuse','upstream-silent','exception-owner-exit','upstream-exit' }
        else { 'entry-exit' })
    try {
        $closed=& $Ops.PrepareClosed $plan $state
        $state.containerSid=$closed.containerSid
        $state.oldConnection=$closed.host.oldConnection
        $state.prefix=$closed.prefix
        $state.logs=$closed.logs
        $state.proxyContext=$closed.proxyContext
        $state.topology=$closed.topology
        $state.probe=$closed.probe
        Assert-N4ProxyScope $closed $state
        if ($state.prefix -cnotmatch '^studio-[a-f0-9]{16}$' -or $state.containerSid -cnotmatch '^S-1-15-2(-[0-9]+){7}$' -or
            !(Test-True $closed.baseReadBeforeCold) -or !(Test-True $closed.liveProbeIdentity) -or
            !(Test-True $closed.bindingReadback) -or !(Test-True $closed.proxyOwnershipVerified) -or
            !(Test-True $closed.hostSameEndpointHealthy) -or !(Test-True $closed.psecSameEndpointDenied) -or
            !(Test-True $closed.ordinarySameEndpointDenied)) { throw 'Closed stage did not prove cold isolation and a healthy but closed proxy endpoint' }
        $null=Read-N4ProxyLogWindow $state.logs $null
        $output.generations+=,(Open-N4ProxyGeneration $plan $state $Ops 1)
        for ($i=0; $i -lt $schedule.Count; $i++) {
            $fault=$schedule[$i]
            $faultStart=(Read-N4ProxyLogWindow $state.logs $null).boundary
            $old=& $Ops.HoldOldFlows $plan $state
            Assert-N4StreamSnapshot $old.http $true
            Assert-N4StreamSnapshot $old.tls $true
            $injected=[Diagnostics.Stopwatch]::GetTimestamp()
            $attempt=@{kind=$fault;injectedTick=$injected;oldStreams=$old;verified=$false}
            $output.faults+=,$attempt
            $policy=$null
            if ($state.proxyContext) {
                $attempt.injection=Invoke-N4ReviewedProxyFault $state $plan.segment $fault
                $policy=Measure-N4ReviewedProxyPolicies $state $plan.segment $fault $injected
                $attempt.policy=$policy
            } else {
                & $Ops.InjectFault $plan $state $fault | Out-Null
            }
            $bad=& $Ops.MeasureFailure $plan $state $fault $injected $policy
            $attempt.proof=$bad
            Assert-N4ProxyScope $bad $state
            if (!(Test-Count $bad.closedTick)) { throw 'N4 fault closure clock is missing' }
            $closedTick=if ($policy) { [Math]::Max($bad.closedTick,$policy.observedTick) } else { $bad.closedTick }
            $elapsed=($closedTick-$injected)*1000.0/[Diagnostics.Stopwatch]::Frequency
            $attempt.elapsedMs=$elapsed
            $faultWindow=Read-N4ProxyLogWindow $state.logs $faultStart
            $attempt.targetEvents=$faultWindow.events.target
            $markers=Confirm-N4ProxyFaultFlows $old $bad.streams $bad.fresh $faultWindow.events $injected $bad.closedTick
            foreach ($marker in $markers) {
                if (!$state.deliveredMarkers.Add($marker)) { throw 'N4 proxy reused a marker from an earlier request' }
            }
            if ($fault -ceq 'exception-owner-exit') {
                $entry=if ($policy) {$policy.entryClosure} else {$bad.entryClosure}
                $generation=$output.generations[-1]
                if ($entry.closeReason -cne 'exception-owner-exit' -or $entry.admitting -isnot [bool] -or $entry.admitting -or
                    $entry.watching -isnot [bool] -or $entry.watching -or !(Test-Count $entry.active) -or $entry.active -ne 0 -or
                    $entry.exceptionOwnerPid -ne $generation.ownerPid -or $entry.exceptionOwnerStartTicks -ne $generation.ownerStartTicks -or
                    !(Test-Count $entry.closedTick) -or $entry.closedTick -lt $injected -or $entry.closedTick -gt $closedTick) {
                    throw 'N4 entry did not close its active flows on exact exception-owner exit'
                }
            }
            if ($bad.kind -cne $fault -or $bad.closedTick -lt $injected -or $elapsed -gt 3000 -or
                !(Test-True $bad.exceptionAbsent) -or !(Test-True $bad.baseRetained) -or
                ($fault -ceq 'exception-owner-exit' -and (!(Test-True $bad.aStillAlive) -or !(Test-True $bad.proxyStillAlive))) -or
                ($fault -ceq 'entry-exit' -and (!(Test-True $bad.upstreamStillAlive) -or !(Test-True $bad.managerSurvived))) -or
                ($policy -and $fault -ceq 'exception-owner-exit' -and (!$policy.probeAlive -or !$policy.entryAlive -or $policy.managerAlive)) -or
                ($fault -in 'entry-exit','upstream-exit' -and !(Test-True $bad.rebindRejected))) {
                throw ('N4 fault evidence failed for '+$fault)
            }
            $state.exceptionActive=$false
            $state.lastFaultBoundary=$faultWindow.boundary
            $attempt.verified=$true
            if ($state.proxyContext) { Complete-N4ReviewedProxyException $state.proxyContext $plan.segment }
            if ($i -lt $schedule.Count-1) {
                $health=& $Ops.RestoreProxyHealth $plan $state $fault
                if (!(Test-True $health.originalPortAndRelay) -or !(Test-True $health.newRoundTrip) -or
                    !(Test-True $health.exceptionAbsent)) { throw 'N4 recovery changed relay or lacked a healthy closed path' }
                $output.generations+=,(Open-N4ProxyGeneration $plan $state $Ops ($i+2))
            }
        }
    } catch { $output.errors += $_.Exception.Message }
    finally {
        try {
            $exceptionCleanupError=$null
            if ($state.proxyContext) {
                try { Complete-N4ReviewedProxyException $state.proxyContext $plan.segment }
                catch { $exceptionCleanupError=$_ }
            }
            $retired=& $Ops.RevokeAndDrain $plan $state
            if ($exceptionCleanupError) { throw $exceptionCleanupError }
            if (!(Test-True $retired.exceptionAbsent) -or !(Test-True $retired.workloadsExited)) {
                throw 'N4 proxy workload or exception remains; preserve account deny'
            }
            $after=& $Ops.RollbackAndMeasure $plan $state
            $output.restoration=$after
            Assert-N4ProxyHost $after.host $state.oldConnection
            if (!(Test-True $after.rulesAbsent) -or !(Test-True $after.portsBindable) -or
                !(Test-True $after.ordinaryARestored) -or !(Test-True $after.traceStoppedAfterControls) -or
                ($state.proxyContext -and !(Test-True $after.dnsEvidence.verified))) {
                throw 'N4 proxy rollback and restoration not fully confirmed'
            }
            $output.cleanupVerified=$true
        } catch { $output.errors += $_.Exception.Message }
    }
    if (!$output.errors.Count -and $output.cleanupVerified -and $output.faults.Count -eq $schedule.Count -and
        $false -notin $output.faults.verified -and
        $state.generationsOpened -eq $plan.exceptionKeys.Count) { $output.outcome = 'passed-account-proxy-'+$plan.segment.ToLowerInvariant() }
    return $output
}

function Assert-N4ProxyPredecessor($Current,$Prior,$Result,[string]$PriorJournalHash) {
    $priorStage=if ($Current.segment -ceq 'F') {'M'} elseif ($Current.segment -ceq 'X') {'F'} else {throw 'Not a proxy stage'}
    if ($PriorJournalHash -cnotmatch '^[A-F0-9]{64}$' -or $Prior.segment -cne $priorStage -or $Result.segment -cne $priorStage -or
        $Result.mode -cne 'reviewed-live' -or !(Test-True $Result.cleanupVerified) -or @($Result.errors).Count -ne 0 -or
        $Result.recovery -cne $PriorJournalHash -or $Result.run -cne $Prior.run -or $Prior.run -cne $Current.run -or
        $Result.accountSid -cne $Prior.accountSid -or $Prior.accountSid -cne $Current.accountSid -or
        $Result.hostSid -cne $Prior.hostSid -or $Prior.hostSid -cne $Current.hostSid) {
        throw 'N4 proxy stage requires a clean, reviewed result from its exact predecessor'
    }
    if ($priorStage -ceq 'M') {
        if ($Result.outcome -cne 'passed-account-match-m' -or (Get-AccountResult $Result).outcome -cne $Result.outcome) {
            throw 'N4 predecessor M evidence did not independently pass'
        }
    } else {
        if ($Result.outcome -cne 'passed-account-proxy-f' -or
            ($Result.ports -join ',') -cne ($Prior.binding.ports -join ',') -or
            @($Result.ports | Where-Object {$_ -in $Current.binding.ports}).Count -or
            @($Result.generations).Count -ne 4 -or
            ($Result.faults.kind -join ',') -cne 'upstream-refuse,upstream-silent,exception-owner-exit,upstream-exit' -or
            !(Test-True $Result.restoration.rulesAbsent) -or !(Test-True $Result.restoration.ordinaryARestored) -or
            !(Test-True $Result.restoration.portsBindable) -or !(Test-True $Result.restoration.traceStoppedAfterControls) -or
            !(Test-True $Result.restoration.dnsEvidence.verified) -or
            @($Result.faults | Where-Object {!(Test-True $_.verified) -or !$_.policy -or !$_.injection}).Count) {
            throw 'N4 predecessor F lacks exact live fault and cleanup evidence'
        }
        for ($i=0;$i -lt 4;$i++) {
            if ($Result.generations[$i].generation -ne $i+1 -or
                [guid]$Result.generations[$i].key -ne [guid]$Prior.exceptionKeys[$i]) {
                throw 'N4 predecessor F generation differs from its approved list'
            }
        }
    }
}

function Get-N4ReviewedProxyPreflight([string]$Directory,[ValidateSet('F','X')][string]$Segment,
    [string]$ReviewedJournalHash,[string]$PreviousResultSha256) {
    if ($PreviousResultSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'An exact predecessor result SHA-256 is required' }
    $stage=Get-N4ReviewedStageFiles $Directory $ReviewedJournalHash $Segment
    if (Test-Path -LiteralPath (Join-Path $stage.root ('result-'+$Segment+'.json'))) { throw 'This N4 stage already has a result' }
    $trusted=@($stage.plan.hostSid,'S-1-5-18','S-1-5-32-544')
    $priorStage=if ($Segment -ceq 'F') {'M'} else {'F'}
    $resultFile=Assert-RecoveryAcl (Join-Path $stage.root ('result-'+$priorStage+'.json')) $true $false
    if ($resultFile.Length -gt 16777216) { throw 'N4 predecessor result exceeds its evidence limit' }
    $resultBytes=[IO.File]::ReadAllBytes($resultFile.FullName)
    if ((Get-N4ByteDigest $resultBytes) -cne $PreviousResultSha256) { throw 'N4 predecessor result hash differs' }
    $previous=[Text.UTF8Encoding]::new($false,$true).GetString($resultBytes) | ConvertFrom-Json
    $prior=Get-N4ReviewedStageFiles $Directory $previous.recovery $priorStage
    Assert-N4ProxyPredecessor $stage.reviewed $prior.reviewed $previous $previous.recovery
    $proxyDir=Assert-RecoveryAcl (Join-Path $stage.root ('proxy-'+$Segment)) $true $true
    $null=Assert-RecoveryAcl (Join-Path $proxyDir.FullName 'StudioN3Relay.exe') $true $false
    $null=Assert-RecoveryAcl (Join-Path $proxyDir.FullName 'windows-lab-n3-target.cjs') $true $false
    $null=Get-N3ReviewedTopologyFiles $proxyDir.FullName $stage.reviewed.fixtures
    if (!('StudioLabWfp' -as [type])) { Add-Type -Path $stage.library }
    if ([StudioLabWfp].Assembly.Location -ine $stage.library) { throw 'N4 proxy preflight DLL differs' }
    $weights=[StudioLabWfp]::ReadAccountProxyStageWeights($stage.plan.ports)
    if ($weights[0] -ne $stage.plan.accountWeight -or $weights[1] -ne $stage.plan.bindWeight) {
        throw 'Current account or binding priority differs from review'
    }
    return @{stage=$stage;prior=$prior;previous=$previous;proxyDirectory=$proxyDir.FullName}
}

function Initialize-N4ReviewedProxyHost($Context,$Plan,[string]$Directory) {
    $scope=Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash $true $Plan.segment
    Assert-N4WatchActive $Context
    $prefix='studio-'+([guid]::NewGuid().ToString('N').Substring(0,16))
    $Context.observer=@{prefix=$prefix;canaries=(New-N4MatchCanaries);trace=$null;
        receipts=[Collections.Generic.List[object]]::new();hostControlSequence=0}
    $Context.observer.endpoints=$Context.observer.canaries.endpoints
    $Context.endpoints=$Context.observer.endpoints
    $Context.observer.trace=Start-LabDnsTrace $scope.root $prefix -AccountMatch
    $Context.observer.readyTick=[Diagnostics.Stopwatch]::GetTimestamp()
    $Context.observer.ready=$true
    $ordinary=Invoke-N4ReviewedAccountProbe $Context $prefix ordinary baseline $Plan.segment
    $Context.observer.receipts.Add($ordinary.receipt)
    foreach ($transport in 'tcp','udp') {
        if (!(Test-AccountPath $ordinary.$transport $Context.endpoints.$transport $true)) { throw 'Ordinary A baseline did not reach the test endpoint' }
    }
    $Context.baseline=Invoke-N4HostControl $Context baseline $Plan.segment
    Assert-N4ProxyHost $Context.baseline $Context.observer.canaries.oldId
    $Context.topology=Initialize-N3Topology $Directory $prefix $Plan.ports $scope.reviewed.fixtures
    Assert-N4ProxyOwnerListener $Plan.ports[0] $Context.topology.entry.process
    Assert-N4ProxyOwnerListener $Plan.ports[1] $Context.topology.upstream.process
    Assert-N4WatchActive $Context
    $spec=[StudioLabWfp+AccountGuardSpec]::new($Plan.userSid,'',$Plan.accountLayer,$Plan.accountKeys,$Plan.accountWeight,0)
    $writer=[StudioLabWfp]::CreateStaticGuard()
    try {
        $writer.InstallAccountBase($spec)
        $writer.InstallAccountBindings($spec,$Plan.exceptionKeys,$Plan.bindLayer,$Plan.bindKeys,$Plan.ports,$Plan.bindWeight)
    } finally { $writer.Dispose() }
    $base=[StudioLabWfp]::InspectAccountGuard($spec,$true,$false)
    if ($base.Count -ne 5 -or $false -in $base) { throw 'Staged F/X account rules were not independently read back' }
    $null=[StudioLabWfp]::VerifyBindGuard($Plan.bindLayer,$Plan.bindKeys,$Plan.ports,$Plan.bindWeight,2)
    $Context.baseReadTick=[Diagnostics.Stopwatch]::GetTimestamp()
}

function Measure-N4ProxyDns($Trace,$Receipts,[string]$Prefix,[long]$ObserverReady,[int]$Generations) {
    $required=@('host-baseline','ordinary-baseline','host-blocked','psec-blocked','host-restored','ordinary-restored')
    for ($i=1;$i -le $Generations;$i++) {
        $required+=@("host-healthy$i","psec-healthy$i","host-fault$i","psec-fault$i")
    }
    $sources=@{}
    $names=@{}
    $errors=[Collections.Generic.List[string]]::new()
    foreach ($receipt in $Receipts) {
        $key=$receipt.role+'-'+$(if ($receipt.role -ceq 'psec') {$receipt.stage} else {$receipt.phase})
        if ($key -cnotin $required -or $sources.ContainsKey($key) -or $receipt.identity.pid -le 0 -or
            ($receipt.role -ceq 'psec' -and $receipt.phase -cnotmatch '^cold[0-9]{1,2}$') -or
            $receipt.tickFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
            !(Test-Count $receipt.firstProbeTick) -or $receipt.firstProbeTick -le $ObserverReady -or
            ($receipt.dnsQueries.api -join ',') -cne 'DnsQuery_W,GetAddrInfoW') {
            $errors.Add('Invalid or repeated probe receipt: '+$key)
            continue
        }
        $sources[$key]=@()
        foreach ($query in $receipt.dnsQueries) {
            $tag=if ($query.api -ceq 'DnsQuery_W') {'dns'} else {'addr'}
            $expected=$Prefix+'-'+$receipt.role+'-'+$receipt.phase+'-'+$tag+'.test'
            if ($query.name.TrimEnd('.') -cne $expected -or $names.ContainsKey($expected) -or
                !(Test-Count $query.startedTick) -or !(Test-Count $query.completedTick) -or
                $query.startedTick -lt $receipt.firstProbeTick -or $query.completedTick -lt $query.startedTick) {
                $errors.Add('DNS query name, order or clock differs: '+$key)
                continue
            }
            $row=@{name=$expected;role=$receipt.role;phase=$receipt.phase;pid=$receipt.identity.pid;api=$query.api;sends=0;replies=0}
            $sources[$key]+=,$row
            $names[$expected]=$row
        }
    }
    $loss=$Trace.lossBeforeStop
    if (!(Test-True $Trace.stopped) -or $Trace.lossError -or $ObserverReady -le 0 -or
        !(Test-Count $Trace.servicePid) -or $Trace.servicePid -le 0 -or $Trace.servicePidAfter -ne $Trace.servicePid) {
        $errors.Add('DNS trace boundary or Dnscache identity differs')
    }
    foreach ($field in 'eventsLost','logBuffersLost','realtimeBuffersLost') {
        $value=$loss.$field
        if (($value -isnot [uint32] -and !(Test-Count $value)) -or $value -ne 0) { $errors.Add('Missing or nonzero ETW loss counter: '+$field) }
    }
    foreach ($event in $Trace.events) {
        if ($event.event -notin 3010,3011) { continue }
        $query=$names[[string]$event.name]
        if (!$query -or $event.role -cne $query.role -or $event.phase -cne $query.phase -or
            $event.emitterPid -ne $Trace.servicePid -or $event.clientPid -ne $query.pid) {
            $errors.Add('Unattributed DNS send or reply: '+$event.name)
            continue
        }
        if ($event.event -eq 3010) { $query.sends++ } else { $query.replies++ }
    }
    foreach ($key in $required) {
        $rows=$sources[$key]
        if (@($rows).Count -ne 2) { $errors.Add('Missing DNS observations: '+$key); continue }
        if ($key.StartsWith('psec-')) {
            if (@($rows | Where-Object {$_.sends -or $_.replies}).Count) { $errors.Add('Container DNS forwarded: '+$key) }
        } elseif (!@($rows | Where-Object {$_.sends -gt 0 -and $_.replies -gt 0}).Count) {
            $errors.Add('Missing positive DNS control: '+$key)
        }
    }
    return @{verified=($errors.Count -eq 0);errors=$errors.ToArray();queries=$sources}
}

function Read-N4ProxyProbeFrame([IO.TextReader]$Output,[string]$Nonce,[int]$Sequence,[string]$Action,[long]$Started,[int]$DeadlineMs) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $DeadlineMs) {
        $pending=$Output.ReadLineAsync()
        if (!$pending.Wait([Math]::Max(1,$DeadlineMs-[int]$watch.ElapsedMilliseconds))) { throw 'N4 proxy probe frame timed out' }
        $line=$pending.Result
        if ($null -eq $line) { throw 'N4 proxy probe closed stdout before its frame' }
        if ($line.Length -gt 65536) { throw 'N4 proxy probe output exceeded its frame limit' }
        if (!$line.StartsWith('N4-PROXY:',[StringComparison]::Ordinal)) { continue }
        $value=$line.Substring(9) | ConvertFrom-Json
        if ($value.nonce -cne $Nonce -or !(Test-Count $value.sequence) -or $value.sequence -ne $Sequence -or
            $value.action -cne $Action -or !(Test-Count $value.tick) -or $value.tick -lt $Started -or
            $value.tick -gt [Diagnostics.Stopwatch]::GetTimestamp() -or $value.frequency -ne [Diagnostics.Stopwatch]::Frequency) {
            throw 'N4 proxy probe frame does not match its command or clock'
        }
        return $value
    }
    throw 'N4 proxy probe transcript expired'
}

function Invoke-N4ProxyProbeCommand($Probe,[ValidateSet('ping','probe','trust','direct','aux','aux-done','hold','held','finish')][string]$Action,
    [int]$DeadlineMs=5000) {
    if ($Probe.failed -or $Probe.executor.HasExited -or ($Probe.process -and $Probe.process.HasExited) -or
        $Probe.sequence -ge 64) { throw 'N4 proxy probe is unavailable for a new command' }
    $Probe.sequence++
    $tick=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $Probe.executor.StandardInput.WriteLine(('{0} {1} {2}' -f $Probe.nonce,$Probe.sequence,$Action))
        $Probe.executor.StandardInput.Flush()
        $value=Read-N4ProxyProbeFrame $Probe.executor.StandardOutput $Probe.nonce $Probe.sequence $Action $tick $DeadlineMs
        if ($value.identity.pid -ne $Probe.identity.pid -or $value.identity.startTicks -ne $Probe.identity.startTicks -or
            $value.identity.userSid -cne $Probe.identity.userSid -or $value.identity.containerSid -cne $Probe.identity.containerSid) {
            throw 'N4 proxy probe changed identity across replies'
        }
        return $value
    } catch { $Probe.failed=$true; throw }
}

function New-N4ProxyProbeArguments($Context,$Plan,[string]$Mode,[string]$Nonce) {
    $target=$Context.topology.targetReady
    $endpoints=$Context.observer.endpoints
    $argsList=@($Mode,$Nonce,$Context.observer.prefix,$endpoints.tcpPort,$endpoints.udpPort,
        $Plan.ports[0],$Plan.ports[1],$target.http,$target.tls,$target.half,$target.wrongCertificate,$Context.topology.pin)
    if ($argsList[-1] -cnotmatch '^[A-F0-9]{64}$' -or $argsList[2] -cnotmatch '^studio-[a-f0-9]{16}$' -or
        @($argsList[3..10] | Where-Object {!(Test-Count $_) -or $_ -lt 40000 -or $_ -gt 65535}).Count) {
        throw 'N4 live probe has an unreviewed endpoint or command-line argument'
    }
    return $argsList
}

function Start-N4ReviewedProxyProbe($Context,[string]$Segment) {
    $scope=Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash $true $Segment
    Assert-N4WatchActive $Context
    if (!$Context.baseReadTick -or !$Context.topology -or $Context.liveProbe) { throw 'N4 proxy probe lacks exact base proof or already exists' }
    $trusted=@($scope.plan.hostSid,'S-1-5-18','S-1-5-32-544')
    $root=Assert-RecoveryAcl (Join-Path $scope.root 'fixtures') $false $true
    $probePath=Get-N4FixtureFile (Join-Path $root.FullName 'StudioProbe.exe') $scope.reviewed.fixtures.probeSha256 $trusted
    $exe=Get-N4FixtureFile (Join-Path $root.FullName 'wxc-exec.exe') 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D' $trusted
    $account=(Get-LabAccounts -AccountIds A).A
    if ($account.Sid -cne $scope.plan.userSid) { throw 'N4 live probe account differs from review' }
    $nonce=[guid]::NewGuid().ToString('N')
    $argsList=New-N4ProxyProbeArguments $Context $scope.plan 'n4-account-proxy' $nonce
    if ($probePath -match '["\r\n]') { throw 'Invalid N4 probe path for MXC' }
    $policy=[ordered]@{version='1.0.0';containment='processcontainer';
        process=@{commandLine=('"'+$probePath+'" '+($argsList -join ' '));cwd=$root.FullName;timeout=180000};
        filesystem=@{readonlyPaths=@($root.FullName)};ui=@{disable=$false};
        network=@{egress=@{default='deny'};ingress=@{default='deny';hostLoopback='allow'}}}
    $wire=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($policy | ConvertTo-Json -Depth 8 -Compress)))
    $launch=[Diagnostics.ProcessStartInfo]::new($exe,('--config-base64 '+$wire))
    $launch.UserName=$account.Name
    $launch.Domain=$env:COMPUTERNAME
    $launch.Password=$account.Credential.Password
    $launch.LoadUserProfile=$true
    $launch.WorkingDirectory=$root.FullName
    $launch.UseShellExecute=$false
    $launch.CreateNoWindow=$true
    $launch.RedirectStandardInput=$true
    $launch.RedirectStandardOutput=$true
    $launch.RedirectStandardError=$true
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    $entry=[Diagnostics.Process]::Start($launch)
    $state=@{executor=$entry;nonce=$nonce;sequence=0;failed=$true;process=$null;identity=$null;stderr=$entry.StandardError.ReadToEndAsync()}
    $Context.liveProbe=$state
    $cold=Read-N4ProxyProbeFrame $entry.StandardOutput $nonce 0 'cold' $started 18000
    if (!(Test-Count $cold.data.firstProbeTick) -or $cold.data.firstProbeTick -lt $started -or $cold.data.firstProbeTick -gt $cold.tick -or
        ![string]::Equals($entry.MainModule.FileName,$exe,[StringComparison]::OrdinalIgnoreCase)) { throw 'N4 cold probe clock or executor differs' }
    $validated=Open-N4ValidatedProbeProcess @{role='psec';identity=$cold.identity} $account.Sid $probePath $entry.SessionId
    $state.process=$validated.process
    $state.lineage=Assert-N4ProbeLineage $entry $state.process ''
    $state.identity=$cold.identity
    $state.path=$probePath
    $state.cold=$cold
    $state.policy=$policy
    $state.failed=$false
    $null=Invoke-N4ProxyProbeCommand $state ping 1500
    return $state
}

function Stop-N4ReviewedProxyProbe($Context) {
    $probe=$Context.liveProbe
    if (!$probe) { return }
    if (!$probe.failed -and !$probe.executor.HasExited) {
        try { $null=Invoke-N4ProxyProbeCommand $probe finish 1000 }
        catch { $probe.failed=$true }
    }
    if (!$probe.executor.HasExited) {
        $probe.executor.StandardInput.Close()
        if (!$probe.executor.WaitForExit(2000)) { $probe.executor.Kill() }
    }
    if (!$probe.executor.WaitForExit(1500) -or ($probe.process -and !$probe.process.WaitForExit(1500))) {
        throw 'N4 proxy probe or executor still alive; retain account deny'
    }
    if ($probe.process) { $probe.process.Dispose() }
    $probe.executor.Dispose()
    $Context.liveProbe=$null
}

function Measure-N4LiveProxyProtocols($Probe) {
    $primary=(Invoke-N4ProxyProbeCommand $Probe probe).data
    $trust=(Invoke-N4ProxyProbeCommand $Probe trust).data
    $begin=[Diagnostics.Stopwatch]::GetTimestamp()
    $child=(Invoke-N4ProxyProbeCommand $Probe aux).data
    $receipt=$child.receipt
    $liveChild=$null
    try {
        if ($receipt.nonce -cne $Probe.nonce -or $receipt.sequence -ne 0 -or $receipt.action -cne 'aux' -or
            $receipt.tick -lt $begin -or $receipt.tick -gt [Diagnostics.Stopwatch]::GetTimestamp() -or
            $receipt.frequency -ne [Diagnostics.Stopwatch]::Frequency -or $child.launchedPid -ne $receipt.identity.pid -or
            $receipt.identity.containerSid -cne $Probe.identity.containerSid) { throw 'N4 auxiliary receipt differs from the current live container' }
        $liveChild=Open-N4ValidatedProbeProcess @{role='psec';identity=$receipt.identity} $Probe.identity.userSid $Probe.path $Probe.process.SessionId
        $lineage=Assert-N4ProbeLineage $Probe.process $liveChild.process ''
        $null=Invoke-N4ProxyProbeCommand $Probe 'aux-done' 2200
        if (!$liveChild.process.WaitForExit(800) -or $liveChild.process.ExitCode -ne 0) { throw 'N4 auxiliary exit was not observed cleanly' }
        return @{primary=$primary;auxiliary=$receipt.data;wrongCertificate=$trust.http;wrongHost=$trust.tls;auxiliaryLineage=$lineage}
    } finally { if ($liveChild) {$liveChild.process.Dispose()} }
}

function Read-N4LiveHeldFlows($Probe,[bool]$Active,[long]$Deadline) {
    do {
        $left=[int](($Deadline-[Diagnostics.Stopwatch]::GetTimestamp())*1000.0/[Diagnostics.Stopwatch]::Frequency)
        if ($left -le 0) { throw 'N4 old flow observation deadline expired' }
        $held=(Invoke-N4ProxyProbeCommand $Probe held $left).data
        if ($Active) {
            $complete=$held.http.state -ceq 'active' -and $held.tls.state -ceq 'active' -and
                @($held.http.marks).Count -ge 2 -and @($held.tls.marks).Count -ge 2
        } else {
            $complete=$held.http.state -and $held.tls.state -and
                $held.http.state -cnotin 'active','starting' -and $held.tls.state -cnotin 'active','starting'
        }
        if ($complete) { return $held }
        Start-Sleep -Milliseconds 25
    } while ($true)
}

function Stop-N4PreparedProxyRelays($Context) {
    if (!$Context.topology) { return }
    $errors=@()
    foreach ($role in 'entry','upstream','target') {
        $relay=$Context.topology[$role]
        if (!$relay) { continue }
        try {
            if ($relay.process.HasExited) { $relay.process.Dispose() }
            else { Stop-N3Process $relay }
        } catch { $errors+=$_.Exception.Message }
    }
    if ($errors.Count) { throw ('N4 relay cleanup failed: '+($errors -join ', ')) }
}

function Invoke-N4OrdinaryProxyControl($Context,$Plan,[int]$BindPort=0) {
    $scope=Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash $true $Plan.segment
    $trusted=@($scope.plan.hostSid,'S-1-5-18','S-1-5-32-544')
    $root=Assert-RecoveryAcl (Join-Path $scope.root 'fixtures') $false $true
    $path=Get-N4FixtureFile (Join-Path $root.FullName 'StudioProbe.exe') $scope.reviewed.fixtures.probeSha256 $trusted
    $account=(Get-LabAccounts -AccountIds A).A
    if ($account.Sid -cne $scope.plan.userSid) { throw 'Ordinary control account differs from review' }
    $nonce=[guid]::NewGuid().ToString('N')
    if ($BindPort) {
        if ($BindPort -notin $Plan.ports) { throw 'Ordinary bind control is outside reviewed ports' }
        $argsList=@('n4-proxy-bind-control',$nonce,$BindPort)
        $action='bind'
    } else {
        $argsList=New-N4ProxyProbeArguments $Context $Plan 'n4-proxy-ordinary' $nonce
        $action='ordinary'
    }
    $line='& '+(ConvertTo-LabLiteral $path)+' '+(($argsList | ForEach-Object {ConvertTo-LabLiteral ([string]$_)}) -join ' ')
    $body=$line+' | ForEach-Object {[Console]::WriteLine([string]$_);[Console]::Out.Flush()}; exit $LASTEXITCODE'
    $tick=[Diagnostics.Stopwatch]::GetTimestamp()
    $proc=Start-LabProbe $account $body -StreamOutput
    $live=$null
    try {
        $frame=Read-N4ProxyProbeFrame $proc.Process.StandardOutput $nonce 0 $action $tick 12000
        $live=Open-N4ValidatedProbeProcess @{role='ordinary';identity=$frame.identity} $account.Sid $path $proc.Process.SessionId
        $lineage=Assert-N4ProbeLineage $proc.Process $live.process ''
        if (!$proc.Process.WaitForExit(6500) -or !$live.process.WaitForExit(1000) -or
            $proc.Process.ExitCode -ne 0 -or $live.process.ExitCode -ne 0) { throw 'Ordinary A control did not exit cleanly' }
        return @{frame=$frame;lineage=$lineage}
    } finally {
        if ($live) { $live.process.Dispose() }
        Stop-LabProbe $proc
    }
}

function Assert-N4DeniedProxyPair($Pair) {
    foreach ($protocol in 'http','tls') {
        $probe=$Pair.$protocol
        if ($probe.test -cne $protocol -or $probe.ok -isnot [bool] -or $probe.ok -or
            $probe.marker -cnotmatch '^[a-f0-9]{16}$' -or $probe.status -cnotin 'ConnectFailure','Timeout') {
            throw 'A control reached the reserved proxy without its scoped exception'
        }
    }
}

function Measure-N4HostProxyPositive($Context,$Plan,[bool]$ClosedControls) {
    $topology=$Context.topology
    if ($Context.proxyOwner -or $topology.entry.process.HasExited -or $topology.upstream.process.HasExited) {
        throw 'Host comparison requires the original closed-generation relay pair'
    }
    $begin=(Read-N4ProxyLogWindow $topology.logSources $null).boundary
    try {
        $armed=Invoke-N3Child $topology.entry 'arm-protocol'
        if (!(Test-True $armed.admitting) -or $armed.watching -ne $false) { throw 'Host-only relay control did not arm' }
        $routes=foreach ($protocol in 'http','tls') { Invoke-N3Probe $topology $protocol }
        $log=Read-N4ProxyLogWindow $topology.logSources $begin
        foreach ($route in $routes) {
            if (!(Find-N3Path $log.events $route $route.test $topology.prefix)) { throw 'Host proxy control did not reach the target' }
        }
        $psec=$null;$ordinary=$null
        if ($ClosedControls) {
            $psec=(Invoke-N4ProxyProbeCommand $Context.liveProbe probe).data
            $ordinary=Invoke-N4OrdinaryProxyControl $Context $Plan
            Assert-N4DeniedProxyPair $psec
            Assert-N4DeniedProxyPair $ordinary.frame.data
            $logsAfter=Read-N4ProxyLogWindow $topology.logSources $log.boundary
            $forbidden=@($psec.http.marker,$psec.tls.marker,$ordinary.frame.data.http.marker,$ordinary.frame.data.tls.marker)
            if (@($logsAfter.events.target | Where-Object {$_.marker -cin $forbidden}).Count) { throw 'Closed proxy control reached the target' }
        }
        return @{routes=@($routes);psec=$psec;ordinary=$ordinary}
    } finally { $null=Invoke-N3Child $topology.entry 'halt' }
}

function Measure-N4ProxyStageScope($Context,$Plan,[string]$Phase,$Frame) {
    $data=$Frame.data
    $targets=@($Context.topology.targetReady.http,$Context.topology.targetReady.tls,$Context.topology.targetReady.half,
        $Context.topology.targetReady.wrongCertificate,$Plan.ports[1])
    $actual=@($data.targets | ForEach-Object {$_.endpoint})
    if ($data.tcp.endpoint -cne $Context.endpoints.tcp -or $data.udp.endpoint -cne $Context.endpoints.udp -or
        $actual.Count -ne 5 -or @($targets | Where-Object {('127.0.0.1:'+$_) -cnotin $actual}).Count -or
        @($data.targets | Where-Object {!(Test-Count $_.submittedBytes) -or $_.submittedBytes -ne 0 -or
            !(Test-Count $_.nativeError) -or $_.nativeError -eq 0}).Count) {
        throw 'Direct activity reached a reviewed synthetic target or did not produce full evidence'
    }
    $hits=Read-N4CanaryHits $Context.observer.canaries $data.marker
    if ($hits.tcp.hits -ne 0 -or $hits.udp.hits -ne 0) { throw 'A bypassed the proxy to a direct canary' }
    if (($data.dnsQueries.api -join ',') -cne 'DnsQuery_W,GetAddrInfoW' -or
        @($data.dnsQueries | Where-Object {!(Test-Count $_.status) -or $_.status -eq 0}).Count) {
        throw 'Isolated DNS API returned an answer or lacked a receipt'
    }
    $tag=$data.dnsQueries[0].name
    if ($tag -cnotmatch ('^'+[regex]::Escape($Context.observer.prefix)+'-psec-(cold[0-9]{1,2})-dns\.test\.$')) {
        throw 'Isolated DNS API returned an unexpected canary name'
    }
    $dns=@{identity=$Frame.identity;role='psec';phase=$Matches[1];stage=$Phase;dnsQueries=$data.dnsQueries;
        firstProbeTick=$data.firstProbeTick;tickFrequency=$Frame.frequency}
    $Context.observer.receipts.Add($dns)
    $hostProof=Invoke-N4HostControl $Context $Phase $Plan.segment
    Assert-N4ProxyHost $hostProof $Context.baseline.oldConnection
    return @{directClean=$true;dnsReceipt=$dns;host=$hostProof;containerSid=$Frame.identity.containerSid;directEvidence=$Frame.data}
}

function Invoke-N4PreparedProxyStage([string]$Directory,[ValidateSet('F','X')][string]$Segment,
    [string]$ReviewedJournalHash,[string]$PreviousResultSha256) {
    $preflight=Get-N4ReviewedProxyPreflight $Directory $Segment $ReviewedJournalHash $PreviousResultSha256
    $stage=$preflight.stage
    $lease=Open-N4RecoveryLease $stage.root
    $proxyRunContext=@{accountSid=$stage.plan.userSid;hostSid=$stage.plan.hostSid;runLease=$lease;reviewedJournalHash=$ReviewedJournalHash}
    $stagedOperations=@{}
    $stagedOperations.OpenReviewedException={throw 'Staged N4 has no fallback exception writer'}
    $stagedOperations.InjectFault={throw 'Staged N4 has no fallback fault controller'}
    $stagedOperations.PrepareClosed={
        param($plan,$state)
        Initialize-N4ReviewedProxyHost $proxyRunContext $plan $preflight.proxyDirectory
        $live=Start-N4ReviewedProxyProbe $proxyRunContext $plan.segment
        if ($live.process.HasExited -or $live.cold.data.firstProbeTick -le $proxyRunContext.baseReadTick) {
            throw 'Staged N4 closed state has no live probe after exact base readback'
        }
        $closed=Measure-N4ProxyStageScope $proxyRunContext $plan blocked $live.cold
        $closed.sameEndpoint=Measure-N4HostProxyPositive $proxyRunContext $plan $true
        $closed.hostSameEndpointHealthy=$true
        $closed.psecSameEndpointDenied=$true
        $closed.ordinarySameEndpointDenied=$true
        $closed.probe=$live.process
        $closed.firstBusinessTick=$live.cold.data.firstProbeTick
        $closed.liveProbeIdentity=$true
        $closed.proxyContext=$proxyRunContext
        $closed.topology=$proxyRunContext.topology
        $closed.prefix=$proxyRunContext.observer.prefix
        $closed.logs=$proxyRunContext.topology.logSources
        $closed.bindingReadback=$true
        $closed.baseReadBeforeCold=$true
        $closed.proxyOwnershipVerified=$true
        $closed
    }
    $stagedOperations.MeasureHealthy={
        param($plan,$state)
        $protocols=Measure-N4LiveProxyProtocols $proxyRunContext.liveProbe
        $frame=Invoke-N4ProxyProbeCommand $proxyRunContext.liveProbe direct 15000
        $evidence=Measure-N4ProxyStageScope $proxyRunContext $plan ('healthy'+$state.generationsOpened) $frame
        $ordinary=Invoke-N4OrdinaryProxyControl $proxyRunContext $plan
        Assert-N4DeniedProxyPair $ordinary.frame.data
        $evidence.ordinaryADenied=$true
        $evidence.ordinaryProxy=$ordinary
        $evidence.replayed=0 # The coordinator independently scans the authenticated log window.
        $evidence.protocols=$protocols
        $evidence
    }
    $stagedOperations.HoldOldFlows={
        param($plan,$state)
        $null=Invoke-N4ProxyProbeCommand $proxyRunContext.liveProbe hold
        $until=[Diagnostics.Stopwatch]::GetTimestamp()+2*[Diagnostics.Stopwatch]::Frequency
        Read-N4LiveHeldFlows $proxyRunContext.liveProbe $true $until
    }
    $stagedOperations.MeasureFailure={
        param($plan,$state,$fault,$injected,$policy)
        $until=$injected+3*[Diagnostics.Stopwatch]::Frequency
        $streams=Read-N4LiveHeldFlows $proxyRunContext.liveProbe $false $until
        $left=[int](($until-[Diagnostics.Stopwatch]::GetTimestamp())*1000.0/[Diagnostics.Stopwatch]::Frequency)
        if ($left -le 0) { throw 'N4 fresh-request fault deadline expired' }
        $fresh=Invoke-N4ProxyProbeCommand $proxyRunContext.liveProbe probe $left
        $frame=Invoke-N4ProxyProbeCommand $proxyRunContext.liveProbe direct 15000
        $evidence=Measure-N4ProxyStageScope $proxyRunContext $plan ('fault'+$state.generationsOpened) $frame
        $evidence.kind=$fault
        $evidence.exceptionAbsent=$policy.readbackTick -gt 0
        $evidence.baseRetained=$policy.readbackTick -gt 0
        $evidence.aStillAlive=$policy.probeAlive
        $evidence.proxyStillAlive=$policy.entryAlive
        $evidence.upstreamStillAlive=$policy.upstreamAlive
        $evidence.managerSurvived=$policy.managerAlive
        if ($fault -cin 'entry-exit','upstream-exit') {
            $port=$plan.ports[[int]($fault -ceq 'upstream-exit')]
            $bind=Invoke-N4OrdinaryProxyControl $proxyRunContext $plan $port
            $evidence.ordinaryRebind=$bind
            $evidence.rebindRejected=$policy.hostRebind.nativeError -eq 10013 -and $bind.frame.data.port -eq $port -and
                $bind.frame.data.stage -ceq 'bind' -and $bind.frame.data.nativeError -eq 10013
        }
        $evidence.closedTick=$fresh.tick
        $evidence.streams=$streams
        $evidence.fresh=$fresh.data
        $evidence
    }
    $stagedOperations.RestoreProxyHealth={
        param($plan,$state,$fault)
        if ($fault -cin 'upstream-refuse','upstream-silent') {
            $changed=Invoke-N3Child $proxyRunContext.topology.upstream 'serve'
            if ($changed.mode -cne 'serve') { throw 'N4 upstream did not restore service' }
        }
        $positive=Measure-N4HostProxyPositive $proxyRunContext $plan $false
        @{originalPortAndRelay=$true;newRoundTrip=($positive.routes.Count -eq 2);exceptionAbsent=(!$proxyRunContext.proxyOwner)}
    }
    $stagedOperations.RevokeAndDrain={
        param($plan,$state)
        try { Stop-N4ReviewedProxyProbe $proxyRunContext }
        finally { Stop-N4PreparedProxyRelays $proxyRunContext }
        @{exceptionAbsent=(!$proxyRunContext.proxyOwner);workloadsExited=(!$proxyRunContext.liveProbe)}
    }
    $stagedOperations.RollbackAndMeasure={
        param($plan,$state)
        Assert-NoRecoveryWorkload $plan $stage.root
        $lease.Dispose()
        $removed=Invoke-N4ReviewedRollback $proxyRunContext $Segment
        $proxyRunContext.rulesAbsent=$true
        $proxyRunContext.restoredAllowed=$true
        $plain=Invoke-N4ReviewedAccountProbe $proxyRunContext $proxyRunContext.observer.prefix ordinary restored $Segment
        $proxyRunContext.observer.receipts.Add($plain.receipt)
        $after=@{host=(Invoke-N4HostControl $proxyRunContext restored $Segment);ordinary=$plain}
        $after.ordinaryARestored=(Test-AccountPath $plain.tcp $proxyRunContext.endpoints.tcp $true) -and
            (Test-AccountPath $plain.udp $proxyRunContext.endpoints.udp $true)
        $after.rulesAbsent=Test-True $removed.listedObjectsAbsent
        $after.portReadback=@(foreach ($port in $plan.ports) {Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'})
        $after.portsBindable=$after.portReadback.Count -eq 2 -and
            @($after.portReadback | Where-Object { $_.stage -cne 'listening' }).Count -eq 0
        $after.trace=Stop-LabDnsTrace $proxyRunContext.observer.trace -MeasureLoss
        $proxyRunContext.traceStopped=Test-True $after.trace.stopped
        $after.traceStoppedAfterControls=$proxyRunContext.traceStopped
        $after.dnsReceipts=$proxyRunContext.observer.receipts.ToArray()
        $observer=$proxyRunContext.observer
        $after.dnsEvidence=Measure-N4ProxyDns $after.trace $after.dnsReceipts $observer.prefix $observer.readyTick $plan.exceptionKeys.Count
        $after
    }
    try {
        $trusted=@($stage.plan.hostSid,'S-1-5-18','S-1-5-32-544')
        $prior=$preflight.prior.plan
        $oldSpec=[StudioLabWfp+AccountGuardSpec]::new($prior.userSid,'',$prior.accountLayer,$prior.accountKeys,$prior.accountWeight,0)
        [StudioLabWfp]::VerifyAccountStageAbsent($oldSpec,$prior.exceptionKeys,$prior.bindLayer,$prior.bindKeys,$prior.ports,$prior.bindWeight)
        Assert-NoRecoveryWorkload $stage.plan $stage.root
        $oldPath=Join-Path $stage.root 'recovery.json'
        if (!(Test-Path -LiteralPath $oldPath)) { $oldPath=Join-Path $stage.root ('recovery-'+$prior.segment+'.json') }
        $null=Assert-RecoveryAcl $oldPath $true $false
        $null=Archive-N4PreviousRecoveryJournal $stage.run $prior.segment $preflight.previous.recovery $lease
        $proxyRunContext.journal=Write-N4RecoveryJournal $stage.reviewed $stage.run $lease $stage.bytes $Segment
        if ($proxyRunContext.journal.sha256 -cne $ReviewedJournalHash) { throw 'Staged N4 journal hash changed' }
        $watch=Start-N4ReviewedRecoveryWatch $proxyRunContext $Segment
        if (!(Test-True $watch.ready)) { throw 'Staged N4 recovery watcher did not arm' }
        $result=Invoke-N4ProxyFaultSchedule $stage.reviewed $preflight.previous $stagedOperations
        $result.mode='reviewed-live'
        $result.hostSid=$stage.plan.hostSid
        $result.recovery=$ReviewedJournalHash
        $result.saved=Save-N4StagedResult $stage.root $Segment $result
        return $result
    } finally {
        $lease.Dispose()
        try {
            if ($proxyRunContext.observer.trace -and !$proxyRunContext.traceStopped) {
                $null=Stop-LabDnsTrace $proxyRunContext.observer.trace -MeasureLoss
            }
        } finally {
            Close-N4MatchCanaries $proxyRunContext.observer.canaries
            Complete-N4Watch $proxyRunContext.recoveryWatch ([bool]$proxyRunContext.rulesAbsent)
        }
    }
}

if ($loadN4ProxyOnly) { return }

function New-N4ProxyRouteFixture([string]$Prefix,[int]$Generation,[string]$FailureScenario) {
    $eventLists=@{}
    foreach ($part in 'entry','upstream','target') { $eventLists[$part]=[Collections.Generic.List[object]]::new() }
    $readings=@{}
    $counter=0
    foreach ($role in 'primary','auxiliary') {
        $readings[$role]=@{}
        foreach ($protocol in 'http','tls') {
            $counter++
            $marker='{0:x16}' -f (100*$Generation+$counter)
            $readings[$role][$protocol]=@{ok=$true;status=200;marker=$marker}
            $eventLists.target.Add(@{kind='target';marker=$marker;protocol=$protocol;peer=51000+$counter})
            $method=if ($protocol -ceq 'http') {'GET'} else {'CONNECT'}
            $authority=$Prefix+'-a-window-healthy.test'+$(if ($protocol -ceq 'tls') {':443'})
            $headerMarker=if ($method -ceq 'GET') {$marker} else {$null}
            if ($FailureScenario -ne 'missing-upstream' -or $counter -ne 1) {
                $eventLists.upstream.Add(@{kind='routed';method=$method;authority=$authority;marker=$headerMarker;peer=52000+$counter;outbound=51000+$counter})
            }
            $eventLists.entry.Add(@{kind='routed';method=$method;authority=$authority;marker=$headerMarker;outbound=52000+$counter})
        }
    }
    $readings.wrongCertificate=@{test='wrong-cert';ok=$false;status='TrustFailure';marker=('a'*16)}
    $readings.wrongHost=@{test='wrong-host';ok=$false;status='TrustFailure';marker=('b'*16)}
    foreach ($suffix in '-a-window-healthy.test:9443','-a-window-fake.test:443') {
        $counter++
        $authority=$Prefix+$suffix
        $eventLists.entry.Add(@{kind='routed';method='CONNECT';authority=$authority;outbound=52000+$counter})
        if ($FailureScenario -ne 'missing-trust-route') {
            $eventLists.upstream.Add(@{kind='routed';method='CONNECT';authority=$authority;peer=52000+$counter;outbound=51000+$counter})
        }
    }
    if ($FailureScenario -eq 'duplicate-marker') { $readings.auxiliary.tls.marker=$readings.primary.tls.marker }
    if ($FailureScenario -eq 'wrong-cert-delivered') {
        $eventLists.target.Add(@{kind='target';marker=$readings.wrongCertificate.marker;protocol='tls';peer=51005})
    }
    return @{protocols=$readings;events=$eventLists}
}

function Add-N4FixtureLogRows($Logs,$Events) {
    foreach ($part in 'entry','upstream','target') {
        $lines=@(foreach ($row in $Events.$part) {
            (@{pid=$Logs.$part.pid}+$row) | ConvertTo-Json -Compress
        })
        if ($lines.Count) { [IO.File]::AppendAllText($Logs.$part.path,($lines -join "`n")+"`n") }
    }
}

function Invoke-N4ProxyFixture([string]$Segment,[string]$FailureScenario,$Previous) {
    $keys=@(1..14 | ForEach-Object {[guid]::NewGuid().ToString()})
    $fixturePorts=$(if ($Segment -ceq 'F' -or $FailureScenario -ceq 'reuse-port') {40000,40001} else {40002,40003})
    $manifest=[ordered]@{schema='studio-n4-account-recovery-v1';run=$Previous.run;segment=$Segment;
        accountSid=$Previous.accountSid;hostSid='S-1-5-21-1-2-3-1002';librarySha256=('A'*64);controllerSha256=('B'*64);
        account=@{sublayer=$keys[0];keys=$keys[1..4];weight=50}; binding=@{sublayer=$keys[5];keys=$keys[6..9];ports=$fixturePorts;weight=49};
        exceptionKeys=$(if ($Segment -ceq 'F') { @($keys[10..13]) } else { ,$keys[10] })}
    $hostFixture=@{oldConnection='same-connection';dns=$true;oldMarker=$true;newMarker=$true}
    $container='S-1-15-2-1-2-3-4-5-6-7'
    $prefix='studio-0123456789abcdef'
    $calls=[Collections.Generic.List[string]]::new()
    $scope=@{host=$hostFixture;containerSid=$container;directClean=$true;systemDnsClean=$true}
    $logRoot=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioN4LogTest-'+[guid]::NewGuid().ToString('N'))
    $logs=@{
        entry=@{path=(Join-Path $logRoot 'entry.ndjson');pid=101}
        upstream=@{path=(Join-Path $logRoot 'upstream.ndjson');pid=102}
        target=@{path=(Join-Path $logRoot 'target.ndjson');pid=103}
    }
    $ops=@{
        PrepareClosed={param($p,$s) $calls.Add('closed'); $scope+@{prefix=$prefix;logs=$logs;baseReadBeforeCold=$true;liveProbeIdentity=$true;bindingReadback=$true;
            proxyOwnershipVerified=$true;hostSameEndpointHealthy=($FailureScenario -ne 'no-positive');psecSameEndpointDenied=$true;ordinarySameEndpointDenied=$true}}
        OpenReviewedException={param($p,$s,$key) $calls.Add('open'); @{exactReadback=$true;key=$key;port=$p.ports[0];containerSid=$container;
            ownerPid=(200+$s.generationsOpened);ownerStartTicks=(1000+$s.generationsOpened)}}
        MeasureHealthy={
            param($p,$s)
            $fixture=New-N4ProxyRouteFixture $prefix $s.generationsOpened $FailureScenario
            if ($FailureScenario -eq 'historical-trust-route') {
                $fixture=New-N4ProxyRouteFixture $prefix $s.generationsOpened 'missing-trust-route'
            }
            if ($FailureScenario -eq 'rewrite-log') {
                $prior=[IO.File]::ReadAllText($logs.entry.path)
                [IO.File]::WriteAllText($logs.entry.path,$prior.Replace('routed','edited'))
            }
            Add-N4FixtureLogRows $logs $fixture.events
            if ($FailureScenario -eq 'wrong-pid') { [IO.File]::AppendAllText($logs.entry.path,'{"kind":"routed","pid":999}'+"`n") }
            if ($FailureScenario -eq 'partial-record') { [IO.File]::AppendAllText($logs.target.path,'{"kind":') }
            if ($FailureScenario -eq 'replay-prior-target' -and $s.generationsOpened -eq 2) {
                $previousReading=New-N4ProxyRouteFixture $prefix 1 'none'
                Add-N4FixtureLogRows $logs @{target=@($previousReading.events.target[0])}
            }
            $scope+@{protocols=$fixture.protocols;ordinaryADenied=($FailureScenario -ne 'ordinary-allowed');replayed=0}
        }
        HoldOldFlows={
            param($p,$s)
            $tick=[Diagnostics.Stopwatch]::GetTimestamp()
            $s.fixtureStreams=@{}
            $targets=@(foreach ($protocol in 'http','tls') {
                $role=if ($protocol -ceq 'http') {'c'} else {'d'}
                $marker=$role+('{0:x15}' -f $s.generationsOpened)
                $s.fixtureStreams[$protocol]=@{marker=$marker;state='active';marks=@("${marker}:1","${marker}:2");receivedTicks=@(($tick-1),$tick)}
                if ($FailureScenario -cne 'missing-old-target' -or $protocol -cne 'tls') {
                    @{kind='target';action='hold';marker=$marker;protocol=$protocol}
                }
            })
            Add-N4FixtureLogRows $logs @{target=$targets}
            $s.fixtureStreams
        }
        InjectFault={param($p,$s,$kind) $calls.Add($kind)}
        MeasureFailure={
            param($p,$s,$kind,$tick)
            $streams=@{}
            $fresh=@{}
            foreach ($protocol in 'http','tls') {
                $previous=$s.fixtureStreams[$protocol]
                $streams[$protocol]=@{marker=$previous.marker;state='eof';marks=@($previous.marks);receivedTicks=@($previous.receivedTicks)}
                $role=if ($protocol -ceq 'http') {'e'} else {'f'}
                $fresh[$protocol]=@{test=$protocol;marker=($role+('{0:x15}' -f $s.generationsOpened));ok=$false;status='ConnectFailure'}
            }
            if ($FailureScenario -ceq 'rewritten-old-stream') { $streams.tls.receivedTicks=@(($tick-1),$tick) }
            if ($FailureScenario -ceq 'late-old-stream') {
                $streams.http.marks+=($streams.http.marker+':3')
                $streams.http.receivedTicks+=($tick+4*[Diagnostics.Stopwatch]::Frequency)
            }
            if ($FailureScenario -ceq 'fresh-target-hit') {
                Add-N4FixtureLogRows $logs @{target=@(@{kind='target';action='n3';marker=$fresh.tls.marker;protocol='tls'})}
            }
            $scope+@{kind=$kind;closedTick=($tick+$(if ($FailureScenario -eq 'deadline') { 4*[Diagnostics.Stopwatch]::Frequency } else { 1 }));
            exceptionAbsent=($FailureScenario -ne 'old-exception');baseRetained=$true;streams=$streams;fresh=$fresh;
            aStillAlive=$true;proxyStillAlive=$true;upstreamStillAlive=$true;managerSurvived=$true;rebindRejected=$true;
            entryClosure=@{closeReason=$(if ($FailureScenario -eq 'manual-entry-halt') {'controller-halt'} else {'exception-owner-exit'});
                admitting=$false;watching=$false;active=0;closedTick=$tick;
                exceptionOwnerPid=(199+$s.generationsOpened);exceptionOwnerStartTicks=(999+$s.generationsOpened)}}}
        RestoreProxyHealth={
            param($p,$s,$kind)
            $calls.Add('restore')
            if ($FailureScenario -ceq 'restore-replay') {
                Add-N4FixtureLogRows $logs @{target=@(@{kind='target';action='hold';marker=$s.fixtureStreams.http.marker;protocol='http'})}
            }
            @{originalPortAndRelay=$true;newRoundTrip=$true;exceptionAbsent=$true}
        }
        RevokeAndDrain={param($p,$s) $calls.Add('drain'); @{exceptionAbsent=$true;workloadsExited=($FailureScenario -ne 'live-a')}}
        RollbackAndMeasure={param($p,$s) $calls.Add('rollback'); @{host=$hostFixture;rulesAbsent=$true;portsBindable=$true;ordinaryARestored=$true;traceStoppedAfterControls=$true}}
    }
    if ([IO.Directory]::Exists($logRoot)) { throw 'N4 log fixture directory collision' }
    [void][IO.Directory]::CreateDirectory($logRoot)
    try {
        $historical=New-N4ProxyRouteFixture $prefix 0 'none'
        Add-N4FixtureLogRows $logs $historical.events
        $result=Invoke-N4ProxyFaultSchedule $manifest $Previous $ops
        return @{result=$result;calls=$calls.ToArray();manifest=$manifest}
    } finally {
        foreach ($log in $logs.Values) { [IO.File]::Delete($log.path) }
        [IO.Directory]::Delete($logRoot)
    }
}

$prior=@{run=('a'*32);accountSid='S-1-5-21-1-2-3-1001';outcome='passed-account-match-m';cleanupVerified=$true}
$f=Invoke-N4ProxyFixture F none $prior
$x=Invoke-N4ProxyFixture X none $f.result
if ($f.result.outcome -cne 'passed-account-proxy-f' -or $f.result.generations.Count -ne 4 -or $f.result.faults.Count -ne 4 -or
    ($f.result.faults.kind -join ',') -cne 'upstream-refuse,upstream-silent,exception-owner-exit,upstream-exit' -or
    $x.result.outcome -cne 'passed-account-proxy-x' -or $x.result.generations.Count -ne 1 -or $x.result.faults.Count -ne 1 -or
    $f.result.generations[0].routes.Count -ne 4 -or $x.result.generations[0].routes.Count -ne 4 -or
    $f.result.generations[0].logWindow.start.entry.length -le 0 -or
    $f.result.generations[1].logWindow.start.entry.length -ne $f.result.generations[0].logWindow.end.entry.length -or
    $x.result.faults[0].kind -cne 'entry-exit') { throw 'Valid F or X schedule failed' }
foreach ($case in 'no-positive','ordinary-allowed','old-exception','deadline','live-a','missing-upstream','duplicate-marker','wrong-cert-delivered','missing-trust-route') {
    $test=Invoke-N4ProxyFixture F $case $prior
    if ($test.result.outcome -ceq 'passed-account-proxy-f' -or 'drain' -notin $test.calls -or
        ($case -eq 'live-a' -and 'rollback' -in $test.calls) -or ($case -eq 'no-positive' -and 'open' -in $test.calls) -or
        ($case -in 'old-exception','deadline' -and 'restore' -in $test.calls)) { throw ('Unsafe proxy schedule passed '+$case) }
}
$logFailures=@{
    'historical-trust-route'='N4 proxy wrongCertificate lacks one generation-local CONNECT through both relays'
    'rewrite-log'='N4 entry proxy log changed before the generation boundary'
    'wrong-pid'='N4 entry proxy log contains an event of unknown origin'
    'partial-record'='N4 target proxy log has a partial record at the boundary'
    'replay-prior-target'='N4 proxy replayed a delivered marker from an earlier generation'
    'manual-entry-halt'='N4 entry did not close its active flows on exact exception-owner exit'
    'missing-old-target'='N4 old stream has no unique pre-fault target request'
    'rewritten-old-stream'='N4 old stream rewrote markers observed before fault'
    'late-old-stream'='N4 old stream identity or closure timestamp differs'
    'fresh-target-hit'='N4 fresh request lacks a clean fault rejection'
    'restore-replay'='N4 proxy replayed a previous request before the new generation'
}
foreach ($case in $logFailures.Keys) {
    $test=Invoke-N4ProxyFixture F $case $prior
    if ($test.result.outcome -ceq 'passed-account-proxy-f' -or $logFailures[$case] -cnotin $test.result.errors -or
        !$test.result.cleanupVerified) { throw ('N4 log rejection did not reach rollback: '+$case) }
    if ($case -cin 'missing-old-target','rewritten-old-stream','late-old-stream','fresh-target-hit' -and
        ($test.result.faults.Count -ne 1 -or $test.result.faults[0].verified -ne $false -or !$test.result.faults[0].proof)) {
        throw ('N4 fault evidence was lost on rejection: '+$case)
    }
}
try { $null=Invoke-N4ProxyFixture X reuse-port $f.result; throw 'X accepted F relay ports' }
catch { if ($_.Exception.Message -cne 'N4 X cannot reuse the F relay ports') { throw } }

function Test-N4ProxyPredecessor {
    $digest='C'*64
    $m=New-SyntheticAccountReport
    $m.segment='M';$m.mode='reviewed-live';$m.run=$prior.run;$m.errors=@();$m.cleanupVerified=$true
    $m.recovery=$digest;$m.outcome='passed-account-match-m'
    $mPlan=@{segment='M';run=$m.run;accountSid=$m.accountSid;hostSid=$m.hostSid}
    Assert-N4ProxyPredecessor $f.manifest $mPlan $m $digest
    $fLive=$f.result | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $fLive | Add-Member -NotePropertyMembers @{mode='reviewed-live';hostSid=$f.manifest.hostSid;recovery=$digest}
    $fLive.restoration | Add-Member -NotePropertyMembers @{dnsEvidence=@{verified=$true}}
    foreach ($fault in $fLive.faults) {
        $fault | Add-Member -NotePropertyMembers @{policy=@{synthetic=$true};injection=@{synthetic=$true}}
    }
    Assert-N4ProxyPredecessor $x.manifest $f.manifest $fLive $digest
    $negative=@(
        {param($v) $v.mode='orchestration'},
        {param($v) $v.recovery='D'*64},
        {param($v) $v.accountSid='S-1-5-21-1-2-3-1003'},
        {param($v) $v.ports=@(40002,40003)},
        {param($v) $v.faults[0].policy=$null},
        {param($v) $v.restoration.traceStoppedAfterControls=$false},
        {param($v) $v.restoration.dnsEvidence.verified=$false},
        {param($v) $v.generations[0].key=[guid]::NewGuid()}
    )
    foreach ($change in $negative) {
        $copy=$fLive | ConvertTo-Json -Depth 30 | ConvertFrom-Json
        & $change $copy
        $rejected=$false
        try { Assert-N4ProxyPredecessor $x.manifest $f.manifest $copy $digest }
        catch { $rejected=$true }
        if (!$rejected) { throw ('Invalid N4 predecessor unexpectedly passed: '+$change) }
    }
    $m.cleanup.rulesAbsent=$false
    try { Assert-N4ProxyPredecessor $f.manifest $mPlan $m $digest; throw 'M cleanup evidence was accepted after alteration' }
    catch { if ($_.Exception.Message -cne 'N4 predecessor M evidence did not independently pass') { throw } }
    return ($negative.Count+1)
}

function Test-N4ProxyRecoveryHandoff {
    $run='a'*32
    $testRoot=Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype')) ('n4-handoff-test-'+[guid]::NewGuid().ToString('N'))
    $location=Join-Path $testRoot ('ClaudeStudioN4Account-'+$run)
    $active=Join-Path $location 'recovery.json'
    $archive=Join-Path $location 'recovery-M.json'
    $leaseFile=Join-Path $location 'recovery.lease'
    $resultFile=Join-Path $location 'result-M.json'
    if ([IO.Directory]::Exists($testRoot)) { throw 'N4 handoff fixture collision' }
    [void][IO.Directory]::CreateDirectory($location)
    [IO.File]::WriteAllBytes($leaseFile,[byte[]]@())
    $lease=Open-N4RecoveryLease $location
    try {
        $m=@{schema='studio-n4-account-recovery-v1';run=$run;segment='M';accountSid=$f.manifest.accountSid;
            hostSid=$f.manifest.hostSid;librarySha256='A'*64;controllerSha256='B'*64;
            account=@{sublayer=[guid]::NewGuid().ToString();weight=50;keys=@(1..4 | ForEach-Object {[guid]::NewGuid().ToString()})};
            binding=$null;exceptionKeys=@()}
        $old=Write-N4RecoveryJournal $m $run $lease
        try { $null=Archive-N4PreviousRecoveryJournal $run 'M' ('0'*64) $lease; throw 'Bad predecessor digest archived' }
        catch { if ($_.Exception.Message -cne 'Predecessor journal differs from verified receipt') { throw } }
        if (![IO.File]::Exists($active) -or [IO.File]::Exists($archive)) { throw 'Rejected archival changed the recovery files' }
        if ((Archive-N4PreviousRecoveryJournal $run 'M' $old.sha256 $lease) -ine $archive -or [IO.File]::Exists($active)) {
            throw 'N4 prior recovery journal was not atomically archived'
        }
        if ((Archive-N4PreviousRecoveryJournal $run 'M' $old.sha256 $lease) -ine $archive) { throw 'N4 handoff did not tolerate interrupted activation' }
        $nextBytes=[Text.UTF8Encoding]::new($false).GetBytes(($f.manifest|ConvertTo-Json -Depth 12 -Compress))
        $next=Write-N4RecoveryJournal $f.manifest $run $lease $nextBytes 'F'
        if ($next.plan.segment -cne 'F' -or $next.sha256 -cne (Get-N4ByteDigest $nextBytes) -or
            (Get-FileHash -LiteralPath $archive).Hash -cne $old.sha256) { throw 'N4 handoff changed the exact journal bytes' }
        try { $null=Archive-N4PreviousRecoveryJournal $run 'M' $old.sha256 $lease; throw 'N4 handoff reused an active recovery journal' }
        catch { if ($_.Exception.Message -cne 'Expected exactly one active or archived predecessor journal') { throw } }
        $saved=Save-N4StagedResult $location 'M' @{test='synthetic'}
        $collision=$false
        try { $null=Save-N4StagedResult $location 'M' @{test='changed'} }
        catch [IO.IOException] { $collision=$true }
        if (!$collision -or (Get-FileHash -LiteralPath $resultFile).Hash -cne $saved.sha256) { throw 'N4 staged result was overwritten' }
        return $true
    } finally {
        $lease.Dispose()
        foreach ($path in $active,$archive,$leaseFile,$resultFile) { [IO.File]::Delete($path) }
        [IO.Directory]::Delete($location)
        [IO.Directory]::Delete($testRoot)
    }
}

function Test-N4ProxyDns {
    $prefix='studio-0123456789abcdef'
    $receiptList=[Collections.Generic.List[object]]::new()
    $events=[Collections.Generic.List[object]]::new()
    $controlStages=@('host-baseline','ordinary-baseline','host-blocked','psec-blocked','host-restored','ordinary-restored')
    for ($i=1;$i -le 4;$i++) { $controlStages+=@("host-healthy$i","psec-healthy$i","host-fault$i","psec-fault$i") }
    $number=0
    foreach ($key in $controlStages) {
        $role,$label=$key.Split('-',2)
        $number++
        $phase=if ($role -ceq 'psec') {'cold'+$number} else {$label}
        $caller=1000+$number
        $queries=@(foreach ($tag in 'dns','addr') {
            $name="$prefix-$role-$phase-$tag.test."
            $api=if ($tag -ceq 'dns') {'DnsQuery_W'} else {'GetAddrInfoW'}
            @{name=$name;api=$api;startedTick=11L;completedTick=12L}
            if ($role -cne 'psec' -and $tag -ceq 'dns') {
                $send=Convert-LabDnsEvent @{Id=3010;ProcessId=17;Properties=@(@{Value=$name},@{Value=0},@{Value='fixture'},@{Value=$caller})} $prefix $true
                $reply=Convert-LabDnsEvent @{Id=3011;ProcessId=17;Properties=@(@{Value=$name},@{Value=0},@{Value='fixture'},@{Value=0},@{Value=$caller})} $prefix $true
                $events.Add($send)
                $events.Add($reply)
            }
        })
        $receiptList.Add(@{role=$role;stage=$label;phase=$phase;identity=@{pid=$caller};firstProbeTick=10L;
            tickFrequency=[Diagnostics.Stopwatch]::Frequency;dnsQueries=$queries})
    }
    $fixture=@{trace=@{stopped=$true;servicePid=17;servicePidAfter=17;
        lossBeforeStop=@{eventsLost=0;logBuffersLost=0;realtimeBuffersLost=0};events=$events.ToArray()};receipts=$receiptList.ToArray()}
    $good=Measure-N4ProxyDns $fixture.trace $fixture.receipts $prefix 1 4
    if (!$good.verified -or $good.queries.Count -ne $controlStages.Count) { throw ('F DNS fixture failed: '+($good.errors -join ', ')) }
    $badCases=@(
        {param($v) $v.trace.lossBeforeStop.eventsLost=1},
        {param($v) $v.trace.lossBeforeStop.eventsLost=$null},
        {param($v) $v.trace.servicePidAfter=19},
        {param($v) $v.trace.events[0].clientPid=99},
        {param($v) $v.trace.events[1].name='studio-0123456789abcdef-a-window-healthy.test'},
        {param($v) $v.trace.events=@($v.trace.events | Where-Object {$_.phase -cne 'healthy3'})},
        {param($v) $v.receipts=@($v.receipts | Where-Object {$_.stage -cne 'fault2'})},
        {param($v) $v.receipts[3].dnsQueries[0].startedTick=0},
        {param($v)
            $psec=$v.receipts[3]
            $v.trace.events+=@{event=3010;role='psec';phase=$psec.phase;emitterPid=17;
                clientPid=$psec.identity.pid;name=$psec.dnsQueries[0].name.TrimEnd('.')}
        }
    )
    foreach ($change in $badCases) {
        $copy=$fixture | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        & $change $copy
        if ((Measure-N4ProxyDns $copy.trace $copy.receipts $prefix 1 4).verified) { throw ('Unsafe DNS evidence accepted: '+$change) }
    }
    $xReceipts=@($fixture.receipts | Where-Object {$_.stage -cnotmatch '[2-4]$'})
    $fixture.trace.events=@($fixture.trace.events | Where-Object {$_.phase -cnotmatch '[2-4]$'})
    if (!(Measure-N4ProxyDns $fixture.trace $xReceipts $prefix 1 1).verified) { throw 'X DNS fixture failed' }
    return $badCases.Count
}

[ordered]@{mode='offline-proxy-schedule';FOpenGenerations=4;XOpenGenerations=1;routesPerGeneration=4;rejected=(10+$logFailures.Count);
    rejectedPredecessors=(Test-N4ProxyPredecessor);protectedHandoffLogic=(Test-N4ProxyRecoveryHandoff);
    rejectedDnsEvidence=(Test-N4ProxyDns);wfpWrites=0;actualProxyStarts=0}
