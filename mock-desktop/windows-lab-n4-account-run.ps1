[CmdletBinding(DefaultParameterSetName='Test')]
param(
    [Parameter(Mandatory,ParameterSetName='Library')][switch]$FunctionsOnly,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$loadMFunctionsOnly = [bool]$FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n4-account-control.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n4-account-result.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-dns-trace.ps1')

function Get-N4ByteDigest([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','') }
    finally { $sha.Dispose() }
}

function Write-N4RecoveryJournal($Manifest, [string]$Run, [IO.FileStream]$Lease, [byte[]]$ReviewedBytes,
    [ValidateSet('M','F','X')][string]$ExpectedSegment='M') {
    if (!$Lease.CanWrite -or [IO.Path]::GetFileName($Lease.Name) -cne 'recovery.lease') { throw 'Recovery lease is missing' }
    $directory = [IO.Path]::GetDirectoryName($Lease.Name)
    if ([IO.Path]::GetFileName($directory) -cne "ClaudeStudioN4Account-$Run") { throw 'Recovery lease belongs to a different run' }
    $path = Join-Path $directory 'recovery.json'
    $utf8 = [Text.UTF8Encoding]::new($false,$true)
    $bytes = $ReviewedBytes
    if (!$bytes) { $bytes = $utf8.GetBytes(($Manifest | ConvertTo-Json -Depth 12 -Compress)) }
    $json = $utf8.GetString($bytes)
    $plan = Read-RecoveryPlan ($json | ConvertFrom-Json) $Run
    if ($plan.segment -cne $ExpectedSegment) { throw 'Recovery manifest is for another stage' }
    $pending = Join-Path $directory ('recovery-'+[guid]::NewGuid().ToString('N')+'.pending')
    $created = $false
    try {
        $stream = [IO.File]::Open($pending,'CreateNew','Write','None')
        $created = $true
        try {
            $stream.Write($bytes,0,$bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        [IO.File]::Move($pending,$path) # Same directory. Never replace a prior recovery journal.
        $created = $false
    } finally { if ($created) { Remove-Item -LiteralPath $pending -ErrorAction Stop } }
    return @{ sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; plan=$plan; path=$path }
}

function Archive-N4PreviousRecoveryJournal([string]$Run,[ValidateSet('M','F')][string]$Segment,
    [string]$ExpectedHash,[IO.FileStream]$Lease) {
    if (!$Lease.CanWrite -or [IO.Path]::GetFileName($Lease.Name) -cne 'recovery.lease' -or
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($Lease.Name)) -cne "ClaudeStudioN4Account-$Run" -or
        $ExpectedHash -cnotmatch '^[A-F0-9]{64}$') { throw 'Missing matching lease or predecessor digest' }
    $directory=[IO.Path]::GetDirectoryName($Lease.Name)
    $active=Join-Path $directory 'recovery.json'
    $archive=Join-Path $directory ('recovery-'+$Segment+'.json')
    if ((Test-Path -LiteralPath $active) -eq (Test-Path -LiteralPath $archive)) {
        throw 'Expected exactly one active or archived predecessor journal'
    }
    $path=if (Test-Path -LiteralPath $active) { $active } else { $archive }
    $item=Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536) {
        throw 'Invalid predecessor recovery journal'
    }
    $bytes=[IO.File]::ReadAllBytes($item.FullName)
    if ((Get-N4ByteDigest $bytes) -cne $ExpectedHash) { throw 'Predecessor journal differs from verified receipt' }
    $plan=Read-RecoveryPlan ([Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json) $Run
    if ($plan.segment -cne $Segment) { throw 'Predecessor journal is for another stage' }
    if ($path -ceq $active) { [IO.File]::Move($active,$archive) }
    return $archive
}

function Assert-N4Phase($Phase, [string]$Name, $Context, [bool]$Reachable) {
    if ($Phase.name -cne $Name -or !(Test-AccountIdentity $Phase.psec.identity $Context.accountSid $true) -or
        ($Name -ne 'cold' -and !(Test-AccountIdentity $Phase.ordinary.identity $Context.accountSid $false)) -or
        $Phase.host.sid -cne $Context.hostSid -or !$Phase.host.oldConnection -or
        !(Test-True $Phase.host.dns) -or !(Test-True $Phase.host.oldMarker) -or !(Test-True $Phase.host.newMarker)) {
        throw ('Invalid A or host evidence for '+$Name)
    }
    foreach ($protocol in 'tcp','udp') {
        if (!(Test-AccountPath $Phase.psec.$protocol $Context.endpoints.$protocol $Reachable) -or
            ($Name -ne 'cold' -and !(Test-AccountPath $Phase.ordinary.$protocol $Context.endpoints.$protocol $Reachable))) {
            throw ('Unexpected A '+$protocol+' result for '+$Name)
        }
    }
    if ($Context.oldConnection -and $Phase.host.oldConnection -cne $Context.oldConnection) { throw 'Host old flow was replaced' }
}

function Measure-N4DnsEvidence($Trace, [object[]]$Receipts, [object[]]$Phases, [string]$Prefix, [long]$ObserverReadyTick) {
    $names = @{}
    $verifiedPids = @{}
    $service = $Trace.servicePid
    $coldTick = 0
    foreach ($phase in $Phases) {
        $verifiedPids.Add(('psec-'+$phase.name),$phase.psec.identity.pid)
        if ($phase.ordinary.identity.pid) { $verifiedPids.Add(('ordinary-'+$phase.name),$phase.ordinary.identity.pid) }
        if ($phase.host.dnsPid) { $verifiedPids.Add(('host-'+$phase.name),$phase.host.dnsPid) }
    }
    $reported = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($receipt in $Receipts) {
        $tagForReceipt = $receipt.role+'-'+$receipt.phase
        if ($receipt.role -cnotin 'psec','ordinary','host' -or $receipt.phase -cnotin 'baseline','blocked','cold','restored' -or
            ($receipt.phase -ceq 'cold' -and $receipt.role -ceq 'ordinary') -or $receipt.identity.pid -le 0 -or
            $verifiedPids[$tagForReceipt] -ne $receipt.identity.pid -or !$reported.Add($tagForReceipt) -or
            @($receipt.dnsQueries).Count -ne 2 -or $receipt.tickFrequency -ne [Diagnostics.Stopwatch]::Frequency) {
            throw 'Missing N4 DNS receipt identity or clock'
        }
        foreach ($query in $receipt.dnsQueries) {
            $tag = switch -CaseSensitive ($query.api) { 'DnsQuery_W' { 'dns' }; 'GetAddrInfoW' { 'addr' }; default { throw 'Unknown N4 DNS API' } }
            $name = $Prefix+'-'+$receipt.role+'-'+$receipt.phase+'-'+$tag+'.test'
            if ($query.name.TrimEnd('.') -cne $name -or $names.ContainsKey($name) -or
                $query.startedTick -lt $receipt.firstProbeTick -or $query.completedTick -lt $query.startedTick) {
                throw 'N4 DNS receipt name or timing mismatch'
            }
            $names.Add($name,@{name=$name;api=$query.api;callerPid=$receipt.identity.pid;role=$receipt.role;
                phase=$receipt.phase;sends=0;replies=0})
        }
        if ($receipt.phase -ceq 'cold' -and $receipt.role -ceq 'psec') { $coldTick = $receipt.firstProbeTick }
    }
    foreach ($phaseName in 'baseline','blocked','cold','restored') {
        if (!$reported.Contains('psec-'+$phaseName)) { throw ('Missing DNS probes for PSEC '+$phaseName) }
    }
    $loss = 0L
    $lossKnown = (Test-True $Trace.stopped) -and !$Trace.lossError -and $service -gt 0 -and $service -eq $Trace.servicePidAfter
    foreach ($key in 'eventsLost','logBuffersLost','realtimeBuffersLost') {
        $value = $Trace.lossBeforeStop.$key
        if (($value -is [uint32] -or $value -is [int] -or $value -is [long]) -and $value -ge 0) { $loss += $value }
        else { $lossKnown = $false }
    }
    $unknown = 0
    foreach ($event in $Trace.events) {
        if ($event.event -notin 3010,3011) { continue }
        $expected = $names[[string]$event.name]
        if (!$expected -or $event.role -cne $expected.role -or $event.phase -cne $expected.phase -or
            $event.emitterPid -ne $service -or $event.clientPid -ne $expected.callerPid) { $unknown++; continue }
        if ($event.event -eq 3010) { $expected.sends++ } else { $expected.replies++ }
    }
    $cold = @($names.Values | Where-Object { $_.role -ceq 'psec' -and $_.phase -ceq 'cold' } | Sort-Object @{Expression={ $_.api -ceq 'GetAddrInfoW' }})
    # Any system traffic from another PSEC phase also makes M fail.
    $otherPsecTraffic = @($names.Values | Where-Object { $_.role -ceq 'psec' -and $_.phase -cne 'cold' -and ($_.sends -gt 0 -or $_.replies -gt 0) }).Count
    $hostPositive = @($names.Values | Where-Object { $_.role -ceq 'host' -and $_.sends -gt 0 -and $_.replies -gt 0 }).Count -gt 0
    $ordinaryPositive = @($names.Values | Where-Object { $_.role -ceq 'ordinary' -and $_.sends -gt 0 -and $_.replies -gt 0 }).Count -gt 0
    return @{ servicePid=$service; lossCountsVerified=[bool]$lossKnown;lostEvents=$loss;unknownAttributions=$unknown;
        otherPsecTraffic=$otherPsecTraffic; coveredFirstProbe=($ObserverReadyTick -gt 0 -and $coldTick -gt $ObserverReadyTick);
        hostPositive=$hostPositive;ordinaryPositive=$ordinaryPositive;queries=$cold }
}

function Invoke-N4MatchStage([string]$Directory, $Manifest, [hashtable]$Operation, [byte[]]$ReviewedJournalBytes, [string]$ReviewedJournalHash) {
    # A live adapter must supply independent evidence and hold its worker lease until it drains.
    $names = 'ArmRecovery','StartObservation','MeasureBaseline','InstallBase','ReadBase','MeasureBlocked',
        'StartColdProbe','DrainA','RunIndependentRollback','MeasureRestored','StopObservation','FinishRecovery'
    foreach ($name in $names) {
        if ($Operation[$name] -isnot [scriptblock]) { throw ('Missing M operation '+$name) }
    }
    if ($ReviewedJournalBytes -or $ReviewedJournalHash) {
        if (!$ReviewedJournalBytes -or $ReviewedJournalBytes.Length -gt 65536 -or $ReviewedJournalHash -cnotmatch '^[0-9A-F]{64}$' -or
            (Get-N4ByteDigest $ReviewedJournalBytes) -cne $ReviewedJournalHash) { throw 'Reviewed journal bytes and digest differ' }
        $ReviewedJournalBytes = [byte[]]$ReviewedJournalBytes.Clone()
        $Manifest = [Text.UTF8Encoding]::new($false,$true).GetString($ReviewedJournalBytes) | ConvertFrom-Json
    }
    $lease = Open-N4RecoveryLease $Directory
    $result = [ordered]@{ schema='studio-n4-account-match-v1'; mode=$(if ($ReviewedJournalBytes) {'reviewed-live'} else {'orchestration'});
        segment='M'; run=$Manifest.run; accountSid=$Manifest.accountSid;
        hostSid=$Manifest.hostSid; endpoints=$null; phases=@(); cleanup=@{workloadsExited=$false;rulesAbsent=$false;
        sublayersAbsent=$false; traceStoppedAfterControls=$false}; events=@(); errors=@(); recovery=$null; rawObservation=$null }
    $context = @{ accountSid=$Manifest.accountSid; hostSid=$Manifest.hostSid; endpoints=$null;
        oldConnection=$null; journal=$null; observer=$null; startRequest=$null; runLease=$lease; reviewedJournalHash=$ReviewedJournalHash }
    $tracing = $false
    $mayHaveWritten = $false
    $cold = $null
    $restored = $false
    try {
        $context.journal = Write-N4RecoveryJournal $Manifest $Manifest.run $lease $ReviewedJournalBytes
        $result.recovery = $context.journal.sha256
        $armed = & $Operation.ArmRecovery $context
        if (!(Test-True $armed.ready) -or $armed.journalSha256 -cne $result.recovery) { throw 'Independent recovery not armed for this journal' }
        $tracing = $true
        $context.observer = & $Operation.StartObservation $context
        $observerReady = [Diagnostics.Stopwatch]::GetTimestamp()
        if (!(Test-True $context.observer.ready) -or !$context.observer.endpoints.tcp -or !$context.observer.endpoints.udp) {
            throw 'No trace and canary readiness evidence'
        }
        $context.endpoints = $context.observer.endpoints
        $result.endpoints = $context.endpoints
        $result.events += 'observer-ready'
        $baseline = & $Operation.MeasureBaseline $context
        Assert-N4Phase $baseline 'baseline' $context $true
        $context.oldConnection = $baseline.host.oldConnection
        $result.phases += ,$baseline
        $result.events += 'baseline-passed'
        if ((Get-FileHash -LiteralPath $context.journal.path).Hash -cne $result.recovery) { throw 'Recovery journal changed before rule write' }
        $mayHaveWritten = $true # A writer can commit and then lose its success response.
        $commit = & $Operation.InstallBase $context
        $committed = [Diagnostics.Stopwatch]::GetTimestamp()
        if (!(Test-True $commit.committed)) { throw 'Account rule commit unconfirmed' }
        $result.events += 'base-committed'
        $readback = & $Operation.ReadBase $context
        $readTick = [Diagnostics.Stopwatch]::GetTimestamp()
        if (!(Test-True $readback.exact) -or !(Test-True $readback.independent) -or
            $readback.journalSha256 -cne $result.recovery -or $committed -ge $readTick) { throw 'Independent base readback failed' }
        $result.events += 'base-read-back'
        $blocked = & $Operation.MeasureBlocked $context
        Assert-N4Phase $blocked 'blocked' $context $false
        $result.phases += ,$blocked
        $lastReadback = & $Operation.ReadBase $context
        $readTick = [Diagnostics.Stopwatch]::GetTimestamp()
        if (!(Test-True $lastReadback.exact) -or !(Test-True $lastReadback.independent) -or
            $lastReadback.journalSha256 -cne $result.recovery) { throw 'Independent base readback failed before cold launch' }
        $context.startRequest = [Diagnostics.Stopwatch]::GetTimestamp()
        if ($context.startRequest -le $readTick) { throw 'Cold launch cannot be placed after base readback' }
        $cold = & $Operation.StartColdProbe $context
        Assert-N4Phase $cold 'cold' $context $false
        $cold.timeline.observerReady = $observerReady
        $cold.timeline.commit = $committed
        $cold.timeline.independentReadback = $readTick
        $cold.timeline.startRequest = $context.startRequest
        $cold.timeline.readbackExact = $true
        $result.phases += ,$cold
        $result.events += 'cold-probed'
    } catch { $result.errors += $_.Exception.Message }
    finally {
        try {
            if ($tracing) {
                $drain = & $Operation.DrainA $context
                if (!(Test-True $drain.workloadsExited)) { throw 'A workload exit unconfirmed; retain default deny' }
                $result.cleanup.workloadsExited = $true
                $result.events += 'workload-drained'
            }
        } catch { $result.errors += $_.Exception.Message }
        finally { $lease.Dispose() }
        if ($mayHaveWritten -and $result.cleanup.workloadsExited) {
            try {
                $removed = & $Operation.RunIndependentRollback $context
                if (!(Test-True $removed.listedObjectsAbsent)) { throw 'WFP removal unconfirmed; retain recovery journal' }
                $result.cleanup.rulesAbsent = $true
                $result.cleanup.sublayersAbsent = $true
                $result.events += 'independent-rollback-read-back'
                $context.restoredAllowed = $true
                $after = & $Operation.MeasureRestored $context
                Assert-N4Phase $after 'restored' $context $true
                $result.phases += ,$after
                $restored = $true
                $result.events += 'restored-controls-passed'
            } catch { $result.errors += $_.Exception.Message }
        }
        if ($tracing) {
            try {
                $stopped = & $Operation.StopObservation $context
                if (!(Test-True $stopped.stopped)) { throw 'Observation stop unconfirmed' }
                $result.rawObservation = @{trace=$stopped.trace;receipts=$stopped.receipts;prefix=$stopped.prefix}
                if ($restored) { $result.cleanup.traceStoppedAfterControls = $true }
                if ($cold) { $cold.dns = Measure-N4DnsEvidence $stopped.trace $stopped.receipts $result.phases $stopped.prefix $observerReady }
            } catch { $result.errors += $_.Exception.Message }
        }
        try {
            $safeToDisarm = !$mayHaveWritten -or ($result.cleanup.rulesAbsent -and $result.cleanup.sublayersAbsent)
            & $Operation.FinishRecovery $context $safeToDisarm | Out-Null
        } catch { $result.errors += $_.Exception.Message }
    }
    $result.assessment = Get-AccountResult $result
    if ($result.errors.Count -and $result.assessment.outcome -eq 'passed-account-match-m') {
        $result.assessment.outcome = 'failed-or-incomplete-account-match-m'
    }
    $result.outcome = $result.assessment.outcome
    $result.cleanupVerified = [bool]$result.assessment.checks.cleanup
    return $result
}

if ($loadMFunctionsOnly) { return }

function Invoke-OfflineMatchCase([string]$Fault) {
    $run = [guid]::NewGuid().ToString('N')
    $work = Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype')) ("ClaudeStudioN4Account-$run")
    [void][IO.Directory]::CreateDirectory($work)
    [IO.File]::WriteAllBytes((Join-Path $work 'recovery.lease'),[byte[]]@())
    $reference = New-SyntheticAccountReport
    $reference.phases[0].host.dnsPid = 14
    $manifest = New-N4OfflineManifest $run $reference
    $called = [Collections.Generic.List[string]]::new()
    $workers = @{
        ArmRecovery = { param($c)
            $called.Add('arm')
            # Opening the actual same Windows file a second time must fail while startup owns it.
            try { $collision = Open-N4RecoveryLease $work; $collision.Dispose(); throw 'Launcher did not acquire the recovery lease' }
            catch [IO.IOException] {}
            $hash = (Get-FileHash -LiteralPath $c.journal.path).Hash
            @{ready=$true;journalSha256=$hash}
        }
        StartObservation = { param($c) $called.Add('observe'); @{ready=$true;endpoints=$reference.endpoints} }
        MeasureBaseline = { param($c) $called.Add('baseline'); if ($Fault -eq 'baseline') { $reference.phases[0].ordinary.udp.hits=0 }; $reference.phases[0] }
        InstallBase = { param($c) $called.Add('write'); if ($Fault -eq 'write-receipt') { throw 'Simulated commit response lost' }; @{committed=$true} }
        ReadBase = { param($c)
            $called.Add('read')
            $wrong = $Fault -eq 'readback' -or ($Fault -eq 'late-readback' -and $called.Contains('blocked'))
            @{exact=$true;independent=(!$wrong);journalSha256=$c.journal.sha256}
        }
        MeasureBlocked = { param($c) $called.Add('blocked'); $reference.phases[1] }
        StartColdProbe = { param($c)
            $called.Add('cold')
            $reference.phases[2].timeline.launchTick = [Diagnostics.Stopwatch]::GetTimestamp()
            $reference.phases[2].timeline.firstProbe = [Diagnostics.Stopwatch]::GetTimestamp()
            $reference.phases[2].timeline.observedTick = [Diagnostics.Stopwatch]::GetTimestamp()
            $reference.phases[2]
        }
        DrainA = { param($c) $called.Add('drain'); @{workloadsExited=($Fault -ne 'drain')} }
        RunIndependentRollback = { param($c)
            $called.Add('rollback')
            $independent = Open-N4RecoveryLease $work
            try { @{listedObjectsAbsent=($Fault -ne 'rollback')} } finally { $independent.Dispose() }
        }
        MeasureRestored = { param($c) $called.Add('restored'); $reference.phases[3] }
        StopObservation = { param($c)
            $called.Add('stop')
            New-N4OfflineDnsObservation $reference.phases[2].timeline.firstProbe $Fault
        }
        FinishRecovery = { param($c,$safe)
            if ($safe -ne ($Fault -notin 'drain','rollback')) { throw 'Recovery watcher disarm differs from confirmed rule removal' }
        }
    }
    $reviewed = [Text.Encoding]::UTF8.GetBytes((($manifest | ConvertTo-Json -Depth 8)+[Environment]::NewLine))
    $digest = Get-N4ByteDigest $reviewed
    $result = Invoke-N4MatchStage $work $null $workers $reviewed $digest
    $retained = Test-Path -LiteralPath (Join-Path $work 'recovery.json') -PathType Leaf
    if (!$retained -or $result.recovery -cne $digest) { throw 'Offline reviewed journal not retained byte for byte' }
    $paths = @('recovery.json','recovery.lease' | ForEach-Object { Join-Path $work $_ })
    foreach ($path in $paths) { Remove-Item -LiteralPath $path }
    Remove-Item -LiteralPath $work
    return @{ result=$result; calls=($called -join ',') }
}

function New-N4OfflineDnsObservation([long]$ColdTick, [string]$Fault) {
    $prefix = 'studio-0000000000000001'
    $receipts = @()
    $events = @()
    foreach ($profile in @(@{role='host';phase='baseline';pid=14},@{role='ordinary';phase='baseline';pid=12},
        @{role='psec';phase='baseline';pid=11},@{role='psec';phase='blocked';pid=11},
        @{role='psec';phase='cold';pid=11},@{role='psec';phase='restored';pid=11})) {
        if ($Fault -eq 'dns-missing' -and $profile.role -eq 'psec' -and $profile.phase -eq 'blocked') { continue }
        $queries = @()
        foreach ($api in 'dns','addr') {
            $name = "$prefix-$($profile.role)-$($profile.phase)-$api.test."
            $queries += @{name=$name;api=$(if ($api -eq 'dns') {'DnsQuery_W'} else {'GetAddrInfoW'});
                startedTick=($ColdTick+1);completedTick=($ColdTick+2)}
            if ($profile.role -ne 'psec' -or ($Fault -eq 'dns-leak' -and $profile.phase -eq 'baseline')) {
                $value = @($name,0,'synthetic-dns',$profile.pid)
                $props = @($value | ForEach-Object { @{Value=$_} })
                $events += Convert-LabDnsEvent @{Id=3010;ProcessId=13;Properties=$props} $prefix $true
                $reply = @($props[0..2])+@(@{Value=0},$props[3])
                $events += Convert-LabDnsEvent @{Id=3011;ProcessId=13;Properties=$reply} $prefix $true
            }
        }
        $receipts += @{role=$profile.role;phase=$profile.phase;identity=@{pid=$profile.pid};
            tickFrequency=[Diagnostics.Stopwatch]::Frequency;firstProbeTick=$ColdTick;dnsQueries=$queries}
    }
    if ($Fault -eq 'dns-unknown') {
        $events += Convert-LabDnsEvent @{Id=3010;ProcessId=13;Properties=@(@{Value="$prefix-unplanned.test"})} $prefix $true
    }
    return @{stopped=$true;prefix=$prefix;receipts=$receipts;trace=@{servicePid=13;servicePidAfter=13;stopped=$true;
        lossBeforeStop=@{eventsLost=[uint32]($Fault -eq 'dns-loss');logBuffersLost=[uint32]0;realtimeBuffersLost=[uint32]0};events=$events}}
}

function New-N4OfflineManifest([string]$Run, $Reference) {
    @{schema='studio-n4-account-recovery-v1';run=$Run;segment='M';accountSid=$Reference.accountSid;hostSid=$Reference.hostSid;
        librarySha256=('A'*64);controllerSha256=('F'*64);account=@{sublayer=[guid]::NewGuid().ToString();weight=40;
            keys=@(1..4 | ForEach-Object { [guid]::NewGuid().ToString() })};exceptionKeys=@()}
}

function Test-N4CrashedLeaseOwner {
    $run = [guid]::NewGuid().ToString('N')
    $work = Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype')) ("ClaudeStudioN4Account-$run")
    [void][IO.Directory]::CreateDirectory($work)
    $leasePath = Join-Path $work 'recovery.lease'
    [IO.File]::WriteAllBytes($leasePath,[byte[]]@())
    $lease = Open-N4RecoveryLease $work
    try { $journal = Write-N4RecoveryJournal (New-N4OfflineManifest $run (New-SyntheticAccountReport)) $run $lease }
    finally { $lease.Dispose() }
    $literal = "'"+$leasePath.Replace("'","''")+"'"
    $script = '[IO.FileStream]$held=[IO.File]::Open('+$literal+',''Open'',''ReadWrite'',''None''); '+
        'try { [Console]::WriteLine(''ready''); [Console]::Out.Flush(); Start-Sleep -Seconds 15 } finally { $held.Dispose() }'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $settings = [Diagnostics.ProcessStartInfo]::new($shell,('-NoProfile -NonInteractive -EncodedCommand '+$encoded))
    $settings.UseShellExecute = $false
    $settings.CreateNoWindow = $true
    $settings.RedirectStandardOutput = $true
    $owner = [Diagnostics.Process]::Start($settings)
    try {
        $ready = $owner.StandardOutput.ReadLineAsync()
        if (!$ready.Wait(4000) -or $ready.Result -cne 'ready' -or $owner.HasExited) { throw 'Independent lock holder was not ready' }
        try { $collision = Open-N4RecoveryLease $work; $collision.Dispose(); throw 'Recovery acquired an active owner''s lease' }
        catch [IO.IOException] {}
        $owner.Kill()
        if (!$owner.WaitForExit(4000)) { throw 'Synthetic lease owner did not exit' }
        $recovery = Open-N4RecoveryLease $work
        try {
            if ((Get-FileHash -LiteralPath $journal.path).Hash -cne $journal.sha256) { throw 'Crash lost the recovery journal' }
        } finally { $recovery.Dispose() }
    } finally {
        if (!$owner.HasExited) { $owner.Kill(); [void]$owner.WaitForExit(4000) }
        $owner.Dispose()
        Remove-Item -LiteralPath $journal.path,$leasePath
        Remove-Item -LiteralPath $work
    }
    return $true
}

$expected = [ordered]@{
    none='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,restored,stop';
    baseline='arm,observe,baseline,drain,stop';
    readback='arm,observe,baseline,write,read,drain,rollback,restored,stop';
    'late-readback'='arm,observe,baseline,write,read,blocked,read,drain,rollback,restored,stop';
    'write-receipt'='arm,observe,baseline,write,drain,rollback,restored,stop';
    drain='arm,observe,baseline,write,read,blocked,read,cold,drain,stop';
    rollback='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,stop';
    'dns-loss'='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,restored,stop';
    'dns-unknown'='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,restored,stop';
    'dns-leak'='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,restored,stop';
    'dns-missing'='arm,observe,baseline,write,read,blocked,read,cold,drain,rollback,restored,stop'
}
foreach ($case in $expected.Keys) {
    $exercise = Invoke-OfflineMatchCase $case
    if ($exercise.calls -cne $expected[$case] -or
        ($exercise.result.assessment.outcome -ceq 'passed-account-match-m') -ne ($case -eq 'none')) {
        throw ('Unsafe M control flow for '+$case+' -> '+$exercise.calls+' ('+($exercise.result.errors -join ', ')+')')
    }
}
$legacy = Convert-LabDnsEvent @{Id=3011;ProcessId=2;Properties=@(@{Value='studio-0000000000000001-a-dns-cold1.test.'},
    @{Value=0},@{Value='synthetic-dns'},@{Value=0},@{Value=3})} 'studio-0000000000000001' $false
if ($legacy.profile -cne 'A' -or $legacy.phase -cne 'cold1' -or $legacy.probe -cne 'dns' -or $legacy.clientPid -ne 3) {
    throw 'Legacy DNS event extraction changed'
}
[ordered]@{mode='offline-m-orchestration';positive=1;faultScenarios=($expected.Count-1);realFileLease=$true;
    crashedOwnerLeaseReleased=(Test-N4CrashedLeaseOwner);legacyDnsEvent=$true;wfpWrites=0;accountLaunches=0}
