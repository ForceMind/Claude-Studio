[CmdletBinding(DefaultParameterSetName='Test', SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory,ParameterSetName='Library')][switch]$FunctionsOnly,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest,
    [Parameter(Mandatory,ParameterSetName='Recovery')][switch]$Rollback,
    [Parameter(Mandatory,ParameterSetName='Watch')][switch]$Watch,
    [Parameter(Mandatory,ParameterSetName='ProxyOwner')][switch]$ProxyOwner,
    [Parameter(Mandatory,ParameterSetName='ProxyOwner')][ValidateRange(1,4)][int]$Generation,
    [Parameter(Mandatory,ParameterSetName='ProxyOwner')][ValidatePattern('^[A-F0-9]{64}$')][string]$RequestSha256,
    [Parameter(Mandatory,ParameterSetName='Watch')][ValidateRange(1,2147483647)][int]$OwnerPid,
    [Parameter(Mandatory,ParameterSetName='Watch')][long]$OwnerStartTicks,
    [Parameter(Mandatory,ParameterSetName='Recovery')][Parameter(Mandatory,ParameterSetName='Watch')][Parameter(Mandatory,ParameterSetName='ProxyOwner')][string]$Directory,
    [Parameter(Mandatory,ParameterSetName='Recovery')][Parameter(Mandatory,ParameterSetName='Watch')][Parameter(Mandatory,ParameterSetName='ProxyOwner')]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ManifestSha256
)
$ErrorActionPreference = 'Stop'

function Read-ExactKeys($Values, [int]$Count, [Collections.Generic.HashSet[guid]]$Used) {
    if (@($Values).Count -ne $Count) { throw 'Wrong recovery GUID count' }
    foreach ($value in $Values) {
        $key = [guid]::Empty
        if ($value -isnot [string] -or ![guid]::TryParseExact($value,'D',[ref]$key) -or !$Used.Add($key)) {
            throw 'Empty, invalid or duplicate recovery GUID'
        }
        $key
    }
}

function Read-ExactUInt16($Value, [int]$Minimum, [int]$Maximum) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) {
        throw 'Unexpected numeric recovery parameter'
    }
    return [uint16]$Value
}

function Read-RecoveryPlan($Value, [string]$Run) {
    if ($Value.schema -cne 'studio-n4-account-recovery-v1' -or $Value.run -cne $Run -or
        $Run -cnotmatch '^[a-f0-9]{32}$' -or $Value.segment -cnotin 'M','F','X' -or
        $Value.librarySha256 -cnotmatch '^[A-F0-9]{64}$' -or $Value.controllerSha256 -cnotmatch '^[A-F0-9]{64}$' -or
        $Value.accountSid -cnotmatch '^S-1-5-21(-[0-9]+){4}$' -or $Value.hostSid -cnotmatch '^S-1-5-21(-[0-9]+){4}$' -or
        $Value.accountSid -ceq $Value.hostSid) { throw 'Invalid N4 recovery manifest' }
    $used = [Collections.Generic.HashSet[guid]]::new()
    [void]$used.Add([guid]::Empty)
    $accountLayer = Read-ExactKeys @($Value.account.sublayer) 1 $used
    $accountKeys = [guid[]]@(Read-ExactKeys $Value.account.keys 4 $used)
    $accountWeight = Read-ExactUInt16 $Value.account.weight 1 65535
    $keys = [guid[]]@()
    $bindLayer = [guid]::Empty
    $bindKeys = $null
    $ports = $null
    [uint16]$bindWeight = 0
    if ($Value.segment -eq 'M') {
        if ($null -ne $Value.binding -or @($Value.exceptionKeys).Count) { throw 'M cannot own proxy filters' }
    } else {
        $bindLayer = Read-ExactKeys @($Value.binding.sublayer) 1 $used
        $bindKeys = [guid[]]@(Read-ExactKeys $Value.binding.keys 4 $used)
        if (@($Value.binding.ports).Count -ne 2) { throw 'Expected exactly two protected ports' }
        $ports = [uint16[]]@($Value.binding.ports | ForEach-Object { Read-ExactUInt16 $_ 40000 49151 })
        $bindWeight = Read-ExactUInt16 $Value.binding.weight 1 65535
        if ($ports[0] -eq $ports[1] -or $bindWeight -eq $accountWeight) { throw 'Duplicate protected port or sublayer weight' }
        $keys = [guid[]]@(Read-ExactKeys $Value.exceptionKeys $(if ($Value.segment -eq 'F') { 4 } else { 1 }) $used)
    }
    return @{ segment=$Value.segment; hostSid=$Value.hostSid; userSid=$Value.accountSid; dllHash=$Value.librarySha256; controllerHash=$Value.controllerSha256;
        accountLayer=$accountLayer; accountKeys=$accountKeys; accountWeight=$accountWeight;
        bindLayer=$bindLayer; bindKeys=$bindKeys; ports=$ports; bindWeight=$bindWeight; exceptionKeys=$keys }
}

function Assert-RecoveryAcl([string]$Path, [bool]$Private, [bool]$Container) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Container -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Unexpected recovery path or reparse point'
    }
    $acl = Get-Acl -LiteralPath $item.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        ($Private -and $Container -and !$acl.AreAccessRulesProtected)) {
        throw 'Recovery path ownership or inheritance is untrusted'
    }
    $writeMask = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin $trusted -and
            ($Private -or ($ace.FileSystemRights -band $writeMask))) { throw 'Recovery ACL grants access outside the trusted identities' }
    }
    return $item
}

function Test-RecoveryPidExists([int]$ProcessId) {
    try { $live = [Diagnostics.Process]::GetProcessById($ProcessId) }
    catch [ArgumentException] { return $false }
    try { return $true } finally { $live.Dispose() }
}

function Assert-NoRecoveryWorkload($Plan, [string]$PrivateRoot) {
    # Known PIDs alone cannot prove the launcher did not start a child before dying.
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $processes = @(Get-CimInstance Win32_Process -OperationTimeoutSec 8)
    if (!$processes.Count) { throw 'Empty process inventory; preserve N4 default deny' }
    foreach ($process in $processes) {
        if ($watch.Elapsed.TotalSeconds -ge 25) { throw 'Process inventory deadline expired; preserve N4 default deny' }
        if ($process.ProcessId -in 0,4) { continue }
        if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($PrivateRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw 'An executable from the recovery directory is still active'
        }
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -OperationTimeoutSec 5
        } catch {
            if (Test-RecoveryPidExists $process.ProcessId) { throw }
            continue
        }
        if ($owner.ReturnValue -ne 0 -or !$owner.Sid) {
            if (Test-RecoveryPidExists $process.ProcessId) {
                throw ('Process ownership unresolved; preserve N4 default deny. PID '+$process.ProcessId)
            }
            continue
        }
        if ($owner.Sid -ceq $Plan.userSid) { throw 'A still has a live process; preserve N4 default deny' }
    }

    if ($Plan.ports) {
        $ip = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $occupied = @($ip.GetActiveTcpListeners() | ForEach-Object Port)
        $occupied += @($ip.GetActiveTcpConnections() | Where-Object State -ne 'TimeWait' | ForEach-Object { $_.LocalEndPoint.Port })
        if (@($Plan.ports | Where-Object { $_ -in $occupied }).Count) { throw 'A protected port still has a live socket' }
    }
}

function Open-N4RecoveryLease([string]$Directory) {
    return [IO.File]::Open((Join-Path $Directory 'recovery.lease'),'Open','ReadWrite','None')
}

function Open-N4RecoveryOwner([int]$ProcessId, [long]$StartTicks) {
    if ($ProcessId -eq $PID -or $StartTicks -le 0) { throw 'Invalid N4 watchdog owner claim' }
    $owner = [Diagnostics.Process]::GetProcessById($ProcessId)
    try {
        [void]$owner.Handle
        if ($owner.HasExited -or $owner.StartTime.ToUniversalTime().Ticks -ne $StartTicks) {
            throw 'N4 watchdog owner no longer matches the starting process'
        }
        return $owner
    } catch { $owner.Dispose(); throw }
}

function Wait-N4RecoveryOwnerExit([Diagnostics.Process]$Owner, [int]$DeadlineMs) {
    if (!$Owner.WaitForExit($DeadlineMs)) { throw 'N4 owner is still active at the watchdog deadline' }
}

function Invoke-N4ProxyOwnerLifecycle([hashtable]$Ops,[int]$ArmMilliseconds=8000,[int]$LifetimeMilliseconds=120000) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $active=$false
    $reason='closed'
    try {
        & $Ops.Emit 'ready'
        while (& $Ops.Live) {
            if ($timer.ElapsedMilliseconds -ge $(if ($active) {$LifetimeMilliseconds} else {$ArmMilliseconds})) {
                $reason='deadline'
                break
            }
            if ($active -and !(& $Ops.Healthy)) { $reason='entry-unhealthy'; break }
            $command=& $Ops.Command
            if ($null -eq $command) { continue }
            if ($command -ceq 'close' -or $command -ceq 'eof') { $reason=$command; break }
            if ($command -cne 'open' -or $active) { throw 'Unexpected N4 exception owner command' }
            if (!(& $Ops.Live) -or !(& $Ops.Healthy)) { throw 'N4 exception owner cannot open without the exact healthy entry' }
            $active=$true # The rule may commit even if readback or the acknowledgement fails.
            & $Ops.Acquire
            if (!(& $Ops.Live) -or !(& $Ops.Healthy)) { throw 'N4 exception owner lost health during open' }
            & $Ops.Emit 'opened'
        }
        if ($reason -ceq 'closed') { $reason='process-exit' }
    } finally {
        if ($active) { & $Ops.Release }
    }
    & $Ops.Emit $reason
    if ($active -and $reason -ceq 'process-exit' -and $Ops.ObserveReleased) {
        & $Ops.ObserveReleased
    }
}

function Receive-N4ProxyCommand([IO.StreamReader]$Reader,[hashtable]$Transport) {
    if (!$Transport.pending) { $Transport.pending=$Reader.ReadLineAsync() }
    if ($Transport.pending.Wait(45)) {
        $line=$Transport.pending.Result
        $Transport.pending=$null
        if ($null -eq $line) { 'eof' } else { $line }
    }
}

function Wait-N4ReleasedProxyOwner([IO.StreamReader]$Reader,[hashtable]$Transport,
    [Diagnostics.Process]$Launcher,[Diagnostics.Process]$Upstream,[int]$Milliseconds=6500) {
    $observe=[Diagnostics.Stopwatch]::StartNew()
    while (!$Launcher.HasExited -and !$Upstream.HasExited -and $observe.ElapsedMilliseconds -lt $Milliseconds) {
        $lastCommand=Receive-N4ProxyCommand $Reader $Transport
        if ($lastCommand -in 'close','eof') { return }
        if ($null -ne $lastCommand) { throw 'A released N4 exception cannot reopen' }
    }
}

function Read-N4EntryPulse([string]$Path,[int]$EntryId,[int]$ExceptionOwnerId,[long]$OwnerTicks) {
    $share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    try {
        $file=Assert-RecoveryAcl $Path $true $false
        $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        try {
            if ($stream.Length -gt 4096) { return }
            $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
            try { $value=$reader.ReadToEnd() | ConvertFrom-Json }
            finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
    } catch [IO.IOException] { return }
    if (($value.publishedTick -isnot [long] -and $value.publishedTick -isnot [int]) -or $value.publishedTick -le 0) { return }
    $age=([Diagnostics.Stopwatch]::GetTimestamp()-$value.publishedTick)*1000.0/[Diagnostics.Stopwatch]::Frequency
    if ($age -ge 0 -and $age -le 1800 -and $value.pid -eq $EntryId -and $value.exceptionOwnerPid -eq $ExceptionOwnerId -and
        $value.exceptionOwnerStartTicks -eq $OwnerTicks -and $value.admitting -is [bool] -and $value.admitting -and
        $value.watching -is [bool] -and $value.watching -and !$value.closeReason -and
        ($value.generation -is [int] -or $value.generation -is [long]) -and $value.generation -ge 1) { return $value }
}

function Assert-N4ProxyOwnerListener([uint16]$Port,[Diagnostics.Process]$Owner) {
    $listeners=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    if ($Owner.HasExited -or $listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1' -or
        $listeners[0].OwningProcess -ne $Owner.Id) { throw 'Reviewed N4 relay does not own its exact loopback listener' }
}

if ($FunctionsOnly) { return }

if ($Rollback -or $Watch -or $ProxyOwner) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'N4 staged control requires an elevated host token'
    }
    $trusted = @($identity.User.Value,'S-1-5-18','S-1-5-32-544')
    $root = Assert-RecoveryAcl $Directory $true $true
    $base = [IO.Path]::GetTempPath().TrimEnd('\')
    if ($root.Name -cnotmatch '^ClaudeStudioN4Account-([a-f0-9]{32})$' -or $root.Parent.FullName -ine $base -or
        $PSScriptRoot -ine $root.FullName) { throw 'Expected the staged controller inside its protected host TEMP run directory' }
    $run = $Matches[1]
    for ($ancestor = $root.Parent; $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Recovery ancestor is a reparse point' }
    }
    $null = Assert-RecoveryAcl $base $false $true
    $null = Assert-RecoveryAcl $PSCommandPath $true $false
    $leaseFile = Assert-RecoveryAcl (Join-Path $root.FullName 'recovery.lease') $true $false
    $manifest = Assert-RecoveryAcl (Join-Path $root.FullName 'recovery.json') $true $false
    $library = Assert-RecoveryAcl (Join-Path $root.FullName 'N4AccountGuard.dll') $true $false
    if ($ProxyOwner) {
        if ((Get-FileHash -LiteralPath $manifest.FullName).Hash -cne $ManifestSha256) { throw 'N4 exception journal hash differs' }
        $reviewed=Get-Content -LiteralPath $manifest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $plan=Read-RecoveryPlan $reviewed $run
        if ($plan.segment -cnotin 'F','X' -or $Generation -gt $plan.exceptionKeys.Count -or
            $identity.User.Value -cne $plan.hostSid -or (Get-LocalUser -Name ClaudeStudioLabA).SID.Value -cne $plan.userSid -or
            (Get-FileHash -LiteralPath $library.FullName).Hash -cne $plan.dllHash -or
            (Get-FileHash -LiteralPath $PSCommandPath).Hash -cne $plan.controllerHash) { throw 'N4 exception stage, host, A or staged file differs' }
        $requestFile=Assert-RecoveryAcl (Join-Path $root.FullName ('proxy-owner-'+$plan.segment+'-'+$Generation+'.json')) $true $false
        if ($requestFile.Length -gt 8192 -or (Get-FileHash -LiteralPath $requestFile.FullName).Hash -cne $RequestSha256) {
            throw 'N4 exception request hash differs'
        }
        $request=Get-Content -LiteralPath $requestFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($request.run -cne $run -or $request.segment -cne $plan.segment -or $request.generation -ne $Generation -or
            $request.journalSha256 -cne $ManifestSha256 -or $request.containerSid -cnotmatch '^S-1-15-2(-[0-9]+){7}$') {
            throw 'N4 exception request differs from the approved stage'
        }
        try {
            $unexpectedLease=Open-N4RecoveryLease $root.FullName
            $unexpectedLease.Dispose()
            throw 'N4 exception requires an active launcher lease'
        } catch [IO.IOException] {
            if (($_.Exception.HResult -band 0xffff) -ne 32) { throw }
        }
        $topology=Assert-RecoveryAcl (Join-Path $root.FullName ('proxy-'+$plan.segment)) $true $true
        $relay=Assert-RecoveryAcl (Join-Path $topology.FullName 'StudioN3Relay.exe') $true $false
        $fixtureRoot=Assert-RecoveryAcl (Join-Path $root.FullName 'fixtures') $false $true
        $fixture=Assert-RecoveryAcl (Join-Path $fixtureRoot.FullName 'StudioProbe.exe') $false $false
        if ((Get-FileHash -LiteralPath $relay.FullName).Hash -cne $reviewed.fixtures.relaySha256 -or
            (Get-FileHash -LiteralPath $fixture.FullName).Hash -cne $reviewed.fixtures.probeSha256) { throw 'N4 proxy or A fixture differs' }
        $handles=@{}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        $inputReader=$null
        try {
            foreach ($role in 'launcher','entry','upstream','probe') {
                $claim=$request.$role
                if (($claim.pid -isnot [int] -and $claim.pid -isnot [long]) -or $claim.pid -lt 1 -or $claim.pid -gt [int]::MaxValue -or
                    ($claim.startTicks -isnot [long] -and $claim.startTicks -isnot [int])) { throw 'Invalid N4 live process claim' }
                $handles[$role]=Open-N4RecoveryOwner $claim.pid $claim.startTicks
            }
            if (@($handles.Values.Id | Select-Object -Unique).Count -ne 4 -or
                $handles.entry.MainModule.FileName -ine $relay.FullName -or $handles.upstream.MainModule.FileName -ine $relay.FullName) {
                throw 'N4 worker identities or relay image differ'
            }
            if (!('StudioLabWfp' -as [type])) { Add-Type -Path $library.FullName }
            if ([StudioLabWfp].Assembly.Location -ine $library.FullName) { throw 'N4 exception DLL is outside the review' }
            $parents=[StudioLabWfp]::ReadAccountProcessParents()
            if ($parents[$PID] -ne $handles.launcher.Id -or $parents[$handles.entry.Id] -ne $handles.launcher.Id -or
                $parents[$handles.upstream.Id] -ne $handles.launcher.Id) { throw 'N4 launcher and relay lineage differ' }
            [StudioLabWfp]::ValidateAccountProbe($handles.probe,$request.probe.startTicks,$handles.launcher.SessionId,
                $fixture.FullName,$plan.userSid,$request.containerSid)
            Assert-N4ProxyOwnerListener $plan.ports[0] $handles.entry
            Assert-N4ProxyOwnerListener $plan.ports[1] $handles.upstream
            $key=$plan.exceptionKeys[$Generation-1]
            $spec=[StudioLabWfp+AccountGuardSpec]::new($plan.userSid,$request.containerSid,$plan.accountLayer,
                [guid[]]($plan.accountKeys+@($key)),$plan.accountWeight,$plan.ports[0])
            [StudioLabWfp]::VerifyBoundAccountProxy($spec,$plan.bindLayer,$plan.bindKeys,$plan.ports,$plan.bindWeight,$false)
            $pulsePath=Join-Path $topology.FullName 'n3-entry-state.json'
            $selfTicks=$self.StartTime.ToUniversalTime().Ticks
            $inputReader=[IO.StreamReader]::new([Console]::OpenStandardInput())
            $worker=@{guard=$null;pending=$null;healthGeneration=$null}
            $ops=@{
                Emit={param($eventName)
                    $row=@{event=$eventName;run=$run;segment=$plan.segment;generation=$Generation;key=$key;
                        pid=$PID;startTicks=$selfTicks;journalSha256=$ManifestSha256;requestSha256=$RequestSha256}
                    [Console]::WriteLine('N4-EXCEPTION:'+($row | ConvertTo-Json -Compress))
                    [Console]::Out.Flush()
                }
                Live={ @($handles.Values | Where-Object {$_.HasExited}).Count -eq 0 }
                Command={ Receive-N4ProxyCommand $inputReader $worker }
                Healthy={
                    $pulse=Read-N4EntryPulse $pulsePath $handles.entry.Id $PID $selfTicks
                    if (!$pulse) { return $false }
                    if ($null -eq $worker.healthGeneration) { $worker.healthGeneration=$pulse.generation }
                    return $pulse.generation -eq $worker.healthGeneration
                }
                Acquire={
                    $worker.guard=[StudioLabWfp]::CreateStaticExceptionGuard()
                    $worker.guard.OpenAccountProxy($spec,$plan.bindLayer,$plan.bindKeys,$plan.ports,$plan.bindWeight)
                    [StudioLabWfp]::VerifyBoundAccountProxy($spec,$plan.bindLayer,$plan.bindKeys,$plan.ports,$plan.bindWeight,$true)
                }
                Release={
                    if ($worker.guard) { $worker.guard.Dispose();$worker.guard=$null }
                    [StudioLabWfp]::VerifyBoundAccountProxy($spec,$plan.bindLayer,$plan.bindKeys,$plan.ports,$plan.bindWeight,$false)
                }
            }
            if ($plan.segment -ceq 'X') {
                $ops.ObserveReleased={
                    # The observer needs a surviving manager after entry exit to distinguish explicit
                    # session close from implicit rollback caused by termination of this process.
                    if (!$handles.entry.HasExited) { return }
                    Wait-N4ReleasedProxyOwner $inputReader $worker $handles.launcher $handles.upstream
                }
            }
            if (!$PSCmdlet.ShouldProcess($root.Name, 'Own the exact reviewed N4 dynamic exception')) { return }
            Invoke-N4ProxyOwnerLifecycle $ops
        } finally {
            if ($inputReader) { $inputReader.Dispose() }
            foreach ($handle in $handles.Values) { $handle.Dispose() }
            $self.Dispose()
        }
        return
    }
    if ($Watch) {
        if ((Get-FileHash -LiteralPath $manifest.FullName).Hash -ine $ManifestSha256) { throw 'Watchdog recovery manifest hash differs' }
        $watchPlan = Read-RecoveryPlan (Get-Content -LiteralPath $manifest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) $run
        if ($identity.User.Value -cne $watchPlan.hostSid -or (Get-LocalUser -Name ClaudeStudioLabA).SID.Value -cne $watchPlan.userSid -or
            (Get-FileHash -LiteralPath $library.FullName).Hash -cne $watchPlan.dllHash -or
            (Get-FileHash -LiteralPath $PSCommandPath).Hash -cne $watchPlan.controllerHash) { throw 'Watchdog host, A or staged files differ' }
        $owner = Open-N4RecoveryOwner $OwnerPid $OwnerStartTicks
        try {
            $ready = @{ready=$true;watcherPid=$PID;ownerPid=$owner.Id;ownerStartTicks=$OwnerStartTicks;journalSha256=$ManifestSha256.ToUpperInvariant()}
            [Console]::WriteLine('N4-WATCH:'+($ready | ConvertTo-Json -Compress))
            [Console]::Out.Flush()
            Wait-N4RecoveryOwnerExit $owner 420000
        } finally { $owner.Dispose() }
    }
    # The launcher must retain the same lease until its work and socket owners have stopped.
    $lease = Open-N4RecoveryLease $root.FullName
    try {
        if ((Get-FileHash -LiteralPath $manifest.FullName).Hash -ine $ManifestSha256) { throw 'Recovery manifest hash differs' }
        $plan = Read-RecoveryPlan (Get-Content -LiteralPath $manifest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) $run
        if ($identity.User.Value -cne $plan.hostSid -or (Get-LocalUser -Name ClaudeStudioLabA).SID.Value -cne $plan.userSid -or
            (Get-FileHash -LiteralPath $library.FullName).Hash -cne $plan.dllHash -or
            (Get-FileHash -LiteralPath $PSCommandPath).Hash -cne $plan.controllerHash) { throw 'Recovery host, test account, script or DLL differs' }
        if (!$PSCmdlet.ShouldProcess($root.Name, 'Remove this segment''s exact WFP objects')) { return }
        Assert-NoRecoveryWorkload $plan $root.FullName
        Add-Type -Path $library.FullName
        $spec = [StudioLabWfp+AccountGuardSpec]::new($plan.userSid,'',$plan.accountLayer,$plan.accountKeys,$plan.accountWeight,0)
        [StudioLabWfp]::RemoveAccountStage($spec,$plan.exceptionKeys,$plan.bindLayer,$plan.bindKeys,$plan.ports,$plan.bindWeight)
        [ordered]@{ segment=$plan.segment; listedObjectsAbsent=$true; recoveryDirectoryRetained=$true }
    } finally { $lease.Dispose() }
    return
}

function New-LocalRecoveryFixture([string]$Segment) {
    $keys = @((1..14) | ForEach-Object { [guid]::NewGuid().ToString() })
    $fixture = [ordered]@{ schema='studio-n4-account-recovery-v1'; segment=$Segment; run=('b'*32);
        accountSid='S-1-5-21-1-2-3-1001'; hostSid='S-1-5-21-1-2-3-1002'; librarySha256=('A'*64); controllerSha256=('F'*64);
        account=@{sublayer=$keys[0];keys=@($keys[1..4]);weight=40}; binding=$null; exceptionKeys=@() }
    if ($Segment -ne 'M') {
        $fixture.binding = @{sublayer=$keys[5];keys=@($keys[6..9]);ports=@(44000,44100);weight=41}
        $fixture.exceptionKeys = if ($Segment -eq 'F') { @($keys[10..13]) } else { ,$keys[10] }
    }
    return $fixture
}

foreach ($segment in 'M','F','X') {
    $fixture = New-LocalRecoveryFixture $segment
    $parsed = Read-RecoveryPlan ($fixture | ConvertTo-Json -Depth 7 | ConvertFrom-Json) $fixture.run
    if ($parsed.segment -cne $segment -or $parsed.accountKeys.Count -ne 4) { throw 'Recovery control failed its JSON roundtrip' }
}
$changes = @(
    { param($v) $v.hostSid=$v.accountSid },
    { param($v) $v.binding.keys[0]=$v.account.keys[0] },
    { param($v) $v.binding.ports[1]=10810 },
    { param($v) $v.binding.ports[1]=$v.binding.ports[0] },
    { param($v) $v.binding.weight=$v.account.weight },
    { param($v) $v.exceptionKeys[0]=$v.binding.sublayer },
    { param($v) $v.exceptionKeys=@($v.exceptionKeys[0]) },
    { param($v) $v.segment='M' },
    { param($v) $v.account.weight='40' },
    { param($v) $v.run=('c'*32) },
    { param($v) $v.Remove('controllerSha256') }
)
foreach ($change in $changes) {
    $fixture = New-LocalRecoveryFixture 'F'
    & $change $fixture
    $rejected = $false
    try { $null = Read-RecoveryPlan ($fixture | ConvertTo-Json -Depth 7 | ConvertFrom-Json) ('b'*32) }
    catch { $rejected = $true }
    if (!$rejected) { throw ('Unsafe recovery manifest was accepted: '+$change.ToString()) }
}

function Test-N4ProxyOwnerLifecycle([string]$Scenario,[string]$Expected) {
    $trace=[Collections.Generic.List[string]]::new()
    $state=@{requests=0;acquired=$false;released=$false;healthy=$true}
    $ops=@{
        Emit={param($eventName) $trace.Add($eventName)}
        Live={ $Scenario -ne 'dead-after-open' -or !$state.acquired }
        Command={
            $state.requests++
            if ($state.requests -eq 1) { if ($Scenario -ne 'arm-deadline') {'open'} }
            elseif ($Scenario -ceq 'duplicate-open') {'open'}
            elseif ($Scenario -ceq 'eof') {'eof'}
            else {'close'}
        }
        Healthy={ $Scenario -ne 'unarmed' -and $state.healthy }
        Acquire={
            $trace.Add('acquire')
            $state.acquired=$true
            if ($Scenario -ceq 'readback-lost') { throw 'simulated readback failure' }
        }
        Release={ $trace.Add('release');$state.released=$true }
    }
    if ($Scenario -ceq 'stale-after-open') {
        $ops.Emit={param($eventName)
            $trace.Add($eventName)
            if ($eventName -ceq 'opened') { $state.healthy=$false }
        }
    }
    if ($Scenario -ceq 'observe-released') {
        $ops.Live={ $state.requests -lt 2 }
        $ops.Command={ $state.requests++; if ($state.requests -eq 1) { 'open' } }
        $ops.ObserveReleased={ if (!$state.released) { throw 'Observation began before release' }; $trace.Add('observe') }
    }
    try { Invoke-N4ProxyOwnerLifecycle $ops $(if ($Scenario -ceq 'arm-deadline') {0} else {8000}) }
    catch { $trace.Add($_.Exception.Message) }
    if (($trace -join ',') -cne $Expected -or ($state.acquired -ne $state.released)) {
        throw "Unexpected exception lifecycle for ${Scenario}: $($trace -join ',')"
    }
}

$proxyCases=[ordered]@{
    'close'='ready,acquire,opened,release,close'
    'eof'='ready,acquire,opened,release,eof'
    'dead-after-open'='ready,acquire,release,N4 exception owner lost health during open'
    'stale-after-open'='ready,acquire,opened,release,entry-unhealthy'
    'readback-lost'='ready,acquire,release,simulated readback failure'
    'duplicate-open'='ready,acquire,opened,release,Unexpected N4 exception owner command'
    'unarmed'='ready,N4 exception owner cannot open without the exact healthy entry'
    'arm-deadline'='ready,deadline'
    'observe-released'='ready,acquire,opened,release,process-exit,observe'
}
foreach ($case in $proxyCases.GetEnumerator()) { Test-N4ProxyOwnerLifecycle $case.Key $case.Value }
[ordered]@{ mode='offline-recovery-selftest'; positive=3; rejected=$changes.Count; exceptionLifecycleCases=$proxyCases.Count; systemWrites=0 }
