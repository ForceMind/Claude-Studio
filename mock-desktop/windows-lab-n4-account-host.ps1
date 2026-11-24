[CmdletBinding(DefaultParameterSetName='Test')]
param(
    [Parameter(Mandatory,ParameterSetName='Library')][switch]$FunctionsOnly,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$loadN4HostOnly = [bool]$FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n4-account-run.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')

function Close-N4MatchCanaries($State) {
    if (!$State) { return }
    Close-GatePair $State.hostOld
    if ($State.hostListener) { $State.hostListener.Dispose() }
    if ($State.udp) { $State.udp.Dispose() }
    if ($State.tcp) { $State.tcp.Stop() }
}

function New-N4MatchCanaries {
    $state = @{tcp=$null;udp=$null;hostListener=$null;hostOld=$null;oldId=[guid]::NewGuid().ToString('N');endpoints=$null}
    try {
        $local = [Net.IPAddress]::Loopback
        $state.tcp = [Net.Sockets.TcpListener]::new($local,0)
        $state.tcp.ExclusiveAddressUse = $true
        $state.tcp.Start(8)
        $state.udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $state.udp.ExclusiveAddressUse = $true
        $state.udp.Client.Bind([Net.IPEndPoint]::new($local,0))
        $state.hostListener = New-GateSocket
        $state.hostListener.ExclusiveAddressUse = $true
        $state.hostListener.Bind([Net.IPEndPoint]::new($local,0))
        $state.hostListener.Listen(8)
        $state.hostOld = Open-GatePair $state.hostListener
        $ports = @($state.tcp.LocalEndpoint.Port,$state.udp.Client.LocalEndPoint.Port,$state.hostListener.LocalEndPoint.Port)
        if (@($ports | Select-Object -Unique).Count -ne 3 -or @($ports | Where-Object { $_ -lt 40000 }).Count) {
            throw 'Kernel selected overlapping or out-of-scope canary ports'
        }
        $state.endpoints = @{tcp=$state.tcp.LocalEndpoint.ToString();udp=$state.udp.Client.LocalEndPoint.ToString();
            host=$state.hostListener.LocalEndPoint.ToString();tcpPort=$ports[0];udpPort=$ports[1]}
        return $state
    } catch { Close-N4MatchCanaries $state; throw }
}

function Read-N4CanaryHits($State, [string]$Marker) {
    if ($Marker -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid N4 request marker' }
    $count = @{tcp=0;udp=0}
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
    if ($State.tcp.Pending()) {
        $socket = $State.tcp.AcceptSocket()
        try {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $packet = [byte[]]::new(32)
            $filled = 0
            while ($filled -lt $packet.Length) {
                $left = 500-[int]$watch.ElapsedMilliseconds
                if ($left -le 0) { throw 'N4 TCP marker deadline expired' }
                $socket.ReceiveTimeout = $left
                $got = $socket.Receive($packet,$filled,$packet.Length-$filled,[Net.Sockets.SocketFlags]::None)
                if ($got -le 0) { throw 'Truncated N4 TCP marker' }
                $filled += $got
            }
            if ($socket.Available -or [Text.Encoding]::ASCII.GetString($packet) -cne $Marker) { throw 'Unexpected N4 TCP canary traffic' }
            $count.tcp = 1
        } finally { $socket.Dispose() }
    }
    if ($State.udp.Available) {
        $packet = $State.udp.Receive([ref]$remote)
        if ([Text.Encoding]::ASCII.GetString($packet) -cne $Marker) { throw 'Unexpected N4 UDP canary traffic' }
        $count.udp = 1
    }
    if ($State.tcp.Pending() -or $State.udp.Available) { throw 'Extra N4 canary traffic' }
    return @{tcp=@{endpoint=$State.endpoints.tcp;sent=1;hits=$count.tcp;completed=$true};
        udp=@{endpoint=$State.endpoints.udp;sent=1;hits=$count.udp;completed=$true}}
}

function Read-N4HostFlows($State, [byte]$Marker) {
    $fresh = Open-GatePair $State.hostListener
    try {
        return @{oldConnection=$State.oldId;oldMarker=(Send-GateMarker $State.hostOld $Marker);newMarker=(Send-GateMarker $fresh $Marker)}
    } finally { Close-GatePair $fresh }
}

function Open-N4ValidatedProbeProcess($Receipt, [string]$AccountSid, [string]$ExpectedPath, [int]$Session) {
    if ($Receipt.role -cnotin 'ordinary','psec' -or $Receipt.identity.session -ne $Session -or
        !(Test-AccountIdentity $Receipt.identity $AccountSid ($Receipt.role -ceq 'psec')) -or
        ![IO.Path]::IsPathRooted($ExpectedPath)) { throw 'N4 probe claim does not match the staged role or session' }
    $entry = $Receipt.identity
    $process = [Diagnostics.Process]::GetProcessById($entry.pid)
    try {
        [StudioLabWfp]::ValidateAccountProbe($process,$entry.startTicks,$Session,$ExpectedPath,$AccountSid,$entry.containerSid)
        return @{process=$process;pid=$process.Id;creationUtc=$process.StartTime.ToUniversalTime();observedTick=[Diagnostics.Stopwatch]::GetTimestamp()}
    } catch { $process.Dispose(); throw }
}

function Assert-N4ProbeLineage([Diagnostics.Process]$Launcher, [Diagnostics.Process]$Probe, [string]$ExecutorPath) {
    [void]$Launcher.Handle
    [void]$Probe.Handle
    $parents = [StudioLabWfp]::ReadAccountProcessParents()
    if (!$parents.ContainsKey($Probe.Id)) { throw 'N4 probe missing from the process snapshot' }
    $parentId = $parents[$Probe.Id]
    $intermediate = $null
    try {
        if ($ExecutorPath) {
            if (!$parents.ContainsKey($parentId) -or $parents[$parentId] -ne $Launcher.Id) { throw 'N4 executor is outside the launcher lineage' }
            $intermediate = [Diagnostics.Process]::GetProcessById($parentId)
            [void]$intermediate.Handle
            if ($intermediate.HasExited -or $intermediate.MainModule.FileName -ine $ExecutorPath -or
                $intermediate.SessionId -ne $Launcher.SessionId -or $intermediate.StartTime -lt $Launcher.StartTime -or
                $intermediate.StartTime -gt $Probe.StartTime) { throw 'N4 executor identity or creation order differs' }
        } elseif ($parentId -ne $Launcher.Id) { throw 'N4 probe is outside the launcher lineage' }
        if ($Probe.HasExited -or $Launcher.HasExited -or $Probe.SessionId -ne $Launcher.SessionId -or $Probe.StartTime -lt $Launcher.StartTime) {
            throw 'N4 lineage contains a stale process or different session'
        }
        return @{verified=$true;rootPid=$Launcher.Id;probePid=$Probe.Id;intermediatePid=$(if ($intermediate) { $intermediate.Id })}
    } finally { if ($intermediate) { $intermediate.Dispose() } }
}

function New-N4MatchProbeInvocation([string]$Fixtures, [string]$Prefix, [string]$Role, [string]$Phase,
    [int]$TcpPort, [int]$UdpPort, [string]$Marker) {
    if (![IO.Path]::IsPathRooted($Fixtures) -or [IO.Path]::GetFileName($Fixtures) -cne 'fixtures' -or
        $Fixtures -cne [IO.Path]::GetFullPath($Fixtures) -or $Fixtures -match '["\r\n]' -or
        $Prefix -cnotmatch '^studio-[a-f0-9]{16}$' -or $Role -cnotin 'ordinary','psec','host' -or
        $Phase -cnotmatch '^(baseline|blocked|cold|restored|healthy[1-4]|fault[1-4])$' -or
        ($Phase -ceq 'cold' -and $Role -ceq 'ordinary') -or
        $TcpPort -lt 40000 -or $TcpPort -gt 65535 -or $UdpPort -lt 40000 -or $UdpPort -gt 65535 -or $TcpPort -eq $UdpPort -or
        $Marker -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid N4 probe launch specification' }
    $probe = Join-Path $Fixtures 'StudioProbe.exe'
    $arguments = @('n4-account-match',$Prefix,$Role,$Phase,[string]$TcpPort,[string]$UdpPort,$Marker)
    $spec = @{probe=$probe;arguments=$arguments;marker=$Marker;role=$Role;phase=$Phase;
        tcp="127.0.0.1:$TcpPort";udp="127.0.0.1:$UdpPort";policy=$null}
    if ($Role -ceq 'psec') {
        $spec.policy = [ordered]@{version='1.0.0';containment='processcontainer';
            process=@{commandLine=('"'+$probe+'" '+($arguments -join ' '));cwd=$Fixtures;timeout=20000};
            filesystem=@{readonlyPaths=@($Fixtures)};ui=@{disable=$false};
            network=@{egress=@{default='deny'};ingress=@{default='deny';hostLoopback='allow'}}}
    }
    return $spec
}

function Read-N4ProbeOutput([IO.TextReader]$Output, $Invocation, [long]$StartTick, [int]$DeadlineMs = 18000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $DeadlineMs) {
        $read = $Output.ReadLineAsync()
        if (!$read.Wait([Math]::Max(1,$DeadlineMs-[int]$watch.ElapsedMilliseconds))) { throw 'N4 probe output timed out' }
        $line = $read.Result
        if ($null -eq $line) { throw 'N4 probe exited without its receipt' }
        if (!$line.StartsWith('N4-PROBE:',[StringComparison]::Ordinal)) { continue }
        $receipt = $line.Substring(9) | ConvertFrom-Json
        if ($receipt.role -cne $Invocation.role -or $receipt.phase -cne $Invocation.phase -or
            $receipt.marker -cne $Invocation.marker -or $receipt.tcp.endpoint -cne $Invocation.tcp -or
            $receipt.udp.endpoint -cne $Invocation.udp -or $receipt.firstProbeTick -lt $StartTick -or
            $receipt.firstProbeTick -gt [Diagnostics.Stopwatch]::GetTimestamp() -or
            $receipt.tickFrequency -ne [Diagnostics.Stopwatch]::Frequency) { throw 'N4 probe receipt does not match the current attempt' }
        return $receipt
    }
    throw 'N4 probe receipt deadline expired'
}

function Get-N4FixtureFile([string]$Path, [string]$Digest, [string[]]$HostSids) {
    if ($Digest -cnotmatch '^[A-F0-9]{64}$') { throw 'Missing reviewed fixture digest' }
    $item = Get-Item -LiteralPath $Path
    $acl = Get-Acl -LiteralPath $item.FullName
    $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    if ($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $HostSids -or
        @( $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $HostSids -and ($_.FileSystemRights -band $write)
        }).Count -or (Get-FileHash -LiteralPath $item.FullName).Hash -cne $Digest) { throw 'N4 fixture could be modified or differs from review' }
    return $item.FullName
}

function Invoke-N4ReviewedAccountProbe($Context,[string]$Prefix,[string]$Role,[string]$Phase,
    [ValidateSet('M','F','X')][string]$Segment='M') {
    if ($Role -cnotin 'ordinary','psec' -or !(Test-True $Context.observer.ready)) { throw 'N4 A probe requires its calibrated observation' }
    $scope = Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash ($Phase -cne 'restored') $Segment
    $fixtures = Join-Path $scope.root 'fixtures'
    $trusted = @($scope.plan.hostSid,'S-1-5-18','S-1-5-32-544')
    $null = Assert-RecoveryAcl $fixtures $false $true
    if ($Phase -ceq 'restored' -and !($Context.restoredAllowed -eq $true)) { throw 'N4 restored probe requires confirmed rollback' }
    $account = (Get-LabAccounts -AccountIds A).A
    if ($account.Sid -cne $scope.plan.userSid) { throw 'Loaded test credentials are outside the reviewed scope' }
    $attempt = New-N4MatchProbeInvocation $fixtures $Prefix $Role $Phase $Context.endpoints.tcpPort $Context.endpoints.udpPort ([guid]::NewGuid().ToString('N'))
    $probe = Get-N4FixtureFile $attempt.probe $scope.reviewed.fixtures.probeSha256 $trusted
    $arguments = ($attempt.arguments | ForEach-Object { ConvertTo-LabLiteral $_ }) -join ' '
    $executor = $null
    $policyFile = $null
    $line = '& '+(ConvertTo-LabLiteral $probe)+' '+$arguments
    if ($Role -ceq 'psec') {
        $executor = Get-N4FixtureFile (Join-Path $fixtures 'wxc-exec.exe') 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D' $trusted
        $policyFile = Join-Path $fixtures ('n4-'+$Phase+'.json')
        $policyStream = [IO.File]::Open($policyFile,'CreateNew','Write','None')
        try {
            $json = [Text.Encoding]::UTF8.GetBytes(($attempt.policy | ConvertTo-Json -Depth 9 -Compress))
            $policyStream.Write($json,0,$json.Length)
            $policyStream.Flush($true)
        } finally { $policyStream.Dispose() }
        $null = Get-N4FixtureFile $policyFile (Get-N4ByteDigest $json) $trusted
        $line = '& '+(ConvertTo-LabLiteral $executor)+' '+(ConvertTo-LabLiteral $policyFile)
    }
    if (!('StudioLabWfp' -as [type])) { Add-Type -Path $scope.library }
    if ([StudioLabWfp].Assembly.Location -ine $scope.library) { throw 'Loaded A probe validator differs from the reviewed assembly' }
    $body = $line+' | ForEach-Object { [Console]::WriteLine([string]$_); [Console]::Out.Flush() }; exit $LASTEXITCODE'
    $startUtc = [DateTime]::UtcNow.Ticks
    $launchTick = [Diagnostics.Stopwatch]::GetTimestamp()
    $wrapper = $null
    $observed = $null
    try {
        $wrapper = Start-LabProbe $account $body -StreamOutput
        $receipt = Read-N4ProbeOutput $wrapper.Process.StandardOutput $attempt $launchTick
        $observed = Open-N4ValidatedProbeProcess $receipt $account.Sid $probe $wrapper.Process.SessionId
        $lineage = Assert-N4ProbeLineage $wrapper.Process $observed.process $executor
        $observedUtc = [DateTime]::UtcNow.Ticks
        if ($observed.creationUtc.Ticks -lt $startUtc -or $observed.creationUtc.Ticks -gt $observedUtc -or
            $receipt.firstProbeTick -gt $observed.observedTick) { throw 'N4 process creation cannot be placed inside the launch interval' }
        $hits = Read-N4CanaryHits $Context.observer.canaries $attempt.marker
        $tail = $wrapper.Process.StandardOutput.ReadToEndAsync()
        if (!$wrapper.Process.WaitForExit(7000) -or !$observed.process.WaitForExit(1000) -or !$tail.Wait(1000) -or
            !$wrapper.Errors.Wait(1000) -or $wrapper.Process.ExitCode -ne 0 -or $observed.process.ExitCode -ne 0 -or
            $tail.Result.Contains('N4-PROBE:')) { throw 'N4 attempt did not finish cleanly' }
        return @{receipt=$receipt;identity=$receipt.identity;tcp=$hits.tcp;udp=$hits.udp;firstProbeTick=$receipt.firstProbeTick;
            witnessedPid=$observed.pid;lineage=$lineage;probeExitConfirmed=$true;launchTick=$launchTick;
            startUtcTicks=$startUtc;creationUtcTicks=$observed.creationUtc.Ticks;observedUtcTicks=$observedUtc;observedTick=$observed.observedTick}
    } finally {
        if ($observed) { $observed.process.Dispose() }
        if ($wrapper) { Stop-LabProbe $wrapper }
    }
}

function Invoke-N4RecoveryTransport([string]$ScriptBody, [int]$DeadlineMs = 35000,
    [ValidateSet('M','F','X')][string]$ExpectedSegment='M') {
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $body = '$ProgressPreference=''SilentlyContinue''; '+$ScriptBody
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $start = [Diagnostics.ProcessStartInfo]::new($shell,('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (!$child.WaitForExit($DeadlineMs)) {
            $child.Kill()
            [void]$child.WaitForExit(1500)
            throw 'Independent recovery process reached its deadline; retain the journal'
        }
        if (!$stdout.Wait(1000) -or !$stderr.Wait(1000) -or $child.ExitCode -ne 0 -or $stderr.Result.Trim()) {
            throw ('Independent recovery process failed; retain the journal. Exit '+$child.ExitCode)
        }
        $receipt = $stdout.Result | ConvertFrom-Json -ErrorAction Stop
        if ($receipt.segment -cne $ExpectedSegment -or !(Test-True $receipt.listedObjectsAbsent) -or
            !(Test-True $receipt.recoveryDirectoryRetained)) {
            throw 'Independent recovery did not return a valid removal receipt'
        }
        return $receipt
    } finally { $child.Dispose() }
}

function Start-N4WatchTransport([string]$ScriptBody, [int]$OwnerId, [long]$StartedTicks, [string]$Digest) {
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptBody))
    $start = [Diagnostics.ProcessStartInfo]::new($shell,('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::Start($start)
    try {
        $errors = $child.StandardError.ReadToEndAsync()
        $read = $child.StandardOutput.ReadLineAsync()
        if (!$read.Wait(5000) -or !$read.Result -or !$read.Result.StartsWith('N4-WATCH:',[StringComparison]::Ordinal) -or $child.HasExited) {
            throw 'Independent recovery watcher did not arm'
        }
        $ready = $read.Result.Substring(9) | ConvertFrom-Json
        if (!(Test-True $ready.ready) -or $ready.watcherPid -ne $child.Id -or $ready.ownerPid -ne $OwnerId -or
            $ready.ownerStartTicks -ne $StartedTicks -or $ready.journalSha256 -cne $Digest) { throw 'Recovery watcher acknowledged a different owner or journal' }
        return @{process=$child;completion=$child.StandardOutput.ReadToEndAsync();errors=$errors;ready=$ready}
    } catch {
        if (!$child.HasExited) { $child.Kill(); [void]$child.WaitForExit(2000) }
        $child.Dispose()
        throw
    }
}

function Complete-N4Watch($Watcher, [bool]$SafeToDisarm) {
    if (!$Watcher) { return }
    try {
        if ($SafeToDisarm -and !$Watcher.process.HasExited) {
            $Watcher.process.Kill()
            if (!$Watcher.process.WaitForExit(2000)) { throw 'Independent watcher failed to exit' }
        }
    } finally { $Watcher.process.Dispose() }
}

function Assert-N4WatchActive($Context) {
    $watcher = $Context.recoveryWatch
    if (!$watcher -or !(Test-True $watcher.ready.ready) -or $watcher.process.HasExited -or
        $watcher.ready.journalSha256 -cne $Context.reviewedJournalHash) { throw 'N4 independent recovery watcher is absent or stale' }
}

function Get-N4ReviewedHostScope($Context, [string]$ApprovedRecoveryHash, [bool]$RequireLease,
    [ValidateSet('M','F','X')][string]$ExpectedSegment='M') {
    if ($ApprovedRecoveryHash -cnotmatch '^[0-9A-F]{64}$' -or !$Context.journal -or
        $Context.journal.sha256 -cne $ApprovedRecoveryHash) { throw 'Missing matching reviewed recovery digest' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'N4 host adapter requires an already elevated host token'
        }
        $trusted = @($identity.User.Value,'S-1-5-18','S-1-5-32-544')
        $path = [IO.Path]::GetDirectoryName($Context.journal.path)
        $base = [IO.Path]::GetTempPath().TrimEnd('\')
        $root = Assert-RecoveryAcl $path $true $true
        if ($root.Name -cnotmatch '^ClaudeStudioN4Account-([a-f0-9]{32})$' -or $root.Parent.FullName -ine $base) {
            throw 'N4 host adapter requires the private TEMP run directory'
        }
        $run = $Matches[1]
        $null = Assert-RecoveryAcl $base $false $true
        for ($ancestor = $root.Parent; $ancestor; $ancestor = $ancestor.Parent) {
            if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'N4 TEMP ancestor is a reparse point' }
        }
        $journal = Assert-RecoveryAcl (Join-Path $path 'recovery.json') $true $false
        $library = Assert-RecoveryAcl (Join-Path $path 'N4AccountGuard.dll') $true $false
        $control = Assert-RecoveryAcl (Join-Path $path 'windows-lab-n4-account-control.ps1') $true $false
        $leaseFile = Assert-RecoveryAcl (Join-Path $path 'recovery.lease') $true $false
        if ($journal.FullName -ine $Context.journal.path -or
            (Get-FileHash -LiteralPath $journal.FullName).Hash -cne $ApprovedRecoveryHash) { throw 'Reviewed recovery journal differs' }
        $reviewed = Get-Content -LiteralPath $journal.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $plan = Read-RecoveryPlan $reviewed $run
        if ($plan.hostSid -cne $identity.User.Value -or $plan.userSid -cne $Context.accountSid -or $plan.segment -cne $ExpectedSegment -or
            (Get-LocalUser -Name ClaudeStudioLabA).SID.Value -cne $plan.userSid -or
            (Get-FileHash -LiteralPath $library.FullName).Hash -cne $plan.dllHash -or
            (Get-FileHash -LiteralPath $control.FullName).Hash -cne $plan.controllerHash) { throw 'N4 host identity, A, script or binary differs' }
        if ($RequireLease -and (!$Context.runLease.CanWrite -or $Context.runLease.Name -ine $leaseFile.FullName)) {
            throw 'N4 mutation requires the active launcher lease'
        }
        return @{plan=$plan; reviewed=$reviewed; root=$root.FullName; library=$library.FullName; controller=$control.FullName}
    } finally { $identity.Dispose() }
}

function Start-N4ReviewedRecoveryWatch($Context,[ValidateSet('M','F','X')][string]$Segment) {
    $digest=$Context.reviewedJournalHash
    $scope=Get-N4ReviewedHostScope $Context $digest $true $Segment
    $owner=[Diagnostics.Process]::GetCurrentProcess()
    try { $started=$owner.StartTime.ToUniversalTime().Ticks; $id=$owner.Id }
    finally { $owner.Dispose() }
    $script=ConvertTo-LabLiteral $scope.controller
    $directory=ConvertTo-LabLiteral $scope.root
    $command=('$ErrorActionPreference=''Stop''; & '+$script+' -Watch -Directory '+$directory+
        " -ManifestSha256 '$digest' -OwnerPid $id -OwnerStartTicks $started -Confirm:`$false | ConvertTo-Json -Compress")
    $Context.recoveryWatch=Start-N4WatchTransport $command $id $started $digest
    return $Context.recoveryWatch.ready
}

function Invoke-N4ReviewedRollback($Context,[ValidateSet('M','F','X')][string]$Segment) {
    $scope=Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash $false $Segment
    $script=ConvertTo-LabLiteral $scope.controller
    $directory=ConvertTo-LabLiteral $scope.root
    Invoke-N4RecoveryTransport ('$ErrorActionPreference=''Stop''; & '+$script+' -Rollback -Directory '+$directory+
        " -ManifestSha256 '$($Context.reviewedJournalHash)' -Confirm:`$false | ConvertTo-Json -Compress") -ExpectedSegment $Segment
}

function Get-N4NativeMatchOperations {
    # These callbacks are inserted into the reviewed M flow. There is no live command-line mode in this file.
    $arm = { param($context) Start-N4ReviewedRecoveryWatch $context 'M' }
    $install = {
        param($context)
        $scope = Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true
        Assert-N4WatchActive $context
        if (!('StudioLabWfp' -as [type])) { Add-Type -Path $scope.library }
        if ([StudioLabWfp].Assembly.Location -ine $scope.library) { throw 'Loaded rule writer differs from review' }
        $spec = [StudioLabWfp+AccountGuardSpec]::new($scope.plan.userSid,'',$scope.plan.accountLayer,$scope.plan.accountKeys,$scope.plan.accountWeight,0)
        $writer = [StudioLabWfp]::CreateStaticGuard()
        try { $writer.InstallAccountBase($spec) } finally { $writer.Dispose() }
        @{committed=$true}
    }
    $read = {
        param($context)
        $scope = Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true
        $spec = [StudioLabWfp+AccountGuardSpec]::new($scope.plan.userSid,'',$scope.plan.accountLayer,$scope.plan.accountKeys,$scope.plan.accountWeight,0)
        $found = [StudioLabWfp]::InspectAccountGuard($spec,$true,$false)
        @{exact=($found.Count -eq 5 -and $false -notin $found);independent=$true;journalSha256=$context.reviewedJournalHash}
    }
    $rollback = { param($context) Invoke-N4ReviewedRollback $context 'M' }
    $finished = { param($context,$safe) Complete-N4Watch $context.recoveryWatch $safe }
    return @{ArmRecovery=$arm;InstallBase=$install;ReadBase=$read;RunIndependentRollback=$rollback;FinishRecovery=$finished}
}

function Invoke-N4HostControl($Context,[string]$Phase,[ValidateSet('M','F','X')][string]$Segment='M') {
    $state = $Context.observer
    $scope = Get-N4ReviewedHostScope $Context $Context.reviewedJournalHash ($Phase -cne 'restored') $Segment
    $fixtures = Join-Path $scope.root 'fixtures'
    $trusted = @($scope.plan.hostSid,'S-1-5-18','S-1-5-32-544')
    $null = Assert-RecoveryAcl $fixtures $false $true
    $attempt = New-N4MatchProbeInvocation $fixtures $state.prefix host $Phase $state.endpoints.tcpPort $state.endpoints.udpPort ([guid]::NewGuid().ToString('N'))
    $probe = Get-N4FixtureFile $attempt.probe $scope.reviewed.fixtures.probeSha256 $trusted
    $start = [Diagnostics.ProcessStartInfo]::new($probe,($attempt.arguments -join ' '))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $tick = [Diagnostics.Stopwatch]::GetTimestamp()
    $process = [Diagnostics.Process]::Start($start)
    try {
        $errors = $process.StandardError.ReadToEndAsync()
        $receipt = Read-N4ProbeOutput $process.StandardOutput $attempt $tick
        $tail = $process.StandardOutput.ReadToEndAsync()
        if (!$process.WaitForExit(3000) -or !$errors.Wait(1000) -or !$tail.Wait(1000) -or
            $process.ExitCode -ne 0 -or $receipt.identity.pid -ne $process.Id -or
            $receipt.identity.userSid -cne $scope.plan.hostSid -or $receipt.identity.container -ne $false -or
            $tail.Result.Contains('N4-PROBE:')) { throw 'Host-control identity or exit differs' }
        $hits = Read-N4CanaryHits $state.canaries $attempt.marker
        if ($hits.tcp.hits -ne 1 -or $hits.udp.hits -ne 1) { throw 'Host failed its independent TCP or UDP control' }
        $state.receipts.Add($receipt)
        $marker=if ($Segment -ceq 'M') { [byte][Array]::IndexOf(@('baseline','blocked','cold','restored'),$Phase) }
            else { $state.hostControlSequence++; [byte]$state.hostControlSequence }
        $hostFlows = Read-N4HostFlows $state.canaries $marker
        $hostFlows.sid = $scope.plan.hostSid
        $hostFlows.dnsPid = $process.Id
        $hostFlows.dns = @($receipt.dnsQueries | Where-Object { (Test-Count $_.status) -and $_.status -eq 0 }).Count -gt 0
        return $hostFlows
    } finally {
        if (!$process.HasExited) { $process.Kill(); [void]$process.WaitForExit(2000) }
        $process.Dispose()
    }
}

function Measure-N4ReviewedMatchPhase($Context, [string]$Phase) {
    if ($Phase -cne 'restored') { Assert-N4WatchActive $Context }
    $state = $Context.observer
    $psec = Invoke-N4ReviewedAccountProbe $Context $state.prefix psec $Phase
    $state.receipts.Add($psec.receipt)
    $ordinary = $null
    if ($Phase -cne 'cold') {
        $ordinary = Invoke-N4ReviewedAccountProbe $Context $state.prefix ordinary $Phase
        $state.receipts.Add($ordinary.receipt)
    }
    $result = @{name=$Phase;psec=$psec;ordinary=$ordinary;host=(Invoke-N4HostControl $Context $Phase)}
    if ($Phase -ceq 'cold') {
        $result.timeline = @{firstProbe=$psec.firstProbeTick;firstProbeObserved=$true;observedPid=$psec.witnessedPid;
            lineageVerified=$psec.lineage.verified;launchTick=$psec.launchTick;observedTick=$psec.observedTick;
            startRequestUtcTicks=$psec.startUtcTicks;processCreationUtcTicks=$psec.creationUtcTicks;observedUtcTicks=$psec.observedUtcTicks}
    }
    return $result
}

function Get-N4ReviewedMatchOperations {
    $ops = Get-N4NativeMatchOperations
    $ops.StartObservation = {
        param($context)
        $scope = Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true
        $prefix = 'studio-'+([IO.Path]::GetFileName($scope.root).Substring('ClaudeStudioN4Account-'.Length,16))
        $canaries = New-N4MatchCanaries
        try { $trace = Start-LabDnsTrace $scope.root $prefix -AccountMatch }
        catch { Close-N4MatchCanaries $canaries; throw }
        @{ready=$true;prefix=$prefix;root=$scope.root;trace=$trace;canaries=$canaries;endpoints=$canaries.endpoints;
            receipts=[Collections.Generic.List[object]]::new()}
    }
    $ops.MeasureBaseline = { param($context) Measure-N4ReviewedMatchPhase $context baseline }
    $ops.MeasureBlocked = { param($context) Measure-N4ReviewedMatchPhase $context blocked }
    $ops.StartColdProbe = { param($context) Measure-N4ReviewedMatchPhase $context cold }
    $ops.DrainA = {
        param($context)
        $scope = Get-N4ReviewedHostScope $context $context.reviewedJournalHash $true
        Assert-NoRecoveryWorkload $scope.plan $scope.root
        @{workloadsExited=$true}
    }
    $ops.MeasureRestored = { param($context) Measure-N4ReviewedMatchPhase $context restored }
    $ops.StopObservation = {
        param($context)
        $state = $context.observer
        if (!$state) { return @{stopped=$true} }
        try {
            $trace = Stop-LabDnsTrace $state.trace -MeasureLoss
            @{stopped=$trace.stopped;trace=$trace;prefix=$state.prefix;receipts=$state.receipts.ToArray()}
        } finally { Close-N4MatchCanaries $state.canaries }
    }
    return $ops
}

function Get-N4ReviewedStageFiles([string]$Directory,[string]$ReviewedJournalHash,[ValidateSet('M','F','X')][string]$Segment) {
    if ($ReviewedJournalHash -cnotmatch '^[0-9A-F]{64}$') { throw 'A reviewed SHA-256 is required' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Staged N4 requires an already elevated host token'
        }
        $trusted = @($identity.User.Value,'S-1-5-18','S-1-5-32-544')
        $root = Assert-RecoveryAcl $Directory $true $true
        if ($root.Name -cnotmatch '^ClaudeStudioN4Account-([a-f0-9]{32})$' -or
            $root.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\')) { throw 'Staged N4 directory differs' }
        $run = $Matches[1]
        $null = Assert-RecoveryAcl $root.Parent.FullName $false $true
        for ($ancestor = $root.Parent; $ancestor; $ancestor = $ancestor.Parent) {
            if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Staged N4 ancestor is a reparse point' }
        }
        $approved = Assert-RecoveryAcl (Join-Path $root.FullName ('reviewed-'+$Segment+'.json')) $true $false
        $library = Assert-RecoveryAcl (Join-Path $root.FullName 'N4AccountGuard.dll') $true $false
        $control = Assert-RecoveryAcl (Join-Path $root.FullName 'windows-lab-n4-account-control.ps1') $true $false
        $null = Assert-RecoveryAcl (Join-Path $root.FullName 'recovery.lease') $true $false
        if ($approved.Length -gt 65536) { throw 'Reviewed N4 manifest exceeds its size bound' }
        $bytes = [IO.File]::ReadAllBytes($approved.FullName)
        if ((Get-N4ByteDigest $bytes) -cne $ReviewedJournalHash) { throw 'Staged N4 manifest differs from review' }
        $value = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json
        $plan = Read-RecoveryPlan $value $run
        if ($plan.segment -cne $Segment -or $plan.hostSid -cne $identity.User.Value -or
            (Get-LocalUser -Name ClaudeStudioLabA).SID.Value -cne $plan.userSid -or
            (Get-FileHash -LiteralPath $library.FullName).Hash -cne $plan.dllHash -or
            (Get-FileHash -LiteralPath $control.FullName).Hash -cne $plan.controllerHash) { throw 'Staged N4 role, account or fixed build differs' }
        $fixtures = Join-Path $root.FullName 'fixtures'
        $null = Assert-RecoveryAcl $fixtures $false $true
        $null = Get-N4FixtureFile (Join-Path $fixtures 'StudioProbe.exe') $value.fixtures.probeSha256 $trusted
        $null = Get-N4FixtureFile (Join-Path $fixtures 'wxc-exec.exe') 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D' $trusted
        return @{ root=$root.FullName; run=$run; reviewed=$value; plan=$plan; bytes=$bytes; library=$library.FullName }
    } finally { $identity.Dispose() }
}

function Save-N4StagedResult([string]$Root,[ValidateSet('M','F','X')][string]$Segment,$Result) {
    $path=Join-Path $Root ('result-'+$Segment+'.json')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Result | ConvertTo-Json -Depth 40 -Compress))
    $pending=Join-Path $Root ('result-'+$Segment+'-'+[guid]::NewGuid().ToString('N')+'.pending')
    $stream=[IO.File]::Open($pending,'CreateNew','Write','None')
    try {
        try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
        finally { $stream.Dispose() }
        [IO.File]::Move($pending,$path)
    } finally { [IO.File]::Delete($pending) }
    return @{path=$path;sha256=(Get-N4ByteDigest $bytes)}
}

function Invoke-N4StagedReviewedMatch([string]$Directory, [string]$ReviewedJournalHash) {
    $stage=Get-N4ReviewedStageFiles $Directory $ReviewedJournalHash 'M'
    if ((Test-Path -LiteralPath (Join-Path $stage.root 'recovery.json')) -or
        (Test-Path -LiteralPath (Join-Path $stage.root 'result-M.json'))) { throw 'A prior M journal or result still exists' }
    if (!('StudioLabWfp' -as [type])) { Add-Type -Path $stage.library }
    if ([StudioLabWfp].Assembly.Location -ine $stage.library -or [StudioLabWfp]::ReadAccountGuardWeight() -ne $stage.plan.accountWeight) {
        throw 'Current account filter priority differs from the reviewed build or manifest'
    }
    Assert-NoRecoveryWorkload $stage.plan $stage.root
    $result=Invoke-N4MatchStage $stage.root $null (Get-N4ReviewedMatchOperations) $stage.bytes $ReviewedJournalHash
    $result.saved=Save-N4StagedResult $stage.root 'M' $result
    return $result
}

if ($loadN4HostOnly) { return }

$fixturePath = Join-Path $env:SystemRoot 'fixtures'
$invocation = New-N4MatchProbeInvocation $fixturePath 'studio-0000000000000001' psec cold 44100 44101 ('a'*32)
if ($invocation.policy.network.egress.default -cne 'deny' -or $invocation.policy.runtimeConfig -or
    $invocation.policy.process.commandLine -notmatch ' n4-account-match studio-0000000000000001 psec cold 44100 44101 a{32}$') {
    throw 'N4 fixture policy differs from the reviewed scope'
}
$now = [Diagnostics.Stopwatch]::GetTimestamp()
$sample = @{role='psec';phase='cold';marker=('a'*32);tcp=@{endpoint='127.0.0.1:44100'};
    udp=@{endpoint='127.0.0.1:44101'};firstProbeTick=$now;tickFrequency=[Diagnostics.Stopwatch]::Frequency}
$stream = [IO.StringReader]::new("executor note`nN4-PROBE:"+($sample | ConvertTo-Json -Compress))
try { $null = Read-N4ProbeOutput $stream $invocation $now 2000 } finally { $stream.Dispose() }
$sample.marker = 'b'*32
$stream = [IO.StringReader]::new('N4-PROBE:'+($sample | ConvertTo-Json -Compress))
try {
    try { $null = Read-N4ProbeOutput $stream $invocation $now 2000; throw 'Foreign response passed' }
    catch { if ($_.Exception.Message -cne 'N4 probe receipt does not match the current attempt') { throw } }
} finally { $stream.Dispose() }

$canaries = New-N4MatchCanaries
try {
    $marker = [guid]::NewGuid().ToString('N')
    $packet = [Text.Encoding]::ASCII.GetBytes($marker)
    $before = Read-N4HostFlows $canaries 17
    $tcp = [Net.Sockets.TcpClient]::new()
    $udp = [Net.Sockets.UdpClient]::new()
    try {
        $tcp.Connect([Net.IPAddress]::Loopback,$canaries.endpoints.tcpPort)
        $tcp.GetStream().Write($packet,0,$packet.Length)
        $udpTarget = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$canaries.endpoints.udpPort)
        if ($udp.Send($packet,$packet.Length,$udpTarget) -ne $packet.Length) { throw 'Offline loopback send incomplete' }
    } finally { $tcp.Dispose(); $udp.Dispose() }
    $have = Read-N4CanaryHits $canaries $marker
    $empty = Read-N4CanaryHits $canaries $marker
    $after = Read-N4HostFlows $canaries 31
    if ($have.tcp.hits -ne 1 -or $have.udp.hits -ne 1 -or $empty.tcp.hits -ne 0 -or $empty.udp.hits -ne 0 -or
        !$before.oldMarker -or !$before.newMarker -or !$after.oldMarker -or !$after.newMarker -or $before.oldConnection -cne $after.oldConnection) {
        throw 'Real loopback canary or continuous host flow failed'
    }
} finally { Close-N4MatchCanaries $canaries }
$network = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$tcpLeft = @($network.GetActiveTcpListeners() | ForEach-Object ToString)
$udpLeft = @($network.GetActiveUdpListeners() | ForEach-Object ToString)
if ($canaries.endpoints.tcp -in $tcpLeft -or $canaries.endpoints.host -in $tcpLeft -or $canaries.endpoints.udp -in $udpLeft) {
    throw 'Synthetic canary listener remained after cleanup'
}

$good = Invoke-N4RecoveryTransport '[Console]::WriteLine(''{"segment":"M","listedObjectsAbsent":true,"recoveryDirectoryRetained":true}'')' 4000
if (!(Test-True $good.listedObjectsAbsent)) { throw 'Valid child receipt was lost' }
$bad = @(
    @{script='[Console]::WriteLine(''{"segment":"M","listedObjectsAbsent":true,"recoveryDirectoryRetained":true}''); exit 7';deadline=4000},
    @{script='[Console]::WriteLine(''{"segment":"F","listedObjectsAbsent":true,"recoveryDirectoryRetained":true}'')';deadline=4000},
    @{script='[Console]::WriteLine(''{"segment":"M","listedObjectsAbsent":"true","recoveryDirectoryRetained":true}'')';deadline=4000},
    @{script='[Console]::WriteLine(''{"segment":"M","listedObjectsAbsent":true}'')';deadline=4000},
    @{script='[Console]::WriteLine(''{"segment":"M","listedObjectsAbsent":true,"recoveryDirectoryRetained":true}''); Start-Sleep -Seconds 8';deadline=900}
)
foreach ($case in $bad) {
    $rejected = $false
    try { $null = Invoke-N4RecoveryTransport $case.script $case.deadline } catch { $rejected = $true }
    if (!$rejected) { throw 'Recovery transport accepted a failed child' }
}
$callbacks = Get-N4NativeMatchOperations
try { $null = & $callbacks.InstallBase @{reviewedJournalHash=('A'*64);journal=@{sha256=('B'*64)}}; throw 'Wrong reviewed digest passed' }
catch { if ($_.Exception.Message -cne 'Missing matching reviewed recovery digest') { throw } }

$files = @('windows-lab-wfp.cs','windows-lab-wfp-container.cs','windows-lab-wfp-bind.cs','windows-lab-n4-account-guard.cs') |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
Add-Type -Path $files
$shellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$ownerSettings = [Diagnostics.ProcessStartInfo]::new($shellPath,'-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 20"')
$ownerSettings.UseShellExecute = $false
$ownerSettings.CreateNoWindow = $true
$owner = [Diagnostics.Process]::Start($ownerSettings)
$watcher = $null
try {
    $parent = [Diagnostics.Process]::GetCurrentProcess()
    try { $lineage = Assert-N4ProbeLineage $parent $owner '' } finally { $parent.Dispose() }
    if (!$lineage.verified -or $lineage.rootPid -ne $PID -or $lineage.probePid -ne $owner.Id) { throw 'Synthetic process lineage differs' }
    $born = $owner.StartTime.ToUniversalTime().Ticks
    try { $wrong = Open-N4RecoveryOwner $owner.Id ($born+1); $wrong.Dispose(); throw 'Wrong process generation passed' }
    catch { if ($_.Exception.Message -cne 'N4 watchdog owner no longer matches the starting process') { throw } }
    $controller = "'"+(Join-Path $PSScriptRoot 'windows-lab-n4-account-control.ps1').Replace("'","''")+"'"
    $digest = 'F'*64
    $script = '. '+$controller+' -FunctionsOnly; '+
        ('$owner=Open-N4RecoveryOwner '+$owner.Id+' '+$born+'; try {')+
        ('[Console]::WriteLine(''N4-WATCH:''+(@{ready=$true;watcherPid=$PID;ownerPid='+$owner.Id+
         ';ownerStartTicks='+$born+';journalSha256='''+$digest+'''} | ConvertTo-Json -Compress)); ')+
        '[Console]::Out.Flush(); Wait-N4RecoveryOwnerExit $owner 10000; [Console]::WriteLine(''owner-exited'') } finally { $owner.Dispose() }'
    $watcher = Start-N4WatchTransport $script $owner.Id $born $digest
    $watchContext = @{recoveryWatch=$watcher;reviewedJournalHash=$digest}
    Assert-N4WatchActive $watchContext
    $owner.Kill()
    if (!$owner.WaitForExit(2000) -or !$watcher.process.WaitForExit(4000) -or !$watcher.completion.Wait(1000) -or
        $watcher.process.ExitCode -ne 0 -or $watcher.completion.Result.Trim() -cne 'owner-exited') { throw 'Synthetic owner exit was not observed' }
    try { Assert-N4WatchActive $watchContext; throw 'Exited watcher passed the live guard' }
    catch { if ($_.Exception.Message -cne 'N4 independent recovery watcher is absent or stale') { throw } }
} finally {
    if (!$owner.HasExited) { $owner.Kill(); [void]$owner.WaitForExit(2000) }
    $owner.Dispose()
    if ($watcher) { Complete-N4Watch $watcher $true }
}
[ordered]@{mode='offline-m-native-adapter';validChildReceipt=$true;rejectedChildReceipts=$bad.Count;
    digestPreflightRejected=$true;boundedProbePolicy=$true;foreignProbeReceiptRejected=$true;
    localCanaries=$true;sameHostOldFlow=$true;canariesReleased=$true;liveSyntheticLineage=$true;
    independentOwnerExitObserved=$true;wrongOwnerGenerationRejected=$true;wfpWrites=0;accountLaunches=0}
