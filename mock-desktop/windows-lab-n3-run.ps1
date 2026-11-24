[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Run this A experiment in Windows PowerShell 5.1'}
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-bind-scenarios.ps1') -FunctionsOnly

$scopeSignal='S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225'
$lab=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
$stageTag='psec-'+[guid]::NewGuid().ToString('N')
$stage=Join-Path $lab $stageTag
$prefix='studio-'+[guid]::NewGuid().ToString('N').Substring(0,16)
$privateTag='ClaudeStudioTrace-'+$prefix
$privateDir=Join-Path ([IO.Path]::GetTempPath()) $privateTag
$output=Join-Path (Split-Path $lab -Parent) ('mock-results\windows-psec-n3-a-'+$prefix.Substring(7)+'.json')
$report=[ordered]@{outcome='failed-n3-a';run=$prefix;sourceManifest=@{};checks=@{};phases=@();faults=@();cleanup=@{errors=@()}}
$state=@{a=0;guard=0}
$observer=$null;$aWorkload=$null;$topology=$null;$hostOld=$null;$hostListen=$null;$tcpCanary=$null;$udpCanary=$null
$stageCreated=$false;$privateCreated=$false;$observerStarted=$false

function Expand-N3Executor([string]$Directory) {
    $inputPath=Join-Path $lab 'mxc-x64-entry.bin'
    $bytes=[IO.File]::ReadAllBytes($inputPath)
    if($bytes.Length -ne 4514529 -or [BitConverter]::ToUInt32($bytes,0) -ne 0x04034b50 -or [BitConverter]::ToUInt16($bytes,8) -ne 8){
        throw 'Unexpected pinned MXC ZIP entry'
    }
    $nameSize=[BitConverter]::ToUInt16($bytes,26);$extraSize=[BitConverter]::ToUInt16($bytes,28)
    if([Text.Encoding]::UTF8.GetString($bytes,30,$nameSize) -cne 'x64/wxc-exec.exe'){throw 'Wrong MXC entry'}
    $compressed=[IO.MemoryStream]::new($bytes,30+$nameSize+$extraSize,4514455)
    $decoder=[IO.Compression.DeflateStream]::new($compressed,[IO.Compression.CompressionMode]::Decompress)
    try {
        $file=Join-Path $Directory 'wxc-exec.exe'
        $destination=[IO.File]::Create($file)
        try{$decoder.CopyTo($destination)}finally{$destination.Dispose()}
    }finally{$decoder.Dispose();$compressed.Dispose()}
    $hash=(Get-FileHash -LiteralPath $file).Hash
    if($hash -cne 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D'){throw 'Invalid MXC executor hash'}
    return $hash
}

function Wait-N3File([string]$Path,[int]$Milliseconds,[switch]$CheckWorker) {
    $wait=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath $Path)){
        $errorPath=Join-Path $privateDir 'guard-error'
        if(Test-Path -LiteralPath $errorPath){throw [IO.File]::ReadAllText($errorPath)}
        if(($observer -and $observer.HasExited) -or ($CheckWorker -and $aWorkload.Process.HasExited) -or $wait.ElapsedMilliseconds -gt $Milliseconds){
            throw ('N3 file wait ended: '+(Split-Path $Path -Leaf))
        }
        Start-Sleep -Milliseconds 20
    }
}

function Invoke-N3Guard([string]$Action,$Identity=$null) {
    $state.guard++
    $file=Join-Path $privateDir ('n3-control-'+$state.guard+'.json')
    Write-GateJson $file @{action=$Action;identity=$Identity}
    Wait-N3File ($file+'.done') $(if($Action -in 'ports','install','cleanup'){12000}else{2500})
    $result=Get-Content -LiteralPath ($file+'.done') -Raw -Encoding UTF8|ConvertFrom-Json
    if($result.sequence -ne $state.guard -or $result.action -cne $Action){throw 'N3 guard command did not match'}
    return $result.value
}

function Assert-N3Scope($Identity) {
    if(!$Identity -or $Identity.userSid -ne $accounts.A.Sid -or $Identity.session -ne $report.session -or
        $Identity.container -ne $true -or $Identity.inJob -ne $true -or $Identity.containerSid -notmatch '^S-1-15-2(-[0-9]+){7}$' -or
        ($report.windowReady -and $Identity.containerSid -ne $report.windowReady.containerSid) -or
        $Identity.networkCapabilities.Count -ne 1 -or $Identity.networkCapabilities[0] -ne $scopeSignal){throw 'N3 A scope mismatch'}
}

function Invoke-N3Window([string]$Action,[string]$Phase) {
    $state.a++
    $file=Join-Path $run ('n3cmd-'+$state.a+'.json')
    $reply=Join-Path $run ('n3result-'+$state.a+'.json')
    Write-GateJson $file @{action=$Action;phase=$Phase}
    if($Action -eq 'finish'){return $state.a}
    Wait-N3File $reply 15000 -CheckWorker
    $value=Get-Content -LiteralPath $reply -Raw -Encoding UTF8|ConvertFrom-Json
    if($value.number -ne $state.a -or $value.action -cne $Action -or $value.phase -cne $Phase){throw 'N3 simulator command did not match'}
    Assert-N3Scope $value.identity
    return $value.data
}

function Test-N3Host([string]$Phase,[byte]$Marker) {
    $utc=[datetime]::UtcNow.ToString('o')
    $fresh=Open-GatePair $hostListen
    try {
        $answer=@(Resolve-DnsName -Name ($prefix+'-h-'+$Phase+'.test.') -Type A -DnsOnly -NoHostsFile -QuickTimeout)
        if(!$answer.Count){throw 'Host DNS did not return records'}
        return @{phase=$Phase;pid=$PID;startedUtc=$utc;old=(Send-GateMarker $hostOld $Marker);
            fresh=(Send-GateMarker $fresh ($Marker+1));dns='answered';finishedUtc=[datetime]::UtcNow.ToString('o')}
    }finally{Close-GatePair $fresh}
}

function Read-N3Canaries {
    $hits=@{tcp=0;udp=0}
    while($tcpCanary.Pending()){
        $client=$tcpCanary.AcceptTcpClient()
        try{$client.ReceiveTimeout=500;if($client.GetStream().ReadByte() -eq 85){$hits.tcp++}}finally{$client.Dispose()}
    }
    while($udpCanary.Available){
        $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $bytes=$udpCanary.Receive([ref]$remote)
        if($bytes.Length -eq 1 -and $bytes[0] -eq 85){$hits.udp++}
    }
    return $hits
}

function Test-N3Phase([string]$Phase,[bool]$Online,[switch]$Native) {
    $action=if($Native){'native'}else{'probe'}
    $probe=Invoke-N3Window $action $Phase
    Assert-N3Scope $probe.system
    if($Native -and ($probe.launchedPid -ne $probe.system.pid -or $probe.system.pid -eq $report.windowReady.pid)){throw 'N3 child identity mismatch'}
    $hits=Read-N3Canaries
    $item=@{phase=$Phase;online=$Online;native=[bool]$Native;probe=$probe;hits=$hits}
    $report.phases+=@($item)
    if($hits.tcp -ne 0 -or $hits.udp -ne 0 -or 'sent' -in @($probe.directTargets.u,$probe.directTargets.http,$probe.directTargets.tls) -or
        $probe.system.dnsQueryStatus -ne 5 -or $probe.system.getAddrInfoStatus -ne 11001){throw "A observed a direct or DNS path in $Phase"}
    foreach($protocol in 'http','tls'){
        $value=$probe.$protocol
        if($value.ok -ne $Online -or ($Online -and $value.status -ne 200) -or
            (!$Online -and $value.status -notin 'ConnectFailure','Timeout')){
            throw "Unexpected $protocol result in $Phase"
        }
    }
    $item.host=Test-N3Host $Phase 81
    return $item
}

function Set-N3Healthy([string]$Phase) {
    $readiness=Invoke-N3Child $topology.entry 'arm'
    if(!$readiness.admitting -or !$readiness.lastProbe.ok){throw 'N3 target health did not pass'}
    $value=Invoke-N3Guard 'open'
    if($value.exceptionPresent -ne $true){throw 'The exact A exception did not open'}
    return @{phase=$Phase;health=$readiness;scope=$value}
}

function Invoke-N3Fault([string]$Phase,[string]$Fault) {
    $null=Invoke-N3Window 'hold' $Phase
    $time=[Diagnostics.Stopwatch]::StartNew()
    do {
        $before=Invoke-N3Window 'held' $Phase
        if($time.ElapsedMilliseconds -gt 2600){throw 'No positive active HTTP/TLS flow before fault'}
    }until($before.http.marks.Count -ge 2 -and $before.tls.marks.Count -ge 2 -and $before.http.state -eq 'active' -and $before.tls.state -eq 'active')
    $record=@{phase=$Phase;fault=$Fault;before=$before;injectedUtc=[datetime]::UtcNow.ToString('o');injectedTick=[Diagnostics.Stopwatch]::GetTimestamp()}
    $report.faults+=@($record)
    if($Fault -eq 'exit'){
        Stop-N3Process $topology.upstream
        $topology.upstream=$null
        $record.upstreamExited=$true
    }else{$record.injection=Invoke-N3Child $topology.upstream $Fault}
    do {
        $entry=Invoke-N3Child $topology.entry 'status'
        $guard=Invoke-N3Guard 'status'
        $observedTick=[Diagnostics.Stopwatch]::GetTimestamp()
        $elapsed=($observedTick-$record.injectedTick)*1000/[Diagnostics.Stopwatch]::Frequency
        if($elapsed -gt 3000){throw "N3 $Fault exceeded the three-second shutdown limit"}
    }until(!$entry.admitting -and $entry.active -eq 0 -and $guard.open -eq $false -and $guard.shutdown.scope.exceptionPresent -eq $false)
    $record.closedMilliseconds=$elapsed;$record.closedTick=$observedTick;$record.closedUtc=[datetime]::UtcNow.ToString('o');$record.entry=$entry;$record.guard=$guard
    $null=Test-N3Phase $Phase $false
    $record.after=Invoke-N3Window 'held' $Phase
    if($record.after.http.state -in 'active','starting' -or $record.after.tls.state -in 'active','starting'){
        throw 'N3 old controller streams did not observe closure'
    }
    if($Fault -eq 'exit') {
        $record.bindings=Invoke-N3Guard 'bindings'
        $record.rebindU=Test-GateBind $ports[1] ([Net.IPAddress]::Any) 'exclusive'
        if($record.rebindU.stage -ne 'bind' -or $record.rebindU.nativeError -ne 10013){throw 'Old U port did not stay protected'}
        $socket=New-GateSocket
        try {
            $pending=$socket.BeginConnect([Net.IPAddress]::Loopback,$ports[1],$null,$null)
            try {
                if(!$pending.AsyncWaitHandle.WaitOne(1200)){$record.upstreamSocketResult=@{status='timeout';deadlineMs=1200;nativeError=$null}}
                else {
                    $socket.EndConnect($pending)
                    throw 'Post-exit U unexpectedly accepted a connection'
                }
            }catch [Net.Sockets.SocketException]{
                $record.upstreamSocketResult=@{status=$_.Exception.SocketErrorCode.ToString();nativeError=$_.Exception.NativeErrorCode;deadlineMs=1200}
            }
            finally{$pending.AsyncWaitHandle.Dispose()}
        }finally{$socket.Dispose()}
        if($record.upstreamSocketResult.status -notin 'ConnectionRefused','TimedOut','timeout'){throw 'Unexpected TCP connect result at stopped U'}
    }else {
        $null=Invoke-N3Child $topology.upstream 'serve'
        $recovery=if($Fault -eq 'refuse'){'recovered1'}else{'recovered2'}
        $record.reopen=Set-N3Healthy $recovery
        $null=Test-N3Phase $recovery $true
        $record.oldAfterRecovery=Invoke-N3Window 'held' $recovery
        foreach($scheme in 'http','tls'){
            if($record.oldAfterRecovery.$scheme.marker -cne $record.after.$scheme.marker -or
                ($record.oldAfterRecovery.$scheme.marks -join ',') -cne ($record.after.$scheme.marks -join ',')){throw 'N3 old flow advanced during recovery'}
        }
    }
}

try {
    $accounts=Get-LabAccounts
    $report.accountSid=$accounts.A.Sid;$report.session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild="$($windows.CurrentBuildNumber).$($windows.UBR)";$report.sdk='1.1.0'
    $ports=[uint16[]]@(Select-N2Ports 2)
    $report.ports=$ports
    if((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $privateDir)){throw 'N3 run directory collision'}
    [void][IO.Directory]::CreateDirectory($privateDir,(New-N2PrivateAcl));$privateCreated=$true
    [void][IO.Directory]::CreateDirectory($stage);$stageCreated=$true
    $payload=Join-Path $stage 'payload';[void][IO.Directory]::CreateDirectory($payload)
    $run=Join-Path $stage $prefix;[void][IO.Directory]::CreateDirectory($run)
    $report.executorSha256=Expand-N3Executor $stage
    $report.initialPortControl=@(foreach($port in $ports){Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'})
    if(@($report.initialPortControl|Where-Object stage -ne 'listening').Count){throw 'N3 dedicated port failed the positive bind control'}
    $topology=Initialize-N3Topology $privateDir $prefix $ports
    $report.privateAclProtected=(Get-Acl -LiteralPath $privateDir).AreAccessRulesProtected
    $proxyExe=$topology.exe
    $report.privateAccess=Test-N2PrivateAccess
    $exe=Join-Path $payload 'StudioProbe.exe'
    $compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $library=Join-Path $privateDir 'N3Guard.dll'
    $probeSource=@('psec-probe','portguard-flow','n3-protocol','n3-simulator'|ForEach-Object {Join-Path $PSScriptRoot ('windows-lab-'+$_+'.cs')})
    $guardSource=@('wfp','wfp-container','wfp-bind'|ForEach-Object {Join-Path $PSScriptRoot ('windows-lab-'+$_+'.cs')})
    & $compiler /nologo /platform:x64 /target:exe /define:N3_PROTOCOL /main:StudioPsecSimulator /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$exe" $probeSource
    if($LASTEXITCODE -ne 0){throw 'N3 A simulator build failed'}
    & $compiler /nologo /platform:x64 /target:library /optimize+ "/out:$library" $guardSource
    if($LASTEXITCODE -ne 0){throw 'N3 native WFP build failed'}
    Copy-Item -LiteralPath $topology.config -Destination (Join-Path $payload 'fixture.json')
    foreach($name in @('n3-run.ps1','n3-result.ps1','n3-control.ps1','n3-protocol.ps1','n3-target.cjs','psec-run.ps1','psec-observe.ps1','dns-trace.ps1')){
        $source=Join-Path $PSScriptRoot ('windows-lab-'+$name)
        $report.sourceManifest[(Split-Path $source -Leaf)]=(Get-FileHash -LiteralPath $source).Hash
    }
    foreach($source in ($probeSource+$guardSource)){$report.sourceManifest[(Split-Path $source -Leaf)]=(Get-FileHash -LiteralPath $source).Hash}
    $tcpCanary=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$tcpCanary.ExclusiveAddressUse=$true;$tcpCanary.Start()
    $udpCanary=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    $hostListen=New-GateSocket;$hostListen.ExclusiveAddressUse=$true;$hostListen.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0));$hostListen.Listen(8)
    $hostOld=Open-GatePair $hostListen
    $canaries=@($tcpCanary.LocalEndpoint.Port,$udpCanary.Client.LocalEndPoint.Port)
    $policy=@{version='1.0.0';containment='processcontainer';process=@{commandLine=('"'+$exe+'" window '+$prefix+' a healthy '+$ports[0]+' '+$canaries[0]+' '+$canaries[1]+' n3protocol');cwd=$run;timeout=130000};
        filesystem=@{readonlyPaths=@($payload);readwritePaths=@($run)};ui=@{disable=$false};network=@{egress=@{default='deny'};ingress=@{default='deny';hostLoopback='allow'}}}
    [IO.File]::WriteAllText((Join-Path $stage 'hostloopback.json'),($policy|ConvertTo-Json -Depth 8))
    $report.policy=$policy.network
    $manifest=@{mode='n3-synthetic-a';lab=$lab;stage=$stage;probe=$exe;accountSid=$accounts.A.Sid;session=$report.session;
        scope=@{sub=[guid]::NewGuid().ToString();keys=@(1..5|ForEach-Object {[guid]::NewGuid().ToString()});sid=$null;weight=0};
        bind=@{sub=[guid]::NewGuid().ToString();keys=@(1..4|ForEach-Object {[guid]::NewGuid().ToString()});ports=$ports;weight=0};
        relaySha256=(Get-FileHash -LiteralPath $topology.exe).Hash;librarySha256=(Get-FileHash -LiteralPath $library).Hash}
    foreach($role in 'entry','upstream','target'){
        $child=$topology[$role]
        $manifest[$role]=@{pid=$child.process.Id;path=$child.file;startTicks=$child.startTicks}
    }
    Write-GateJson (Join-Path $privateDir 'n3-manifest.json') $manifest
    $control=Join-Path $privateDir 'n3-control.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows-lab-n3-control.ps1') -Destination $control
    $observerBody='$privateDir='+(ConvertTo-LabLiteral $privateDir)+[Environment]::NewLine+'$prefix='+(ConvertTo-LabLiteral $prefix)+[Environment]::NewLine+
        '$guardControlSource='+(ConvertTo-LabLiteral $control)+[Environment]::NewLine+
        [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-dns-trace.ps1'))+[Environment]::NewLine+
        [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-psec-observe.ps1'))
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($observerBody))
    $observer=Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded)
    $observerStarted=$true
    Wait-N3File (Join-Path $privateDir 'ready') 20000
    $report.bindings=Invoke-N3Guard 'ports'
    $report.hostBaseline=Test-N3Host 'baseline' 31
    $baseline='& '+(ConvertTo-LabLiteral $exe)+' n3native '+$prefix+' a baseline '+$ports[0]+' '+$canaries[0]+' '+$canaries[1]+' n3protocol'
    $report.outsideA=Read-LabProbe (Start-LabProbe $accounts.A $baseline)
    $report.outsideHits=Read-N3Canaries
    if($report.outsideA.system.container -ne $false -or $report.outsideA.system.userSid -ne $report.accountSid -or
        $report.outsideHits.tcp -ne 1 -or $report.outsideHits.udp -ne 1 -or
        @($report.outsideA.directTargets.u,$report.outsideA.directTargets.http,$report.outsideA.directTargets.tls|Where-Object {$_ -ne 'sent'}).Count){
        throw 'N3 ordinary A positive control failed'
    }
    $report.coldUpstream=Invoke-N3Child $topology.upstream 'refuse'
    $runner=Join-Path $PSScriptRoot 'windows-lab-psec-run.ps1'
    $aWorkload=& $runner -Stage $stage -Account A -PolicyName hostloopback -Async -HostLoopbackExperiment -N3Protocol
    $ready=Join-Path $run 'sim-ready'
    Wait-N3File $ready 18000 -CheckWorker
    $report.windowReady=Get-Content -LiteralPath $ready -Raw -Encoding UTF8|ConvertFrom-Json
    Assert-N3Scope $report.windowReady
    if(!$report.windowReady.visible){throw 'N3 simulator window not visible'}
    [IO.File]::WriteAllText((Join-Path $privateDir 'sample'),$report.windowReady.containerSid)
    $report.closedScope=Invoke-N3Guard 'install' $report.windowReady
    if($report.closedScope.exceptionPresent -ne $false){throw 'N3 cold startup exception already open'}
    $null=Test-N3Phase 'cold1' $false -Native
    $null=Invoke-N3Child $topology.upstream 'serve'
    $report.firstOpen=Set-N3Healthy 'healthy1'
    $null=Test-N3Phase 'healthy1' $true
    $null=Test-N3Phase 'healthy2' $true -Native
    Invoke-N3Fault 'outage1' 'refuse'
    Invoke-N3Fault 'silent1' 'silent'
    Invoke-N3Fault 'crash1' 'exit'
    $report.finishSequence=Invoke-N3Window 'finish' 'crash1'
    try{$report.execution=Read-LabProbe $aWorkload 10000}finally{$aWorkload=$null}
    if($report.execution.runExit -ne 0){throw ('N3 simulator did not finish cleanly: '+($report.execution.output -join ' '))}
    $report.simulation=($report.execution.output -join [Environment]::NewLine)|ConvertFrom-Json
    Assert-N3Scope $report.simulation
    if($report.simulation.pid -ne $report.windowReady.pid -or $report.simulation.finishSequence -ne $report.finishSequence -or
        $report.simulation.finishPhase -cne 'crash1'){throw 'N3 final acknowledgement did not match'}
    $report.execution.PSObject.Properties.Remove('output')
}catch{$report.error=$_.Exception.Message;$report.errorAt=$_.InvocationInfo.PositionMessage;$report.errorStack=$_.ScriptStackTrace}
finally {
    if($observer -and !$observer.HasExited){
        try{$null=Invoke-N3Guard 'close'}catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    if($aWorkload){
        [IO.File]::WriteAllText((Join-Path $run 'guard-abort'),'1')
        try{$null=Read-LabProbe $aWorkload 12000}catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    if($topology){
        foreach($role in 'entry','upstream','target'){
            try{Stop-N3Process $topology[$role]}catch{$report.cleanup.errors+=@($_.Exception.Message)}
        }
        try{$report.events=Read-N3Events $topology}catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    if($observer){
        if(!$observer.HasExited){
            try {
                $report.cleanup.control=Invoke-N3Guard 'cleanup'
                if($report.cleanup.control.absent -and $report.cleanup.control.bindAbsent){
                    $report.hostAfter=Test-N3Host 'recovered9' 96
                    $report.cleanup.rebind=@(foreach($port in $ports){Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'})
                }
            }catch{$report.cleanup.errors+=@($_.Exception.Message)}
        }
        [IO.File]::WriteAllText((Join-Path $privateDir 'stop'),'1')
        if($observer.WaitForExit(45000) -and (Test-Path -LiteralPath (Join-Path $privateDir 'result.json'))){
            $report.observer=Get-Content -LiteralPath (Join-Path $privateDir 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json
        }else{$report.cleanup.errors+=@('Observer did not write final evidence')}
        $observer.Dispose()
    }
    if($hostOld){Close-GatePair $hostOld}
    if($hostListen){$hostListen.Dispose()}
    if($tcpCanary){$tcpCanary.Stop()}
    if($udpCanary){$udpCanary.Dispose()}
    $clean=$report.observer.staticGuardCleanup.absent -and $report.observer.staticGuardCleanup.bindAbsent
    if($observerStarted -and !$clean){
        $report.cleanup.retainedDirectory=$privateDir
        $report.cleanup.rollbackScript=Join-Path $privateDir 'n3-control.ps1'
    }
    if(!$observerStarted -or $clean){
        try {
            if($stageCreated){
                $stageItem=Get-Item -LiteralPath $stage
                if($stageItem.Parent.FullName -ine $lab -or $stageItem.Name -cne $stageTag -or
                    $stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                    @(Get-ChildItem -LiteralPath $stage -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'N3 stage refused cleanup'}
                Remove-Item -LiteralPath $stageItem.FullName -Recurse -Force
            }
            $report.cleanup.stageGone=!(Test-Path -LiteralPath $stage)
            if($privateCreated){Remove-N3Directory $privateDir $privateTag}
            $report.cleanup.directoryGone=!(Test-Path -LiteralPath $privateDir)
        }catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    try{$report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-n3-result.ps1') $report;$report.outcome=$report.assessment.outcome}
    catch{$report.assessmentError=$_.Exception.Message}
    [IO.File]::WriteAllText($output,($report|ConvertTo-Json -Depth 19))
    [pscustomobject]@{file=$output;outcome=$report.outcome;error=$report.error;assessment=$report.assessment;cleanup=$report.cleanup}|ConvertTo-Json -Depth 6
}
if($report.outcome -ne 'passed-n3-a'){exit 2}
