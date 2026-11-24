param([Parameter(Mandatory)][string]$Stage, [switch]$Networkless, [switch]$Loopback, [switch]$HostLoopback, [switch]$ReferenceRun, [switch]$PortGuard, [switch]$FlowChecks, [switch]$StaticGuard, [switch]$BindGuard)
$ErrorActionPreference = 'Stop'
if($BindGuard){$StaticGuard=$true}
if($StaticGuard){$FlowChecks=$true}
if($FlowChecks){$PortGuard=$true}
if ($PortGuard) {$HostLoopback=$true}
if ($ReferenceRun -and (!$Networkless -or $Loopback -or $HostLoopback)) { throw 'ReferenceRun requires only Networkless' }
if ($HostLoopback -and $Loopback) { throw 'Choose only one loopback mode' }
$Networkless = $Networkless -or $Loopback -or $HostLoopback
$phase = if ($Loopback -or $HostLoopback) { 'healthy' } else { 'stopped' }
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
$Stage = (Resolve-Path -LiteralPath $Stage).Path
$lab = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
if ((Split-Path $Stage -Parent) -ne $lab -or (Split-Path $Stage -Leaf) -notmatch '^psec-[0-9a-f]{32}$') {
    throw 'Expected a dedicated psec lab directory'
}
$accounts = Get-LabAccounts
$prefix = 'studio-' + [guid]::NewGuid().ToString('N').Substring(0,16)
$peer = 'ClaudeStudio.MockProxy.' + (Split-Path $Stage -Leaf).Substring(5)
$run = New-Item -ItemType Directory -Path (Join-Path $Stage $prefix)
$payload = Join-Path $Stage 'payload'
if (!(Test-Path -LiteralPath $payload)) { [void][IO.Directory]::CreateDirectory($payload) }
$exe = Join-Path $payload 'StudioProbe.exe'
function Build-Mock([string]$Destination) {
    & (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') /nologo /target:exe /platform:x64 /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$Destination" (Join-Path $PSScriptRoot 'windows-lab-psec-probe.cs') (Join-Path $PSScriptRoot 'windows-lab-portguard-flow.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Simulator compilation failed' }
}
if(!$BindGuard){Build-Mock $exe}
$reportName = if ($HostLoopback) { 'windows-psec-hostloopback.json' } elseif ($Loopback) { 'windows-psec-s1-loopback.json' } elseif ($Networkless) { 'windows-psec-networkless.json' } else { 'windows-psec-stopped.json' }
$reportPath = Join-Path (Split-Path $lab -Parent) ('mock-results\' + $reportName)
if ($ReferenceRun) { $reportPath=Join-Path (Split-Path $lab -Parent) 'mock-results\windows-psec-hostloopback-baseline.json' }
if ($PortGuard) { $reportPath=Join-Path (Split-Path $lab -Parent) 'mock-results\windows-psec-hostloopback-portguard.json' }
if ($FlowChecks) { $reportPath=Join-Path (Split-Path $lab -Parent) 'mock-results\windows-psec-hostloopback-portguard-flows.json' }
if ($StaticGuard) { $reportPath=Join-Path (Split-Path $lab -Parent) 'mock-results\windows-psec-static-guard.json' }
if ($BindGuard) { $reportPath=Join-Path (Split-Path $lab -Parent) 'mock-results\windows-psec-bind-guard.json' }
$report = [ordered]@{experiment='A / ProcessContainer / stopped proxy'; run=$prefix; sdk='1.1.0'; gui='synthetic WinForms'; accountSid=$accounts.A.Sid; controlledProxyRegistered=$false}
$report.executorSha256=(Get-FileHash -LiteralPath (Join-Path $Stage 'wxc-exec.exe') -Algorithm SHA256).Hash
$report.probeSourceSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'windows-lab-psec-probe.cs') -Algorithm SHA256).Hash
if ($Networkless) { $report.experiment='A / ProcessContainer / no network capabilities' }
if ($Loopback -or $HostLoopback) {
    $report.experiment='S1 / A / ProcessContainer / in-container HTTP proxy'
    $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild="$($windows.CurrentBuildNumber).$($windows.UBR)"
}
if ($HostLoopback) { $report.experiment='A / only networkLoopback / temporary host HTTP proxy' }
if ($PortGuard) {$report.experiment='A / exact AppContainer SID / dynamic proxy port guard';$report.portGuard=$true}
if($FlowChecks){$report.flowChecks=$true;$report.flowSourceSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'windows-lab-portguard-flow.cs')).Hash}
if($StaticGuard){
    $report.experiment='N1 / A / static deny with dynamic exception';$report.staticGuard=@{};$report.sourceManifest=@{}
    foreach($name in 'windows-lab-wfp.cs','windows-lab-wfp-container.cs','windows-lab-static-guard-control.ps1','windows-lab-static-guard-scenarios.ps1','windows-lab-static-guard-result.ps1','windows-lab-portguard-flow.cs','windows-lab-portguard-scenarios.ps1','windows-lab-psec-stopped.ps1','windows-lab-psec-run.ps1','windows-lab-psec-observe.ps1','windows-lab-dns-trace.ps1','windows-lab-hostloopback.ps1'){
        $report.sourceManifest[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash
    }
}
$ports = @{}
$close = [Collections.Generic.List[IDisposable]]::new()
$privateDir = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioTrace-' + $prefix)
$proxyExe=$exe
$n2PrivateCreated=$false
$observer = $null
$worker = $null
$proxyProcess = $null
$go = Join-Path $run.FullName 'host-go'

function Wait-GuardFile([string]$Path) {
    $until=[datetime]::UtcNow.AddSeconds($(if($FlowChecks){28}else{16}))
    while (!(Test-Path -LiteralPath $Path)) {
        if (Test-Path -LiteralPath (Join-Path $privateDir 'guard-error')) {throw ([IO.File]::ReadAllText((Join-Path $privateDir 'guard-error')))}
        if ($observer.HasExited -or ($worker -and $worker.Process.HasExited) -or [datetime]::UtcNow -gt $until) {throw ('Guard handoff failed: '+(Split-Path $Path -Leaf))}
        if($StaticGuard -and $guardWorkClock -and $guardWorkClock.Elapsed.TotalSeconds -gt 90 -and $Path -notlike '*guard-cleanup-done'){throw 'N1 work deadline exceeded'}
        Start-Sleep -Milliseconds 60
    }
}

function New-Listener {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $listener.ExclusiveAddressUse=$true
    $listener.Start()
    return $listener
}
function Open-Pair($Listener) {
    $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Connect([Net.IPAddress]::Loopback,$Listener.LocalEndpoint.Port)
        $server=$Listener.AcceptTcpClient()
        $client.ReceiveTimeout=$server.ReceiveTimeout=1800
        return @{client=$client; server=$server}
    } catch { $client.Dispose(); throw }
}
function Test-Pair($Pair,[byte]$Mark) {
    $c=$Pair.client.GetStream()
    $s=$Pair.server.GetStream()
    $c.WriteByte($Mark)
    if ($s.ReadByte() -ne $Mark) { throw 'Host request lost' }
    $s.WriteByte(255-$Mark)
    if ($c.ReadByte() -ne (255-$Mark)) { throw 'Host reply lost' }
    return $true
}
function Test-Host([string]$Phase,[byte]$Mark) {
    $started=[datetime]::UtcNow.ToString('o')
    $pair=Open-Pair $hostListener
    try {
        $info=@{pid=$PID; old=(Test-Pair $old $Mark); fresh=(Test-Pair $pair $Mark)}
        try {
            $records=@(Resolve-DnsName -Name ($prefix+'-h-'+$Phase+'.test.') -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
            $info.dns='answered'
            $info.records=$records.Count
        } catch { $info.dns=$_.FullyQualifiedErrorId }
        $info.startedUtc=$started;$info.finishedUtc=[datetime]::UtcNow.ToString('o');$info.phase=$Phase
        return $info
    } finally { $pair.client.Dispose(); $pair.server.Dispose() }
}
function Get-DirectHits {
    $tc=0; $dg=0
    while ($tcp.Pending()) {
        $client=$tcp.AcceptTcpClient()
        try { $client.ReceiveTimeout=500; if ($client.GetStream().ReadByte() -eq 85) { $tc++ } } finally { $client.Dispose() }
    }
    while ($udp.Available -gt 0) {
        $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $data=$udp.Receive([ref]$remote)
        if ($data.Length -eq 1 -and $data[0] -eq 85) { $dg++ }
    }
    $result=@{tcp=$tc; udp=$dg}
    if($udpProxy) {
        $count=0
        while($udpProxy.Available -gt 0){$remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0);$data=$udpProxy.Receive([ref]$remote);if($data.Length -eq 1 -and $data[0] -eq 85){$count++}}
        $result.udpProxy=$count
    }
    foreach($entry in @(@{key='alternate';listener=$alternate},@{key='local';listener=$localCanary})) {
        if(!$entry.listener){continue}
        $count=0
        while($entry.listener.Pending()){$client=$entry.listener.AcceptTcpClient();try{$client.ReceiveTimeout=500;if($client.GetStream().ReadByte() -eq 85){$count++}}finally{$client.Dispose()}}
        $result[$entry.key]=$count
    }
    return $result
}
function Verify-Scope($Result) {
    if (!$Result.container -or !$Result.inJob -or $Result.userSid -ne $accounts.A.Sid -or $Result.session -ne $report.session -or
        $Result.containerSid -notmatch '^S-1-15-2(-[0-9]+){7}$') { throw 'Simulator token or session mismatch' }
}
function Test-HostToContainer([int]$Port) {
    $result = @{attempted=$true; connected=$false}
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connect = $client.BeginConnect([Net.IPAddress]::Loopback,$Port,$null,$null)
        $completed = $connect.AsyncWaitHandle
        try {
            if (!$completed.WaitOne(1600)) {
                $result.status='timeout'
                return $result
            }
            $client.EndConnect($connect)
        } finally { $completed.Dispose() }
        $result.connected=$true
        $result.status='connected'
        $client.SendTimeout=800
        $request=('GET http://{0}-a-window-{1}.test/studio-probe?host HTTP/1.1' -f $prefix,$phase) + "`r`nConnection: close`r`n`r`n"
        $bytes=[Text.Encoding]::ASCII.GetBytes($request)
        $client.GetStream().Write($bytes,0,$bytes.Length)
    } catch [Net.Sockets.SocketException] {
        $result.status=$_.Exception.SocketErrorCode.ToString()
        $result.nativeError=$_.Exception.NativeErrorCode
    } catch [IO.IOException] {
        $result.status='send-failed'
    } finally { $client.Dispose() }
    return $result
}

try {
    if($BindGuard){
        $report.experiment='N2 / A / sealed TCP ports with proxy rotation'
        $report.bindGuard=@{}
        . (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly
        . (Join-Path $PSScriptRoot 'windows-lab-bind-scenarios.ps1') -FunctionsOnly
        $n2Ports=[uint16[]]@(Select-N2Ports 2)
        $report.bindGuard.ports=$n2Ports
        if(Test-Path -LiteralPath $privateDir){throw 'N2 private directory collision'}
        [void][IO.Directory]::CreateDirectory($privateDir,(New-N2PrivateAcl))
        $n2PrivateCreated=$true
        $report.bindGuard.privateAclProtected=(Get-Acl -LiteralPath $privateDir).AreAccessRulesProtected
        $proxyExe=Join-Path $privateDir 'StudioN2Proxy.exe'
        Build-Mock $proxyExe
        $report.bindGuard.proxySha256=(Get-FileHash -LiteralPath $proxyExe).Hash
        Copy-Item -LiteralPath $proxyExe -Destination $exe
        if($report.bindGuard.proxySha256 -ne (Get-FileHash -LiteralPath $exe).Hash){throw 'N2 proxy copy hash mismatch'}
        foreach($source in 'windows-lab-wfp-bind.cs','windows-lab-bind-scenarios.ps1','windows-lab-bind-gate.ps1','windows-lab-bind-result.ps1'){
            $report.sourceManifest[$source]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $source)).Hash
        }
        $report.bindGuard.aclControl=Test-N2PrivateAccess
        $report.bindGuard.preBind=@(Invoke-N2BindMatrix $n2Ports[0] -Baseline)
    }
    if (!$Loopback -and !$HostLoopback) {
        # Reserve but never listen on the proxy port.
        $reservation=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
        $close.Add($reservation); $reservation.ExclusiveAddressUse=$true
        $reservation.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    }
    $tcp=New-Listener
    $udp=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    $close.Add($udp)
    $hostListener=New-Listener
    $old=Open-Pair $hostListener
    $close.Add($old.client); $close.Add($old.server)
    $ports=@{tcp=$tcp.LocalEndpoint.Port; udp=$udp.Client.LocalEndPoint.Port; host=$hostListener.LocalEndpoint.Port}
    if ($reservation) { $ports.proxy=$reservation.LocalEndPoint.Port }
    if ($HostLoopback) {
        $proxyArgs=if($FlowChecks){'guardproxy '+$prefix+' a healthy '+$(if($BindGuard){$n2Ports[0]}else{0})+' '+$ports.tcp+' '+$ports.udp+' portguardflow'}else{'hostproxy '+$prefix+' a healthy '+$ports.tcp+' '+$ports.tcp+' '+$ports.udp+' hostloopback'}
        $start=[Diagnostics.ProcessStartInfo]::new($proxyExe,$proxyArgs)
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $proxyProcess=[Diagnostics.Process]::Start($start)
        $proxyErrors=$proxyProcess.StandardError.ReadToEndAsync()
        $proxyReady=$proxyProcess.StandardOutput.ReadLineAsync()
        if (!$proxyReady.Wait(5000) -or !$proxyReady.Result) { throw 'Host proxy did not start' }
        $report.proxyReady=$proxyReady.Result | ConvertFrom-Json
        if (!$report.proxyReady.listening -or $report.proxyReady.container -or $report.proxyReady.pid -ne $proxyProcess.Id) { throw 'Unexpected host proxy scope' }
        $ports.proxy=[int]$report.proxyReady.port
    }
    if($PortGuard) {
        $udpProxy=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$ports.proxy));$close.Add($udpProxy)
        $alternate=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.2'),$(if($BindGuard){0}else{$ports.proxy}));$alternate.ExclusiveAddressUse=$true;$alternate.Start()
        $extra=@{proxyPort=$ports.proxy;alternatePort=$alternate.LocalEndpoint.Port}
        $localAddress=@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -eq 'Ethernet'} | ForEach-Object {$_.GetIPProperties().UnicastAddresses} | Where-Object {$_.Address.AddressFamily -eq 'InterNetwork' -and ![Net.IPAddress]::IsLoopback($_.Address)} | Select-Object -First 1)
        if($localAddress.Count) {$localCanary=[Net.Sockets.TcpListener]::new($localAddress[0].Address,0);$localCanary.ExclusiveAddressUse=$true;$localCanary.Start();$ports.local=$localCanary.LocalEndpoint.Port;$extra.localAddress=$localAddress[0].Address.ToString();$extra.localPort=$ports.local}
        [IO.File]::WriteAllText((Join-Path $run.FullName 'guard-extra.json'),($extra|ConvertTo-Json))
        $report.extraCanaries=$extra
    }
    $proxyPort = if ($Loopback) { $ports.tcp } else { $ports.proxy }
    foreach ($p in $ports.GetEnumerator()) { if ($p.Value -lt 49152 -and !($BindGuard -and $p.Key -eq 'proxy' -and $p.Value -eq $n2Ports[0])) {throw 'Expected a dynamic or checked N2 port'} }
    $report.ports=$ports
    $report.session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    $argsText=' a '+$phase+' '+$proxyPort+' '+$ports.tcp+' '+$ports.udp
    if ($FlowChecks) { $argsText+=' portguardflow' } elseif ($PortGuard) { $argsText+=' portguard' } elseif ($HostLoopback) { $argsText+=' hostloopback' } elseif ($Loopback) { $argsText+=' loopback' } elseif ($Networkless) { $argsText+=' networkless' }
    $policy=[ordered]@{version='1.0.0';containment='processcontainer';process=@{commandLine=('"'+$exe+'" window '+$prefix+$argsText);cwd=$run.FullName;timeout=55000}
        filesystem=@{readonlyPaths=@($payload);readwritePaths=@($run.FullName)}
        ui=@{disable=$false}; network=@{egress=@{default='deny'};ingress=@{default='deny';hostLoopback='deny'}}}
    if (!$Networkless) {
        $policy.network.ingress.default='allow'
        $policy.runtimeConfig=@{networkProxy=('http://127.0.0.1:'+$ports.proxy)}
        $policy.processContainer=@{network=@{allowedProxyPeer=$peer}}
    }
    if ($HostLoopback) { $policy.network.ingress.hostLoopback='allow' }
    if($FlowChecks){$policy.process.timeout=165000}
    if($StaticGuard){$policy.process.timeout=90000}
    $policyName=if ($HostLoopback) {'hostloopback'} else {'stopped'}
    $policyPath=Join-Path $Stage ($policyName+'.json')
    [IO.File]::WriteAllText($policyPath,($policy | ConvertTo-Json -Depth 8))
    $report.policy=@{peer=$policy.processContainer.network.allowedProxyPeer;egress='deny';ingress=$policy.network.ingress.default;
        hostLoopback=$policy.network.ingress.hostLoopback;runtimeProxy=$policy.runtimeConfig.networkProxy;networkless=[bool]$Networkless;loopback=[bool]$Loopback;hostLoopbackExperiment=[bool]$HostLoopback;phase=$phase}
    if (!$BindGuard){
    if (Test-Path -LiteralPath $privateDir) { throw 'Trace directory collision' }
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    [void][IO.Directory]::CreateDirectory($privateDir,$acl)
    }
    $guardControlSource=$null
    if ($PortGuard) {
        $library=Join-Path $(if($BindGuard){$privateDir}else{$Stage}) 'ContainerGuard.dll'
        $wfpSources=@((Join-Path $PSScriptRoot 'windows-lab-wfp.cs'),(Join-Path $PSScriptRoot 'windows-lab-wfp-container.cs'))
        if($BindGuard){$wfpSources+=@(Join-Path $PSScriptRoot 'windows-lab-wfp-bind.cs')}
        & (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') /nologo /target:library /platform:x64 /optimize+ "/out:$library" $wfpSources
        if ($LASTEXITCODE -ne 0) {throw 'Container guard compilation failed'}
        $settings=@{library=$library;sublayer=[guid]::NewGuid().ToString();keys=@(1..7|ForEach-Object {[guid]::NewGuid().ToString()});port=$ports.proxy;accountSid=$accounts.A.Sid;session=$report.session;executable=$exe}
        if($StaticGuard){$settings.keys=@(1..5|ForEach-Object {[guid]::NewGuid().ToString()});$settings.mode='static-a-only';$settings.owners=@();$settings.proxyPid=$proxyProcess.Id}
        if($BindGuard){
            $settings.mode='bind-guard-a-only';$settings.lab=$lab;$settings.proxyExecutable=$proxyExe
            $settings.bind=@{sub=[guid]::NewGuid().ToString();keys=@(1..4|ForEach-Object {[guid]::NewGuid().ToString()});ports=$n2Ports;owners=@();weight=0}
        }
        [IO.File]::WriteAllText((Join-Path $privateDir 'guard-settings.json'),($settings|ConvertTo-Json -Depth 4))
        $guardControlSource=Join-Path $PSScriptRoot 'windows-lab-portguard-control.ps1'
        if($StaticGuard){$guardControlSource=Join-Path $PSScriptRoot 'windows-lab-static-guard-control.ps1'}
        if($BindGuard){
            $privateControl=Join-Path $privateDir 'windows-lab-static-guard-control.ps1'
            Copy-Item -LiteralPath $guardControlSource -Destination $privateControl
            $guardControlSource=$privateControl
        }
    }
    $observerCode='$privateDir='+ (ConvertTo-LabLiteral $privateDir) + [Environment]::NewLine + '$prefix=' + (ConvertTo-LabLiteral $prefix) +
        [Environment]::NewLine + '$guardControlSource=' + (ConvertTo-LabLiteral $guardControlSource) +
        [Environment]::NewLine + [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-dns-trace.ps1')) +
        [Environment]::NewLine + [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-lab-psec-observe.ps1'))
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($observerCode))
    $observer=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru
    $until=[datetime]::UtcNow.AddSeconds(20)
    while (!(Test-Path -LiteralPath (Join-Path $privateDir 'ready'))) {
        if ($observer.HasExited -or [datetime]::UtcNow -gt $until) { throw 'DNS observer did not start' }
        Start-Sleep -Milliseconds 100
    }
    $report.hostBefore=Test-Host 'baseline' 31
    if($BindGuard){
        . (Join-Path $PSScriptRoot 'windows-lab-portguard-scenarios.ps1') -FunctionsOnly
        $claim=Get-N2ProxyClaim $proxyProcess $n2Ports[0] $report.proxyReady
        $report.bindGuard.pReadback=Invoke-N2Control 'bind-install' $claim
        $report.bindGuard.pHealthBeforeA=Test-N2ProxyHealth 'healthy8'
        if(!$report.bindGuard.pHealthBeforeA){throw 'P proxy health failed after bind guard'}
        $report.bindGuard.liveBind=@(Invoke-N2BindMatrix $n2Ports[0] -Live)
    }
    if($StaticGuard){$guardWorkClock=[Diagnostics.Stopwatch]::StartNew()}
    $baselineBody='& '+(ConvertTo-LabLiteral $exe)+' native '+$prefix+' a baseline '+$proxyPort+' '+$ports.tcp+' '+$ports.udp
    $report.baseline=Read-LabProbe (Start-LabProbe $accounts.A $baselineBody)
    $report.baselineHits=Get-DirectHits
    if ($report.baseline.container -or $report.baselineHits.tcp -ne 1 -or $report.baselineHits.udp -ne 1) { throw 'Ordinary A control failed' }
    if ($Loopback) {
        $existingHostPorts=@([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object Port)
    }
    $runner=Join-Path $PSScriptRoot 'windows-lab-psec-run.ps1'
    $worker=& $runner -Stage $Stage -Account A -PolicyName $policyName -Async -HostLoopbackExperiment:$HostLoopback -StaticGuard:$StaticGuard
    $ready=Join-Path $run.FullName 'sim-ready'
    $until=[datetime]::UtcNow.AddSeconds(18)
    while (!(Test-Path -LiteralPath $ready) -and !$worker.Process.HasExited -and [datetime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
    if (Test-Path -LiteralPath $ready) {
        $identity=Get-Content -LiteralPath $ready -Raw -Encoding UTF8 | ConvertFrom-Json
        Verify-Scope $identity
        $report.windowReady=$identity
        [IO.File]::WriteAllText((Join-Path $privateDir 'sample'),$identity.containerSid)
        if ($HostLoopback -and ($identity.networkCapabilities.Count -ne 1 -or
            $identity.networkCapabilities[0] -ne 'S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225')) { throw 'Unexpected network capabilities' }
        if ($PortGuard) {
            Verify-Scope $identity.listenerReady
            if($identity.listenerReady.containerSid -ne $identity.containerSid -or $identity.listenerReady.pid -eq $identity.pid -or
                $identity.listenerReady.networkCapabilities.Count -ne 1 -or $identity.listenerReady.networkCapabilities[0] -ne $identity.networkCapabilities[0]){throw 'Guard listener scope mismatch'}
            [IO.File]::WriteAllText((Join-Path $run.FullName 'guard-baseline-go'),'1')
            $baselineFile=Join-Path $run.FullName 'guard-baseline-result.json'
            Wait-GuardFile $baselineFile
            $report.guardBaseline=Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json
            Verify-Scope $report.guardBaseline.native
            $report.guardBaselineHits=Get-DirectHits
            $report.hostReverseBaseline=Test-HostToContainer $identity.listenerReady.port
            if ($report.guardBaseline.windowHttp -ne 'matched' -or $report.guardBaseline.native.proxyHttp -ne 'matched' -or
                $report.guardBaselineHits.tcp -ne 1 -or $report.guardBaselineHits.udp -ne 1) {throw 'Same-container baseline failed'}
            [IO.File]::WriteAllText((Join-Path $privateDir 'guard-install'),($identity|ConvertTo-Json -Depth 5))
            Wait-GuardFile (Join-Path $privateDir 'guard-install-done')
            if($StaticGuard){$report.staticGuard.installClosedReadback=Get-Content -LiteralPath (Join-Path $privateDir 'guard-install-done') -Raw|ConvertFrom-Json}
            [IO.File]::WriteAllText((Join-Path $run.FullName 'guard-gate-go'),'1')
            $gateFile=Join-Path $run.FullName 'guard-gate-result.json'
            Wait-GuardFile $gateFile
            $report.guardGate=Get-Content -LiteralPath $gateFile -Raw | ConvertFrom-Json
            Verify-Scope $report.guardGate.native
            $report.guardGateHits=Get-DirectHits
            $report.hostReverseGate=Test-HostToContainer $identity.listenerReady.port
            $report.hostGate=Test-Host 'stopped' 51
            $controlBody='Set-Location -LiteralPath '+(ConvertTo-LabLiteral $run.FullName)+[Environment]::NewLine+'& '+(ConvertTo-LabLiteral $exe)+' native '+$prefix+' a stopped '+$proxyPort+' '+$ports.tcp+' '+$ports.udp+' portguard'
            $report.outsideGate=Read-LabProbe (Start-LabProbe $accounts.A $controlBody)
            $report.outsideGateHits=Get-DirectHits
            if($report.guardGate.windowHttp -eq 'matched' -or $report.guardGate.native.proxyHttp -eq 'matched' -or
                $report.guardGateHits.tcp -ne 0 -or $report.guardGateHits.udp -ne 0) {throw 'Offline gate did not block A; stop before further phases'}
            if($report.hostReverseBaseline.connected -and $report.hostReverseGate.connected){throw 'Container inbound guard failed'}
            if($report.outsideGate.container -or $report.outsideGate.native -or $report.outsideGate.proxyHttp -ne 'matched' -or
                $report.outsideGateHits.tcp -ne 1 -or $report.outsideGateHits.udp -ne 1) {throw 'Gate affected ordinary A control'}
            [IO.File]::WriteAllText((Join-Path $privateDir 'guard-open'),'1')
            Wait-GuardFile (Join-Path $privateDir 'guard-open-done')
            if($StaticGuard){$report.staticGuard.initialPermitReadback=Get-Content -LiteralPath (Join-Path $privateDir 'guard-open-done') -Raw|ConvertFrom-Json}
        }
        if ($Loopback) {
            Verify-Scope $identity.listenerReady
            if ($identity.listenerReady.containerSid -ne $identity.containerSid -or
                $identity.listenerReady.pid -eq $identity.pid -or $identity.listenerReady.networkCapabilities.Count -ne 0 -or
                $identity.networkCapabilities.Count -ne 0) { throw 'Unexpected listener token or process' }
            if ($identity.listenerReady.listening) {
                $ports.inner=$identity.listenerReady.port
                if ($ports.inner -lt 49152 -or $ports.inner -gt 65535) { throw 'Invalid container listener port' }
                if ($ports.inner -in $existingHostPorts) { throw 'Container listener collides with an existing host TCP listener' }
                $report.hostReverse=Test-HostToContainer $ports.inner
            }
        }
        $report.hostDuring=Test-Host $phase 65
        $until=[datetime]::UtcNow.AddSeconds(12)
        while (!(Test-Path -LiteralPath (Join-Path $privateDir 'sampled')) -and [datetime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
    }
    [IO.File]::WriteAllText($go,'1')
    if($FlowChecks){
        Wait-GuardFile (Join-Path $run.FullName 'guard-healthy-result.json')
        $report.healthyCheckpoint=Get-Content -LiteralPath (Join-Path $run.FullName 'guard-healthy-result.json') -Raw | ConvertFrom-Json
        $report.healthyCheckpointHits=Get-DirectHits
        if($report.healthyCheckpoint.windowHttp -ne 'matched' -or $report.healthyCheckpoint.native.proxyHttp -ne 'matched' -or
            @($report.healthyCheckpointHits.Values|Where-Object {$_ -ne 0}).Count){throw 'Expanded healthy guard failed'}
        if($BindGuard){. (Join-Path $PSScriptRoot 'windows-lab-bind-scenarios.ps1')}
        elseif($StaticGuard){. (Join-Path $PSScriptRoot 'windows-lab-static-guard-scenarios.ps1')}
        else {. (Join-Path $PSScriptRoot 'windows-lab-portguard-scenarios.ps1')}
    }
    try { $report.execution=Read-LabProbe $worker 65000 } finally { $worker=$null }
    $report.containerHits=Get-DirectHits
    if ($report.execution.runExit -ne 0 -or !$report.windowReady) { throw 'Container window did not complete, see execution output' }
    $report.simulation=($report.execution.output -join [Environment]::NewLine) | ConvertFrom-Json
    Verify-Scope $report.simulation
    Verify-Scope $report.simulation.native
    if (!$report.simulation.visible -or $report.simulation.containerSid -ne $report.simulation.native.containerSid) { throw 'Window visibility or child container membership failed' }
    $report.execution.PSObject.Properties.Remove('output')
} catch { $report.error=$_.Exception.Message }
finally {
    if ($worker) {
        if ($PortGuard) {[IO.File]::WriteAllText((Join-Path $run.FullName 'guard-abort'),'1')}
        else {[IO.File]::WriteAllText($go,'1')}
        try { $report.unfinished=Read-LabProbe $worker 65000 } catch { $report.workerError=$_.Exception.Message } finally {$worker=$null}
    }
    if ($old) { try { $report.hostAfter=Test-Host 'recovered' 86 } catch { $report.hostError=$_.Exception.Message } }
    if ($proxyProcess) {
        try {
            if($FlowChecks -and !$proxyProcess.HasExited -and (Get-Command Invoke-GuardProxy -ErrorAction SilentlyContinue)){$report.proxyFinal=Invoke-GuardProxy 'exit'}
            $proxyProcess.StandardInput.Close()
            $proxyResult=$proxyProcess.StandardOutput.ReadToEndAsync()
            if (!$proxyProcess.WaitForExit(5000)) { $proxyProcess.Kill(); $report.proxyError='Proxy timeout' }
            elseif ($proxyProcess.ExitCode -ne 0) { $report.proxyError='Proxy failed' }
            elseif ($proxyResult.Wait(1000) -and $proxyResult.Result) { $report.proxyResult=$proxyResult.Result | ConvertFrom-Json }
            if ($proxyErrors.Wait(1000) -and $proxyErrors.Result) { $report.proxyError=$proxyErrors.Result }
        } catch { $report.proxyError=$_.Exception.Message; if(!$proxyProcess.HasExited){$proxyProcess.Kill();[void]$proxyProcess.WaitForExit(2000)} }
        finally { $proxyProcess.Dispose() }
    }
    if ($observer) {
        if($StaticGuard -and !$observer.HasExited){
            try {
                [IO.File]::WriteAllText((Join-Path $privateDir 'guard-cleanup'),'1')
                Wait-GuardFile (Join-Path $privateDir 'guard-cleanup-done')
                $report.postRollbackHost=Test-Host 'recovered9' 97
                if($BindGuard){$report.bindGuard.rebind=@(foreach($port in $n2Ports){Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'})}
            } catch {$report.staticCleanupError=$_.Exception.Message}
        }
        [IO.File]::WriteAllText((Join-Path $privateDir 'stop'),'1')
        if ($observer.WaitForExit(50000) -and (Test-Path -LiteralPath (Join-Path $privateDir 'result.json'))) {
            $report.observer = Get-Content -LiteralPath (Join-Path $privateDir 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        } else { $report.observerError='Observer did not produce a final report' }
        $observer.Dispose()
        if($StaticGuard -and $report.observer){$report.staticGuard.installationSessionClosed=$report.observer.installationSessionClosed;$report.staticGuard.installClosedUtc=$report.observer.installClosedUtc}
    }
    if ($tcp) { $tcp.Stop() }
    if ($hostListener) { $hostListener.Stop() }
    if ($alternate) {$alternate.Stop()}
    if ($localCanary) {$localCanary.Stop()}
    foreach($resource in $close) { $resource.Dispose() }
    $ip=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $report.remainingTcpListeners=@($ip.GetActiveTcpListeners() | Where-Object { $_.Port -in (@($ports.proxy,$ports.host,$ports.tcp,$ports.inner,$ports.local)+@($n2Ports)) } | ForEach-Object Port)
    $report.remainingUdpListeners=@($ip.GetActiveUdpListeners() | Where-Object { $_.Port -in (@($ports.udp,$ports.proxy)+@($n2Ports)) } | ForEach-Object Port)
    if (Test-Path -LiteralPath $privateDir) {
        # Only remove our named evidence handoff files after the observer finishes.
        if ($report.observer -and (!$StaticGuard -or $report.observer.staticGuardCleanup.absent)) {
            foreach ($file in 'result.json','stop','ready','sample','sampled','guard-settings.json','guard-settings.json.tmp','guard-settings.json.bak','guard-install','guard-install-done','guard-open','guard-open-done','guard-close','guard-close-done','guard-error') {
                $owned=Join-Path $privateDir $file
                if (Test-Path -LiteralPath $owned) { Remove-Item -LiteralPath $owned }
            }
            if($StaticGuard){
                Get-ChildItem -LiteralPath $privateDir -File|Where-Object {$_.Name -match '^(owner-(start|stop|ready|error)-[12]|guard-(crash|recover|cleanup)(-done)?|independent-rollback\.json)$'}|Remove-Item
            }
            if($BindGuard){
                Get-ChildItem -LiteralPath $privateDir -File | Where-Object {$_.Name -match '^(guard-(bind-(install|read-p|rotate|read-q)|crash-next)(-done)?|StudioN2Proxy\.exe|ContainerGuard\.dll|windows-lab-static-guard-control\.ps1)$'} | ForEach-Object {Remove-Item -LiteralPath $_.FullName}
            }
            if (!@(Get-ChildItem -LiteralPath $privateDir -Force).Count) { [IO.Directory]::Delete($privateDir) }
        }
        if($BindGuard -and $n2PrivateCreated -and !$observer){
            # No elevated process started, so no rule could have been written.
            foreach($name in 'StudioN2Proxy.exe','ContainerGuard.dll','windows-lab-static-guard-control.ps1','guard-settings.json'){
                $owned=Join-Path $privateDir $name
                if(Test-Path -LiteralPath $owned){Remove-Item -LiteralPath $owned}
            }
            if(!@(Get-ChildItem -LiteralPath $privateDir -Force).Count){[IO.Directory]::Delete($privateDir)}
            $report.bindGuard.noObserverNoRuleWrite=$true
        }
        $report.privateDirectoryGone=!(Test-Path -LiteralPath $privateDir)
    }
    if ($report.simulation -and $report.observer.dns) {
        $dns=$report.observer.dns
        $events=@($dns.events)
        $report.dnsResult=@{}
        foreach ($api in 'dns','addr') {
            $sent=@($events | Where-Object { $_.profile -eq 'A' -and $_.phase -eq $phase -and $_.probe -eq $api -and $_.event -eq 3010 -and $_.clientPid -eq $report.simulation.native.pid -and $_.emitterPid -eq $dns.servicePid })
            $reply=@($events | Where-Object { $_.profile -eq 'A' -and $_.phase -eq $phase -and $_.probe -eq $api -and $_.event -eq 3011 -and $_.clientPid -eq $report.simulation.native.pid -and $_.emitterPid -eq $dns.servicePid })
            $report.dnsResult[$api]=@{serviceSends=$sent.Count; serviceReplies=$reply.Count}
        }
    }
    if ($Loopback -or $HostLoopback) {
        $known=@(@($report.windowReady.pid,$report.windowReady.listenerReady.pid,$report.simulation.native.pid,$report.proxyReady.pid,$report.guardBaseline.native.pid,$report.guardGate.native.pid) | Where-Object { $_ -gt 0 })
        $report.remainingProbePids=@(if ($known.Count) {
            Get-Process -Id $known -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq 'StudioProbe' } | ForEach-Object Id
        })
    }
    foreach ($marker in 'sim-ready','sim-ready.tmp','host-go','guard-abort','guard-baseline-go','guard-gate-go','guard-baseline-result.json','guard-gate-result.json','guard-baseline-result.json.tmp','guard-gate-result.json.tmp','guard-extra.json','guard-healthy-result.json') {
        $file=Join-Path $run.FullName $marker
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    if($FlowChecks){Get-ChildItem -LiteralPath $run.FullName -File | Where-Object {$_.Name -match '^flow-(command|result)-[0-9]+\.json(\.tmp)?$'} | Remove-Item}
    if (!@(Get-ChildItem -LiteralPath $run.FullName -Force).Count) { [IO.Directory]::Delete($run.FullName) }
    $report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-psec-result.ps1') $report
    if ($PortGuard -and !$StaticGuard) {$report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-portguard-result.ps1') $report}
    if ($FlowChecks -and !$StaticGuard) {$report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-portguard-flow-result.ps1') $report}
    if ($BindGuard) {$report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-bind-result.ps1') $report}
    elseif ($StaticGuard) {$report.assessment=& (Join-Path $PSScriptRoot 'windows-lab-static-guard-result.ps1') $report}
    [IO.File]::WriteAllText($reportPath,($report | ConvertTo-Json -Depth 16))
    [pscustomobject]@{file=$reportPath;run=$prefix;error=$report.error;assessment=$report.assessment;dns=$report.dnsResult} | ConvertTo-Json -Depth 5
}
if ($report.assessment.outcome -like 'failed-*') { exit 2 }
if ($report.assessment.outcome -in 'passed-container-loopback','passed-host-loopback-healthy','passed-container-portguard-healthy-gate','passed-container-portguard-fault-matrix','passed-static-guard-n1','passed-bind-guard-n2') { exit 0 }
if ($report.assessment.outcome -notlike 'no-leak-observed-*') { exit 1 }
