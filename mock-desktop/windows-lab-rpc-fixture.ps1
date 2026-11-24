param([switch]$Elevated)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$lab=Join-Path $root '.prototype\windows-lab'
$output=Join-Path $root '.prototype\mock-results\windows-rpc-fixture.json'
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if(!$Elevated) {
    $csc=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:x64 /r:System.Web.Extensions.dll ("/out:"+(Join-Path $lab 'StudioRpcFixture.exe')) (Join-Path $PSScriptRoot 'windows-lab-rpc-fixture.cs')
    if($LASTEXITCODE -ne 0){throw 'RPC fixture compilation failed'}
    & $csc /nologo /platform:x64 ("/out:"+(Join-Path $lab 'StudioRpcFixtureRule.exe')) (Join-Path $PSScriptRoot 'windows-lab-wfp.cs') (Join-Path $PSScriptRoot 'windows-lab-wfp-rpc-fixture.cs')
    if($LASTEXITCODE -ne 0){throw 'RPC rule compilation failed'}
    $process=Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',('"'+$PSCommandPath+'"'),'-Elevated') -PassThru
    if(!$process.WaitForExit(240000)){throw 'RPC fixture runner is still active'}
    $result=Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Remove-Item -LiteralPath (Join-Path $lab 'StudioRpcFixture.exe'),(Join-Path $lab 'StudioRpcFixtureRule.exe')
    [pscustomobject]@{file=$output;run=$result.run;error=$result.error;cases=@($result.cases).Count;loss=$result.loss;traceStopped=$result.traceStopped;privateDirectoryGone=$result.privateDirectoryGone} | ConvertTo-Json -Depth 4
    exit $process.ExitCode
}
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
. (Join-Path $PSScriptRoot 'windows-lab-dns-trace.ps1')
$report=[ordered]@{run=('studio-rpc-'+[guid]::NewGuid().ToString('N'));interface='fd53aacc-6237-4a11-a9dc-093b984145af';cases=@();rules=@();events=@();servers=@()}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$report.build="$($build.CurrentBuildNumber).$($build.UBR)"
$directory=Join-Path $env:TEMP $report.run
$fixture=Join-Path $lab 'StudioRpcFixture.exe'
$ruleExe=Join-Path $lab 'StudioRpcFixtureRule.exe'
$traceLive=$false
$server=$null
$owner=$null
$account=$null
$marker=100
function Start-FixtureProcess([string]$Arguments, [switch]$AsA) {
    $si=[Diagnostics.ProcessStartInfo]::new()
    $si.FileName=if($AsA){$fixture}else{$ruleExe}
    $si.Arguments=$Arguments
    $si.WorkingDirectory=$env:SystemRoot
    $si.UseShellExecute=$false
    $si.CreateNoWindow=$true
    $si.RedirectStandardInput=$true
    $si.RedirectStandardOutput=$true
    $si.RedirectStandardError=$true
    if($AsA){$si.UserName=$account.Name;$si.Domain=$env:COMPUTERNAME;$si.Password=$account.Credential.Password;$si.LoadUserProfile=$true}
    return [Diagnostics.Process]::Start($si)
}
function Stop-FixtureProcess($Process) {
    if(!$Process){return}
    if(!$Process.HasExited){$Process.StandardInput.Close();if(!$Process.WaitForExit(5000)){$Process.Kill();[void]$Process.WaitForExit(3000)}}
}
function Invoke-FixtureCall([string]$Phase,[string]$Protocol,[string]$Endpoint) {
    $script:marker++
    $client=Start-FixtureProcess "client $Protocol $Endpoint $script:marker" -AsA
    $started=[datetime]::UtcNow.ToString('o')
    $stdout=$client.StandardOutput.ReadToEndAsync()
    $stderr=$client.StandardError.ReadToEndAsync()
    try {
        if(!$client.WaitForExit(6000)){
            $client.Kill();[void]$client.WaitForExit(3000)
            $result=[pscustomobject]@{status=$null;timedOut=$true;marker=$script:marker;pid=$client.Id;startedUtc=$started;finishedUtc=[datetime]::UtcNow.ToString('o')}
        } else {
            if($client.ExitCode -ne 0){throw ('Client failed: '+$stderr.Result)}
            $result=$stdout.Result | ConvertFrom-Json
            if($result.userSid -ne $account.Sid){throw 'Unexpected client token'}
            $result.PSObject.Properties.Remove('userSid')
        }
    } finally {$client.Dispose()}
    $result | Add-Member phase $Phase
    $result | Add-Member protocol $Protocol
    $result | Add-Member serverPid $server.Id
    $report.cases+= $result
    if($result.status -eq 0 -and $result.reply -ne ($result.marker -bxor 0x13579)){throw 'Incorrect RPC response'}
    return $result
}
try {
    $account=(Get-LabAccounts).A
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544'){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    [void][IO.Directory]::CreateDirectory($directory,$acl)
    $etl=Join-Path $directory 'rpc.etl'
    $null=& logman.exe create trace $report.run -o $etl -p 'Microsoft-Windows-RPC' 0x4000000000000000 4 -bs 256 -nb 64 256 -max 128 -ets
    if($LASTEXITCODE -ne 0){throw 'RPC metadata trace did not start'}
    $traceLive=$true
    foreach($protocol in 'ncacn_ip_tcp','ncalrpc') {
        $endpoint=if($protocol -eq 'ncalrpc'){$report.run}else{
            $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
            $socket.Start();$port=$socket.LocalEndpoint.Port;$socket.Stop()
            if($port -eq 10810){throw 'Reserved port selected'}
            [string]$port
        }
        $server=Start-FixtureProcess "server $protocol $endpoint" -AsA
        $ready=$server.StandardOutput.ReadLineAsync()
        if(!$ready.Wait(8000) -or $ready.Result -notmatch '^READY \d+$'){
            Stop-FixtureProcess $server
            throw ('Fixture did not start: '+$server.StandardError.ReadToEnd())
        }
        $serverInfo=[ordered]@{pid=$server.Id;protocol=$protocol;endpoint=$endpoint}
        $report.servers+= $serverInfo
        $baseline=Invoke-FixtureCall 'baseline' $protocol $endpoint
        if($baseline.status -ne 0){throw ('Fixture baseline failed '+$baseline.status)}
        foreach($scope in 'unmatched','A') {
            $sub=[guid]::NewGuid().ToString();$key=[guid]::NewGuid().ToString()
            $sid=if($scope -eq 'A'){$account.Sid}else{'S-1-5-21-0-0-0-999'}
            $entry=[ordered]@{scope=$scope;protocol=$protocol;filterKey=$key;sublayer=$sub;startedUtc=[datetime]::UtcNow.ToString('o')}
            $report.rules+=$entry
            try {
                $owner=Start-FixtureProcess "hold $sub $key $sid"
                $ready=$owner.StandardOutput.ReadLineAsync()
                if(!$ready.Wait(8000) -or $ready.Result -notmatch '^READY (\d+)$'){
                    Stop-FixtureProcess $owner
                    throw ('Rule did not start: '+$owner.StandardError.ReadToEnd())
                }
                $entry.filterId=$Matches[1]
                $entry.verifiedUtc=[datetime]::UtcNow.ToString('o')
                # This settling interval is not treated as proof of service-side readiness.
                Start-Sleep -Seconds 2
                $result=Invoke-FixtureCall $scope $protocol $endpoint
                if($scope -eq 'unmatched' -and $result.status -ne 0){throw 'Unmatched rule blocked the fixture'}
            } finally {
                Stop-FixtureProcess $owner
                if($owner){$entry.ownerExit=$owner.ExitCode;$owner.Dispose();$owner=$null}
                $absent=@(& $ruleExe absent $sub $key 2>&1)
                $entry.absent=($LASTEXITCODE -eq 0 -and $absent -contains 'ABSENT')
                $entry.removedUtc=[datetime]::UtcNow.ToString('o')
                if(!$entry.absent){throw 'Temporary rule rollback not verified'}
            }
            $recovery=Invoke-FixtureCall ('recovered-'+$scope) $protocol $endpoint
            if($recovery.status -ne 0){throw 'Fixture recovery failed'}
        }
        Stop-FixtureProcess $server
        $serverInfo.exit=$server.ExitCode
        $serverInfo.dispatch=@($server.StandardOutput.ReadToEnd() -split '[\r\n]+' | Where-Object {$_ -match '^CALL \d+ LENGTH \d+$'})
        $server.Dispose();$server=$null
    }
} catch {$report.error=$_.Exception.Message}
finally {
    Stop-FixtureProcess $owner
    Stop-FixtureProcess $server
    if($server){$report.lastServerExit=$server.ExitCode;$report.lastServerOutput=$server.StandardOutput.ReadToEnd();$server.Dispose()}
    if($traceLive){
        try {$report.loss=Get-LabDnsTraceLoss $report.run}catch{$report.lossError=$_.Exception.Message}
        $null=& logman.exe stop $report.run -ets
        $report.traceStopped=($LASTEXITCODE -eq 0)
        try {
            foreach($event in Get-WinEvent -Path $etl -Oldest -ErrorAction Stop) {
                try {
                    if($event.Id -notin 2,5,6){continue}
                    $props=$event.Properties
                    $iface=if($event.Id -eq 2){[string]$props[1].Value}else{[string]$props[0].Value}
                    if($iface.Trim('{}') -ne $report.interface){continue}
                    $row=@{id=$event.Id;pid=$event.ProcessId;tid=$event.ThreadId;utc=$event.TimeCreated.ToUniversalTime().ToString('o')}
                    if($event.Id -eq 2){$row.filterKey=[string]$props[2].Value}else{$row.operation=$props[1].Value;$row.protocol=$props[2].Value}
                    $report.events+=$row
                } finally {$event.Dispose()}
            }
        } catch {$report.eventReadError=$_.Exception.Message}
    }
    if($etl -and (Test-Path -LiteralPath $etl)){Remove-Item -LiteralPath $etl}
    if(Test-Path -LiteralPath $directory){[IO.Directory]::Delete($directory)}
    $report.privateDirectoryGone=!(Test-Path -LiteralPath $directory)
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding UTF8
}
if($report.error){exit 1}
