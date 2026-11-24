[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Run the N4 A preflight in Windows PowerShell 5.1'}
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly

$lab=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
$cache=Join-Path $lab 'n4-mxc-v1.1.0-entry.bin'
$run='studio-'+[guid]::NewGuid().ToString('N').Substring(0,16)
$tag='ClaudeStudioN4-'+$run.Substring(7)
$base=Join-Path ([IO.Path]::GetTempPath()) $tag
$sealed=Join-Path $base 'sealed'
$scratch=Join-Path $base 'scratch'
$executor=Join-Path $sealed 'wxc-exec.exe'
$exe=Join-Path $sealed 'StudioN4Preflight.exe'
$policy=Join-Path $sealed 'preflight.json'
$targetClaims=Join-Path $sealed 'targets.json'
$stop=Join-Path $scratch 'stop'
$ordinaryReady=Join-Path $scratch 'ordinary-ready.json'
$executorReady=Join-Path $scratch 'executor-ready.json'
$bootstrapReady=Join-Path $scratch 'bootstrap-ready.json'
$output=Join-Path (Split-Path $lab -Parent) ('mock-results\windows-psec-n4-preflight-'+$run.Substring(7)+'.json')
$report=[ordered]@{run=$run;outcome='inconclusive-n4-preflight';sdk='1.1.0';wfpWrites=0;canStartStageTwo=$false;
    sources=@{};checks=[ordered]@{};cleanup=@{errors=@()}}
$workload=$null;$ordinaryProcess=$null;$hostListener=$null;$hostOld=$null
$created=$false

function Expand-N4Executor {
    $data=[IO.File]::ReadAllBytes($cache)
    if($data.Length -ne 4514529 -or [BitConverter]::ToUInt32($data,0) -ne 0x04034b50 -or [BitConverter]::ToUInt16($data,8) -ne 8){
        throw 'Unexpected pinned MXC ZIP entry'
    }
    $name=[BitConverter]::ToUInt16($data,26);$extra=[BitConverter]::ToUInt16($data,28)
    if([Text.Encoding]::UTF8.GetString($data,30,$name) -cne 'x64/wxc-exec.exe'){throw 'Wrong MXC ZIP entry'}
    $source=[IO.MemoryStream]::new($data,30+$name+$extra,4514455)
    $inflated=[IO.Compression.DeflateStream]::new($source,[IO.Compression.CompressionMode]::Decompress)
    $destination=[IO.File]::Create($executor)
    try{$inflated.CopyTo($destination)}finally{$destination.Dispose();$inflated.Dispose();$source.Dispose()}
    $hash=(Get-FileHash -LiteralPath $executor).Hash
    if($hash -cne 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D'){throw 'Unexpected MXC executor hash'}
    return $hash
}

function Add-N4Directory([string]$Path,[Security.AccessControl.FileSystemRights]$Rights) {
    $acl=New-N2PrivateAcl
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($account.Sid),$Rights,
        'ContainerInherit,ObjectInherit','None','Allow'))
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    $actual=Get-Acl -LiteralPath $Path
    if(!$actual.AreAccessRulesProtected){throw 'N4 fixture directory ACL unexpectedly inherits'}
}

function Get-N4HostCheck([string]$Phase,[byte]$Marker) {
    $fresh=Open-GatePair $hostListener
    try {
        $answers=@(Resolve-DnsName -Name ($run+'-h-'+$Phase+'.test.') -Type A -DnsOnly -NoHostsFile -QuickTimeout)
        if(!$answers.Count){throw 'N4 host DNS returned no records'}
        return @{dns=$true;records=$answers.Count;old=(Send-GateMarker $hostOld $Marker);fresh=(Send-GateMarker $fresh ($Marker+1))}
    }finally{Close-GatePair $fresh}
}

function Wait-N4Receipt([string]$Path,$Owner) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath $Path)){
        if($Owner.Process.HasExited -or $watch.ElapsedMilliseconds -gt 12000){
            $detail=if($Owner.Errors.IsCompleted){$Owner.Errors.Result.Trim()}else{''}
            $status=if($Owner.Process.HasExited){$Owner.Process.ExitCode}else{'timeout'}
            throw ('N4 missing '+(Split-Path $Path -Leaf)+' (status '+$status+'): '+$detail)
        }
        Start-Sleep -Milliseconds 35
    }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json
}

function Get-N4Files {
    $probe=@'
$sealed=SEALED_PATH
$scratch=SCRATCH_PATH
$base=ROOT_PATH
$read=[IO.File]::ReadAllText((Join-Path $sealed 'preflight-control.txt')) -ceq 'host-owned-preflight'
$rows=[ordered]@{sid=$id.User.Value;readControl=$read}
try{[IO.File]::WriteAllText((Join-Path $scratch 'allowed-source.txt'),'sacrificial replacement');$rows.scratchWritable=$true}
catch{$rows.scratchWritable=$false}
$actions=[ordered]@{
  write={ $stream=[IO.File]::Open((Join-Path $sealed 'write-sample.txt'),'Open','Write','ReadWrite');$stream.Dispose() }
  delete={ [IO.File]::Delete((Join-Path $sealed 'delete-sample.txt')) }
  replace={ [IO.File]::Replace((Join-Path $scratch 'allowed-source.txt'),(Join-Path $sealed 'replace-sample.txt'),(Join-Path $scratch 'replace-backup.txt')) }
  createInSealed={ [IO.File]::WriteAllText((Join-Path $sealed 'unexpected.txt'),'preflight test') }
  createInParent={ [IO.File]::WriteAllText((Join-Path $base 'unexpected.txt'),'preflight test') }
}
foreach($name in $actions.Keys){
    try{& $actions[$name];$rows[$name]='granted'}
    catch [UnauthorizedAccessException]{$rows[$name]='denied'}
    catch{$rows[$name]=$_.Exception.Message}
}
$rows|ConvertTo-Json -Compress
'@
    $body=$probe.Replace('SEALED_PATH',(ConvertTo-LabLiteral $sealed)).Replace('SCRATCH_PATH',(ConvertTo-LabLiteral $scratch)).Replace('ROOT_PATH',(ConvertTo-LabLiteral $base))
    return Read-LabProbe (Start-LabProbe $account $body)
}

function Start-N4ClosedContainer {
    $template=@'
$exe=MXC_PATH
$policy=POLICY_PATH
$receipt=RECEIPT_PATH
function Get-N4ProfileNames {
    $root=Join-Path $env:LOCALAPPDATA 'Packages'
    if(Test-Path -LiteralPath $root){Get-ChildItem -LiteralPath $root -Directory -Force|ForEach-Object Name}
}
$before=@(Get-N4ProfileNames)
$capability=(& $exe --probe $policy | Out-String)|ConvertFrom-Json
if($LASTEXITCODE -ne 0 -or $capability.tier -cne 'base-container'){throw 'N4 requires native PSEC BaseContainer'}
$launch=[Diagnostics.ProcessStartInfo]::new($exe,('"'+$policy+'"'))
$launch.UseShellExecute=$false;$launch.CreateNoWindow=$true
$launch.RedirectStandardInput=$true;$launch.RedirectStandardOutput=$true;$launch.RedirectStandardError=$true
$process=[Diagnostics.Process]::Start($launch)
try {
    $process.StandardInput.Close()
    $text=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    $thread=@($process.Threads|Sort-Object StartTime|Select-Object -First 1)
    if($thread.Count -ne 1){throw 'Failed to capture a live exact MXC thread'}
    $record=@{role='executor';pid=$process.Id;tid=$thread[0].Id;startTicks=$process.StartTime.ToUniversalTime().Ticks;
        tier=$capability.tier;callerSid=$id.User.Value}
    [IO.File]::WriteAllText($receipt+'.tmp',($record|ConvertTo-Json -Compress))
    [IO.File]::Move($receipt+'.tmp',$receipt)
    if(!$process.WaitForExit(32000)){throw 'N4 executor did not exit'}
    if(!$text.Wait(1500) -or !$errors.Wait(1500)){throw 'N4 executor streams not drained'}
    $after=@(Get-N4ProfileNames)
    [pscustomobject]@{pid=$process.Id;runExit=$process.ExitCode;stdout=$text.Result;stderr=$errors.Result;
        addedProfileDirs=@($after|Where-Object {$_ -notin $before})} | ConvertTo-Json -Compress -Depth 5
}finally{
    if(!$process.HasExited){$process.Kill();[void]$process.WaitForExit(2500)}
    $process.Dispose()
}
'@
    $body=$template.Replace('MXC_PATH',(ConvertTo-LabLiteral $executor)).Replace('POLICY_PATH',(ConvertTo-LabLiteral $policy)).
        Replace('RECEIPT_PATH',(ConvertTo-LabLiteral $executorReady))
    return Start-LabProbe $account $body
}

try {
    $account=(Get-LabAccounts -AccountIds A).A
    $report.accountSid=$account.Sid
    $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.windowsBuild="$($windows.CurrentBuildNumber).$($windows.UBR)"
    foreach($name in 'n4-preflight.ps1','n4-preflight.cs','local.ps1','bind-gate.ps1'){
        $file='windows-lab-'+$name;$report.sources[$file]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file)).Hash
    }
    $hostListener=New-GateSocket;$hostListener.ExclusiveAddressUse=$true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0));$hostListener.Listen(4)
    if($hostListener.LocalEndPoint.Port -lt 49152){throw 'Host control requires a normal ephemeral loopback port'}
    $hostOld=Open-GatePair $hostListener
    $report.hostBefore=Get-N4HostCheck 'baseline' 41
    if(Test-Path -LiteralPath $base){throw 'Preflight temporary path already exists'}
    [void][IO.Directory]::CreateDirectory($base,(New-N2PrivateAcl));$created=$true
    Add-N4Directory $sealed ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Add-N4Directory $scratch ([Security.AccessControl.FileSystemRights]::Modify)
    $report.executorSha256=Expand-N4Executor
    $csc=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$exe" (Join-Path $PSScriptRoot 'windows-lab-n4-preflight.cs')
    if($LASTEXITCODE -ne 0){throw 'N4 preflight compile failed'}
    [IO.File]::WriteAllText((Join-Path $sealed 'preflight-control.txt'),'host-owned-preflight')
    foreach($name in 'write-sample.txt','delete-sample.txt','replace-sample.txt'){
        [IO.File]::WriteAllText((Join-Path $sealed $name),'sacrificial N4 positive fixture')
    }
    $report.files=Get-N4Files
    $report.checks.files=$report.files.sid -eq $account.Sid -and $report.files.readControl -eq $true -and $report.files.scratchWritable -eq $true -and
        @($report.files.write,$report.files.delete,$report.files.replace,$report.files.createInSealed,$report.files.createInParent|Where-Object {$_ -ne 'denied'}).Count -eq 0
    if(!$report.checks.files){throw 'N4 file permission gate did not pass'}
    $report.simulatorSha256=(Get-FileHash -LiteralPath $exe).Hash
    $spec=[ordered]@{version='1.0.0';containment='processcontainer';
        process=@{commandLine=('"'+$exe+'" bootstrap "'+$bootstrapReady+'" "'+$stop+'"');cwd=$scratch;timeout=28000};
        filesystem=@{readonlyPaths=@($sealed);readwritePaths=@($scratch)};
        ui=@{disable=$false};
        network=@{egress=@{default='deny'};ingress=@{default='deny';hostLoopback='deny'}}}
    [IO.File]::WriteAllText($policy,($spec|ConvertTo-Json -Depth 8))
    $report.policy=$spec.network
    $ordinaryCmd='& '+(ConvertTo-LabLiteral $exe)+' ordinary '+(ConvertTo-LabLiteral $ordinaryReady)+' '+(ConvertTo-LabLiteral $stop)+[Environment]::NewLine+'exit $LASTEXITCODE'
    $ordinaryProcess=Start-LabProbe $account $ordinaryCmd
    $ordinary=Wait-N4Receipt $ordinaryReady $ordinaryProcess
    $workload=Start-N4ClosedContainer
    $mx=Wait-N4Receipt $executorReady $workload
    $bootstrap=Wait-N4Receipt $bootstrapReady $workload
    $report.receipts=@{ordinary=$ordinary;executor=$mx;bootstrap=$bootstrap}
    $targets=@(foreach($item in $ordinary,$mx,$bootstrap){
        @{role=$item.role;pid=$item.pid;tid=$item.tid;startTicks=$item.startTicks}
    })
    Write-GateJson $targetClaims $targets
    $cmd='& '+(ConvertTo-LabLiteral $exe)+' audit '+(ConvertTo-LabLiteral $targetClaims)+[Environment]::NewLine+'exit $LASTEXITCODE'
    $report.audit=Read-LabProbe (Start-LabProbe $account $cmd)
    $actual=@{};foreach($item in $report.audit.targets){$actual[$item.role]=$item}
    $vm=$actual.bootstrap.identity
    $report.checks.identity=$report.audit.auditor.userSid -eq $account.Sid -and $report.audit.auditor.admin -eq $false -and
        $report.audit.auditor.appContainer -eq $false -and @($actual.Keys).Count -eq 3 -and
        $actual.ordinary.identity.appContainer -eq $false -and $actual.executor.identity.appContainer -eq $false -and
        $vm.appContainer -eq $true -and $vm.inJob -eq $true -and $vm.containerSid -match '^S-1-15-2(-[0-9]+){7}$' -and
        $vm.containerSid -ceq $bootstrap.containerSid -and $vm.admin -eq $false -and @($vm.networkCapabilities).Count -eq 0 -and
        $bootstrap.controlReadable -eq $true -and $bootstrap.controlWriteDenied -eq $true
    foreach($item in $targets){
        $identity=$actual[$item.role].identity
        if($identity.pid -ne $item.pid -or $identity.startTicks -ne $item.startTicks -or $identity.userSid -ne $account.Sid -or $identity.admin -ne $false -or
            $identity.session -ne $report.audit.auditor.session){$report.checks.identity=$false}
    }
    $report.checks.positiveControl=@($actual.ordinary.processRights).Count -eq 9 -and @($actual.ordinary.threadRights).Count -eq 5 -and
        @(@($actual.ordinary.processRights)+@($actual.ordinary.threadRights)|Where-Object {!$_.granted}).Count -eq 0
    if(!$report.checks.identity -or !$report.checks.positiveControl){throw 'N4 identity or same-account permission control did not pass'}
    $report.decidingRights=@(foreach($role in 'bootstrap','executor'){
        foreach($kind in 'processRights','threadRights'){
            foreach($entry in $actual[$role].$kind){
                if($entry.granted -or $entry.error -ne 5){[pscustomobject]@{role=$role;part=$kind;right=$entry.right;granted=$entry.granted;error=$entry.error}}
            }
        }
    })
    $report.checks.rightsMeasured=@($actual.bootstrap.processRights).Count -eq 9 -and @($actual.bootstrap.threadRights).Count -eq 5 -and
        @($actual.executor.processRights).Count -eq 9 -and @($actual.executor.threadRights).Count -eq 5 -and
        !@($report.decidingRights|Where-Object {!$_.granted}).Count
    if(!$report.checks.rightsMeasured){throw 'N4 lacks attributable rights results'}
    $report.checks.noCriticalRightGranted=$report.decidingRights.Count -eq 0
    $report.hostDuring=Get-N4HostCheck 'during' 51
}catch{
    $report.error=$_.Exception.Message;$report.errorAt=$_.InvocationInfo.PositionMessage
}finally {
    if($created -and (Test-Path -LiteralPath $scratch)){
        try{[IO.File]::WriteAllText($stop,'cleanup')}catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    if($workload){try{$report.mxExit=Read-LabProbe $workload 14000}catch{$report.cleanup.errors+=@($_.Exception.Message)}}
    if($ordinaryProcess){try{$report.ordinaryExit=Read-LabProbe $ordinaryProcess 14000}catch{$report.cleanup.errors+=@($_.Exception.Message)}}
    if($created){
        try {
            $remaining=@(Get-CimInstance Win32_Process -Filter "Name = 'StudioN4Preflight.exe' OR Name = 'wxc-exec.exe'" | Where-Object {
                $_.ExecutablePath -ieq $exe -or $_.ExecutablePath -ieq $executor
            })
            $report.cleanup.remainingOwnedPids=@($remaining|ForEach-Object ProcessId)
            if($remaining.Count){throw 'N4 owned process remains; retain its directory for inspection'}
            $checked=Get-Item -LiteralPath $base
            if($checked.Name -cne $tag -or $checked.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or
                $checked.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                @(Get-ChildItem -LiteralPath $base -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'N4 cleanup path identity mismatch'}
            Remove-Item -LiteralPath $checked.FullName -Recurse -Force
        }catch{$report.cleanup.errors+=@($_.Exception.Message)}
    }
    $report.cleanup.directoryGone=!(Test-Path -LiteralPath $base)
    if($hostOld){
        try{$report.hostAfter=Get-N4HostCheck 'recovered' 61}catch{$report.cleanup.errors+=@($_.Exception.Message)}
        finally{Close-GatePair $hostOld}
    }
    if($hostListener){$hostListener.Dispose()}
    $report.checks.cleanup=$report.cleanup.directoryGone -eq $true -and !$report.cleanup.errors.Count -and $report.hostAfter.old -eq $true -and
        $report.hostAfter.fresh -eq $true -and $report.hostAfter.dns -eq $true -and $report.mxExit.runExit -eq 0 -and
        @($report.mxExit.addedProfileDirs).Count -eq 0 -and $report.ordinaryExit.stopped -eq $true
    if(!$report.error -and $report.checks.cleanup){
        $report.canStartStageTwo=$report.checks.noCriticalRightGranted -eq $true
        $report.outcome=if($report.canStartStageTwo){'passed-n4-closed-preflight'}else{'stopped-n4-critical-right-granted'}
    }
    [IO.File]::WriteAllText($output,($report|ConvertTo-Json -Depth 11))
    [pscustomobject]@{file=$output;outcome=$report.outcome;checks=$report.checks;error=$report.error;
        grantedCritical=@($report.decidingRights|Where-Object granted).Count;cleanup=$report.cleanup}|ConvertTo-Json -Depth 5
}
if($report.outcome -eq 'inconclusive-n4-preflight'){exit 2}
