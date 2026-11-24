[CmdletBinding()]
param([switch]$Elevated,[string]$BrokerDirectory)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess){throw 'Use x64 Windows PowerShell 5.1'}

function Write-HostReceipt([string]$Path,$Value) {
    [IO.File]::WriteAllText($Path+'.pending',($Value|ConvertTo-Json -Depth 14))
    [IO.File]::Move($Path+'.pending',$Path)
}

function Read-HostReceipt([string]$Path) {
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-HostFixtureDirectory([string]$Path) {
    $item=Get-Item -LiteralPath $Path
    if(!$item.PSIsContainer -or $item.Name -cnotmatch '^ClaudeStudioN4Host-[a-f0-9]{16}$' -or
        $item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){
        throw 'Unexpected host fixture directory'
    }
    return $item.FullName
}

function Get-HostFixtureError($Record) {
    $native=$Record.Exception
    while($native.InnerException -and $native -isnot [ComponentModel.Win32Exception]){$native=$native.InnerException}
    return @{message=$native.Message;type=$native.GetType().FullName;stage=$Record.InvocationInfo.ScriptLineNumber;
        nativeError=if($native -is [ComponentModel.Win32Exception]){$native.NativeErrorCode}else{$null}}
}

if($Elevated){
    $protectedRoot=Get-HostFixtureDirectory $BrokerDirectory
    $hostIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($hostIdentity)
    $hostSid=$hostIdentity.User.Value
    $allowed=@($hostSid,'S-1-5-18','S-1-5-32-544')
    $rootAcl=Get-Acl -LiteralPath $protectedRoot
    if($PSCommandPath -ine (Join-Path $protectedRoot 'broker.ps1') -or !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        !$rootAcl.AreAccessRulesProtected -or $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed -or
        @($rootAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -notin $allowed}).Count){
        throw 'Expected a private fixture and an elevated host'
    }
    $result=[ordered]@{brokerPid=$PID;hostSid=$hostSid;status='error';creationAttempted=$false;created=$false;cleanupErrors=@()}
    $held=$null
    try{
        . (Join-Path $protectedRoot 'local.ps1')
        $localA=(Get-LabAccounts -AccountIds A).A
        $result.accountSid=$localA.Sid
        $whoami=Join-Path $env:SystemRoot 'System32\whoami.exe'
        $privileges=@(& $whoami /priv /fo csv /nh | ConvertFrom-Csv -Header name,description,state)
        if($LASTEXITCODE -ne 0){throw 'Cannot read elevated privileges'}
        $result.privileges=@(foreach($name in 'SeIncreaseQuotaPrivilege','SeAssignPrimaryTokenPrivilege'){
            $row=$privileges|Where-Object name -CEQ $name
            [pscustomobject]@{name=$name;present=[bool]$row;state=$row.state}
        })
        $fixture=Join-Path $protectedRoot 'sealed\StudioN4HostProbe.exe'
        [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($fixture))
        $result.broker=[StudioN4HostCreation]::BrokerIdentity()
        $result.creationAttempted=$true
        $held=[StudioN4HostCreation]::Start($fixture,$localA.Name,$env:COMPUTERNAME,$localA.Credential.Password,$hostSid)
        $result.created=$true
        $result.before=$held.Snapshot($hostSid)
        Write-HostReceipt (Join-Path $protectedRoot 'ready.json') $result
        $deadline=[Diagnostics.Stopwatch]::StartNew()
        while(!(Test-Path -LiteralPath (Join-Path $protectedRoot 'broker-stop')) -and $deadline.ElapsedMilliseconds -lt 28000){
            Start-Sleep -Milliseconds 30
        }
        $result.stopReceived=Test-Path -LiteralPath (Join-Path $protectedRoot 'broker-stop')
        $result.after=$held.Snapshot($hostSid)
        $result.status='created'
    }catch{
        $result.error=Get-HostFixtureError $_
    }finally{
        if($held){
            try{$result.termination=$held.TerminateAndWait()}catch{$result.cleanupErrors+=@(Get-HostFixtureError $_)}
            finally{$held.Dispose()}
        }
        Write-HostReceipt (Join-Path $protectedRoot 'broker-result.json') $result
    }
    return
}

. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly
$runId=[guid]::NewGuid().ToString('N').Substring(0,16)
$base=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioN4Host-'+$runId)
$sealed=Join-Path $base 'sealed'
$scratch=Join-Path $base 'scratch'
$fixture=Join-Path $sealed 'StudioN4HostProbe.exe'
$output=Join-Path $PSScriptRoot ('..\.prototype\mock-results\windows-psec-n4-host-create-'+$runId+'.json')
$report=[ordered]@{run=$runId;outcome='inconclusive-n4-host-create';wfpWrites=0;checks=[ordered]@{};sources=@{};cleanup=[ordered]@{errors=@()}}
$lifted=$null;$ordinaryControl=$null;$hostListener=$null;$hostOld=$null;$madeDirectory=$false
$readyPath=Join-Path $base 'ready.json'
$resultPath=Join-Path $base 'broker-result.json'
$ordinaryReady=Join-Path $scratch 'ordinary-ready.json'
$ordinaryStop=Join-Path $scratch 'stop'
$controllerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Add-HostFixtureDirectory([string]$Path,[Security.AccessControl.FileSystemRights]$Rights) {
    $acl=New-N2PrivateAcl
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($account.Sid),$Rights,
        'ContainerInherit,ObjectInherit','None','Allow'))
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    if(!(Get-Acl -LiteralPath $Path).AreAccessRulesProtected){throw 'Fixture ACL unexpectedly inherits'}
}

function Get-HostConnectionCheck([string]$Phase,[byte]$Marker) {
    $fresh=Open-GatePair $hostListener
    try{
        $answers=@(Resolve-DnsName -Name ('studio-'+$runId+'-h-'+$Phase+'.test.') -Type A -DnsOnly -NoHostsFile -QuickTimeout)
        if(!$answers.Count){throw 'Host DNS returned no records'}
        return @{dns=$true;records=$answers.Count;old=(Send-GateMarker $hostOld $Marker);fresh=(Send-GateMarker $fresh ($Marker+1))}
    }finally{Close-GatePair $fresh}
}

function Test-HostFixture($Snapshot) {
    return $Snapshot.pid -gt 0 -and $Snapshot.tid -gt 0 -and $Snapshot.identity.userSid -ceq $account.Sid -and
        !$Snapshot.identity.admin -and !$Snapshot.identity.appContainer -and $Snapshot.identity.tokenType -eq 1 -and
        $Snapshot.identity.path -ieq $fixture -and $Snapshot.processSecurity.owner -ceq $controllerSid -and
        $Snapshot.threadSecurity.owner -ceq $controllerSid -and $Snapshot.processSecurity.expected -and
        $Snapshot.threadSecurity.expected -and !$Snapshot.processInheritable -and !$Snapshot.threadInheritable -and
        $Snapshot.inCleanupJob -and $Snapshot.requestedSuspended -and $Snapshot.resumeCalls -eq 0 -and $Snapshot.threadUserTime -eq 0
}

function Test-HostBroker($Receipt) {
    $identity=$Receipt.broker.identity
    return $Receipt.brokerPid -eq $report.brokerPid -and $identity.pid -eq $report.brokerPid -and
        $Receipt.accountSid -ceq $account.Sid -and $Receipt.hostSid -ceq $controllerSid -and $Receipt.broker.tid -gt 0 -and
        $identity.userSid -ceq $controllerSid -and $identity.tokenType -eq 1 -and $identity.admin -and
        !$identity.appContainer -and $identity.integrity -ceq 'S-1-16-12288'
}

try{
    $account=(Get-LabAccounts -AccountIds A).A
    $report.osBuild=[Environment]::OSVersion.Version.ToString()
    foreach($name in 'windows-lab-n4-host-create.ps1','windows-lab-n4-host-create.cs','windows-lab-n4-preflight.cs','windows-lab-local.ps1','windows-lab-bind-gate.ps1'){
        $report.sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash
    }
    $hostListener=New-GateSocket
    $hostListener.ExclusiveAddressUse=$true
    $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    if($hostListener.LocalEndPoint.Port -lt 49152){throw 'Expected a normal ephemeral loopback port'}
    $hostListener.Listen(4)
    $hostOld=Open-GatePair $hostListener
    $report.hostBefore=Get-HostConnectionCheck 'before' 41
    if(Test-Path -LiteralPath $base){throw 'Fixture temporary directory already exists'}
    [void][IO.Directory]::CreateDirectory($base,(New-N2PrivateAcl));$madeDirectory=$true
    Add-HostFixtureDirectory $sealed ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Add-HostFixtureDirectory $scratch ([Security.AccessControl.FileSystemRights]::Modify)
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $base 'broker.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows-lab-local.ps1') -Destination (Join-Path $base 'local.ps1')
    $csc=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:x64 /target:exe /optimize+ /define:N4_HOST_CREATE /reference:System.Web.Extensions.dll "/out:$fixture" `
        (Join-Path $PSScriptRoot 'windows-lab-n4-preflight.cs') (Join-Path $PSScriptRoot 'windows-lab-n4-host-create.cs')
    if($LASTEXITCODE -ne 0){throw 'Host fixture compile failed'}
    $report.fixtureSha256=(Get-FileHash -LiteralPath $fixture).Hash
    [IO.File]::WriteAllText((Join-Path $sealed 'preflight-control.txt'),'host-owned-preflight')
    $argsText='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $base 'broker.ps1')+'" -Elevated -BrokerDirectory "'+$base+'"'
    $lifted=Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList $argsText
    $report.brokerPid=$lifted.Id
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath $readyPath) -and !(Test-Path -LiteralPath $resultPath) -and !$lifted.HasExited -and $clock.ElapsedMilliseconds -lt 24000){
        Start-Sleep -Milliseconds 30
    }
    $report.initialReceipt=if(Test-Path -LiteralPath $readyPath){'ready'}
        elseif(Test-Path -LiteralPath $resultPath){'terminal'}elseif($lifted.HasExited){'exited'}else{'pending'}
    if(Test-Path -LiteralPath $readyPath){
        $live=Read-HostReceipt $readyPath
        $broker=$live.broker.identity
        $report.checks.brokerIdentity=Test-HostBroker $live
        $report.checks.createdProtection=Test-HostFixture $live.before
        if($report.checks.brokerIdentity -and $report.checks.createdProtection){
            $command='& '+(ConvertTo-LabLiteral $fixture)+' ordinary '+(ConvertTo-LabLiteral $ordinaryReady)+' '+(ConvertTo-LabLiteral $ordinaryStop)+"`n"+'exit $LASTEXITCODE'
            $ordinaryControl=Start-LabProbe $account $command
            $clock.Restart()
            while(!(Test-Path -LiteralPath $ordinaryReady) -and !$ordinaryControl.Process.HasExited -and $clock.ElapsedMilliseconds -lt 8000){Start-Sleep -Milliseconds 30}
            $ordinary=Read-HostReceipt $ordinaryReady
            $report.ordinary=$ordinary
            $claims=@(
                @{role='ordinary';pid=$ordinary.pid;tid=$ordinary.tid;startTicks=$ordinary.startTicks}
                @{role='suspended';pid=$live.before.pid;tid=$live.before.tid;startTicks=$live.before.identity.startTicks}
                @{role='broker';pid=$broker.pid;tid=$live.broker.tid;startTicks=$broker.startTicks}
            )
            $request=Join-Path $sealed 'audit.json'
            Write-HostReceipt $request $claims
            $command='& '+(ConvertTo-LabLiteral $fixture)+' host-create-audit '+(ConvertTo-LabLiteral $request)+"`n"+'exit $LASTEXITCODE'
            $report.audit=Read-LabProbe (Start-LabProbe $account $command) 8000
            $auditor=$report.audit.auditor
            $control=$report.audit.targets[0]
            $report.checks.aIdentity=$true
            foreach($identity in $auditor,$control.identity,$live.before.identity){
                if($identity.userSid -cne $account.Sid -or $identity.admin -or $identity.appContainer -or $identity.tokenType -ne 1 -or
                    $identity.session -ne $auditor.session -or $identity.integrity -cne 'S-1-16-8192'){$report.checks.aIdentity=$false}
            }
            $report.checks.positiveControl=$ordinary.controlReadable -and $ordinary.controlWriteDenied -and $control.limitedQuery.granted -and
                @($control.processRights).Count -eq 9 -and @($control.threadRights).Count -eq 5 -and
                !@(@($control.processRights)+@($control.threadRights)|Where-Object {!$_.granted -or $_.error -ne 0}).Count
            if($report.checks.aIdentity -and $report.checks.positiveControl){
                $report.checks.auditTargets=$true
                $report.decidingRights=@(for($i=1;$i -le 2;$i++){
                    $target=$report.audit.targets[$i];$claim=$claims[$i]
                    if($target.role -cne $claim.role -or $target.pid -ne $claim.pid -or $target.tid -ne $claim.tid -or
                        @($target.processRights).Count -ne 9 -or @($target.threadRights).Count -ne 5){$report.checks.auditTargets=$false}
                    foreach($kind in 'limitedQuery','processRights','threadRights'){
                        foreach($right in $target.$kind){
                            if($right.granted -or $right.error -ne 5){@{role=$target.role;kind=$kind;right=$right.right;granted=$right.granted;error=$right.error}}
                        }
                    }
                })
                $report.checks.allCriticalDenied=$report.checks.auditTargets -and !$report.decidingRights.Count
            }
        }
    }
    $report.hostDuring=Get-HostConnectionCheck 'during' 51
}catch{
    $report.error=Get-HostFixtureError $_
}finally{
    if($ordinaryControl){
        try{[IO.File]::WriteAllText($ordinaryStop,'cleanup');$report.ordinaryExit=Read-LabProbe $ordinaryControl 8000}
        catch{$report.cleanup.errors+=@(Get-HostFixtureError $_)}
    }
    if($lifted){
        try{
            [IO.File]::WriteAllText((Join-Path $base 'broker-stop'),'cleanup')
            if(!$lifted.WaitForExit(32000)){throw 'Elevated helper did not exit within the cleanup deadline'}
            $report.cleanup.brokerExitCode=$lifted.ExitCode
            if(Test-Path -LiteralPath $resultPath){$report.broker=Read-HostReceipt $resultPath}
            if($lifted.ExitCode -ne 0 -or !$report.broker -or @($report.broker.cleanupErrors).Count){throw 'Elevated helper did not prove cleanup'}
        }catch{$report.cleanup.errors+=@(Get-HostFixtureError $_)}
        finally{$report.cleanup.brokerExited=$lifted.HasExited;$lifted.Dispose()}
    }
    if($madeDirectory){
        try{
            $knownIds=@($report.broker.before.pid,$report.ordinary.pid)|Where-Object {$_ -gt 0}
            $processes=@(Get-CimInstance Win32_Process -Filter "Name = 'StudioN4HostProbe.exe'" | Where-Object {
                $_.ExecutablePath -ieq $fixture -or $_.ProcessId -in $knownIds
            })
            $report.cleanup.remainingOwnedPids=@($processes|ForEach-Object ProcessId)
            if($processes.Count -or ($lifted -and !$report.cleanup.brokerExited)){throw 'Fixture still active; its directory has been retained'}
            $checked=Get-HostFixtureDirectory $base
            if(@(Get-ChildItem -LiteralPath $checked -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){
                throw 'Fixture contains a reparse point; its directory has been retained'
            }
            Remove-Item -LiteralPath $checked -Recurse -Force
        }catch{$report.cleanup.errors+=@(Get-HostFixtureError $_)}
    }
    $report.cleanup.directoryGone=!(Test-Path -LiteralPath $base)
    if($hostOld){
        try{$report.hostAfter=Get-HostConnectionCheck 'after' 61}
        catch{$report.cleanup.errors+=@(Get-HostFixtureError $_)}
        finally{Close-GatePair $hostOld}
    }
    if($hostListener){$hostListener.Dispose()}
    $report.checks.cleanup=$report.cleanup.directoryGone -and $report.cleanup.brokerExited -and !$report.cleanup.errors.Count -and
        !$report.cleanup.remainingOwnedPids.Count -and (!$ordinaryControl -or $report.ordinaryExit.stopped)
    $report.checks.host=$true
    foreach($phase in 'hostBefore','hostDuring','hostAfter'){
        $check=$report[$phase]
        if(!$check.dns -or !$check.old -or !$check.fresh){$report.checks.host=$false}
    }
    if($report.broker.created){
        $end=$report.broker.termination
        $report.checks.cleanup=$report.checks.cleanup -and $end.processSignaled -and $end.threadSignaled -and $end.exitCode -eq $end.expectedExitCode
        $report.checks.heldThroughAudit=(Test-HostFixture $report.broker.after) -and $report.broker.stopReceived -and
            $report.broker.before.pid -eq $report.broker.after.pid -and $report.broker.before.tid -eq $report.broker.after.tid -and
            $report.broker.before.identity.startTicks -eq $report.broker.after.identity.startTicks
    }
    if($report.broker){$report.checks.terminalBrokerIdentity=Test-HostBroker $report.broker}
    if(!$report.error -and $report.checks.cleanup -and $report.checks.host){
        if($report.checks.terminalBrokerIdentity -and $report.broker.creationAttempted -and !$report.broker.created -and $report.broker.error.nativeError -eq 1314 -and
            $report.broker.error.message -ceq 'CreateProcessAsUserW'){$report.outcome='stopped-n4-host-create-1314'}
        elseif($report.checks.createdProtection -and $report.checks.brokerIdentity -and $report.checks.aIdentity -and
            $report.checks.positiveControl -and $report.checks.heldThroughAudit -and $report.checks.auditTargets){
            if($report.checks.allCriticalDenied){$report.outcome='passed-n4-host-create'}
            elseif(@($report.decidingRights|Where-Object granted).Count){$report.outcome='stopped-n4-host-create-rights'}
        }
        elseif($report.broker.created -and $report.checks.createdProtection -eq $false){$report.outcome='stopped-n4-host-create-ownership'}
    }
    $output=[IO.Path]::GetFullPath($output)
    Write-HostReceipt $output $report
    [pscustomobject]@{outcome=$report.outcome;report=$output;brokerError=$report.broker.error;error=$report.error;cleanup=$report.checks.cleanup;host=$report.checks.host}
}
