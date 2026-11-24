param([string]$EvidenceDirectory,[switch]$Owner,[switch]$Rollback,[ValidateRange(1,2)][int]$Generation=1)
$ErrorActionPreference='Stop'
function Read-StaticSettings([string]$Directory) {
    $resolved=(Resolve-Path -LiteralPath $Directory).Path
    if((Split-Path $resolved -Parent) -ne [IO.Path]::GetTempPath().TrimEnd('\') -or (Split-Path $resolved -Leaf) -notmatch '^ClaudeStudioTrace-studio-[a-f0-9]{16}$') {throw 'Unexpected static evidence directory'}
    if((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Evidence directory is a reparse point'}
    $value=Get-Content -LiteralPath (Join-Path $resolved 'guard-settings.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $n2=$value.mode -ceq 'bind-guard-a-only'
    $lab=(Resolve-Path -LiteralPath $(if($n2){$value.lab}else{Join-Path $PSScriptRoot '..\.prototype\windows-lab'})).Path
    $expectedLibrary=if($n2){Join-Path $resolved 'ContainerGuard.dll'}else{Join-Path (Split-Path (Split-Path $value.executable -Parent) -Parent) 'ContainerGuard.dll'}
    if($value.executable -notmatch ('^'+[regex]::Escape($lab)+'\\psec-[a-f0-9]{32}\\payload\\StudioProbe\.exe$') -or
        $value.library -ne $expectedLibrary -or $value.mode -cnotin 'static-a-only','bind-guard-a-only' -or $value.keys.Count -ne 5 -or
        (!$n2 -and $value.port -lt 49152) -or ($n2 -and ($value.bind.ports.Count -ne 2 -or $value.port -notin $value.bind.ports -or
        $value.proxyExecutable -ine (Join-Path $resolved 'StudioN2Proxy.exe')))){throw 'Invalid static guard manifest'}
    return $value
}
function Write-StaticJson([string]$Path,$Value) {
    $temp=$Path+'.tmp';[IO.File]::WriteAllText($temp,($Value|ConvertTo-Json -Depth 14))
    if(Test-Path -LiteralPath $Path){
        $backup=$Path+'.bak'
        if(Test-Path -LiteralPath $backup){throw 'Review existing manifest backup before replacement'}
        [IO.File]::Replace($temp,$Path,$backup);[IO.File]::Delete($backup)
    }else{[IO.File]::Move($temp,$Path)}
}
if($Owner){
    $settings=Read-StaticSettings $EvidenceDirectory
    Add-Type -Path $settings.library
    $dynamic=$null
    try {
        $deadline=[datetime]::UtcNow.AddSeconds(85)
        $go=Join-Path $EvidenceDirectory ('owner-start-'+$Generation)
        while(!(Test-Path -LiteralPath $go)){if([datetime]::UtcNow -gt $deadline){throw 'Owner startup timeout'};Start-Sleep -Milliseconds 25}
        $dynamic=[StudioLabWfp]::CreateStaticExceptionGuard()
        $dynamic.AttachStaticException([guid]$settings.sublayer,[guid[]]$settings.keys,$settings.containerSid,[uint16]$settings.port,[uint16]$settings.weight)
        $dynamic.SetStaticException($true)
        $readback=[StudioLabWfp]::VerifyStatic([guid]$settings.sublayer,[guid[]]$settings.keys,$settings.containerSid,[uint16]$settings.port,[uint16]$settings.weight,$true)
        Write-StaticJson (Join-Path $EvidenceDirectory ('owner-ready-'+$Generation)) @{pid=$PID;startTicks=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks;readback=$readback}
        while(!(Test-Path -LiteralPath (Join-Path $EvidenceDirectory ('owner-stop-'+$Generation)))){
            if([datetime]::UtcNow -gt $deadline){throw 'Owner lifetime expired'}
            Start-Sleep -Milliseconds 50
        }
    } catch {Write-StaticJson (Join-Path $EvidenceDirectory ('owner-error-'+$Generation)) @{error=$_.Exception.Message};exit 2}
    finally {if($dynamic){$dynamic.Dispose()}}
    exit 0
}
if($Rollback){$privateDir=(Resolve-Path -LiteralPath $EvidenceDirectory).Path;$evidence=[ordered]@{}}
$guardSettings=Read-StaticSettings $privateDir
Add-Type -Path $guardSettings.library
$n2GuardMode=$guardSettings.mode -ceq 'bind-guard-a-only'
$guardKeys=[guid[]]$guardSettings.keys;$guardSub=[guid]$guardSettings.sublayer
$script:dynamicOwner=$null;$script:ownerGeneration=0;$script:staticCleaned=$false
$evidence.staticGuardCleanup=@{absent=$false;emergencyStoppedPids=@();errors=@()}
$evidence.guard=@{manifest=$guardSettings;commands=@()}
$staticGuardMode=$true
$script:staticControlFile=Join-Path $PSScriptRoot 'windows-lab-static-guard-control.ps1'
function Save-StaticManifest {Write-StaticJson (Join-Path $privateDir 'guard-settings.json') $guardSettings}
function Read-N2Bind([int]$Count) {
    $bind=$guardSettings.bind
    [StudioLabWfp]::VerifyBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,$Count)
}
function Install-N2Bind([int]$Index,$OwnerClaim) {
    $bind=$guardSettings.bind
    $owner=Get-Process -Id $OwnerClaim.pid -ErrorAction Stop
    try {
        [void]$owner.Handle
        if($owner.HasExited -or $owner.StartTime.ToUniversalTime().Ticks -ne $OwnerClaim.startTicks -or
            $owner.MainModule.FileName -ine $guardSettings.proxyExecutable -or $OwnerClaim.port -ne $bind.ports[$Index]){throw 'Invalid N2 proxy ownership'}
        $listeners=@(Get-NetTCPConnection -State Listen -LocalPort $OwnerClaim.port -ErrorAction Stop)
        if($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1' -or $listeners[0].OwningProcess -ne $owner.Id){throw 'Unexpected N2 bind owner or endpoint'}
        if($Index -eq 1){
            [void][StudioLabWfp]::VerifyStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight,$false)
            if($dynamicOwner){throw 'N2 rotation requires an owner-free exception'}
        }
        $binding=[StudioLabWfp]::CreateStaticGuard()
        try {
            if($Index -eq 0){$bind.weight=$binding.PrepareBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports)}
            $bind.owners+=@($OwnerClaim)
            Save-StaticManifest
            $binding.InstallBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,$Index)
            $evidence.guard['bindPriority'+$Index]=$binding.PriorityEvidence
        } finally {$binding.Dispose()}
        if($owner.HasExited){throw 'N2 proxy exited during rule installation'}
        return (Read-N2Bind ($Index+1))
    } finally {$owner.Dispose()}
}
function Stop-StaticOwner {
    foreach($entry in @($guardSettings.owners)){
        if(!$entry){continue}
        $process=Get-Process -Id $entry.pid -ErrorAction SilentlyContinue
        if(!$process){continue}
        try {
            [void]$process.Handle
            if($process.StartTime.ToUniversalTime().Ticks -ne $entry.startTicks -or $process.ProcessName -ne 'powershell'){continue}
            [IO.File]::WriteAllText((Join-Path $privateDir ('owner-stop-'+$entry.generation)),'1')
            if(!$process.WaitForExit(1500)){$process.Kill();if(!$process.WaitForExit(1500)){throw 'Owner did not exit'}}
        } finally {$process.Dispose()}
    }
    if($script:dynamicOwner){$script:dynamicOwner.Dispose();$script:dynamicOwner=$null}
}
function Start-StaticOwner {
    if($script:dynamicOwner){throw 'An owner is still held'}
    $script:ownerGeneration++
    if($script:ownerGeneration -gt 2){throw 'N1 only allows two owner instances'}
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script:staticControlFile+'" -EvidenceDirectory "'+$privateDir+'" -Owner -Generation '+$script:ownerGeneration
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $script:dynamicOwner=[Diagnostics.Process]::Start($start)
    $entry=@{pid=$dynamicOwner.Id;startTicks=$dynamicOwner.StartTime.ToUniversalTime().Ticks;generation=$script:ownerGeneration}
    $guardSettings.owners+=@($entry);Save-StaticManifest
    [IO.File]::WriteAllText((Join-Path $privateDir ('owner-start-'+$script:ownerGeneration)),'1')
    $ready=Join-Path $privateDir ('owner-ready-'+$script:ownerGeneration)
    $until=[datetime]::UtcNow.AddSeconds(6)
    while(!(Test-Path -LiteralPath $ready)){
        $errorFile=Join-Path $privateDir ('owner-error-'+$script:ownerGeneration)
        if(Test-Path -LiteralPath $errorFile){throw ([IO.File]::ReadAllText($errorFile))}
        if($dynamicOwner.HasExited -or [datetime]::UtcNow -gt $until){throw 'Dynamic owner not ready'}
        Start-Sleep -Milliseconds 25
    }
    $value=Get-Content -LiteralPath $ready -Raw -Encoding UTF8|ConvertFrom-Json
    if($value.pid -ne $entry.pid -or $value.startTicks -ne $entry.startTicks){throw 'Owner handoff identity mismatch'}
    return $value.readback
}
function Remove-StaticObjects {
    if($script:staticCleaned){return}
    Stop-StaticOwner
    # Stop this stage's A processes before its host proxy. No PID-only selection.
    $ownedExecutables=@($guardSettings.executable)
    if($n2GuardMode){$ownedExecutables+=@($guardSettings.proxyExecutable)}
    $remaining=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath -iin $ownedExecutables})
    $evidence.staticGuardCleanup.emergencyStoppedPids=@()
    foreach($item in @($remaining|Sort-Object @{Expression={if($_.ProcessId -eq $guardSettings.proxyPid -or ($n2GuardMode -and $_.ExecutablePath -ieq $guardSettings.proxyExecutable)){1}else{0}}})){
        $process=Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if(!$process){continue}
        try {
            [void]$process.Handle
            if($process.HasExited){continue}
            if($process.MainModule.FileName -ine $item.ExecutablePath -or
                [Math]::Abs(($process.StartTime.ToUniversalTime()-$item.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 1){continue}
            $evidence.staticGuardCleanup.emergencyStoppedPids+=@($process.Id)
            $process.Kill();if(!$process.WaitForExit(2000)){throw 'A process did not exit before static removal'}
        }finally{$process.Dispose()}
    }
    if(@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath -iin $ownedExecutables}).Count){throw 'Stage processes remain; retain static protection'}
    if($guardSettings.containerSid -and $null -ne $guardSettings.weight){
        [StudioLabWfp]::RemoveStatic($guardSub,$guardKeys,$guardSettings.containerSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight)
        [StudioLabWfp]::VerifyStaticAbsent($guardSub,$guardKeys,$guardSettings.containerSid,[uint16]$guardSettings.port)
    } else {
        # No installation is allowed until SID and weight were durably written.
        [StudioLabWfp]::VerifyContainerAbsent($guardSub,$guardKeys)
    }
    if($n2GuardMode){
        $bind=$guardSettings.bind
        [StudioLabWfp]::RemoveBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight)
        $evidence.staticGuardCleanup.bindAbsent=$true
    }
    $evidence.staticGuardCleanup.absent=$true
    $evidence.staticGuardCleanup.removedUtc=[datetime]::UtcNow.ToString('o')
    $script:staticCleaned=$true
}
function Invoke-GuardMailbox {
    $commands=if($n2GuardMode){'bind-install','install','open','bind-read-p','crash','bind-rotate','recover','crash-next','bind-read-q','cleanup'}else{'install','open','crash','recover','cleanup'}
    foreach($command in $commands){
        $request=Join-Path $privateDir ('guard-'+$command);$ack=$request+'-done'
        if(!(Test-Path -LiteralPath $request) -or (Test-Path -LiteralPath $ack)){continue}
        try {
            switch($command){
                'bind-install' { $value=Install-N2Bind 0 (Get-Content -LiteralPath $request -Raw -Encoding UTF8|ConvertFrom-Json) }
                'bind-read-p' {
                    if(!$dynamicOwner -or $dynamicOwner.HasExited){throw 'N2 proxy-only control requires live exception owner'}
                    $value=@{bind=(Read-N2Bind 1);scope=[StudioLabWfp]::VerifyStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight,$true);ownerPid=$dynamicOwner.Id}
                }
                'bind-rotate' {
                    $value=Install-N2Bind 1 (Get-Content -LiteralPath $request -Raw -Encoding UTF8|ConvertFrom-Json)
                    $guardSettings.port=$guardSettings.bind.ports[1];Save-StaticManifest
                }
                'bind-read-q' { $value=Read-N2Bind 2 }
                install {
                    $identity=Get-Content -LiteralPath $request -Raw -Encoding UTF8|ConvertFrom-Json
                    if($identity.containerSid -cne $clientSid){throw 'Wrong container SID handoff'}
                    [StudioLabWfp]::ValidateContainerProcess($identity.pid,$identity.startTicks,$guardSettings.accountSid,$clientSid,$guardSettings.session,$guardSettings.executable)
                    $guardSettings|Add-Member containerSid $clientSid -Force
                    $installer=[StudioLabWfp]::CreateStaticGuard()
                    try {
                        $weight=$installer.PrepareStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,$guardSettings.executable)
                        $guardSettings|Add-Member weight $weight -Force
                        Save-StaticManifest
                        $installer.InstallStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,$guardSettings.executable,[uint16]$weight)
                        $evidence.guard.priorityEvidence=$installer.PriorityEvidence
                    } finally {$installer.Dispose()}
                    $closedUtc=[datetime]::UtcNow.ToString('o')
                    $value=[StudioLabWfp]::VerifyStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight,$false)
                    $evidence.installClosedUtc=$closedUtc;$evidence.installationSessionClosed=$true
                }
                open {if($n2GuardMode){[void](Read-N2Bind 1)};$value=Start-StaticOwner}
                {$_ -in 'crash','crash-next'} {
                    if(!$dynamicOwner -or $dynamicOwner.HasExited){throw 'No live owner to terminate'}
                    $crash=@{managerPid=$dynamicOwner.Id;injectedUtc=[datetime]::UtcNow.ToString('o');managerWasOnlyKilled=$true}
                    $dynamicOwner.Kill();if(!$dynamicOwner.WaitForExit(1500)){throw 'Owner exit signal missing'}
                    $crash.exitSignalUtc=[datetime]::UtcNow.ToString('o');$crash.exitUtc=$dynamicOwner.ExitTime.ToUniversalTime().ToString('o')
                    $dynamicOwner.Dispose();$script:dynamicOwner=$null
                    $deadline=[datetimeoffset]::Parse($crash.exitSignalUtc).UtcDateTime.AddSeconds(3)
                    while([StudioLabWfp]::StaticExceptionPresent($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight)){
                        if([datetime]::UtcNow -gt $deadline){throw 'Dynamic exception survived owner exit deadline'}
                        Start-Sleep -Milliseconds 15
                    }
                    $crash.permitAbsentUtc=[datetime]::UtcNow.ToString('o')
                    $crash.readback=[StudioLabWfp]::VerifyStatic($guardSub,$guardKeys,$clientSid,[uint16]$guardSettings.port,[uint16]$guardSettings.weight,$false)
                    $value=$crash
                }
                recover {if($n2GuardMode){[void](Read-N2Bind 2)};$value=Start-StaticOwner}
                cleanup {Remove-StaticObjects;$value=$evidence.staticGuardCleanup}
            }
            $evidence.guard.commands+=@{command=$command;utc=[datetime]::UtcNow.ToString('o');readback=$value}
            Write-StaticJson $ack $value
        } catch {$evidence.guard.error=$_.Exception.Message;[IO.File]::WriteAllText((Join-Path $privateDir 'guard-error'),$_.Exception.Message);throw}
    }
}
function Close-GuardOwner {
    try {Remove-StaticObjects}
    catch {$evidence.staticGuardCleanup.errors+=@($_.Exception.Message);$evidence.guard.cleanupError=$_.Exception.Message}
}
if($Rollback){
    Close-GuardOwner
    Write-StaticJson (Join-Path $privateDir 'independent-rollback.json') $evidence
    if(!$evidence.staticGuardCleanup.absent){throw 'Independent static cleanup not verified; retain evidence'}
    $evidence.staticGuardCleanup|ConvertTo-Json -Depth 5
}
