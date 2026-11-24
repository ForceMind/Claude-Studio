param([switch]$Rollback,[string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
if($Rollback){$privateDir=$EvidenceDirectory;$evidence=[ordered]@{}}
$item=Get-Item -LiteralPath $privateDir
if($item.Name -cnotmatch '^ClaudeStudioTrace-studio-[a-f0-9]{16}$' -or
    $item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or
    $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or !(Get-Acl -LiteralPath $privateDir).AreAccessRulesProtected){
    throw 'Unexpected N3 evidence directory'
}
$privateDir=$item.FullName
$manifestPath=Join-Path $privateDir 'n3-manifest.json'
$n3Manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$n3Library=Join-Path $privateDir 'N3Guard.dll'
$n3Relay=Join-Path $privateDir 'StudioN3Relay.exe'
$expectedStage=$n3Manifest.stage
if($n3Manifest.mode -ne 'n3-synthetic-a' -or (Split-Path $expectedStage -Parent) -ine $n3Manifest.lab -or
    (Split-Path $expectedStage -Leaf) -cnotmatch '^psec-[a-f0-9]{32}$' -or $n3Manifest.probe -ine (Join-Path $expectedStage 'payload\StudioProbe.exe') -or
    $n3Manifest.entry.path -ine $n3Relay -or $n3Manifest.upstream.path -ine $n3Relay -or
    $n3Manifest.bind.ports.Count -ne 2 -or $n3Manifest.scope.keys.Count -ne 5 -or
    (Get-FileHash -LiteralPath $n3Library).Hash -ne $n3Manifest.librarySha256 -or
    (Get-FileHash -LiteralPath $n3Relay).Hash -ne $n3Manifest.relaySha256){throw 'Invalid N3 recovery manifest or binary'}
Add-Type -Path $n3Library
$n3State=@{sequence=0;exception=$null;open=$false;cleaned=$false;portsReady=$false;scopeReady=$false;shutdown=$null}
$evidence.guard=@{manifest=$n3Manifest;commands=@();automaticClosures=@()}
$evidence.staticGuardCleanup=@{absent=$false;bindAbsent=$false;errors=@();forced=@()}
$n2GuardMode=$true # Enables mailbox polling before the A container SID exists.

function Save-N3Manifest {
    $pending=$manifestPath+'.tmp';$backup=$manifestPath+'.bak'
    [IO.File]::WriteAllText($pending,($n3Manifest|ConvertTo-Json -Depth 10))
    [IO.File]::Replace($pending,$manifestPath,$backup)
    [IO.File]::Delete($backup)
}

function Read-N3Lease {
    $file=Join-Path $privateDir 'n3-entry-state.json'
    $share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    try{
        $stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        try{$reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8);$value=$reader.ReadToEnd()|ConvertFrom-Json}
        finally{$stream.Dispose()}
        $age=([Diagnostics.Stopwatch]::GetTimestamp()-[long]$value.publishedTick)/[Diagnostics.Stopwatch]::Frequency
        if($age -ge 0 -and $age -le 2 -and $value.pid -eq $n3Manifest.entry.pid){return $value}
    }catch [IO.IOException]{}
    return $null
}

function Assert-N3PortOwner($Owner,[int]$Port) {
    $process=Get-Process -Id $Owner.pid -ErrorAction Stop
    try {
        [void]$process.Handle
        if($process.HasExited -or $process.MainModule.FileName -ine $Owner.path -or
            $process.StartTime.ToUniversalTime().Ticks -ne $Owner.startTicks){throw 'N3 port owner differs from manifest'}
        $listen=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
        if($listen.Count -ne 1 -or $listen[0].LocalAddress -ne '127.0.0.1' -or $listen[0].OwningProcess -ne $Owner.pid){
            throw 'N3 listener owner or address differs'
        }
    }finally{$process.Dispose()}
}

function Read-N3Scope {
    $s=$n3Manifest.scope
    [StudioLabWfp]::VerifyStatic([guid]$s.sub,[guid[]]$s.keys,$s.sid,[uint16]$n3Manifest.bind.ports[0],[uint16]$s.weight,$n3State.open)
}

function Close-N3Exception([string]$Reason,$Lease) {
    if(!$n3State.open){return}
    $n3State.exception.SetStaticException($false)
    $n3State.open=$false
    $n3State.shutdown=@{reason=$Reason;tick=[Diagnostics.Stopwatch]::GetTimestamp();utc=[datetime]::UtcNow.ToString('o');lease=$Lease;scope=(Read-N3Scope)}
    $evidence.guard.automaticClosures+=@($n3State.shutdown)
}

function Stop-N3ManifestPid($Owner) {
    if(!$Owner){return}
    $process=Get-Process -Id $Owner.pid -ErrorAction SilentlyContinue
    if(!$process){return}
    try {
        [void]$process.Handle
        if($process.HasExited -or $process.StartTime.ToUniversalTime().Ticks -ne $Owner.startTicks){return}
        if($process.MainModule.FileName -ine $Owner.path){throw 'Unexpected executable for N3 rollback PID'}
        $evidence.staticGuardCleanup.forced+=@($process.Id)
        $process.Kill()
        if(!$process.WaitForExit(2300)){throw 'N3 owned process did not exit'}
    }finally{$process.Dispose()}
}

function Remove-N3Objects {
    if($n3State.cleaned){return}
    $s=$n3Manifest.scope;$bind=$n3Manifest.bind
    if($n3State.exception){
        try{Close-N3Exception 'cleanup' $null}finally{$n3State.exception.Dispose();$n3State.exception=$null;$n3State.open=$false}
    }
    $remaining=@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -ieq $n3Manifest.probe})
    foreach($probe in $remaining){
        $process=Get-Process -Id $probe.ProcessId -ErrorAction SilentlyContinue
        if(!$process){continue}
        try {
            if(!$process.HasExited -and $process.MainModule.FileName -ieq $n3Manifest.probe -and
                [math]::Abs(($process.StartTime.ToUniversalTime()-$probe.CreationDate.ToUniversalTime()).TotalMilliseconds) -lt 1){
                Stop-N3ManifestPid @{pid=$process.Id;path=$n3Manifest.probe;startTicks=$process.StartTime.ToUniversalTime().Ticks}
            }
        }finally{$process.Dispose()}
    }
    if(@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -ieq $n3Manifest.probe}).Count){throw 'A must exit before N3 rollback'}
    foreach($owner in $n3Manifest.entry,$n3Manifest.upstream,$n3Manifest.target){Stop-N3ManifestPid $owner}
    if($s.sid -and $s.weight){
        [StudioLabWfp]::RemoveStatic([guid]$s.sub,[guid[]]$s.keys,$s.sid,[uint16]$bind.ports[0],[uint16]$s.weight)
        [StudioLabWfp]::VerifyStaticAbsent([guid]$s.sub,[guid[]]$s.keys,$s.sid,[uint16]$bind.ports[0])
    }else{[StudioLabWfp]::VerifyContainerAbsent([guid]$s.sub,[guid[]]$s.keys)}
    [StudioLabWfp]::RemoveBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight)
    $evidence.staticGuardCleanup.absent=$true;$evidence.staticGuardCleanup.bindAbsent=$true
    $evidence.staticGuardCleanup.removedUtc=[datetime]::UtcNow.ToString('o');$n3State.cleaned=$true
}

function Invoke-GuardMailbox {
    if($n3State.open){
        $lease=Read-N3Lease
        if(!$lease -or $lease.admitting -ne $true -or $lease.watching -ne $true){Close-N3Exception 'entry-unhealthy' $lease}
    }
    $next=$n3State.sequence+1
    $path=Join-Path $privateDir ('n3-control-'+$next+'.json')
    if(!(Test-Path -LiteralPath $path)){return}
    $request=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    $operation=$request.action
    $s=$n3Manifest.scope;$bind=$n3Manifest.bind;$port=[uint16]$bind.ports[0]
    try {
        switch($operation){
            ports {
                if($n3State.portsReady){throw 'N3 bind rules already installed'}
                Assert-N3PortOwner $n3Manifest.entry $port
                Assert-N3PortOwner $n3Manifest.upstream $bind.ports[1]
                $installer=[StudioLabWfp]::CreateStaticGuard()
                try {
                    $bind.weight=$installer.PrepareBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports)
                    Save-N3Manifest
                    $installer.InstallBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,0)
                    $installer.InstallBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,1)
                    $evidence.guard.bindPriority=$installer.PriorityEvidence
                }finally{$installer.Dispose()}
                $value=[StudioLabWfp]::VerifyBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,2)
                $n3State.portsReady=$true
            }
            install {
                if(!$n3State.portsReady -or $n3State.scopeReady -or !$clientSid -or $request.identity.containerSid -cne $clientSid){throw 'Unexpected A rule handoff'}
                [StudioLabWfp]::ValidateContainerProcess($request.identity.pid,$request.identity.startTicks,$n3Manifest.accountSid,$clientSid,
                    $n3Manifest.session,$n3Manifest.probe)
                $s.sid=$clientSid
                $installer=[StudioLabWfp]::CreateStaticGuard()
                try {
                    $s.weight=$installer.PrepareStatic([guid]$s.sub,[guid[]]$s.keys,$s.sid,$port,$n3Manifest.probe)
                    Save-N3Manifest
                    $installer.InstallStatic([guid]$s.sub,[guid[]]$s.keys,$s.sid,$port,$n3Manifest.probe,[uint16]$s.weight)
                    $evidence.guard.scopePriority=$installer.PriorityEvidence
                }finally{$installer.Dispose()}
                $n3State.exception=[StudioLabWfp]::CreateStaticExceptionGuard()
                $n3State.exception.AttachStaticException([guid]$s.sub,[guid[]]$s.keys,$s.sid,$port,[uint16]$s.weight)
                $n3State.scopeReady=$true
                $value=Read-N3Scope
            }
            open {
                $lease=Read-N3Lease
                if(!$n3State.scopeReady -or $n3State.open -or !$lease -or $lease.admitting -ne $true -or $lease.watching -ne $true){throw 'N3 lacks fresh verified entry health'}
                [void][StudioLabWfp]::VerifyBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,2)
                $n3State.exception.SetStaticException($true);$n3State.open=$true;$n3State.shutdown=$null
                $value=Read-N3Scope
            }
            status {$value=@{open=$n3State.open;shutdown=$n3State.shutdown}}
            bindings {$value=[StudioLabWfp]::VerifyBindGuard([guid]$bind.sub,[guid[]]$bind.keys,[uint16[]]$bind.ports,[uint16]$bind.weight,2)}
            close {Close-N3Exception 'controller-stop' $null;$value=@{open=$n3State.open;shutdown=$n3State.shutdown}}
            cleanup {Remove-N3Objects;$value=$evidence.staticGuardCleanup}
            default {throw 'Unknown N3 control command'}
        }
        $n3State.sequence=$next
        $evidence.guard.commands+=@{sequence=$next;action=$operation;utc=[datetime]::UtcNow.ToString('o');value=$value}
        $reply=$path+'.done';$pending=$reply+'.tmp'
        [IO.File]::WriteAllText($pending,(@{sequence=$next;action=$operation;value=$value}|ConvertTo-Json -Depth 14))
        [IO.File]::Move($pending,$reply)
    }catch{[IO.File]::WriteAllText((Join-Path $privateDir 'guard-error'),$_.Exception.Message);throw}
}

function Close-GuardOwner {
    try{Remove-N3Objects}catch{$evidence.staticGuardCleanup.errors+=@($_.Exception.Message)}
}

if($Rollback){
    Close-GuardOwner
    [IO.File]::WriteAllText((Join-Path $privateDir 'manual-clean.json'),($evidence.staticGuardCleanup|ConvertTo-Json -Depth 6))
    if(!$evidence.staticGuardCleanup.absent){exit 2}
}
