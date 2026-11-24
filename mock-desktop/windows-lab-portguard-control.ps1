param([string]$EvidenceDirectory,[switch]$Rollback)
# Normally dot-sourced by the elevated, bounded DNS observer. All messages are in
# the host-only evidence directory, never in the A-writable simulator directory.
if($Rollback) {
    $resolved=(Resolve-Path -LiteralPath $EvidenceDirectory).Path
    if((Split-Path $resolved -Parent) -ne [IO.Path]::GetTempPath().TrimEnd('\') -or
        (Split-Path $resolved -Leaf) -notmatch '^ClaudeStudioTrace-studio-[a-f0-9]{16}$') {throw 'Not an owned trace directory'}
    $settings=Get-Content -LiteralPath (Join-Path $resolved 'guard-settings.json') -Raw | ConvertFrom-Json
    $lab=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
    if($settings.executable -notmatch ('^'+[regex]::Escape($lab)+'\\psec-[a-f0-9]{32}\\payload\\StudioProbe\.exe$') -or
        $settings.library -ne (Join-Path (Split-Path (Split-Path $settings.executable -Parent) -Parent) 'ContainerGuard.dll')) {throw 'Unexpected rollback manifest paths'}
    foreach($process in @(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath -ieq $settings.executable})) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    }
    [IO.File]::WriteAllText((Join-Path $resolved 'stop'),'1')
    $until=[datetime]::UtcNow.AddSeconds(25)
    while(!(Test-Path -LiteralPath (Join-Path $resolved 'result.json')) -and [datetime]::UtcNow -lt $until) {Start-Sleep -Milliseconds 100}
    if(!(Test-Path -LiteralPath (Join-Path $resolved 'result.json'))) {throw 'A stopped; bounded observer has not finished cleanup yet'}
    Add-Type -Path $settings.library
    [StudioLabWfp]::VerifyContainerAbsent([guid]$settings.sublayer,[guid[]]$settings.keys)
    Write-Output 'A stopped; container guard rules and sublayer absent'
    return
}
$containerGuard=$null
$guardSettings=Get-Content -LiteralPath (Join-Path $privateDir 'guard-settings.json') -Raw | ConvertFrom-Json
Add-Type -Path $guardSettings.library
$guardKeys=[guid[]]$guardSettings.keys
$guardSub=[guid]$guardSettings.sublayer
$evidence.guard=@{manifest=$guardSettings;commands=@()}
function Invoke-GuardMailbox {
    foreach($command in 'install','open','close') {
        $request=Join-Path $privateDir ('guard-'+$command)
        $ack=Join-Path $privateDir ('guard-'+$command+'-done')
        if (!(Test-Path -LiteralPath $request) -or (Test-Path -LiteralPath $ack)) {continue}
        try {
            if ($command -eq 'install') {
                if($script:containerGuard) {throw 'Guard already exists'}
                $identity=Get-Content -LiteralPath $request -Raw | ConvertFrom-Json
                if($identity.containerSid -cne $clientSid) {throw 'Unexpected container SID handoff'}
                [StudioLabWfp]::ValidateContainerProcess($identity.pid,$identity.startTicks,$guardSettings.accountSid,$clientSid,$guardSettings.session,$guardSettings.executable)
                [StudioLabWfp]::ValidateContainerSpec($guardSub,$guardKeys,$clientSid,$guardSettings.port)
                $script:containerGuard=[StudioLabWfp]::CreateContainerGuard()
                try {$script:containerGuard.InstallContainer($guardSub,$guardKeys,$clientSid,$guardSettings.port,$guardSettings.executable)}
                finally {$evidence.guard.priorityEvidence=$script:containerGuard.PriorityEvidence}
            } else {
                if(!$script:containerGuard) {throw 'No guard owner'}
                $script:containerGuard.SetContainerGate($command -eq 'close')
            }
            $verified=$script:containerGuard.VerifyContainer()
            $evidence.guard.commands+=@{command=$command;utc=[datetime]::UtcNow.ToString('o');readback=$verified}
            [IO.File]::WriteAllText($ack,($verified|ConvertTo-Json -Depth 10))
        } catch {
            $evidence.guard.error=$_.Exception.Message
            [IO.File]::WriteAllText((Join-Path $privateDir 'guard-error'),$_.Exception.Message)
            throw
        }
    }
}
function Close-GuardOwner {
    # On observer failure the ordinary controller may still be waiting. Stop
    # only this stage's simulator binary before releasing its dynamic rules.
    $remaining=@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath -ieq $guardSettings.executable})
    $evidence.guard.emergencyStoppedPids=@($remaining | ForEach-Object ProcessId)
    foreach($process in $remaining) {Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop}
    if($script:containerGuard) {
        try {$script:containerGuard.RemoveContainer()}
        catch {$evidence.guard.removeError=$_.Exception.Message}
        finally {$script:containerGuard.Dispose();$script:containerGuard=$null}
    }
    try {[StudioLabWfp]::VerifyContainerAbsent($guardSub,$guardKeys);$evidence.guard.absent=$true}
    catch {$evidence.guard.absent=$false;$evidence.guard.cleanupError=$_.Exception.Message}
}
