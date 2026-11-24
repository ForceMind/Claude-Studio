param(
    [Parameter(Mandatory)][string]$Stage,
    [ValidateSet('A','B')][string]$Account = 'A',
    [ValidatePattern('^[A-Za-z0-9-]+$')][string]$PolicyName = 'scope',
    [switch]$ProbeOnly,
    [switch]$Async,
    [switch]$HostLoopbackExperiment,
    [switch]$StaticGuard,
    [switch]$N3Protocol
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-lab-local.ps1')
$Stage = (Resolve-Path -LiteralPath $Stage).Path
$lab = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype\windows-lab')).Path
if ((Split-Path $Stage -Parent) -ne $lab -or (Split-Path $Stage -Leaf) -notmatch '^psec-[0-9a-f]{32}$') {
    throw 'Expected a temporary ProcessContainer lab directory'
}
$executor = Join-Path $Stage 'wxc-exec.exe'
if ((Get-FileHash -LiteralPath $executor -Algorithm SHA256).Hash -notin @(
    '6D466C6B0109BAB4BCACE6738E11F886D801EA977346DB49707488FCBD3AFC8A',
    'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D')) {
    throw 'Unexpected Windows x64 executor; this test uses Microsoft MXC 1.1.0'
}
$config = Join-Path $Stage ($PolicyName + '.json')
$spec = Get-Content -LiteralPath $config -Encoding UTF8 -Raw | ConvertFrom-Json
if($StaticGuard -and (!$HostLoopbackExperiment -or $Account -cne 'A' -or $PolicyName -cne 'hostloopback' -or
    $spec.process.timeout -ne 90000 -or $spec.process.commandLine -notmatch ' portguardflow$')){throw 'N1 requires bounded A-only flow simulator policy'}
if($N3Protocol -and (!$HostLoopbackExperiment -or $Account -cne 'A' -or $PolicyName -cne 'hostloopback' -or
    $spec.process.timeout -ne 130000 -or $spec.process.commandLine -notmatch ' n3protocol$')){throw 'N3 requires its bounded A-only simulator policy'}
if ($spec.containment -cne 'processcontainer' -or $spec.network.egress.default -cne 'deny' -or
    $spec.network.ingress.hostLoopback -cne $(if ($HostLoopbackExperiment) {'allow'} else {'deny'}) -or $spec.network.egress.allow) {
    throw 'The test requires ProcessContainer, no direct destinations and closed host loopback'
}
if ($HostLoopbackExperiment -and ($Account -cne 'A' -or $PolicyName -cne 'hostloopback' -or
    $spec.network.ingress.default -cne 'deny' -or $spec.runtimeConfig -or $spec.processContainer -or
    $spec.process.timeout -gt $(if($N3Protocol -or $spec.process.commandLine -match ' portguardflow$'){165000}else{85000}) -or $spec.process.timeout -le 0 -or
    $spec.process.commandLine -notmatch $(if($N3Protocol){'StudioProbe\.exe" window studio-[a-f0-9]{16} a healthy [0-9]+ [0-9]+ [0-9]+ n3protocol$'}else{'StudioProbe\.exe" window studio-[a-f0-9]{16} a healthy [0-9]+ [0-9]+ [0-9]+ (hostloopback|portguard|portguardflow)$'}))) {
    throw 'Host loopback experiment must be A-only, bounded, without proxy peers, extra capabilities or denial capture'
}
if ($spec.runtimeConfig.networkProxy) {
    $uri = [uri]$spec.runtimeConfig.networkProxy
    if ($uri.Host -ne '127.0.0.1' -or $uri.Port -lt 49152 -or $spec.processContainer.network.allowedProxyPeer -cne
        ('ClaudeStudio.MockProxy.' + (Split-Path $Stage -Leaf).Substring(5))) {
        throw 'Unexpected proxy endpoint or peer'
    }
}
$accounts = Get-LabAccounts
$inner = @'
function Get-ProfileNames {
    $base = Join-Path $env:LOCALAPPDATA 'Packages'
    if (Test-Path -LiteralPath $base) { Get-ChildItem -Directory -Force -LiteralPath $base | ForEach-Object Name }
}
$before = @(Get-ProfileNames)
$executor = EXECUTOR_PATH
$config = CONFIG_PATH
$output = @(& $executor --probe $config)
$probeCode = $LASTEXITCODE
$capability = $output -join [Environment]::NewLine | ConvertFrom-Json
$output = @()
$runCode = $null
if ($probeCode -eq 0 -and $capability.tier -eq 'base-container' -and RUN_WORKLOAD) {
    $ErrorActionPreference = 'Continue'
    $output = @(& $executor $config 2>&1 | ForEach-Object { [string]$_ })
    $runCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
}
$after = @(Get-ProfileNames)
[pscustomobject]@{callerSid=$id.User.Value; session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    tier=$capability.tier; probeExit=$probeCode; warnings=$capability.warnings; runExit=$runCode
    output=$output; addedProfileDirs=@($after | Where-Object {$_ -notin $before})
} | ConvertTo-Json -Compress -Depth 6
'@
$inner = $inner.Replace('EXECUTOR_PATH', (ConvertTo-LabLiteral $executor)).Replace('CONFIG_PATH', (ConvertTo-LabLiteral $config))
$inner = $inner.Replace('RUN_WORKLOAD', $(if ($ProbeOnly) {'$false'} else {'$true'}))
$probe = Start-LabProbe $accounts[$Account] $inner
if ($Async) { return $probe }
$result = Read-LabProbe $probe ([Math]::Max(20000, [int]$spec.process.timeout + 20000))
$result | ConvertTo-Json -Depth 6
