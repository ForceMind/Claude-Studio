param([Parameter(Mandatory)][string]$RunDirectory, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dir = [IO.Path]::GetFullPath($RunDirectory)
if ((Split-Path -Leaf $dir) -cnotmatch '^net-[0-9a-f]{32}$' -or
    (Split-Path -Leaf (Split-Path -Parent $dir)) -ne 'windows-lab') { throw 'Unexpected run directory' }
$status = Join-Path $dir 'wfp.json'
$report = [ordered]@{installed=$false; rollback=$false}
$engine = $null
$trace = $null

function Save-Status {
    [IO.File]::WriteAllText($status + '.tmp', ($report | ConvertTo-Json -Depth 5))
    if ([IO.File]::Exists($status)) { [IO.File]::Replace($status + '.tmp', $status, [NullString]::Value) }
    else { [IO.File]::Move($status + '.tmp', $status) }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The WFP helper requires an elevated token' }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $dir 'manifest.json') | ConvertFrom-Json
    $workspace = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $dir))
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $workspace 'mock-desktop\windows-lab-wfp.cs')))
    $sublayer = [guid]$manifest.sublayer
    $keys = [guid[]]$manifest.filters
    $engine = [StudioLabWfp]::new()
    if ($Rollback) {
        $engine.Remove($sublayer, $keys)
        $report.rollback = $true
        return
    }
    $sids = [string[]]@(foreach ($name in 'ClaudeStudioLabA','ClaudeStudioLabB') { (Get-LocalUser -Name $name).SID.Value })
    if ($sids[0] -ne $manifest.sidA -or $sids[1] -ne $manifest.sidB -or $id.User.Value -in $sids) {
        throw 'Test SIDs no longer match the planned scope'
    }
    if ($manifest.dnsPrefix) {
        & ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $workspace 'mock-desktop\windows-lab-ipv6.ps1')))) -Workspace $workspace
        . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $workspace 'mock-desktop\windows-lab-dns-trace.ps1'))))
        $trace = Start-LabDnsTrace $dir $manifest.dnsPrefix
        $report.dnsTraceReady = $true
        Save-Status
        $wait = [Diagnostics.Stopwatch]::StartNew()
        while ($wait.ElapsedMilliseconds -lt 45000 -and !(Test-Path -LiteralPath (Join-Path $dir 'install-wfp'))) {
            if (Test-Path -LiteralPath (Join-Path $dir 'remove-wfp')) { return }
            Start-Sleep -Milliseconds 100
        }
        if ($wait.ElapsedMilliseconds -ge 45000) { throw 'Timed out waiting for the DNS baseline' }
    }
    $engine.Install($sublayer, $keys, $sids, [uint16]$manifest.port)
    $report.installed = $true
    $engine.Verify($sublayer, $keys, $true)
    $report.filtersReadBack = $keys.Count
    Save-Status
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.ElapsedMilliseconds -lt 100000 -and !(Test-Path -LiteralPath (Join-Path $dir 'remove-wfp'))) {
        Start-Sleep -Milliseconds 200
    }
    if ($clock.ElapsedMilliseconds -ge 100000) { $report.error = 'WFP verification timed out' }
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($engine) {
        try {
            if (!$Rollback) {
                $engine.Remove($sublayer, $keys)
                $report.rollback = $true
            }
        } catch { $report.rollbackError = $_.Exception.Message }
        $engine.Dispose()
    }
    if ($trace) {
        try { $report.dns = Stop-LabDnsTrace $trace }
        catch { $report.dnsError = $_.Exception.Message }
    }
    $report.finished = [DateTime]::UtcNow.ToString('o')
    Save-Status
}
