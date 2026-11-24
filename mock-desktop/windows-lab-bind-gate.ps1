[CmdletBinding()]
param([string]$Directory, [switch]$Worker, [switch]$Watch, [switch]$Rollback, [switch]$FunctionsOnly)
$ErrorActionPreference = 'Stop'
$tempRoot = [IO.Path]::GetTempPath().TrimEnd('\')
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Write-GateJson([string]$Path, $Value) {
    $pending = $Path + '.tmp'
    [IO.File]::WriteAllText($pending, ($Value | ConvertTo-Json -Depth 12))
    [IO.File]::Move($pending, $Path)
}

function Read-GateDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    if (!$item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $item.Parent.FullName -ine $tempRoot -or $item.Name -cnotmatch '^ClaudeStudioBind-[a-f0-9]{32}$') {
        throw 'Unexpected N2 gate directory'
    }
    return $item.FullName
}

function Read-TcpRanges([int]$Family) {
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $dynamic = @(& $netsh interface "ipv$Family" show dynamicportrange protocol=tcp store=active)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot query TCP dynamic range' }
    $values = @($dynamic | ForEach-Object { if ($_ -match '^\s*[^:]+:\s*(\d+)\s*$') { [int]$Matches[1] } })
    if ($values.Count -ne 2 -or $values[0] -lt 1 -or $values[1] -lt 1 -or ($values[0] + $values[1]) -gt 65536) {
        throw 'Unrecognized TCP dynamic range output'
    }
    $excluded = @(& $netsh interface "ipv$Family" show excludedportrange protocol=tcp store=active)
    if ($LASTEXITCODE -ne 0 -or !($excluded -match '^\s*-+\s+-+\s*$')) { throw 'Cannot verify TCP port exclusions' }
    $ranges = @(@{ first=$values[0]; last=($values[0]+$values[1]-1); source='dynamic' })
    foreach ($line in $excluded) {
        if ($line -match '^\s*(\d+)\s+(\d+)\s*\*?\s*$') { $ranges += @{first=[int]$Matches[1];last=[int]$Matches[2];source='excluded'} }
    }
    return $ranges
}

function Select-N2Ports([ValidateRange(1,2)][int]$Count) {
    $ranges = @(Read-TcpRanges 4) + @(Read-TcpRanges 6)
    $ip = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $occupied = @($ip.GetActiveTcpConnections() | ForEach-Object {$_.LocalEndPoint.Port})
    $occupied += @($ip.GetActiveTcpListeners() | ForEach-Object {$_.Port})
    $ports = @(Get-Random -InputObject (40000..49151) -Count 100 | Where-Object {
        $candidate = $_
        $candidate -notin $occupied -and !@($ranges | Where-Object {$candidate -ge $_.first -and $candidate -le $_.last}).Count
    } | Select-Object -First $Count)
    if ($ports.Count -ne $Count) { throw 'No eligible temporary test ports found' }
    return [uint16[]]$ports
}

function New-N2PrivateAcl {
    $root = [IO.Path]::GetTempPath().TrimEnd('\')
    $trusted = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Temporary parent is a reparse point' }
    $acl = Get-Acl -LiteralPath $root
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Unexpected TEMP owner' }
    $writeMask = 'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership' -as [Security.AccessControl.FileSystemRights]
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin $trusted -and ($ace.FileSystemRights -band $writeMask)) {
            throw 'TEMP parent grants mutation rights outside the trusted identities'
        }
    }
    $privateAcl = [Security.AccessControl.DirectorySecurity]::new()
    $privateAcl.SetAccessRuleProtection($true,$false)
    foreach ($sid in $trusted) {
        $privateAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    return $privateAcl
}

function New-GateSocket {
    $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
    $socket.SendTimeout = 1000
    $socket.ReceiveTimeout = 1000
    return $socket
}

function Test-GateBind([int]$Port, [Net.IPAddress]$Address, [string]$Option) {
    $socket = New-GateSocket
    $stage = 'bind'
    try {
        if ($Option -eq 'exclusive') { $socket.ExclusiveAddressUse = $true }
        if ($Option -eq 'reuse') { $socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,[Net.Sockets.SocketOptionName]::ReuseAddress,$true) }
        $socket.Bind([Net.IPEndPoint]::new($Address,$Port))
        $stage = 'listen'
        $socket.Listen(1)
        return @{address=$Address.ToString();option=$Option;stage='listening';nativeError=0}
    } catch [Net.Sockets.SocketException] {
        return @{address=$Address.ToString();option=$Option;stage=$stage;nativeError=$_.Exception.NativeErrorCode}
    } finally { $socket.Dispose() }
}

function Open-GatePair($Listener) {
    $client = New-GateSocket
    $server = $null
    try {
        $pending = $client.BeginConnect($Listener.LocalEndPoint,$null,$null)
        try {
            if (!$pending.AsyncWaitHandle.WaitOne(1500)) { throw 'Loopback connection timed out' }
            $client.EndConnect($pending)
        } finally { $pending.AsyncWaitHandle.Dispose() }
        if (!$Listener.Poll(1000000,[Net.Sockets.SelectMode]::SelectRead)) { throw 'Loopback accept timed out' }
        $server = $Listener.Accept()
        $server.SendTimeout = 1000
        $server.ReceiveTimeout = 1000
        return @{ client=$client;server=$server }
    } catch { $client.Dispose(); if ($server) { $server.Dispose() }; throw }
}

function Send-GateMarker($Pair, [byte]$Marker) {
    $bytes = [byte[]]@($Marker)
    $read = [byte[]]@(0)
    if ($Pair.client.Send($bytes) -ne 1 -or $Pair.server.Receive($read) -ne 1 -or $read[0] -ne $Marker) {
        throw 'Client to listener marker failed'
    }
    $read[0] = 0
    if ($Pair.server.Send($bytes) -ne 1 -or $Pair.client.Receive($read) -ne 1 -or $read[0] -ne $Marker) {
        throw 'Listener to client marker failed'
    }
    return $true
}

function Close-GatePair($Pair) {
    if (!$Pair) { return }
    # Abort only this synthetic connection so TIME_WAIT cannot impersonate a WFP denial.
    $Pair.client.LingerState = [Net.Sockets.LingerOption]::new($true,0)
    $Pair.server.LingerState = [Net.Sockets.LingerOption]::new($true,0)
    $Pair.client.Dispose()
    $Pair.server.Dispose()
}

if ($FunctionsOnly) { return }

if ($Worker -or $Watch -or $Rollback) {
    if (@($Worker,$Watch,$Rollback | Where-Object { $_ }).Count -ne 1) { throw 'Select exactly one gate role' }
    $Directory = Read-GateDirectory $Directory
    $library = Join-Path $Directory 'BindGuard.dll'
    $manifestFile = Join-Path $Directory 'gate-manifest.json'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'N2 WFP gate requires an elevated process'
    }
    Add-Type -Path $library
    if ($Watch -or $Rollback) {
        $manifest = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $process = Get-Process -Id $manifest.pid -ErrorAction SilentlyContinue
        if ($process) {
            try {
                [void]$process.Handle
                if ($process.StartTime.ToUniversalTime().Ticks -eq $manifest.startTicks) {
                    if ($Rollback) { throw 'Stop the active gate worker before manual rollback' }
                    Write-GateJson (Join-Path $Directory 'watch-ready.json') @{pid=$PID}
                    if (!$process.WaitForExit(25000)) {
                        $process.Kill()
                        if (!$process.WaitForExit(3000)) { throw 'Gate worker still alive; retain recovery manifest' }
                    }
                }
            } finally { $process.Dispose() }
        }
        [StudioLabWfp]::RemoveBindGuard([guid]$manifest.sub,[guid[]]$manifest.keys,[uint16[]]$manifest.ports,[uint16]$manifest.weight)
        $path = Join-Path $Directory $(if ($Watch) { 'watch-clean.json' } else { 'manual-clean.json' })
        Write-GateJson $path @{absent=$true}
        return
    }

    $report = [ordered]@{ outcome='incomplete'; nativeIPv6='readback only'; cleanup=@{absent=$false} }
    $guard = $null; $manifest = $null; $listener = $null; $old = $null; $new = $null; $hostOld = $null; $hostNew = $null; $hostListener = $null; $watcher = $null
    try {
        $port = [uint16](Select-N2Ports 1)
        $report.port = $port
        $report.controlBefore = Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'
        if ($report.controlBefore.stage -ne 'listening') { throw 'No positive bind control' }
        $listener = New-GateSocket
        $listener.ExclusiveAddressUse = $true
        $listener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$port))
        $listener.Listen(4)
        $old = Open-GatePair $listener
        $report.proxyOldBefore = Send-GateMarker $old 31
        $hostListener = New-GateSocket
        $hostListener.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
        $hostListener.Listen(4)
        $hostOld = Open-GatePair $hostListener
        $report.hostOldBefore = Send-GateMarker $hostOld 32
        $report.hostDnsBefore = [Net.Dns]::GetHostAddresses('example.com').Count -gt 0
        if (!$report.hostDnsBefore) { throw 'Host DNS baseline failed' }

        $guard = [StudioLabWfp]::CreateStaticGuard()
        $process = [Diagnostics.Process]::GetCurrentProcess()
        $manifest = @{ pid=$PID;startTicks=$process.StartTime.ToUniversalTime().Ticks;sub=[guid]::NewGuid().ToString();
            keys=@([guid]::NewGuid().ToString(),[guid]::NewGuid().ToString());ports=@($port);weight=0 }
        $manifest.weight = $guard.PrepareBindGuard([guid]$manifest.sub,[guid[]]$manifest.keys,[uint16[]]$manifest.ports)
        $report.priority = $guard.PriorityEvidence
        Write-GateJson $manifestFile $manifest
        $watcher = Start-Process -FilePath $powershell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Watch','-Directory',('"'+$Directory+'"'))
        $deadline = [datetime]::UtcNow.AddSeconds(5)
        while (!(Test-Path -LiteralPath (Join-Path $Directory 'watch-ready.json'))) {
            if ($watcher.HasExited -or [datetime]::UtcNow -ge $deadline) { throw 'Independent rollback did not become ready' }
            Start-Sleep -Milliseconds 40
        }
        $guard.InstallBindGuard([guid]$manifest.sub,[guid[]]$manifest.keys,[uint16[]]$manifest.ports,[uint16]$manifest.weight,0)
        $guard.Dispose(); $guard = $null
        $report.readback = [StudioLabWfp]::VerifyBindGuard([guid]$manifest.sub,[guid[]]$manifest.keys,[uint16[]]$manifest.ports,[uint16]$manifest.weight,1)
        $report.proxyOldAfter = Send-GateMarker $old 33
        $new = Open-GatePair $listener
        $report.proxyNewAfter = Send-GateMarker $new 34
        Close-GatePair $new; $new = $null
        Close-GatePair $old; $old = $null
        $listener.Dispose(); $listener = $null
        $report.bindDeniedAfterClose = @(foreach ($address in @([Net.IPAddress]::Loopback,[Net.IPAddress]::Any)) {
            foreach ($option in 'default','reuse','exclusive') { Test-GateBind $port $address $option }
        })
        if (@($report.bindDeniedAfterClose | Where-Object { $_.stage -ne 'bind' -or $_.nativeError -ne 10013 }).Count) {
            throw 'New binds did not all fail with WSAEACCES at bind'
        }
        $report.hostOldDuring = Send-GateMarker $hostOld 35
        $hostNew = Open-GatePair $hostListener
        $report.hostNewDuring = Send-GateMarker $hostNew 36
        Close-GatePair $hostNew; $hostNew = $null
        $report.hostDnsDuring = [Net.Dns]::GetHostAddresses('example.com').Count -gt 0
        if (!$report.hostDnsDuring) { throw 'Host DNS during bind guard failed' }
        $report.outcome = 'gate-verified-pending-rollback'
    } catch { $report.error = $_.Exception.ToString() }
    finally {
        try {
            if ($guard) { $guard.Dispose() }
            Close-GatePair $old
            Close-GatePair $new
            if ($listener) { $listener.Dispose() }
            if ($manifest -and (Test-Path -LiteralPath $manifestFile)) {
                [StudioLabWfp]::RemoveBindGuard([guid]$manifest.sub,[guid[]]$manifest.keys,[uint16[]]$manifest.ports,[uint16]$manifest.weight)
                $report.cleanup.absent = $true
                $report.cleanup.rebind = Test-GateBind $port ([Net.IPAddress]::Any) 'exclusive'
                $report.cleanup.hostOld = Send-GateMarker $hostOld 37
                $hostNew = Open-GatePair $hostListener
                $report.cleanup.hostNew = Send-GateMarker $hostNew 38
                $report.cleanup.hostDns = [Net.Dns]::GetHostAddresses('example.com').Count -gt 0
                if ($report.outcome -eq 'gate-verified-pending-rollback' -and $report.cleanup.rebind.stage -eq 'listening' -and $report.cleanup.hostDns) {
                    $report.outcome = 'passed-bind-gate'
                }
            } else { $report.cleanup.noManifestNoWrite = $true }
        } catch { $report.cleanup.error = $_.Exception.ToString() }
        finally {
            Close-GatePair $hostNew
            Close-GatePair $hostOld
            if ($hostListener) { $hostListener.Dispose() }
            if ($report.outcome -ne 'passed-bind-gate') { $report.outcome = 'failed-bind-gate' }
            Write-GateJson (Join-Path $Directory 'gate-report.json') $report
        }
    }
    if ($report.outcome -ne 'passed-bind-gate') { exit 2 }
    return
}

if ($Directory) { throw 'The controller allocates its own private directory' }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use Windows PowerShell 5.1 for this gate' }
$Directory = Join-Path $tempRoot ('ClaudeStudioBind-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Directory,(New-N2PrivateAcl))
$canRemove = $true
try {
    $privateScript = Join-Path $Directory 'gate.ps1'
    [IO.File]::WriteAllBytes($privateScript,[IO.File]::ReadAllBytes($PSCommandPath))
    $sources = @('windows-lab-wfp.cs','windows-lab-wfp-container.cs','windows-lab-wfp-bind.cs' | ForEach-Object {
        $dest = Join-Path $Directory $_
        [IO.File]::WriteAllBytes($dest,[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $_)))
        $dest
    })
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $library = Join-Path $Directory 'BindGuard.dll'
    & $csc /nologo /target:library /platform:x64 /optimize+ "/out:$library" $sources
    if ($LASTEXITCODE -ne 0) { throw 'N2 bind guard compilation failed' }
    $sha = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash
    $canRemove = $false
    $workerProcess = Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$privateScript+'"'),'-Worker','-Directory',('"'+$Directory+'"'))
    if (!$workerProcess.WaitForExit(35000)) { throw 'Gate worker did not exit; retain rollback files' }
    $report = Get-Content -LiteralPath (Join-Path $Directory 'gate-report.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $report | Add-Member librarySha256 $sha
    if ($report.cleanup.absent) {
        $deadline = [datetime]::UtcNow.AddSeconds(5)
        while (!(Test-Path -LiteralPath (Join-Path $Directory 'watch-clean.json')) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 60 }
        $report | Add-Member independentCleanup (Test-Path -LiteralPath (Join-Path $Directory 'watch-clean.json'))
        $canRemove = $report.independentCleanup
    } elseif ($report.cleanup.noManifestNoWrite) { $canRemove = $true }
} finally {
    if ($canRemove) {
        $verified = Read-GateDirectory $Directory
        if (@(Get-ChildItem -LiteralPath $verified -Force | Where-Object { $_.PSIsContainer -or $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
            throw 'Unexpected content in the N2 private directory; retain for inspection'
        }
        Get-ChildItem -LiteralPath $verified -Force | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
        Remove-Item -LiteralPath $verified
    } else { Write-Warning "N2 cleanup not verified. Retain rollback directory: $Directory" }
}
$report | Add-Member privateDirectoryRemoved (!(Test-Path -LiteralPath $Directory))
$reportPath = Join-Path $PSScriptRoot ('..\.prototype\mock-results\windows-psec-bind-gate-'+[guid]::NewGuid().ToString('N')+'.json')
Write-GateJson $reportPath $report
[pscustomobject]@{outcome=$report.outcome;cleanup=$report.cleanup;report=(Resolve-Path -LiteralPath $reportPath).Path} | ConvertTo-Json -Depth 6
if ($report.outcome -ne 'passed-bind-gate' -or !$report.independentCleanup -or !$report.privateDirectoryRemoved) { exit 2 }
