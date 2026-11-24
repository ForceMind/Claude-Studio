param([Parameter(Mandatory)][string]$Workspace)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$reportRoot = Join-Path $Workspace '.prototype\mock-results'
$report = [ordered]@{cases=@(); finished=$null}
if (-not ('StudioLabWfp' -as [type])) { Add-Type -Path (Join-Path $Workspace 'mock-desktop\windows-lab-wfp.cs') }
$wfp = [StudioLabWfp]::new()
try {
    foreach ($protocol in 'TCP','UDP') {
        $local = $null
        $client = $null
        $eventFile = Join-Path $reportRoot ('ipv6-events-' + [guid]::NewGuid().ToString('N') + '.xml')
        $entry = [ordered]@{protocol=$protocol; filter=@()}
        try {
            if ($protocol -eq 'TCP') {
                $local = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback,0)
                $local.Start()
                $localPort = $local.LocalEndpoint.Port
                $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
                $client.Connect([Net.IPAddress]::IPv6Loopback,$localPort)
            } else {
                $local = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::IPv6Loopback,0))
                $localPort = $local.Client.LocalEndPoint.Port
                $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
                $client.Connect([Net.IPAddress]::IPv6Loopback,$localPort)
                [void]$client.Send([byte[]]@(73),1)
                $local.Client.ReceiveTimeout = 800
                $sender = [Net.IPEndPoint]::new([Net.IPAddress]::IPv6Any,0)
                [void]$local.Receive([ref]$sender)
            }
            $entry.reachable = $true
        } catch {
            $cause = $_.Exception
            while ($cause.InnerException) { $cause = $cause.InnerException }
            $entry.reachable = $false
            $entry.error = $cause.Message
            if ($cause -is [Net.Sockets.SocketException]) { $entry.socketError = [int]$cause.SocketErrorCode }
        } finally {
            if ($client) { $client.Close() }
            $entry.port = $localPort
            try {
                $number = if ($protocol -eq 'TCP') { 6 } else { 17 }
                $readback = & netsh.exe wfp show netevents ("file=" + $eventFile) "protocol=$number" 'remoteaddr=::1' "remoteport=$localPort" 'timewindow=30'
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $eventFile)) {
                    [xml]$events = Get-Content -Raw -LiteralPath $eventFile
                    $ids = @($events.SelectNodes("//*[local-name()='classifyDrop']/*[local-name()='filterId']") |
                        ForEach-Object InnerText | Where-Object { $_ -match '^[1-9][0-9]*$' } | Select-Object -Unique)
                    foreach ($id in $ids) {
                        try { $entry.filter += $wfp.Describe([uint64]$id) } catch { $entry.lookupError = $_.Exception.Message }
                    }
                    if (!$ids.Count) { $entry.noMatchingDrop = $true }
                } else { $entry.eventError = ($readback -join ' ') }
            } finally {
                if (Test-Path -LiteralPath $eventFile) { Remove-Item -LiteralPath $eventFile }
                if ($local -is [Net.Sockets.TcpListener]) {$local.Stop()}
                elseif ($local) {$local.Close()}
            }
        }
        $report.cases += $entry
    }
} finally {
    $wfp.Dispose()
    $report.finished = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $reportRoot 'windows-ipv6-diagnosis.json') -Encoding UTF8
}
