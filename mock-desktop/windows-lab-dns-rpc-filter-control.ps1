# The caller supplies the private handoff directory and the four experiment inputs.
function Get-RpcFilterSnapshot {
    $path = Join-Path $directory 'rpc-filters.xml'
    try {
        $null = & netsh.exe wfp show filters "file=$path" verbose=on
        if ($LASTEXITCODE -ne 0) { throw 'WFP filter enumeration failed' }
        $doc = [Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($path)
        $entries = @($doc.SelectNodes("//*[local-name()='filterKey']/..") | Where-Object layerKey)
        if (!@($entries | Where-Object layerKey -eq 'FWPM_LAYER_ALE_AUTH_CONNECT_V4').Count) {
            throw 'WFP inventory has no IPv4 control entries'
        }
        return @($entries | Where-Object { ([string]$_.layerKey).Trim('{}') -in
            'FWPM_LAYER_RPC_UM','75a89dda-95e4-40f3-adc7-7688a9c847e1' } | ForEach-Object { [string]$_.filterKey })
    } finally {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
}

function Invoke-LabRpcRule($State, [int]$ServicePid) {
    $exe = Join-Path $directory 'StudioRpcRule.exe'
    $livePath = Join-Path $directory 'rule-live'
    $releasePath = Join-Path $directory 'release'
    $applyPath = Join-Path $directory 'apply'
    $stopPath = Join-Path $directory 'stop'
    $owner = $null
    $ownerErrors = $null
    try {
        $deadline = [datetime]::UtcNow.AddSeconds(15)
        while (!(Test-Path -LiteralPath $applyPath)) {
            if ((Test-Path -LiteralPath $releasePath) -or (Test-Path -LiteralPath $stopPath)) { return }
            if ([datetime]::UtcNow -gt $deadline) { throw 'Timed out waiting for the approved test phase' }
            Start-Sleep -Milliseconds 50
        }
        if (Test-Path -LiteralPath $releasePath) { return }
        if ($ServicePid -ne $baselineServicePid -or (Get-LabDnsServicePid) -ne $ServicePid) { throw 'DNS service PID differs from baseline' }
        $account = Get-LocalUser -SID $accountSid -ErrorAction Stop
        if (!$account.Enabled -or $account.Name -cne 'ClaudeStudioLabA') { throw 'Unexpected local A account' }
        $who = "$env:COMPUTERNAME\$($account.Name)"
        $other = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object UserName -eq $who)
        if ($other.Count) { throw 'Account A already has running processes' }
        $State.before = @(Get-RpcFilterSnapshot)
        if ($State.before.Count) { throw 'Existing RPC filters require review' }
        $null = & $exe absent $subKey $filterKey
        if ($LASTEXITCODE -ne 0) { throw 'Object IDs were not both absent before applying' }
        if (Test-Path -LiteralPath $releasePath) { return }
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $exe
        $start.Arguments = "hold $subKey $filterKey $accountSid"
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $owner = [Diagnostics.Process]::Start($start)
        $State.ownerPid = $owner.Id
        $State.startedUtc = [datetime]::UtcNow.ToString('o')
        $ownerErrors = $owner.StandardError.ReadToEndAsync()
        $ready = $owner.StandardOutput.ReadLineAsync()
        if (!$ready.Wait(6000) -or $ready.Result -notmatch '^READY (\d+)$') { throw 'Rule owner did not verify both conditions' }
        $State.filterId = $Matches[1]
        $State.verifiedUtc = [datetime]::UtcNow.ToString('o')
        [IO.File]::WriteAllText($livePath, $State.verifiedUtc)
        $deadline = [datetime]::UtcNow.AddSeconds(48)
        $checkAt = [datetime]::UtcNow
        while (!(Test-Path -LiteralPath $releasePath) -and !(Test-Path -LiteralPath $stopPath)) {
            if ($owner.HasExited -or [datetime]::UtcNow -gt $deadline) { throw 'The temporary rule window expired' }
            if ([datetime]::UtcNow -ge $checkAt) {
                if ((Get-LabDnsServicePid) -ne $ServicePid) { throw 'Service PID changed while the rule was active' }
                $checkAt = [datetime]::UtcNow.AddSeconds(1)
            }
            Start-Sleep -Milliseconds 50
        }
    } catch {
        $State.error = $_.Exception.Message
    } finally {
        try {
            if ($owner) {
                if (!$owner.HasExited) {
                    $owner.StandardInput.Close()
                    if (!$owner.WaitForExit(5500)) { $owner.Kill(); [void]$owner.WaitForExit(3000) }
                }
                if (!$owner.HasExited) { throw 'Dynamic rule owner remains active' }
                $State.ownerExit = $owner.ExitCode
                if ($ownerErrors.Wait(1000) -and $ownerErrors.Result) { $State.ownerError = $ownerErrors.Result.Trim() }
                $State.ownerGone = $true
            }
            $null = & $exe absent $subKey $filterKey
            if ($LASTEXITCODE -ne 0) { throw 'At least one of the experiment GUIDs is still present or unreadable' }
            $State.objectsGone = $true
            $State.removedUtc = [datetime]::UtcNow.ToString('o')
            [IO.File]::WriteAllText((Join-Path $directory 'rule-gone'), $State.removedUtc)
            if ($null -ne $State.before) {
                $State.after = @(Get-RpcFilterSnapshot)
                $State.baselineRestored = $State.after.Count -eq 0
            }
        } catch {
            $State.cleanupError = $_.Exception.Message
        } finally {
            if ($owner) { $owner.Dispose() }
        }
    }
}
