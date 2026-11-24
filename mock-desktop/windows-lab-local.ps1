$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-LabAccounts([ValidateSet('A','B')][string[]]$AccountIds=@('A','B')) {
    $stored = Join-Path $env:LOCALAPPDATA 'Claude-Studio\OfflineRound1'
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
    $accounts = @{}
    foreach ($id in $AccountIds) {
        $name = 'ClaudeStudioLab' + $id
        $account = Get-LocalUser -Name $name
        if (!$account.Enabled -or $account.SID.Value -notin $users -or $account.SID.Value -in $admins) {
            throw "Unexpected group membership or account state for $name"
        }
        $credential = Import-Clixml -LiteralPath (Join-Path $stored ($name + '.xml'))
        if ($credential -isnot [pscredential] -or $credential.UserName -ine "$env:COMPUTERNAME\$name") {
            throw "Unexpected local test credential for $name"
        }
        $accounts[$id] = @{Name=$name; Sid=$account.SID.Value; Credential=$credential}
    }
    return $accounts
}

function Start-LabProbe($Account, [string]$Body, [switch]$StreamOutput) {
    $header = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($id)
if ($id.User.Value -ne '<expected>' -or
    @($id.Groups | ForEach-Object Value) -contains 'S-1-5-32-544' -or
    !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::User)) {
    throw 'Unexpected lab token'
}
'@
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $start.Arguments = '-NoProfile -NonInteractive -Command "& ([scriptblock]::Create([Console]::In.ReadToEnd()))"'
    $start.UserName = $Account.Name
    $start.Domain = $env:COMPUTERNAME
    $start.Password = $Account.Credential.Password
    $start.LoadUserProfile = $true
    $start.WorkingDirectory = $env:SystemRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $result = if (!$StreamOutput) { $process.StandardOutput.ReadToEndAsync() }
        $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($header.Replace('<expected>', $Account.Sid) + [Environment]::NewLine + $Body)
        $process.StandardInput.Close()
        return @{Process=$process; Result=$result; Errors=$errors}
    } catch {
        if (!$process.HasExited) { $process.Kill() }
        $process.Dispose()
        throw
    }
}

function Stop-LabProbe($Probe) {
    if (!$Probe.Process.HasExited) { $Probe.Process.Kill(); [void]$Probe.Process.WaitForExit(3000) }
    $Probe.Process.Dispose()
}

function Read-LabProbe($Probe, [int]$Milliseconds = 15000) {
    try {
        if (!$Probe.Process.WaitForExit($Milliseconds) -or !$Probe.Result.Wait(1000)) { throw 'Lab probe timed out' }
        if ($Probe.Process.ExitCode -ne 0) {
            $message = if ($Probe.Errors.Wait(1000)) { $Probe.Errors.Result } else { '' }
            throw ('Lab probe exited ' + $Probe.Process.ExitCode + ' ' + $message)
        }
        return $Probe.Result.Result | ConvertFrom-Json
    } finally { Stop-LabProbe $Probe }
}

function ConvertTo-LabLiteral([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }
