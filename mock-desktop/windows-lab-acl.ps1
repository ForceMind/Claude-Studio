param([Parameter(Mandatory)][string]$Workspace, [string]$RollbackRun)
Set-StrictMode -Version Latest
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $Workspace 'mock-desktop\windows-lab-local.ps1'))))

$hostSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$rootParent = [IO.Path]::GetFullPath((Join-Path $Workspace '.prototype\windows-lab'))
$root = Join-Path $rootParent ('acl-' + [guid]::NewGuid().ToString('N'))
$reportPath = Join-Path $Workspace '.prototype\mock-results\windows-acl.json'
$report = [ordered]@{passed=$false; rollback=$false; kind='Windows NTFS DACL with lab account tokens'; fixture=(Split-Path -Leaf $root)}
$snapshots = [ordered]@{}
$aclSection = [Security.AccessControl.AccessControlSections]::Access

function Assert-Lab($Value, [string]$Message) { if (!$Value) { throw $Message } }
function Write-LabAcl($Path, $Acl) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unexpected reparse point: $Path" }
    $item.SetAccessControl($Acl)
}
function Restore-LabAcl($Directory, $Snapshots) {
    $prefix = $Directory + [IO.Path]::DirectorySeparatorChar
    foreach ($name in $Snapshots.Keys) {
        $path = [IO.Path]::GetFullPath($name)
        if ($path -ne $Directory -and !$path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Snapshot contains a path outside the fixture'
        }
        $before = $Snapshots[$name]
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $before.owner) {
            $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($before.owner))
            Write-LabAcl $path $acl
        }
    }
    foreach ($name in $Snapshots.Keys) {
        $acl = Get-Acl -LiteralPath $name
        $acl.SetSecurityDescriptorSddlForm($Snapshots[$name].dacl, $aclSection)
        Write-LabAcl $name $acl
    }
    foreach ($name in $Snapshots.Keys) {
        $current = Get-Acl -LiteralPath $name
        # Windows may add the auto-inherited marker while propagating the restored ACL.
        $actual = $current.GetSecurityDescriptorSddlForm($aclSection) -replace '^D:([A-Z]*)AI', 'D:$1'
        $expected = $Snapshots[$name].dacl -replace '^D:([A-Z]*)AI', 'D:$1'
        Assert-Lab ($actual -eq $expected -and
            $current.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $Snapshots[$name].owner) "ACL rollback mismatch: $name"
    }
}

if ($RollbackRun) {
    if ($RollbackRun -cnotmatch '^acl-[0-9a-f]{32}$') { throw 'Invalid fixture name' }
    $root = Join-Path $rootParent $RollbackRun
    $saved = Get-Content -Raw -LiteralPath (Join-Path $rootParent ($RollbackRun + '-acl-backup.json')) | ConvertFrom-Json
    foreach ($item in $saved.PSObject.Properties) { $snapshots[$item.Name] = $item.Value }
    Restore-LabAcl $root $snapshots
    "ACL rollback verified for $RollbackRun"
    return
}

$accounts = Get-LabAccounts
function Add-SidRule($Acl, $Sid, $Rights, $Inheritance, $Propagation) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]$Sid,
        [Security.AccessControl.FileSystemRights]$Rights,
        [Security.AccessControl.InheritanceFlags]$Inheritance,
        [Security.AccessControl.PropagationFlags]$Propagation,
        [Security.AccessControl.AccessControlType]::Allow)
    $Acl.AddAccessRule($rule)
}

function Set-LabDirectory($Path, [hashtable]$Roles) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.PurgeAccessRules($rule.IdentityReference) }
    foreach ($sid in @($hostSid.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        Add-SidRule $acl $sid 'FullControl' 'ContainerInherit,ObjectInherit' 'None'
    }
    foreach ($id in $Roles.Keys) {
        $sid = $accounts[$id].Sid
        switch ($Roles[$id]) {
            Traverse { Add-SidRule $acl $sid 'Traverse,ReadAttributes' 'None' 'None' }
            Read { Add-SidRule $acl $sid 'ReadAndExecute' 'ContainerInherit,ObjectInherit' 'None' }
            Modify { Add-SidRule $acl $sid 'Modify' 'ContainerInherit,ObjectInherit' 'None' }
            Writer {
                Add-SidRule $acl $sid 'ReadAndExecute,CreateFiles' 'None' 'None'
                Add-SidRule $acl $sid 'Modify' 'ContainerInherit,ObjectInherit' 'InheritOnly'
            }
        }
    }
    Add-SidRule $acl 'S-1-3-4' 'ReadPermissions' 'ContainerInherit,ObjectInherit' 'None'
    Write-LabAcl $Path $acl
}

function Invoke-LabGit($Directory, [string[]]$Arguments) {
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $result = & $git -c core.autocrlf=false -C $Directory @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git command failed' }
    return $result
}

function File-Probe($Id, $Mode) {
    $prefix = '$root=' + (ConvertTo-LabLiteral $root) + [Environment]::NewLine +
              '$profile=' + (ConvertTo-LabLiteral $Id) + [Environment]::NewLine +
              '$mode=' + (ConvertTo-LabLiteral $Mode) + [Environment]::NewLine
    $body = @'
function Denied([scriptblock]$Operation) {
    try { & $Operation; return $false }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [UnauthorizedAccessException] -or $ex.HResult -eq -2147024891) { return $true }
        throw
    }
}
$peer = if ($profile -eq 'A') { 'B' } else { 'A' }
$mine = Join-Path $root ($profile + '\own.txt')
$file = Join-Path $root 'projects\shared\note.txt'
$repo = Split-Path -Parent $file
$result = [ordered]@{ ownRead=([IO.File]::ReadAllText($mine) -eq $profile) }
[IO.File]::WriteAllText($mine, $profile)
$result.peerDenied = Denied { [void][IO.File]::ReadAllText((Join-Path $root ($peer + '\own.txt'))) }
$result.privateProjectDenied = Denied { [void][IO.File]::ReadAllText((Join-Path $root 'projects\restricted\hidden.txt')) }
$result.gitMetadataDenied = Denied { [void][IO.File]::ReadAllText((Join-Path $repo '.git\HEAD')) }
if ($mode -eq 'ro') {
    $result.read = [IO.File]::ReadAllText($file).Trim()
    $result.overwriteDenied = Denied { $s = [IO.File]::Open($file, 'Open', 'Write'); $s.Dispose() }
    $result.createDenied = Denied { [IO.File]::WriteAllText((Join-Path $repo 'reader-created.txt'), $profile) }
    $result.deleteDenied = Denied { [IO.File]::Delete($file) }
} else {
    $script = Join-Path $root 'runtime\project-worker.cjs'
    $node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
    $env:MOCK_PROFILE = $profile
    $key = & $node -e "const s=require('node:fs').statSync(process.argv[1],{bigint:true});console.log(s.dev+'/'+s.ino)" $repo
    if ($LASTEXITCODE -ne 0) {throw 'Could not read fixture identity'}
    $project = & $node $script write $repo $key rw | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {throw 'Simulated Code write failed'}
    $result.write = $project.text.Trim()
    $result.changeDaclDenied = Denied {
        $acl = [IO.File]::GetAccessControl($file)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($id.User,'FullControl','Allow'))
        [IO.File]::SetAccessControl($file, $acl)
    }
}
[pscustomobject]$result | ConvertTo-Json -Compress
'@
    $result = Read-LabProbe (Start-LabProbe $accounts[$Id] ($prefix + $body))
    Assert-Lab ($result.ownRead -and $result.peerDenied -and $result.privateProjectDenied -and $result.gitMetadataDenied) "Isolation failed for $Id"
    if ($Mode -eq 'ro') {
        Assert-Lab ($result.overwriteDenied -and $result.createDenied -and $result.deleteDenied) "Read-only enforcement failed for $Id"
    } else {
        Assert-Lab ($result.changeDaclDenied -and $result.write -eq ('edited by simulated Code ' + $Id)) "Project write or creator DACL check failed for $Id"
    }
    return $result
}

try {
    foreach ($path in @($Workspace, (Join-Path $Workspace '.prototype'), $rootParent)) {
        if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected reparse point: $path"
        }
    }
    [void][IO.Directory]::CreateDirectory($root)
    $repo = Join-Path $root 'projects\shared'
    foreach ($relative in 'A','B','runtime','projects\shared','projects\restricted') {
        [void][IO.Directory]::CreateDirectory((Join-Path $root $relative))
    }
    foreach ($id in 'A','B') { [IO.File]::WriteAllText((Join-Path $root ($id + '\own.txt')), $id) }
    [IO.File]::WriteAllText((Join-Path $root 'projects\restricted\hidden.txt'), 'synthetic')
    Copy-Item -LiteralPath (Join-Path $Workspace 'mock-desktop\project-worker.cjs') -Destination (Join-Path $root 'runtime')
    Invoke-LabGit $repo @('init','--quiet','--template=')
    [IO.File]::WriteAllText((Join-Path $repo 'note.txt'), ('simulated project baseline' + [char]10))
    Invoke-LabGit $repo @('add','--','note.txt')
    foreach ($item in @((Get-Item -LiteralPath $root)) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $snapshots[$item.FullName] = @{dacl=$acl.GetSecurityDescriptorSddlForm($aclSection); owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value}
    }
    $snapshots | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $rootParent ([IO.Path]::GetFileName($root) + '-acl-backup.json')) -Encoding UTF8
    Set-LabDirectory (Join-Path $repo '.git') @{}
    Set-LabDirectory $root @{A='Traverse'; B='Traverse'}
    Set-LabDirectory (Join-Path $root 'A') @{A='Modify'}
    Set-LabDirectory (Join-Path $root 'B') @{B='Modify'}
    Set-LabDirectory (Join-Path $root 'projects') @{A='Traverse'; B='Traverse'}
    Set-LabDirectory (Join-Path $root 'projects\restricted') @{}
    Set-LabDirectory (Join-Path $root 'runtime') @{A='Read'; B='Read'}
    Set-LabDirectory $repo @{A='Writer'; B='Read'}
    $report.AWriter = File-Probe 'A' 'rw'
    $report.BReader = File-Probe 'B' 'ro'
    Assert-Lab ($report.BReader.read -eq 'edited by simulated Code A') 'B did not see A changes on the original path'
    $report.hostDiffA = (Invoke-LabGit $repo @('diff','--no-ext-diff','--','note.txt')) -join [char]10
    Assert-Lab ($report.hostDiffA -match '(?m)^\+edited by simulated Code A$') 'Host Git diff did not show A changes'
    Set-LabDirectory $repo @{A='Read'; B='Writer'}
    $report.AReader = File-Probe 'A' 'ro'
    $report.BWriter = File-Probe 'B' 'rw'
    $report.hostDiffB = (Invoke-LabGit $repo @('diff','--no-ext-diff','--','note.txt')) -join [char]10
    Assert-Lab ($report.hostDiffB -match '(?m)^\+edited by simulated Code B$') 'Host Git diff did not show B changes'
    $report.passed = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    try {
        Restore-LabAcl $root $snapshots
        $report.rollback = $true
    } catch {
        $report.rollbackError = $_.Exception.Message
    }
    foreach ($account in $accounts.Values) { $account.Credential.Password.Dispose() }
    $report.finished = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
}
$report | ConvertTo-Json -Depth 6
if (!$report.passed -or !$report.rollback) { exit 1 }
