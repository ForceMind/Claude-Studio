[CmdletBinding(DefaultParameterSetName='Offline')]
param(
    [Parameter(ParameterSetName='Offline')][switch]$SelfTest,
    [Parameter(Mandatory,ParameterSetName='Host')][switch]$HostCheck,
    [Parameter(ParameterSetName='Host')][string]$ExecutorPath
)
$ErrorActionPreference = 'Stop'

$sources = @('windows-lab-wfp.cs','windows-lab-wfp-container.cs','windows-lab-wfp-bind.cs',
    'windows-lab-n4-account-guard.cs') | ForEach-Object { Join-Path $PSScriptRoot $_ }
Add-Type -Path $sources

if ($HostCheck) {
    # Only read the host. Never import credentials or print machine SIDs.
    $build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $checks = [ordered]@{windows = "$($build.CurrentBuild).$($build.UBR)"; account = $null;
        processInventory = $null; package = $null; executor = $null; wfpPriority = $null; errors = [ordered]@{}}
    try {
        $account = Get-LocalUser -Name ClaudeStudioLabA
        $sid = $account.SID.Value
        $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object { $_.SID.Value })
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
        $checks.account = @{ enabled = [bool]$account.Enabled; users = ($sid -in $users);
            administrators = ($sid -in $admins); distinctHost = ($sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) }
    } catch { $checks.errors.account = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    try {
        if (!$checks.account) { throw 'Account SID unavailable' }
        $owned = [Collections.Generic.List[string]]::new()
        $unresolved = 0
        foreach ($process in (Get-CimInstance Win32_Process)) {
            try {
                $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
                if ($owner.ReturnValue -ne 0 -or !$owner.Sid) { $unresolved++; continue }
                if ($owner.Sid -eq $sid) { $owned.Add($process.Name) }
            } catch { $unresolved++ }
        }
        $checks.processInventory = @{ accountProcesses = @($owned.ToArray()); unresolved = $unresolved }
    } catch { $checks.errors.processInventory = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    try {
        $package = @(Get-AppxPackage -Name Claude)
        if ($package.Count -ne 1) { throw 'Expected exactly one current-user package' }
        $manifest = Get-AppxPackageManifest -Package $package[0]
        $apps = @(foreach ($app in $manifest.SelectNodes("//*[local-name()='Applications']/*[local-name()='Application']")) {
            $row = [ordered]@{}
            foreach ($attribute in $app.Attributes) {
                if ($attribute.LocalName -in 'Id','Executable','EntryPoint','RuntimeBehavior','TrustLevel','AppLifecycleBehavior') {
                    $row[$attribute.Name] = $attribute.Value
                }
            }
            $row
        })
        if (!$apps.Count) { throw 'Package activation declaration unavailable' }
        $checks.package = @{ version = [string]$package[0].Version; applications = $apps;
            aliases = @($manifest.SelectNodes("//*[local-name()='ExecutionAlias']") | ForEach-Object { $_.GetAttribute('Alias') }) }
    } catch { $checks.errors.package = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    try {
        if (!$ExecutorPath) { throw 'Local pinned MXC 1.1.0 executable not supplied' }
        $resolved = (Resolve-Path -LiteralPath $ExecutorPath).ProviderPath
        $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
        $checks.executor = @{ sha256 = $hash; exact = ($hash -ceq 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D') }
    } catch { $checks.errors.executor = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    try { $checks.wfpPriority = [StudioLabWfp]::ReadAccountGuardWeight() }
    catch { $checks.errors.wfpPriority = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    return $checks
}

$accountSid = 'S-1-5-21-1-2-3-1001'
$packageSid = 'S-1-15-2-1-2-3-4-5-6-7'
$sub = [guid]::NewGuid()
$keys = [guid[]]@(1..5 | ForEach-Object { [guid]::NewGuid() })
$type = [StudioLabWfp+AccountGuardSpec]
$base = $type::new($accountSid, '', $sub, [guid[]]$keys[0..3], 100, 0)
$proxy = $type::new($accountSid, $packageSid, $sub, $keys, 100, 45000)
$basePreview = @([StudioLabWfp]::PreviewAccountGuard($base))
$preview = @([StudioLabWfp]::PreviewAccountGuard($proxy))

if (!$SelfTest) {
    return [ordered]@{ mode = 'synthetic-preview'; systemWrites = 0; applicable = $false; rules = $preview }
}

function Assert-Test([bool]$Condition, [string]$Name) {
    if (!$Condition) { throw ('N4 offline assertion failed: ' + $Name) }
}
function Assert-Rejected([scriptblock]$Action, [string]$Name) {
    try { & $Action | Out-Null }
    catch [ArgumentException] { return }
    throw ('N4 offline accepted invalid scope: ' + $Name)
}

$layers = @('c38d57d1-05a7-4c33-904f-7fbceee60e82','4a72393b-319f-44bc-84c3-ba54dcb3b6b4',
    'e1cd9fe7-f4b5-4273-96c0-592e487b8650','a3b42c97-9f04-4672-b87e-cee9c483257f')
$userField = 'af043a0a-b34d-4f86-979c-c90371af6e66'
Assert-Test ($basePreview.Count -eq 4 -and $preview.Count -eq 5) 'base and exception counts'
for ($index = 0; $index -lt 4; $index++) {
    $row = $basePreview[$index]
    Assert-Test ($row.layer -eq $layers[$index] -and $row.key -eq $keys[$index] -and
        $row.sublayer -eq $sub -and $row.action -eq 4097 -and $row.flags -eq 0 -and
        $row.lifetime -ceq 'static' -and $row.conditions.Count -eq 1) 'exact base filter'
    $condition = $row.conditions[0]
    Assert-Test ($condition.field -eq $userField -and $condition.type -eq 14 -and $condition.match -eq 0) 'user descriptor condition'
    $bytes = [Convert]::FromBase64String($condition.value)
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
    Assert-Test ($sd.DiscretionaryAcl.Count -eq 1 -and $sd.DiscretionaryAcl[0].AccessMask -eq 1 -and
        $sd.DiscretionaryAcl[0].SecurityIdentifier.Value -eq $accountSid) 'single SID and mask'
    Assert-Test (($row | ConvertTo-Json -Depth 6 -Compress) -ceq
        ($preview[$index] | ConvertTo-Json -Depth 6 -Compress)) 'same base in proxy scope'
}
$e = $preview[4]
Assert-Test ($e.sublayer -eq $sub -and $e.layer -eq $layers[0] -and $e.flags -eq 0 -and
    $e.action -eq 4098 -and $e.weight -gt $preview[0].weight -and $e.lifetime -ceq 'dynamic-session' -and
    $e.conditions.Count -eq 5) 'soft dynamic exception in same sublayer'
$fields = @($userField,'71bc78fa-f17c-4997-a602-6abb261f351c','3971ef2b-623e-4f9a-8cb1-6e79b806b9a7',
    'b235ae9a-1d64-49b8-a44c-5ff3d9095045','c35a604d-d22b-4e1a-91b4-68f674ee674b')
$values = @($basePreview[0].conditions[0].value,$packageSid,6,0x7f000001,45000)
$types = @(14,13,1,3,2)
for ($index = 0; $index -lt $fields.Count; $index++) {
    $condition = $e.conditions[$index]
    Assert-Test ($condition.field -eq $fields[$index] -and $condition.type -eq $types[$index] -and
        $condition.value -eq $values[$index] -and $condition.match -eq 0) 'exception intersects all five conditions'
}
Assert-Rejected { $type::new('S-1-5-18','',$sub,[guid[]]$keys[0..3],100,0) } 'system SID'
Assert-Rejected { $type::new($accountSid,$accountSid,$sub,$keys,100,45000) } 'account as package SID'
Assert-Rejected { $type::new($accountSid,$packageSid,$sub,$keys,100,10810) } 'reserved port'
Assert-Rejected { $type::new($accountSid,$packageSid,$sub,$keys,100,49152) } 'dynamic port range'
Assert-Rejected { $type::new($accountSid,'',$sub,[guid[]]$keys[0..3],100,45000) } 'deny-only with proxy port'
Assert-Rejected { $type::new($accountSid,'',$sub,[guid[]]$keys[0..2],100,0) } 'missing deny key'
Assert-Rejected { $type::new($accountSid,'',$sub,[guid[]]@($sub,$keys[1],$keys[2],$keys[3]),100,0) } 'sublayer GUID collision'
Assert-Rejected { $type::new($accountSid,'',$sub,[guid[]]$keys[0..3],0,0) } 'implicit sublayer weight'
$binding = [Guid]::NewGuid()
$bindKeys = [Guid[]]@(1..4 | ForEach-Object { [Guid]::NewGuid() })
[StudioLabWfp]::ValidateBoundAccountProxy($proxy,$binding,$bindKeys,[uint16[]]@(45000,45001),99)
Assert-Rejected { [StudioLabWfp]::ValidateBoundAccountProxy($proxy,$binding,$bindKeys,[uint16[]]@(45001,45000),99) } 'permit to the upstream port'
Assert-Rejected { [StudioLabWfp]::ValidateBoundAccountProxy($proxy,$binding,$bindKeys,[uint16[]]@(45000,45001),100) } 'binding weight equals account weight'
Assert-Rejected { [StudioLabWfp]::ValidateBoundAccountProxy($proxy,$sub,$bindKeys,[uint16[]]@(45000,45001),99) } 'binding shared with the account sublayer'
Assert-Rejected { [StudioLabWfp]::ValidateBoundAccountProxy($base,$binding,$bindKeys,[uint16[]]@(45000,45001),99) } 'exception without a runtime package'

[ordered]@{ mode = 'offline-selftest'; passed = $true; denies = 4; exceptionConditions = 5;
    rejectedScopes = 12; systemWrites = 0; sourceHashes = @($sources | ForEach-Object {
        @{ file = (Split-Path $_ -Leaf); sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash }
    }) }
