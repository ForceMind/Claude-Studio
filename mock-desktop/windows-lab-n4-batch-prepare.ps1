[CmdletBinding(DefaultParameterSetName='Prepare')]
param(
    [Parameter(Mandatory,ParameterSetName='Prepare')][switch]$Prepare,
    [Parameter(Mandatory,ParameterSetName='Test')][switch]$SelfTest,
    [Parameter(Mandatory,ParameterSetName='Verify')][switch]$VerifyDraft,
    [Parameter(Mandatory,ParameterSetName='Verify')][string]$Directory,
    [Parameter(Mandatory,ParameterSetName='Verify')][string]$ManifestSha256
)
$ErrorActionPreference = 'Stop'
$testBatchInventory = [bool]$SelfTest
$n4VerificationDirectory = $Directory
$n4VerificationDigest = $ManifestSha256
. (Join-Path $PSScriptRoot 'windows-lab-n4-account-control.ps1') -FunctionsOnly
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly

function New-N4StagePlan([string]$Run, [string]$Stage, $Identity, $Hashes, [int[]]$Ports, $Weights) {
    $proxy = $Stage -ne 'M'
    $entries = if ($Stage -ceq 'F') { 4 } elseif ($Stage -ceq 'X') { 1 } else { 0 }
    $binding = $null
    if ($proxy) {
        $binding = [ordered]@{sublayer=[guid]::NewGuid().ToString();keys=@(1..4 | ForEach-Object {[guid]::NewGuid().ToString()});
            ports=@($Ports);weight=$Weights[$Stage]}
    }
    return [ordered]@{schema='studio-n4-account-recovery-v1';run=$Run;segment=$Stage;accountSid=$Identity.account;
        hostSid=$Identity.host;librarySha256=$Hashes.dll;controllerSha256=$Hashes.control;
        fixtures=@{probeSha256=$Hashes.probe;executorSha256=$Hashes.executor;relaySha256=$Hashes.relay;targetSha256=$Hashes.target};
        account=[ordered]@{sublayer=[guid]::NewGuid().ToString();keys=@(1..4 | ForEach-Object {[guid]::NewGuid().ToString()});weight=$Weights.account};
        binding=$binding;exceptionKeys=@(for ($i=0; $i -lt $entries; $i++) { [guid]::NewGuid().ToString() })}
}

function New-N4RuleInventory($Plan) {
    $layers = 'ALE_AUTH_CONNECT_V4','ALE_AUTH_CONNECT_V6','ALE_AUTH_RECV_ACCEPT_V4','ALE_AUTH_RECV_ACCEPT_V6'
    for ($i=0; $i -lt 4; $i++) {
        [ordered]@{key=$Plan.account.keys[$i];sublayer=$Plan.account.sublayer;layer=$layers[$i];action='BLOCK';
            lifetime='static';filterWeight=[uint64]0x1000000000000000;conditions=@{ALE_USER_ID=$Plan.accountSid}}
    }
    if ($Plan.binding) {
        $bindLayers = 'ALE_RESOURCE_ASSIGNMENT_V4','ALE_RESOURCE_ASSIGNMENT_V6'
        for ($i=0; $i -lt 4; $i++) {
            [ordered]@{key=$Plan.binding.keys[$i];sublayer=$Plan.binding.sublayer;layer=$bindLayers[$i%2];action='BLOCK';
                lifetime='static';filterWeight=[uint64]0x1000000000000000;
                conditions=@{IP_PROTOCOL=6;IP_LOCAL_PORT=$Plan.binding.ports[[Math]::Floor($i/2)]}}
        }
        for ($i=0; $i -lt $Plan.exceptionKeys.Count; $i++) {
            [ordered]@{key=$Plan.exceptionKeys[$i];sublayer=$Plan.account.sublayer;layer='ALE_AUTH_CONNECT_V4';action='PERMIT';
                lifetime='dynamic-session';soft=$true;generation=($i+1);filterWeight=[uint64]0x2000000000000000;
                conditions=@{ALE_USER_ID=$Plan.accountSid;ALE_PACKAGE_ID='verified-live-container-SID';IP_PROTOCOL=6;
                    IP_REMOTE_ADDRESS='127.0.0.1';IP_REMOTE_PORT=$Plan.binding.ports[0]}}
        }
    }
}

function Test-N4BatchInventory($Stages) {
    if (($Stages.segment -join ',') -cne 'M,F,X') { throw 'N4 batch must contain M, F and X in order' }
    $all = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ports = [Collections.Generic.HashSet[int]]::new()
    $totals = @()
    foreach ($item in $Stages) {
        $expected = switch ($item.segment) { M { 0 }; F { 4 }; X { 1 } }
        if ($item.run -cne $Stages[0].run -or $item.accountSid -cne $Stages[0].accountSid -or
            $item.hostSid -cne $Stages[0].hostSid -or @($item.account.keys).Count -ne 4 -or
            @($item.exceptionKeys).Count -ne $expected -or ($expected -eq 0 -and $null -ne $item.binding) -or
            ($expected -gt 0 -and (@($item.binding.keys).Count -ne 4 -or @($item.binding.ports).Count -ne 2))) {
            throw 'N4 batch identity or filter budget differs'
        }
        foreach ($hash in 'librarySha256','controllerSha256') {
            if ($item.$hash -cnotmatch '^[A-F0-9]{64}$' -or $item.$hash -cne $Stages[0].$hash) {
                throw "N4 batch control digest differs: $hash"
            }
        }
        foreach ($hash in 'probeSha256','executorSha256','relaySha256','targetSha256') {
            if ($item.fixtures.$hash -cnotmatch '^[A-F0-9]{64}$' -or $item.fixtures.$hash -cne $Stages[0].fixtures.$hash) {
                throw "N4 batch fixture digest differs: $hash"
            }
        }
        $keys = @($item.account.sublayer)+@($item.account.keys)+@($item.exceptionKeys)
        if ($item.binding) {
            $keys += @($item.binding.sublayer)+@($item.binding.keys)
            foreach ($port in $item.binding.ports) {
                if ($port -lt 40000 -or $port -gt 49151 -or !$ports.Add($port)) { throw 'N4 batch port repeated or outside range' }
            }
        }
        foreach ($key in $keys) {
            $id=[guid]::Empty
            if (![guid]::TryParseExact($key,'D',[ref]$id) -or $id -eq [guid]::Empty -or !$all.Add($key)) { throw 'N4 batch GUID is invalid or repeated' }
        }
        $totals += @(New-N4RuleInventory $item).Count
    }
    if (($totals -join ',') -cne '4,12,9') { throw 'N4 batch writes differ from review budget' }
    return @{totalFilterAdds=25;totalSublayerAdds=5;maximumActiveFilters=9;maximumActiveSublayers=2}
}

function Get-N4BatchIdentity {
    $a = Get-LocalUser -Name ClaudeStudioLabA
    $sid = $a.SID.Value
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $hostSid = $identity.User.Value
        $elevated = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
    if (!$a.Enabled -or !$sid -or $hostSid -eq $sid -or
        $sid -notin @(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object {$_.SID.Value}) -or
        $sid -in @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})) {
        throw 'Expected the enabled dedicated standard A account and a different host'
    }
    return @{account=$sid;host=$hostSid;elevated=$elevated}
}

function Find-N4BatchPorts([string]$Prototype) {
    $ranges = @(Read-TcpRanges 4)+@(Read-TcpRanges 6)
    $ip = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $busy = @($ip.GetActiveTcpListeners() | ForEach-Object Port)+@($ip.GetActiveTcpConnections() | ForEach-Object {$_.LocalEndPoint.Port})
    $n2 = Get-Content -LiteralPath (Join-Path $Prototype 'mock-results\windows-psec-bind-guard.json') -Raw | ConvertFrom-Json
    $n3 = Get-Content -LiteralPath (Join-Path $Prototype 'mock-results\windows-psec-n3-a-0f0ed3ff20544b91.json') -Raw | ConvertFrom-Json
    $historic = @($n2.observer.guard.manifest.bind.ports)+@($n3.ports)
    if ($historic.Count -ne 4 -or $historic -contains $null) { throw 'Historical P/U exclusions were not recovered' }
    $avoid = $busy+$historic+@(10810)
    $selected = @(40000..49151 | Where-Object {
        $port=$_
        $port -notin $avoid -and !@($ranges | Where-Object {$port -ge $_.first -and $port -le $_.last}).Count
    } | Select-Object -First 4)
    if ($selected.Count -ne 4) { throw 'Insufficient current synthetic relay candidates' }
    return $selected
}

function Get-N4BundleScripts {
    'n4-account-host.ps1','n4-account-control.ps1','n4-account-run.ps1','n4-account-result.ps1','local.ps1',
        'bind-gate.ps1','dns-trace.ps1','n3-protocol.ps1','n3-target.cjs','n4-proxy-run.ps1' |
        ForEach-Object { 'windows-lab-'+$_ }
}

function Get-N4DraftEntry([string]$Path,[bool]$Container) {
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Container -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Unexpected N4 draft file type or reparse point'
    }
    return $item
}

function Read-N4DraftJson([string]$Path,[string]$Digest) {
    $file=Get-N4DraftEntry $Path $false
    $stream=[IO.File]::OpenRead($file.FullName)
    try {
        if ($stream.Length -gt 1048576 -or $Digest -cnotmatch '^[A-F0-9]{64}$' -or
            (Get-FileHash -InputStream $stream).Hash -cne $Digest) { throw "N4 draft JSON differs: $($file.Name)" }
        $stream.Position=0
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Confirm-N4ReviewDraft([string]$Directory,[string]$Digest) {
    $root=Get-N4DraftEntry $Directory $true
    if ($root.Name -cnotmatch '^n4-batch-([a-f0-9]{32})$') { throw 'Invalid N4 draft directory name' }
    $run=$Matches[1]
    $review=Read-N4DraftJson (Join-Path $root.FullName 'batch-review.json') $Digest
    if ($review.schema -cne 'studio-n4-batch-review-v1' -or $review.run -cne $run -or
        $review.executionAllowed -isnot [bool] -or $review.executionAllowed -or
        $null -eq $review.systemWrites -or $review.systemWrites -ne 0 -or ($review.stages.segment -join ',') -cne 'M,F,X') {
        throw 'N4 review is not a read-only M/F/X draft'
    }
    $bundle=Get-N4DraftEntry (Join-Path $root.FullName 'bundle') $true
    $null=Get-N4DraftEntry (Join-Path $bundle.FullName 'fixtures') $true
    $expected=@(Get-N4BundleScripts)+@('N4AccountGuard.dll','StudioN3Relay.exe','fixtures/StudioProbe.exe','fixtures/wxc-exec.exe')
    $hashes=@{}
    foreach ($artifact in $review.bundle) {
        $relative=([string]$artifact.relativePath).Replace('\','/')
        if ($relative -cnotin $expected -or $hashes.ContainsKey($relative) -or $artifact.sha256 -cnotmatch '^[A-F0-9]{64}$') {
            throw 'Unexpected or repeated N4 draft bundle entry'
        }
        $file=Get-N4DraftEntry (Join-Path $bundle.FullName $relative) $false
        if ((Get-FileHash -LiteralPath $file.FullName).Hash -cne $artifact.sha256) { throw "N4 bundle file differs: $relative" }
        $hashes[$relative]=$artifact.sha256
    }
    if ($hashes.Count -ne $expected.Count) { throw 'N4 draft bundle is incomplete' }
    $stages=@(foreach ($stage in $review.stages) {
        if ($stage.draft -cne ('draft-'+$stage.segment+'.json')) { throw 'Unexpected N4 stage filename' }
        $plan=Read-N4DraftJson (Join-Path $root.FullName $stage.draft) $stage.sha256
        if ($plan.schema -cne 'studio-n4-account-recovery-v1' -or $plan.run -cne $run -or $plan.segment -cne $stage.segment -or
            $plan.account.weight -ne $stage.accountSublayerWeight -or $plan.binding.weight -ne $stage.bindingSublayerWeight -or
            $plan.librarySha256 -cne $hashes['N4AccountGuard.dll'] -or
            $plan.controllerSha256 -cne $hashes['windows-lab-n4-account-control.ps1'] -or
            $plan.fixtures.probeSha256 -cne $hashes['fixtures/StudioProbe.exe'] -or
            $plan.fixtures.executorSha256 -cne $hashes['fixtures/wxc-exec.exe']) { throw 'N4 stage draft differs from the review' }
        $null=Get-N3ReviewedTopologyFiles $bundle.FullName $plan.fixtures
        $plan
    })
    $budget=Test-N4BatchInventory $stages
    foreach ($entry in $budget.GetEnumerator()) {
        if ($entry.Value -ne $review.budget.($entry.Key)) { throw 'N4 draft review budget differs' }
    }
    return [ordered]@{mode='verified-review-draft';sha256=$Digest;bundleFiles=$hashes.Count;
        stageFiles=$stages.Count;executionAllowed=$false;systemWrites=0}
}

function Compile-N4BatchFixtures([string]$Bundle, [string]$Prototype) {
    $fixtures = Join-Path $Bundle 'fixtures'
    [void][IO.Directory]::CreateDirectory($fixtures)
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $dll = Join-Path $Bundle 'N4AccountGuard.dll'
    $probe = Join-Path $fixtures 'StudioProbe.exe'
    $relay = Join-Path $Bundle 'StudioN3Relay.exe'
    $guardFiles = @('wfp','wfp-container','wfp-bind','n4-account-guard' | ForEach-Object {Join-Path $PSScriptRoot ('windows-lab-'+$_+'.cs')})
    $probeFiles = @('psec-probe','portguard-flow','n3-protocol','n3-simulator','n4-account-probe' | ForEach-Object {Join-Path $PSScriptRoot ('windows-lab-'+$_+'.cs')})
    & $csc /nologo /platform:x64 /target:library /warnaserror+ /optimize+ "/out:$dll" $guardFiles | Out-Host
    if ($LASTEXITCODE) { throw 'N4 guard build failed' }
    & $csc /nologo /platform:x64 /target:exe '/define:N3_PROTOCOL,N4_ACCOUNT_MATCH' /main:StudioPsecSimulator /warnaserror+ /optimize+ `
        /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$probe" $probeFiles | Out-Host
    if ($LASTEXITCODE) { throw 'Combined M/F/X simulator build failed' }
    & $csc /nologo /platform:x64 /target:exe /warnaserror+ /optimize+ /reference:System.Web.Extensions.dll "/out:$relay" (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.cs') | Out-Host
    if ($LASTEXITCODE) { throw 'N3 relay build failed' }
    $cache = Join-Path $Prototype 'windows-lab\n4-mxc-v1.1.0-entry.bin'
    $bytes = [IO.File]::ReadAllBytes($cache)
    if ($bytes.Length -ne 4514529 -or [BitConverter]::ToUInt32($bytes,0) -ne 0x04034b50 -or [BitConverter]::ToUInt16($bytes,8) -ne 8) {
        throw 'Invalid pinned Microsoft archive entry'
    }
    $nameLength=[BitConverter]::ToUInt16($bytes,26);$extraLength=[BitConverter]::ToUInt16($bytes,28)
    if (30+$nameLength+$extraLength+4514455 -ne $bytes.Length -or [Text.Encoding]::UTF8.GetString($bytes,30,$nameLength) -cne 'x64/wxc-exec.exe') {
        throw 'Pinned archive entry layout differs'
    }
    $executor = Join-Path $fixtures 'wxc-exec.exe'
    $memory = [IO.MemoryStream]::new($bytes,30+$nameLength+$extraLength,4514455)
    $decoder = [IO.Compression.DeflateStream]::new($memory,[IO.Compression.CompressionMode]::Decompress)
    $out = [IO.File]::Open($executor,'CreateNew','Write','None')
    try {
        $buffer = [byte[]]::new(65536)
        while (($n=$decoder.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($out.Length+$n -gt 12700472) { throw 'Pinned executor size exceeded' }
            $out.Write($buffer,0,$n)
        }
        if ($out.Length -ne 12700472) { throw 'Pinned executor size differs' }
    } finally { $out.Dispose();$decoder.Dispose();$memory.Dispose() }
    $executorHash = (Get-FileHash -LiteralPath $executor).Hash
    if ($executorHash -cne 'CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D') { throw 'Pinned executor digest differs' }
    foreach ($name in (Get-N4BundleScripts)) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $Bundle }
    return @{dll=(Get-FileHash -LiteralPath $dll).Hash;probe=(Get-FileHash -LiteralPath $probe).Hash;
        relay=(Get-FileHash -LiteralPath $relay).Hash;executor=$executorHash;
        target=(Get-FileHash -LiteralPath (Join-Path $Bundle 'windows-lab-n3-target.cjs')).Hash;
        control=(Get-FileHash -LiteralPath (Join-Path $Bundle 'windows-lab-n4-account-control.ps1')).Hash}
}

if ($VerifyDraft) {
    . (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.ps1') -FunctionsOnly
    Confirm-N4ReviewDraft $n4VerificationDirectory $n4VerificationDigest
    return
}

if ($testBatchInventory) {
    $ids = @{account='S-1-5-21-1-2-3-1001';host='S-1-5-21-1-2-3-1002'}
    $hashes = @{dll='A'*64;control='B'*64;probe='C'*64;executor='D'*64;relay='E'*64;target='F'*64}
    $weights = @{account=50;F=49;X=49}
    $run = [guid]::NewGuid().ToString('N')
    $plans = @((New-N4StagePlan $run M $ids $hashes @() $weights),(New-N4StagePlan $run F $ids $hashes @(40000,40001) $weights),
        (New-N4StagePlan $run X $ids $hashes @(40002,40003) $weights))
    $budget = Test-N4BatchInventory $plans
    foreach ($p in $plans) { $null = Read-RecoveryPlan ($p | ConvertTo-Json -Depth 10 | ConvertFrom-Json) $run }
    $negative = @(
        {param($p) $p[1].exceptionKeys+=@([guid]::NewGuid().ToString())},
        {param($p) $p[2].binding.ports[0]=$p[1].binding.ports[0]},
        {param($p) $p[2].account.keys[0]=$p[0].account.keys[0]},
        {param($p) $p[1].binding.ports[0]=10810},
        {param($p) $p[1].fixtures.targetSha256=$null},
        {param($p) $p[2].fixtures.relaySha256='0'*64},
        {param($p) $p[2].accountSid='S-1-5-21-1-2-3-1003'}
    )
    foreach ($edit in $negative) {
        $copy = $plans | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        & $edit $copy
        $rejected=$false
        try { $null = Test-N4BatchInventory $copy } catch { $rejected=$true }
        if (!$rejected) { throw 'Unsafe N4 batch inventory passed' }
    }
    [ordered]@{mode='offline-batch-inventory';validSegments=3;rejected=$negative.Count;budget=$budget;systemWrites=0}
    return
}

$prototype = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\.prototype')).ProviderPath
$identity = Get-N4BatchIdentity
$ports = @(Find-N4BatchPorts $prototype)
$run = [guid]::NewGuid().ToString('N')
$directory = Join-Path $prototype ('n4-batch-'+$run)
$bundle = Join-Path $directory 'bundle'
[void][IO.Directory]::CreateDirectory($bundle)
$hashes = Compile-N4BatchFixtures $bundle $prototype
$weights = @{account=$null;F=$null;X=$null}
$issue = $null
try {
    Add-Type -Path (Join-Path $bundle 'N4AccountGuard.dll')
    $candidates = [StudioLabWfp]::ReadAccountBatchWeights([uint16[]]$ports)
    $weights = @{account=[int]$candidates[0];F=[int]$candidates[1];X=[int]$candidates[2]}
} catch { $issue = $_.Exception.Message }
$plans = @((New-N4StagePlan $run M $identity $hashes @() $weights),
    (New-N4StagePlan $run F $identity $hashes @($ports[0],$ports[1]) $weights),
    (New-N4StagePlan $run X $identity $hashes @($ports[2],$ports[3]) $weights))
$budget = Test-N4BatchInventory $plans
$files = @(Get-ChildItem -LiteralPath $bundle -Recurse -File | ForEach-Object {
    @{relativePath=$_.FullName.Substring($bundle.Length+1);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
})
$stages = @(foreach ($plan in $plans) {
    if (!$issue) { $null = Read-RecoveryPlan ($plan | ConvertTo-Json -Depth 10 | ConvertFrom-Json) $run }
    $path = Join-Path $directory ('draft-'+$plan.segment+'.json')
    [IO.File]::WriteAllText($path,($plan | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    @{segment=$plan.segment;draft=(Split-Path $path -Leaf);sha256=(Get-FileHash -LiteralPath $path).Hash;
        accountSublayerWeight=$plan.account.weight;bindingSublayerWeight=$plan.binding.weight;rules=@(New-N4RuleInventory $plan)}
})
$target = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStudioN4Account-'+$run)
$summary = [ordered]@{schema='studio-n4-batch-review-v1';run=$run;createdUtc=[DateTime]::UtcNow;
    executionAllowed=$false;priorityRead=(!$issue);priorityIssue=$issue;hostElevated=$identity.elevated;budget=$budget;
    tentativePorts=@{F=@($ports[0],$ports[1]);X=@($ports[2],$ports[3]);recheckBeforeUse=$true};
    staging=@{root=$target;mode='proposal-only';newRootProtectedAcl=$true;fixturesReadExecuteByA=$true;
        preserveParentAcl=$true;preserveExistingAcl=$true;lease='recovery.lease';activeJournal='recovery.json';runtimeCanaryPorts='allocate and record bound loopback only'};
    review=@{separateConsentNeeded=$true;FandXLiveFlowAvailable=$false;MInvocation='Invoke-N4StagedReviewedMatch';
        FandXInvocation='Invoke-N4PreparedProxyStage';FandXInvocationVerifiedLive=$false;
        rollbackScript='windows-lab-n4-account-control.ps1';rollbackRequiresExactActiveJournalSha256=$true};
    bundle=$files;stages=$stages;systemWrites=0}
$summaryPath=Join-Path $directory 'batch-review.json'
[IO.File]::WriteAllText($summaryPath,($summary | ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
[ordered]@{mode='local-review-draft';executionAllowed=$false;summary=$summaryPath;sha256=(Get-FileHash -LiteralPath $summaryPath).Hash;
    priorityRead=(!$issue);priorityIssue=$issue;ports=$ports;budget=$budget;systemWrites=0}
