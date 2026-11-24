param([switch]$FunctionsOnly)

function Invoke-N2Control([string]$Command,$Value=@{}) {
    $path=Join-Path $privateDir ('guard-'+$Command)
    [IO.File]::WriteAllText($path+'.tmp',($Value|ConvertTo-Json -Compress))
    [IO.File]::Move($path+'.tmp',$path)
    Wait-GuardFile ($path+'-done')
    return Get-Content -LiteralPath ($path+'-done') -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-N2ProxyClaim($Process,[uint16]$Port,$Ready) {
    $hostSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($Process.HasExited -or $Process.MainModule.FileName -ine $proxyExe -or $Ready.container -ne $false -or
        $Ready.pid -ne $Process.Id -or $Ready.port -ne $Port -or $Ready.userSid -ne $hostSid -or
        !$Ready.listening -or (Get-FileHash -LiteralPath $proxyExe).Hash -ne $report.bindGuard.proxySha256){throw 'N2 proxy identity mismatch'}
    return @{pid=$Process.Id;startTicks=$Process.StartTime.ToUniversalTime().Ticks;port=$Port;userSid=$hostSid;sha256=$report.bindGuard.proxySha256}
}

function Test-N2PrivateAccess {
    $marker=Join-Path $privateDir 'n2-acl-marker.txt'
    [IO.File]::WriteAllText($marker,'synthesized N2 control')
    try {
        $body=@'
$results = [ordered]@{userSid=$id.User.Value}
foreach($check in @(@{name='readConfig';path=CONFIG;access='Read'},@{name='writeProxy';path=PROXY;access='Write'})) {
    try {
        $file=[IO.File]::Open($check.path,'Open',$check.access,'ReadWrite')
        $file.Dispose();$results[$check.name]='allowed'
    } catch [UnauthorizedAccessException] {$results[$check.name]='denied'}
}
try {[IO.File]::Delete(CONFIG);$results.replaceConfig='allowed'} catch [UnauthorizedAccessException] {$results.replaceConfig='denied'}
$results|ConvertTo-Json -Compress
'@
        $body=$body.Replace('CONFIG',(ConvertTo-LabLiteral $marker)).Replace('PROXY',(ConvertTo-LabLiteral $proxyExe))
        $result=Read-LabProbe (Start-LabProbe $accounts.A $body)
        if($result.userSid -ne $accounts.A.Sid -or $result.readConfig -ne 'denied' -or $result.writeProxy -ne 'denied' -or
            $result.replaceConfig -ne 'denied'){throw 'Standard A can access the private proxy files'}
        return $result
    } finally {if(Test-Path -LiteralPath $marker){Remove-Item -LiteralPath $marker}}
}

function Invoke-N2BindMatrix([uint16]$Port,[switch]$Baseline,[switch]$Live) {
    $addresses=if($Baseline){'0.0.0.0'}else{'127.0.0.1','0.0.0.0'}
    $options=if($Baseline){'exclusive'}else{'default','reuse','exclusive'}
    $outsideLines=foreach($address in $addresses){
        foreach($option in $options){'& '+(ConvertTo-LabLiteral $exe)+" n2-bind $Port $address $option"}
    }
    $body='$rows = @(@('+[Environment]::NewLine+($outsideLines -join [Environment]::NewLine)+[Environment]::NewLine+
        ') | ForEach-Object { ConvertFrom-Json $_ }); @{rows=$rows} | ConvertTo-Json -Depth 6'
    $outside=@((Read-LabProbe (Start-LabProbe $accounts.A $body)).rows)
    if($outside.Count -ne @($outsideLines).Count){throw "Outside A bind control count differs: $($outside.Count)"}
    foreach($address in $addresses){
        foreach($option in $options){
            $hostResult=& $proxyExe n2-bind $Port $address $option | ConvertFrom-Json
            if($LASTEXITCODE -ne 0){throw 'Same-executable bind probe failed'}
            $a=@($outside|Where-Object {$_.address -eq $address -and $_.option -eq $option})
            if($a.Count -ne 1 -or $a[0].userSid -ne $accounts.A.Sid -or $a[0].container -ne $false){throw 'A binding identity mismatch'}
            $plain=Test-GateBind $Port ([Net.IPAddress]::Parse($address)) $option
            $sameHost=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if($hostResult.container -ne $false -or $hostResult.userSid -ne $sameHost -or $hostResult.port -ne $Port -or
                $hostResult.address -ne $address -or $hostResult.option -ne $option){throw 'Host binding identity mismatch'}
            $denials=if($Live){10013,10048}else{10013}
            foreach($row in $a[0],$hostResult,$plain){
                if($Baseline -and ($row.stage -ne 'listening' -or $row.nativeError -ne 0)){throw 'Bind baseline did not reach listen'}
                if(!$Baseline -and ($row.stage -ne 'bind' -or $row.nativeError -notin $denials)){
                    throw "Unexpected bind result: $address $option stage=$($row.stage) native=$($row.nativeError)"
                }
            }
            [pscustomobject]@{port=$Port;address=$address;option=$option;outsideA=$a[0];sameExecutable=$hostResult;host=$plain}
        }
    }
}

function Test-N2ProxyHealth([string]$Phase) {
    $result=Test-ProxyHealth $Phase
    return $result.matched -eq $true
}

function Wait-N2Offline($Fault,[string]$Phase,[string]$FromUtc) {
    $limit=[datetimeoffset]::Parse($FromUtc).UtcDateTime.AddSeconds(4)
    do {
        $snapshot=Invoke-Flow 'snapshot' $Phase
        if([datetime]::UtcNow -gt $limit){throw 'Old socket remained valid beyond N2 deadline'}
        if(!$snapshot.flow.socketInvalid){Start-Sleep -Milliseconds 30}
    }while(!$snapshot.flow.socketInvalid)
    $null=Check-Phase $Phase $false
    $Fault.offlineUtc=[datetime]::UtcNow.ToString('o')
    if([datetimeoffset]::Parse($Fault.offlineUtc).UtcDateTime -gt $limit){throw 'N2 new requests did not fail within the deadline'}
    Start-Sleep -Milliseconds 275
    $snapshot=Invoke-Flow 'snapshot' $Phase
    Assert-OfflineFlow $snapshot $Fault.offlineUtc
    $Fault.flow=$snapshot.flow
}

if($FunctionsOnly){return}
. (Join-Path $PSScriptRoot 'windows-lab-portguard-scenarios.ps1') -FunctionsOnly
$n2=$report.bindGuard
$null=Check-Phase 'healthy1' $true -Native
$n2.oldP=(Invoke-Flow 'start-stream' 'healthy1').flow
$initialProxyPid=$proxyProcess.Id
$n2.proxyOnly=@{pid=$initialProxyPid;injectedUtc=[datetime]::UtcNow.ToString('o')}
Close-ScenarioProxy
$n2.proxyOnly.exitedUtc=[datetime]::UtcNow.ToString('o')
$n2.proxyOnly.readback=Invoke-N2Control 'bind-read-p'
Wait-N2Offline $n2.proxyOnly 'outage1' $n2.proxyOnly.exitedUtc
$n2.proxyOnly.bind=@(Invoke-N2BindMatrix $n2Ports[0])

$n2.both=@{owner=(Invoke-N2Control 'crash')}
Wait-N2Offline $n2.both 'crash1' $n2.both.owner.exitSignalUtc
$n2.both.bind=@(Invoke-N2BindMatrix $n2Ports[0])
$n2.preQ=@(Invoke-N2BindMatrix $n2Ports[1] -Baseline)
$ports.proxy=$n2Ports[1]
Start-ScenarioProxy $proxyExe
$claim=Get-N2ProxyClaim $proxyProcess $n2Ports[1] $report.proxySegments[-1]
$n2.qReadback=Invoke-N2Control 'bind-rotate' $claim
$n2.qHealth=Test-N2ProxyHealth 'healthy9'
if(!$n2.qHealth){throw 'Synthetic Q proxy health failed'}
$n2.clientRotation=Invoke-Flow 'select-proxy' 'recovered1' $n2Ports[1]
$n2.qClosedProbe=Check-Phase 'stopped2' $false
$n2.qPermit=Invoke-N2Control 'recover'
$null=Check-Phase 'recovered1' $true
$null=Check-Phase 'recovered2' $true -Native
$n2.oldPAfterQ=(Invoke-Flow 'snapshot' 'recovered2').flow
$oldPSnapshot=@{flow=$n2.oldPAfterQ}
Assert-OfflineFlow $oldPSnapshot $n2.proxyOnly.offlineUtc
$n2.oldPStillSealed=@(Invoke-N2BindMatrix $n2Ports[0])
$null=Invoke-Flow 'stop-stream' 'recovered2'
$n2.oldQ=(Invoke-Flow 'start-stream' 'recovered2').flow
$n2.ownerOnly=@{owner=(Invoke-N2Control 'crash-next');proxyPid=$proxyProcess.Id}
Wait-N2Offline $n2.ownerOnly 'crash2' $n2.ownerOnly.owner.exitSignalUtc
$n2.ownerOnly.readback=Invoke-N2Control 'bind-read-q'
$n2.ownerOnly.proxyHealthyAfter=Test-N2ProxyHealth 'healthy7'
if(!$n2.ownerOnly.proxyHealthyAfter -or $proxyProcess.HasExited){throw 'The owner-only control also affected Q'}
$report.finalFlow=Invoke-Flow 'finish' 'crash2'
$report.finalProxy=Invoke-GuardProxy 'state'
