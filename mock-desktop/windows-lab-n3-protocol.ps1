param([switch]$FunctionsOnly,[switch]$CertificateOnly,[string]$CertificateDirectory,[string]$CertificatePrefix)
$ErrorActionPreference='Stop'

function Initialize-N3Certificates([string]$Directory,[string]$Prefix) {
    if($PSVersionTable.PSEdition -ne 'Core' -or $Prefix -cnotmatch '^studio-[a-f0-9]{16}$'){
        throw 'N3 certificates require PowerShell Core and a fixture prefix'
    }
    $hostName=$Prefix+'-a-window-healthy.test'
    foreach($name in 'target','wrong') {
        $key=[Security.Cryptography.RSA]::Create(2048)
        try {
            $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(('CN='+$hostName),$key,
                [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            $san.AddDnsName($hostName)
            $request.CertificateExtensions.Add($san.Build())
            $cert=$request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5),[datetimeoffset]::UtcNow.AddHours(1))
            try {
                [IO.File]::WriteAllText((Join-Path $Directory ($name+'.crt')),$cert.ExportCertificatePem())
                [IO.File]::WriteAllText((Join-Path $Directory ($name+'.key')),$key.ExportPkcs8PrivateKeyPem())
                if($name -eq 'target'){
                    [IO.File]::WriteAllText((Join-Path $Directory 'pin.txt'),$cert.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256))
                }
            }finally{$cert.Dispose()}
        }finally{$key.Dispose()}
    }
}

function Start-N3Process([string]$Executable,[string[]]$Arguments,[string]$Directory) {
    foreach($item in $Arguments){if($item -match '["\r\n]'){throw 'Invalid fixture argument'}}
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$Executable
    $start.Arguments=($Arguments | ForEach-Object {'"'+$_+'"'}) -join ' '
    $start.WorkingDirectory=$Directory
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.Encoding]::UTF8;$start.StandardErrorEncoding=[Text.Encoding]::UTF8
    foreach($name in 'NODE_OPTIONS','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED'){
        if($start.EnvironmentVariables.ContainsKey($name)){$start.EnvironmentVariables.Remove($name)}
    }
    $process=[Diagnostics.Process]::Start($start)
    return @{process=$process;errors=$process.StandardError.ReadToEndAsync();file=$Executable;startTicks=$process.StartTime.ToUniversalTime().Ticks}
}

function Read-N3Line($Entry,[int]$Milliseconds=3000) {
    $line=$Entry.process.StandardOutput.ReadLineAsync()
    if(!$line.Wait($Milliseconds) -or !$line.Result){
        $detail=if($Entry.errors.IsCompleted){$Entry.errors.Result.Trim()}else{''}
        throw "N3 child did not respond ($detail)"
    }
    return $line.Result|ConvertFrom-Json
}

function Invoke-N3Child($Entry,[string]$Operation,[int]$Milliseconds=1600) {
    if($Entry.process.HasExited){throw 'N3 child already exited'}
    $Entry.process.StandardInput.WriteLine($Operation)
    $Entry.process.StandardInput.Flush()
    $result=Read-N3Line $Entry $Milliseconds
    if($result.command -cne $Operation -or !$result.ok){throw 'N3 child response mismatched its command'}
    return $result
}

function Stop-N3Process($Entry) {
    if(!$Entry){return}
    $process=$Entry.process
    try {
        if(!$process.HasExited){
            try {$process.StandardInput.WriteLine('exit');$process.StandardInput.Close()}catch{}
            if(!$process.WaitForExit(2000)){$process.Kill();if(!$process.WaitForExit(2000)){throw 'N3 process still alive'}}
        }
        if($process.ExitCode -ne 0){
            $detail=if($Entry.errors.IsCompleted){$Entry.errors.Result.Trim()}else{''}
            throw "N3 child exit $($process.ExitCode) ($detail)"
        }
    }finally{$process.Dispose()}
}

function Get-N3EphemeralPorts {
    $listeners=@([Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0),[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0))
    try {
        foreach($listener in $listeners){$listener.ExclusiveAddressUse=$true;$listener.Start()}
        return @($listeners|ForEach-Object {$_.LocalEndpoint.Port})
    }finally{foreach($listener in $listeners){$listener.Stop()}}
}

function Get-N3ReviewedTopologyFiles([string]$Directory,$ReviewedFixtures) {
    $root=Get-Item -LiteralPath $Directory -Force
    if (!$root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Invalid reviewed N3 topology directory'
    }
    $names=@{relay='StudioN3Relay.exe';target='windows-lab-n3-target.cjs'}
    $files=@{}
    foreach ($role in 'relay','target') {
        $digest=$ReviewedFixtures.($role+'Sha256')
        if ($digest -isnot [string] -or $digest -cnotmatch '^[A-F0-9]{64}$') {
            throw "Missing reviewed N3 $role SHA-256"
        }
        $file=Get-Item -LiteralPath (Join-Path $root.FullName $names[$role]) -Force
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-FileHash -LiteralPath $file.FullName).Hash -cne $digest) {
            throw "Reviewed N3 $role fixture differs"
        }
        $files[$role]=$file.FullName
    }
    return $files
}

function Initialize-N3Topology([string]$Directory,[string]$Prefix,[int[]]$Ports,$ReviewedFixtures) {
    $topology=@{directory=$Directory;prefix=$Prefix;ports=$Ports;children=[Collections.Generic.List[object]]::new()}
    try {
        if ($null -ne $ReviewedFixtures) {
            $files=Get-N3ReviewedTopologyFiles $Directory $ReviewedFixtures
            $topology.exe=$files.relay
            $targetScript=$files.target
            foreach ($name in 'target.crt','target.key','wrong.crt','wrong.key','pin.txt','entry.ndjson','upstream.ndjson',
                'target.ndjson','n3-settings.json','n3-entry-state.json','n3-entry-state.json.tmp') {
                if (Test-Path -LiteralPath (Join-Path $Directory $name)) { throw "Reviewed N3 runtime file already exists: $name" }
            }
        } else {
            $topology.exe=Join-Path $Directory 'StudioN3Relay.exe'
            $compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
            & $compiler /nologo /platform:x64 /target:exe /optimize+ /reference:System.Web.Extensions.dll "/out:$($topology.exe)" (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.cs')
            if($LASTEXITCODE -ne 0){throw 'N3 relay compilation failed'}
            $targetScript=Join-Path $Directory 'n3-target.cjs'
        }
        if($PSVersionTable.PSEdition -eq 'Core'){Initialize-N3Certificates $Directory $Prefix}
        else {
            $pwsh=(Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
            & $pwsh -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'windows-lab-n3-protocol.ps1') -CertificateOnly -CertificateDirectory $Directory -CertificatePrefix $Prefix
            if($LASTEXITCODE -ne 0){throw 'N3 certificate generation failed'}
        }
        foreach($name in 'entry','upstream','target'){
            $topology[$name+'Log']=Join-Path $Directory ($name+'.ndjson')
            [IO.File]::WriteAllText($topology[$name+'Log'],'')
        }
        $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        if ($null -eq $ReviewedFixtures) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows-lab-n3-target.cjs') -Destination $targetScript
        }
        $paths=@('target.crt','target.key','wrong.crt','wrong.key'|ForEach-Object {Join-Path $Directory $_})
        $topology.target=Start-N3Process $node (@($targetScript,$Prefix,$topology.targetLog)+$paths) $Directory
        $topology.children.Add($topology.target)
        $target=Read-N3Line $topology.target 5000
        if($target.kind -ne 'ready' -or $target.pid -ne $topology.target.process.Id -or
            ($null -ne $ReviewedFixtures -and $topology.target.process.MainModule.FileName -ine $node)){throw 'N3 target identity mismatch'}
        $topology.targetReady=$target
        $topology.logSources=@{target=@{path=$topology.targetLog;pid=$target.pid}}
        $topology.config=Join-Path $Directory 'n3-settings.json'
        $topology.pin=[IO.File]::ReadAllText((Join-Path $Directory 'pin.txt'))
        $settings=@{prefix=$Prefix;p=$Ports[0];u=$Ports[1];http=$target.http;tls=$target.tls;half=$target.half;
            wrongCertificate=$target.wrongCertificate;pin=$topology.pin}
        [IO.File]::WriteAllText($topology.config,($settings|ConvertTo-Json -Compress))
        foreach($role in 'upstream','entry') {
            $mode=if($role -ceq 'entry' -and $null -ne $ReviewedFixtures){'entry-n4'}else{$role}
            $child=Start-N3Process $topology.exe @($mode,$topology.config,$topology[$role+'Log']) $Directory
            $topology[$role]=$child;$topology.children.Add($child)
            $child.ready=Read-N3Line $child 4500
            $port=if($role -eq 'entry'){$Ports[0]}else{$Ports[1]}
            if($child.ready.kind -ne 'ready' -or $child.ready.exclusive -ne $true -or $child.ready.pid -ne $child.process.Id -or
                $child.ready.port -ne $port -or $child.process.MainModule.FileName -ine $topology.exe){throw 'N3 relay identity mismatch'}
            $topology.logSources[$role]=@{path=$topology[$role+'Log'];pid=$child.ready.pid}
        }
        return $topology
    }catch{
        foreach($child in $topology.children){try{Stop-N3Process $child}catch{Write-Warning $_.Exception.Message}}
        throw
    }
}

function Read-N3Events($Topology) {
    $result=@{}
    foreach($part in 'entry','upstream','target'){
        $path=$Topology[$part+'Log']
        if((Get-Item -LiteralPath $path).Length -gt 4000000){throw 'N3 event log limit exceeded'}
        $result[$part]=@(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object {$_}|ForEach-Object {$_|ConvertFrom-Json})
    }
    return $result
}

function Find-N3Path($Events,$Probe,[string]$Protocol,[string]$Prefix) {
    if(!$Probe.ok -or $Probe.marker -cnotmatch '^[a-f0-9]{16}$'){return $null}
    $target=@($Events.target|Where-Object {$_.kind -in 'target','half' -and $_.marker -ceq $Probe.marker -and $_.protocol -ceq $Protocol})
    if($target.Count -ne 1){return $null}
    $method=if($Protocol -eq 'http'){'GET'}else{'CONNECT'}
    $authority=$Prefix+'-a-window-healthy.test'+$(if($Protocol -eq 'tls'){':443'}elseif($Protocol -eq 'tcp'){':7443'}else{''})
    $upstream=@($Events.upstream|Where-Object {$_.kind -eq 'routed' -and $_.outbound -eq $target[0].peer -and $_.method -ceq $method -and $_.authority -ceq $authority})
    if($upstream.Count -ne 1 -or ($method -eq 'GET' -and $upstream[0].marker -cne $Probe.marker)){return $null}
    $entry=@($Events.entry|Where-Object {$_.kind -eq 'routed' -and $_.outbound -eq $upstream[0].peer -and $_.method -ceq $method -and $_.authority -ceq $authority})
    if($entry.Count -ne 1 -or ($method -eq 'GET' -and $entry[0].marker -cne $Probe.marker)){return $null}
    return @{entry=$entry[0];upstream=$upstream[0];target=$target[0]}
}

function Invoke-N3Probe($Topology,[string]$Test) {
    $child=Start-N3Process $Topology.exe @($Test,$Topology.config) $Topology.directory
    try {
        $result=Read-N3Line $child 3500
        if(!$child.process.WaitForExit(1500) -or $child.process.ExitCode -ne 0){throw 'N3 protocol probe did not exit successfully'}
        return $result
    }finally{Stop-N3Process $child}
}

function Remove-N3Directory([string]$Directory,[string]$ExpectedName) {
    $item=Get-Item -LiteralPath $Directory
    if($item.Parent.FullName -ine [IO.Path]::GetTempPath().TrimEnd('\') -or $item.Name -cne $ExpectedName -or
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'N3 cleanup directory identity mismatch'}
    $entries=@(Get-ChildItem -LiteralPath $Directory -Force)
    if(@($entries|Where-Object {$_.PSIsContainer -or $_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Unexpected N3 directory contents'}
    foreach($entry in $entries){Remove-Item -LiteralPath $entry.FullName -Force}
    [IO.Directory]::Delete($Directory)
}

if($CertificateOnly){Initialize-N3Certificates $CertificateDirectory $CertificatePrefix;return}
if($FunctionsOnly){return}
. (Join-Path $PSScriptRoot 'windows-lab-bind-gate.ps1') -FunctionsOnly
$null=New-N2PrivateAcl  # Check the existing TEMP parent before placing private keys there.
$tag='ClaudeStudioN3Protocol-'+[guid]::NewGuid().ToString('N')
$directory=Join-Path ([IO.Path]::GetTempPath()) $tag
$prefix='studio-'+[guid]::NewGuid().ToString('N').Substring(0,16)
if(Test-Path -LiteralPath $directory){throw 'N3 protocol temp directory already exists'}
[void][IO.Directory]::CreateDirectory($directory)
$report=[ordered]@{outcome='failed-n3-protocol';prefix=$prefix;sources=@{};checks=[ordered]@{};cleanup=@{processErrors=@()}}
$topology=$null
try {
    foreach($file in 'windows-lab-n3-protocol.cs','windows-lab-n3-target.cjs','windows-lab-n3-protocol.ps1'){
        $report.sources[$file]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file)).Hash
    }
    $topology=Initialize-N3Topology $directory $prefix ([int[]](Get-N3EphemeralPorts))
    $report.health=Invoke-N3Child $topology.entry 'arm-protocol'
    if($report.health.admitting -ne $true){throw 'Synthetic upstream health did not pass'}
    $report.probes=@{}
    foreach($test in 'http','tls','half','wrong-host','wrong-cert','ambiguous','off-route'){
        $report.probes[$test]=Invoke-N3Probe $topology $test
    }
    $null=Invoke-N3Child $topology.upstream 'no-tls'
    $report.probes.connectOnly=Invoke-N3Probe $topology 'tls'
    $report.events=Read-N3Events $topology
    $report.paths=@{}
    foreach($test in 'http','tls','half'){
        $protocol=if($test -eq 'half'){'tcp'}else{$test}
        $report.paths[$test]=Find-N3Path $report.events $report.probes[$test] $protocol $prefix
        $report.checks[$test]=$null -ne $report.paths[$test]
    }
    foreach($test in 'wrong-host','wrong-cert'){
        $probe=$report.probes[$test]
        $report.checks[$test]=$probe.ok -eq $false -and $probe.status -eq 'TrustFailure' -and
            @($report.events.target|Where-Object {$_.marker -ceq $probe.marker}).Count -eq 0
    }
    $report.checks.parsing=$report.probes.ambiguous.ok -eq $true -and $report.probes.'off-route'.ok -eq $true -and
        @($report.events.entry|Where-Object kind -eq 'rejected').Count -eq 2
    $connectOnly=@($report.events.upstream|Where-Object kind -eq 'connect-without-target')
    $report.checks.connectOnly=$report.probes.connectOnly.ok -eq $false -and $connectOnly.Count -ge 1 -and
        @($report.events.target|Where-Object {$_.marker -ceq $report.probes.connectOnly.marker}).Count -eq 0
    foreach($attempt in $connectOnly){
        if(@($report.events.entry|Where-Object {$_.kind -eq 'routed' -and $_.method -eq 'CONNECT' -and
            $_.outbound -eq $attempt.peer -and $_.authority -ceq $attempt.authority}).Count -ne 1){$report.checks.connectOnly=$false}
    }
}catch{$report.error=$_.Exception.Message}
finally {
    if($topology){
        if(!$report.events){try{$report.events=Read-N3Events $topology}catch{$report.evidenceError=$_.Exception.Message}}
        foreach($role in 'entry','upstream','target'){
            try{Stop-N3Process $topology[$role]}catch{$report.cleanup.processErrors+=@($_.Exception.Message)}
        }
    }
    try{Remove-N3Directory $directory $tag;$report.cleanup.directoryGone=!(Test-Path -LiteralPath $directory)}
    catch{$report.cleanup.error=$_.Exception.Message}
    if(!$report.error -and $report.checks.Count -eq 7 -and !@($report.checks.Values|Where-Object {$_ -ne $true}).Count -and
        $report.cleanup.directoryGone -and !$report.cleanup.processErrors.Count){$report.outcome='passed-n3-protocol'}
    $out=Join-Path $PSScriptRoot ('..\.prototype\mock-results\windows-psec-n3-protocol-'+$prefix.Substring(7)+'.json')
    [IO.File]::WriteAllText($out,($report|ConvertTo-Json -Depth 14))
    [pscustomobject]@{file=(Resolve-Path -LiteralPath $out).Path;outcome=$report.outcome;checks=$report.checks;error=$report.error;cleanup=$report.cleanup}|ConvertTo-Json -Depth 5
}
if($report.outcome -ne 'passed-n3-protocol'){exit 2}
