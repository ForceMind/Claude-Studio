[CmdletBinding()]
param([switch]$SignForTest)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$run = 'n4-activation-' + [guid]::NewGuid().ToString('N')
$output = Join-Path $repo (Join-Path '.prototype' $run)
$files = Join-Path $output 'layout'
$assets = Join-Path $files 'assets'
$app = Join-Path $files 'app'
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$makeappx = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe'
foreach ($tool in $csc,$makeappx) {
    if (!(Test-Path -LiteralPath $tool -PathType Leaf)) { throw ('Missing build tool: ' + $tool) }
}
[void][IO.Directory]::CreateDirectory($assets)
[void][IO.Directory]::CreateDirectory($app)
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Destination $files

$exe = Join-Path $app 'StudioActivationWindow.exe'
$compileLog = & $csc /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /reference:System.Web.Extensions.dll `
    /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$exe" (Join-Path $PSScriptRoot 'ActivationMock.cs')
if ($LASTEXITCODE -ne 0) { throw ('Fixture compiler failed: ' + ($compileLog -join [Environment]::NewLine)) }
foreach ($helper in 'StudioActivationHelperOne.exe','StudioActivationHelperTwo.exe','StudioActivationMediumHelper.exe') {
    Copy-Item -LiteralPath $exe -Destination (Join-Path $app $helper)
}

Add-Type -AssemblyName System.Drawing
foreach ($asset in @(@{name='Store.png';size=50},@{name='Square150.png';size=150},@{name='Square44.png';size=44})) {
    $bitmap = [Drawing.Bitmap]::new($asset.size,$asset.size)
    try {
        $drawing = [Drawing.Graphics]::FromImage($bitmap)
        try { $drawing.Clear([Drawing.Color]::SteelBlue) } finally { $drawing.Dispose() }
        $bitmap.Save((Join-Path $assets $asset.name),[Drawing.Imaging.ImageFormat]::Png)
    } finally { $bitmap.Dispose() }
}

$path = Join-Path $output 'Studio.N4.ActivationMock.msix'
$packLog = & $makeappx pack /d $files /p $path
if ($LASTEXITCODE -ne 0) { throw ('Fixture packaging failed: ' + ($packLog -join [Environment]::NewLine)) }
$result = [ordered]@{ path = $path; sha256 = $null;
    name = 'Studio.N4.ActivationMock'; publisher = 'CN=Studio N4 Simulation'; packageVersion = '1.0.0.0';
    signature = 'unsigned'; registrations = 0; fixtureLaunches = 0 }
if ($SignForTest) {
    if ($PSVersionTable.PSEdition -ne 'Core') { throw 'Use PowerShell 7 to build the offline signing fixture' }
    $signTool = Join-Path (Split-Path -Parent $makeappx) 'signtool.exe'
    $pfx = Join-Path ([IO.Path]::GetTempPath()) ($run + '.pfx')
    $password = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $key = [Security.Cryptography.RSA]::Create(3072)
    $certificate = $null
    $createdPfx = $false
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new($result.publisher,$key,
            [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $oid = [Security.Cryptography.OidCollection]::new()
        [void]$oid.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oid,$true))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('DigitalSignature',$true))
        $now = [DateTimeOffset]::UtcNow
        $certificate = $request.CreateSelfSigned($now.AddMinutes(-5),$now.AddDays(7))
        $stream = [IO.File]::Open($pfx,'CreateNew','Write','None')
        $createdPfx = $true
        try {
            $secret = $certificate.Export('Pfx',$password)
            try { $stream.Write($secret,0,$secret.Length) } finally { [Array]::Clear($secret,0,$secret.Length) }
        } finally { $stream.Dispose() }
        # SignTool consumes a temporary file. No trust store or key store is edited.
        $signed = & $signTool sign /fd SHA256 /f $pfx /p $password $path 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'SignTool failed for the local activation fixture' }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) {
            throw 'Package signature did not return the generated certificate'
        }
        $publicFile = Join-Path $output 'Studio.N4.ActivationMock.cer'
        [IO.File]::WriteAllBytes($publicFile,$certificate.Export('Cert'))
        $result.signature = [string]$signature.Status
        $result.publicCertificate = $publicFile
        $result.thumbprint = $certificate.Thumbprint
        $result.certificateExpires = $certificate.NotAfter.ToUniversalTime()
    } finally {
        if ($createdPfx) { Remove-Item -LiteralPath $pfx -ErrorAction Stop }
        if ($certificate) { $certificate.Dispose() }
        $key.Dispose()
    }
}
$result.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$result
