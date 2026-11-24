$ErrorActionPreference = 'Stop'
# Legacy 0.1.1 build. The active Electron build uses npm run build.
$root = Split-Path -Parent $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$node = (Get-Command node.exe -ErrorAction Stop).Source
$dependency = Join-Path $root 'node_modules\playwright-core'
if (!(Test-Path -LiteralPath (Join-Path $dependency 'package.json'))) {
    throw '首次构建请在本工作树运行 npm.cmd ci。'
}
$tag = [Guid]::NewGuid().ToString('N')
$archivePath = Join-Path ([IO.Path]::GetTempPath()) ("claude-browser-" + $tag + ".zip")
$built = Join-Path $root (".build-" + $tag + ".exe")
$legacyDir = Join-Path $root 'release\legacy-0.1.1'
[void][IO.Directory]::CreateDirectory($legacyDir)
$output = Join-Path $legacyDir 'ClaudeBrowser.exe'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
try {
    $archive = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        function Add-File($file, $entry) {
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file, $entry, [IO.Compression.CompressionLevel]::Optimal)
        }
        Add-File $node 'node.exe'
        foreach ($name in 'controller.mjs', 'relay.mjs', 'settings.mjs') {
            Add-File (Join-Path $root "browser\$name") "browser/$name"
        }
        Get-ChildItem -LiteralPath $dependency -File -Recurse | ForEach-Object {
            $entry = $_.FullName.Substring($dependency.Length + 1).Replace('\', '/')
            Add-File $_.FullName ("node_modules/playwright-core/" + $entry)
        }
    } finally { $archive.Dispose() }

    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /utf8output /codepage:65001 "/out:$built" "/resource:$archivePath,browser.zip" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll (Join-Path $PSScriptRoot 'BrowserPanel.cs')
    if ($LASTEXITCODE -ne 0) { throw "图形程序编译失败，退出码 $LASTEXITCODE。" }
    if ([IO.File]::Exists($output)) { [IO.File]::Replace($built, $output, $null) }
    else { [IO.File]::Move($built, $output) }
    Get-Item -LiteralPath $output | Select-Object FullName,Length
} finally {
    if ([IO.File]::Exists($archivePath)) { [IO.File]::Delete($archivePath) }
    if ([IO.File]::Exists($built)) { [IO.File]::Delete($built) }
}
