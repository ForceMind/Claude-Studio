$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function Add-RoundRectangle($figure, [int]$x, [int]$y, [int]$width, [int]$height, [int]$radius) {
    $d = $radius * 2
    $figure.AddArc($x, $y, $d, $d, 180, 90)
    $figure.AddArc(($x + $width - $d), $y, $d, $d, 270, 90)
    $figure.AddArc(($x + $width - $d), ($y + $height - $d), $d, $d, 0, 90)
    $figure.AddArc($x, ($y + $height - $d), $d, $d, 90, 90)
    $figure.CloseFigure()
}

function Draw-ClaudeMark($canvas) {
    $ink = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#CE5D3C'))
    $rays = @(
        @{ Angle =   8; Length = 69; Width = 16; Bend = -3 }
        @{ Angle =  34; Length = 75; Width = 14; Bend = 3 }
        @{ Angle =  68; Length = 60; Width = 16; Bend = -2 }
        @{ Angle =  93; Length = 72; Width = 15; Bend = 3 }
        @{ Angle = 121; Length = 64; Width = 14; Bend = -4 }
        @{ Angle = 147; Length = 73; Width = 16; Bend = 1 }
        @{ Angle = 174; Length = 66; Width = 15; Bend = 3 }
        @{ Angle = 198; Length = 74; Width = 14; Bend = -3 }
        @{ Angle = 230; Length = 65; Width = 15; Bend = 2 }
        @{ Angle = 258; Length = 75; Width = 16; Bend = -2 }
        @{ Angle = 291; Length = 66; Width = 14; Bend = 3 }
        @{ Angle = 321; Length = 73; Width = 15; Bend = 1 }
        @{ Angle = 344; Length = 62; Width = 14; Bend = -3 }
    )
    try {
        $canvas.FillEllipse($ink, 116, 115, 24, 26)
        foreach ($ray in $rays) {
            $state = $canvas.Save()
            $shape = [Drawing.Drawing2D.GraphicsPath]::new()
            try {
                $canvas.TranslateTransform(128, 128)
                $canvas.RotateTransform($ray.Angle)

                $tip = [single]($ray.Length - 5)
                $top = [single]($ray.Bend - $ray.Width / 2)
                $bottom = [single]($ray.Bend + $ray.Width / 2)
                $shape.AddBezier(1, -10, 23, -10, ($tip - 15), ($top - 2), $tip, $top)
                $shape.AddBezier($tip, $top, ($tip + 8), ($top + 1), ($tip + 8), ($bottom - 1), $tip, $bottom)
                $shape.AddBezier($tip, $bottom, ($tip - 17), ($bottom + 2), 27, 12, 1, 10)
                $shape.CloseFigure()
                $canvas.FillPath($ink, $shape)
            } finally {
                $shape.Dispose()
                $canvas.Restore($state)
            }
        }
    } finally {
        $ink.Dispose()
    }
}

function New-IconFrame([int]$size) {
    $bitmap = [Drawing.Bitmap]::new($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $canvas = [Drawing.Graphics]::FromImage($bitmap)
    $tile = [Drawing.Drawing2D.GraphicsPath]::new()
    $background = [Drawing.Drawing2D.LinearGradientBrush]::new(
        [Drawing.Rectangle]::new(0, 0, 256, 256),
        [Drawing.ColorTranslator]::FromHtml('#FFF8F0'),
        [Drawing.ColorTranslator]::FromHtml('#EDE1D5'),
        [single]45
    )
    try {
        $canvas.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $canvas.Clear([Drawing.Color]::Transparent)
        $scale = [single]($size / 256)
        $canvas.ScaleTransform($scale, $scale)
        Add-RoundRectangle $tile 16 16 224 224 52
        $canvas.FillPath($background, $tile)
        Draw-ClaudeMark $canvas

        $png = [IO.MemoryStream]::new()
        try {
            $bitmap.Save($png, [Drawing.Imaging.ImageFormat]::Png)
            return ,$png.ToArray()
        } finally {
            $png.Dispose()
        }
    } finally {
        $background.Dispose()
        $tile.Dispose()
        $canvas.Dispose()
        $bitmap.Dispose()
    }
}

$sizes = @(16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
$images = @{}
foreach ($size in $sizes) { $images[$size] = New-IconFrame $size }
[IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'icon.png'), $images[256])

$iconPath = Join-Path $PSScriptRoot 'icon.ico'
$writer = [IO.BinaryWriter]::new([IO.File]::Create($iconPath))
try {
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    foreach ($size in $sizes) {
        $dimension = [byte]($size % 256)
        $writer.Write($dimension)
        $writer.Write($dimension)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]($images[$size].Length))
        $writer.Write([uint32]$offset)
        $offset += $images[$size].Length
    }
    foreach ($size in $sizes) { $writer.Write([byte[]]$images[$size]) }
} finally {
    $writer.Dispose()
}
