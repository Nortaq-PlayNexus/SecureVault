# Generates the SecureVault application icon (multi-size .ico) from the brand
# mark. Requires Windows + .NET (System.Drawing). Usage:
#   powershell -ExecutionPolicy Bypass -File eng/scripts/generate-icon.ps1
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$outDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\assets\icons"))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$sizes = @(256, 128, 64, 48, 32, 16)
$tempPngs = @()

$bgTop    = [System.Drawing.ColorTranslator]::FromHtml("#2E2E36")
$bgBottom = [System.Drawing.ColorTranslator]::FromHtml("#1E1E22")
$shieldTop = [System.Drawing.ColorTranslator]::FromHtml("#6BAEFF")
$shieldBot = [System.Drawing.ColorTranslator]::FromHtml("#2E7BE6")
$keyhole  = [System.Drawing.ColorTranslator]::FromHtml("#1E1E22")

function New-Single($v) { return [single]$v }

foreach ($size in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap -ArgumentList $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [single]($size / 512.0)

    # Rounded background
    $bgRect = New-Object System.Drawing.RectangleF -ArgumentList `
        (New-Single (8 * $s)), (New-Single (8 * $s)), (New-Single (496 * $s)), (New-Single (496 * $s))
    $radius = New-Single (104 * $s)
    $bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bgPath.AddArc($bgRect.X, $bgRect.Y, $radius, $radius, 180, 90)
    $bgPath.AddArc($bgRect.Right - $radius, $bgRect.Y, $radius, $radius, 270, 90)
    $bgPath.AddArc($bgRect.Right - $radius, $bgRect.Bottom - $radius, $radius, $radius, 0, 90)
    $bgPath.AddArc($bgRect.X, $bgRect.Bottom - $radius, $radius, $radius, 90, 90)
    $bgPath.CloseFigure()
    $bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush -ArgumentList $bgRect, $bgTop, $bgBottom, 45
    $g.FillPath($bgBrush, $bgPath)

    # Shield polygon (fractional points scaled from the 512 design grid)
    $pts = New-Object System.Drawing.PointF[] 10
    $pts[0] = New-Object System.Drawing.PointF -ArgumentList (New-Single (256 * $s)), (New-Single (88 * $s))
    $pts[1] = New-Object System.Drawing.PointF -ArgumentList (New-Single (372 * $s)), (New-Single (132 * $s))
    $pts[2] = New-Object System.Drawing.PointF -ArgumentList (New-Single (372 * $s)), (New-Single (244 * $s))
    $pts[3] = New-Object System.Drawing.PointF -ArgumentList (New-Single (372 * $s)), (New-Single (302 * $s))
    $pts[4] = New-Object System.Drawing.PointF -ArgumentList (New-Single (322 * $s)), (New-Single (396 * $s))
    $pts[5] = New-Object System.Drawing.PointF -ArgumentList (New-Single (256 * $s)), (New-Single (424 * $s))
    $pts[6] = New-Object System.Drawing.PointF -ArgumentList (New-Single (190 * $s)), (New-Single (396 * $s))
    $pts[7] = New-Object System.Drawing.PointF -ArgumentList (New-Single (140 * $s)), (New-Single (302 * $s))
    $pts[8] = New-Object System.Drawing.PointF -ArgumentList (New-Single (140 * $s)), (New-Single (244 * $s))
    $pts[9] = New-Object System.Drawing.PointF -ArgumentList (New-Single (140 * $s)), (New-Single (132 * $s))

    $shieldRect = New-Object System.Drawing.RectangleF -ArgumentList `
        (New-Single (140 * $s)), (New-Single (88 * $s)), (New-Single (232 * $s)), (New-Single (336 * $s))
    $shieldBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush -ArgumentList $shieldRect, $shieldTop, $shieldBot, 45
    $g.FillPolygon($shieldBrush, $pts)

    # Keyhole
    $khRect = New-Object System.Drawing.RectangleF -ArgumentList `
        (New-Single (214 * $s)), (New-Single (202 * $s)), (New-Single (84 * $s)), (New-Single (84 * $s))
    $g.FillEllipse((New-Object System.Drawing.SolidBrush -ArgumentList $keyhole), $khRect)
    $stemRect = New-Object System.Drawing.RectangleF -ArgumentList `
        (New-Single (242 * $s)), (New-Single (272 * $s)), (New-Single (28 * $s)), (New-Single (70 * $s))
    $g.FillRectangle((New-Object System.Drawing.SolidBrush -ArgumentList $keyhole), $stemRect)
    $capRect = New-Object System.Drawing.RectangleF -ArgumentList `
        (New-Single (228 * $s)), (New-Single (314 * $s)), (New-Single (56 * $s)), (New-Single (28 * $s))
    $g.FillEllipse((New-Object System.Drawing.SolidBrush -ArgumentList $keyhole), $capRect)

    $png = Join-Path $env:TEMP ("sv-icon-" + $size + ".png")
    $bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
    $tempPngs += $png
    $g.Dispose(); $bmp.Dispose()
}

# Pack PNGs into a single multi-size .ico (Vista+ PNG-compressed icon format)
$icoPath = Join-Path $outDir "securevault.ico"
$ms = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter -ArgumentList $ms
$w.Write([uint16]0)                      # reserved
$w.Write([uint16]1)                      # type: icon
$w.Write([uint16]$sizes.Count)           # image count
$offset = 6 + 16 * $sizes.Count
$payload = New-Object System.Collections.Generic.List[byte]
foreach ($size in $sizes) {
    $png = Join-Path $env:TEMP ("sv-icon-" + $size + ".png")
    $data = [System.IO.File]::ReadAllBytes($png)
    $dim = if ($size -ge 256) { 0 } else { $size }
    $w.Write([byte]$dim)                 # width (0 == 256)
    $w.Write([byte]$dim)                 # height
    $w.Write([byte]0)                    # palette
    $w.Write([byte]0)                    # reserved
    $w.Write([uint16]1)                  # planes
    $w.Write([uint16]32)                 # bpp
    $w.Write([uint32]$data.Length)
    $w.Write([uint32]$offset)
    $payload.AddRange($data)
    $offset += $data.Length
}
$w.Flush()
$w.Write($payload.ToArray())
[System.IO.File]::WriteAllBytes($icoPath, $ms.ToArray())
$w.Dispose(); $ms.Dispose()
foreach ($p in $tempPngs) { Remove-Item -Force $p -ErrorAction SilentlyContinue }

Write-Output "Generated $icoPath ($([math]::Round((Get-Item $icoPath).Length/1kb)) KB)"
