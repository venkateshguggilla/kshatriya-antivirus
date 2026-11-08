<#
.SYNOPSIS
  Downloads the pinned YARA-X C API library for Windows x64 and verifies its SHA-256 before use.
.DESCRIPTION
  The DLL is not committed to the repository. This script fetches the official release asset from
  github.com/VirusTotal/yara-x, refuses to continue if the archive hash differs from the pinned value,
  and extracts only the files Sentinel needs into native/yara-x/win-x64/.
  The upstream DLL is not Authenticode-signed; the pinned hash is the integrity control.
#>
[CmdletBinding()]
param(
    [string] $Destination = (Join-Path $PSScriptRoot '..\native\yara-x\win-x64')
)

$ErrorActionPreference = 'Stop'

$Version = '1.22.1'
$Asset = "yara-x-capi-v$Version-x86_64-pc-windows-msvc.zip"
$Sha256 = 'f52c2105e52696461de5f4aa6df50051994855ceee069015d566d7c6eb321217'
$Url = "https://github.com/VirusTotal/yara-x/releases/download/v$Version/$Asset"
$LicenseUrl = "https://raw.githubusercontent.com/VirusTotal/yara-x/v$Version/LICENSE"

$Destination = [System.IO.Path]::GetFullPath($Destination)
$marker = Join-Path $Destination 'VERSION'
if ((Test-Path -LiteralPath $marker) -and ((Get-Content -LiteralPath $marker -Raw).Trim() -eq "$Version $Sha256")) {
    Write-Host "YARA-X $Version already present in $Destination"
    return
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-yarax-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work $Asset
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing

    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for $Asset. Expected $Sha256, got $actual. Refusing to use it."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($name in 'yara_x_capi.dll', 'yara_x.h') {
            $entry = $archive.Entries | Where-Object { $_.FullName -eq $name } | Select-Object -First 1
            if (-not $entry) { throw "Archive does not contain $name." }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Destination $name), $true)
        }
    }
    finally {
        $archive.Dispose()
    }

    Invoke-WebRequest -Uri $LicenseUrl -OutFile (Join-Path $Destination 'LICENSE.txt') -UseBasicParsing
    Set-Content -LiteralPath $marker -Value "$Version $Sha256" -Encoding ascii
    Write-Host "YARA-X $Version installed to $Destination (archive SHA-256 verified)."
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
