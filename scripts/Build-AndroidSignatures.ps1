#Requires -Version 5.1
<#
.SYNOPSIS
    Builds an Android signature list (.hashdb) from the Echap stalkerware indicators (ADR 0020).

.DESCRIPTION
    Reads samples.csv (SHA256, Package Name, Certificate, Version, App) and, optionally, watchware.yaml from
    a local copy of https://github.com/AssoEchap/stalkerware-indicators (CC BY 4.0; credit "Echap,
    stalkerware-indicators"). Each sample becomes an exact SHA-256 signature in the category "pua"
    (potentially unwanted): stalkerware is commercial surveillance software, and watchware is sold as
    parental control, so neither is labelled as confirmed malware. Names are
    "Android.Stalkerware.<App>" or "Android.Watchware.<App>" when the package is listed in watchware.yaml.

    The script never downloads anything; fetch the files yourself. Sign the output with
    "kshatriya-content pack" and import it on the phone.

.EXAMPLE
    ./scripts/Build-AndroidSignatures.ps1 -Samples C:\echap\samples.csv -Watchware C:\echap\watchware.yaml -Output C:\build\android-stalkerware.hashdb
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Samples,
    [string] $Watchware,
    [Parameter(Mandatory)] [string] $Output
)

$ErrorActionPreference = 'Stop'
if ([System.IO.Path]::GetExtension($Output) -ne '.hashdb') { throw '-Output must name a .hashdb file.' }

# Packages of watchware apps: lines "  - <package>" under a "packages:" key.
$watchPackages = New-Object 'System.Collections.Generic.HashSet[string]'
if ($Watchware) {
    $inPackages = $false
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path $Watchware).Path)) {
        if ($line -match '^\s*packages:\s*$') { $inPackages = $true; continue }
        if ($inPackages -and $line -match '^\s*-\s+([A-Za-z0-9_.]+)\s*$') { [void] $watchPackages.Add($Matches[1]); continue }
        $inPackages = $false
    }
}

$header = $null
$seen = @{}
$lines = New-Object 'System.Collections.Generic.List[string]'
$skipped = 0
foreach ($row in Import-Csv -LiteralPath (Resolve-Path $Samples).Path) {
    if (-not $header) { $header = $row.PSObject.Properties.Name -join ',' }
    $sha = "$($row.SHA256)".Trim().ToLowerInvariant()
    if ($sha -notmatch '^[0-9a-f]{64}$') { $skipped++; continue }
    if ($seen.ContainsKey($sha)) { continue }
    $app = ("$($row.App)" -replace '[^A-Za-z0-9._-]', '')
    if (-not $app) { $app = 'Unknown' }
    $kind = if ($watchPackages.Contains("$($row.'Package Name')".Trim())) { 'Watchware' } else { 'Stalkerware' }
    $name = "Android.$kind.$app"
    if ($name.Length -gt 128) { $name = $name.Substring(0, 128) }
    $seen[$sha] = $true
    $lines.Add("sha256:$sha $name pua")
}
if ($header -notmatch '^SHA256,Package Name') { throw "Unexpected samples.csv columns: $header" }

$out = @('# kshatriya-hashdb v1',
         "# Source: Echap stalkerware-indicators (https://github.com/AssoEchap/stalkerware-indicators), CC BY 4.0. Built $((Get-Date).ToString('yyyy-MM-dd')).") + ($lines | Sort-Object)
[System.IO.File]::WriteAllText($Output, (($out -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
$watchCount = @($lines | Where-Object { $_ -match ' Android\.Watchware\.' }).Count
Write-Host "Wrote $($lines.Count) signatures ($watchCount watchware) to $Output ($skipped rows skipped)."
