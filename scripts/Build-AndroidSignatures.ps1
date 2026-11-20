#Requires -Version 5.1
<#
.SYNOPSIS
    Builds Android lists from the Echap stalkerware indicators (ADR 0020): file signatures (.hashdb) and,
    optionally, app indicators by package name and signing certificate (.appblock).

.DESCRIPTION
    Reads a local copy of https://github.com/AssoEchap/stalkerware-indicators (CC BY 4.0; credit "Echap,
    stalkerware-indicators"):

    - samples.csv (SHA256, Package Name, Certificate, Version, App): each sample becomes an exact SHA-256
      signature in the category "pua" (potentially unwanted).
    - ioc.yaml and watchware.yaml (with -Ioc / -Watchware and -AppBlockOutput): each app's package names
      and signing certificates (SHA-1, 40 hex digits; SHA-256, 64) become app indicators. Stalkerware entries
      are "pua"; watchware entries (mainstream family-safety apps such as Life360, which can be misused) are
      "suspicious", and win when an app is in both files. Kshatriya reports any package-name match alone
      as "suspicious".

    Stalkerware is commercial surveillance software and watchware is sold as parental control, so neither
    is labelled as confirmed malware. Names are "Android.Stalkerware.<App>" or "Android.Watchware.<App>".
    Entries that are malformed, or that would conflict with another app's entry, are left out and counted.

    The script never downloads anything; fetch the files yourself. Sign the outputs together with
    "kshatriya-content pack" and import the package on the phone.

.EXAMPLE
    ./scripts/Build-AndroidSignatures.ps1 -Samples C:\echap\samples.csv -Ioc C:\echap\ioc.yaml -Watchware C:\echap\watchware.yaml -Output C:\build\android-stalkerware.hashdb -AppBlockOutput C:\build\android-stalkerware.appblock
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Samples,
    [string] $Ioc,
    [string] $Watchware,
    [Parameter(Mandatory)] [string] $Output,
    [string] $AppBlockOutput
)

$ErrorActionPreference = 'Stop'
if ([System.IO.Path]::GetExtension($Output) -ne '.hashdb') { throw '-Output must name a .hashdb file.' }
if ($AppBlockOutput -and [System.IO.Path]::GetExtension($AppBlockOutput) -ne '.appblock') { throw '-AppBlockOutput must name a .appblock file.' }
if ($AppBlockOutput -and -not ($Ioc -or $Watchware)) { throw '-AppBlockOutput needs -Ioc and/or -Watchware.' }
$utf8 = New-Object System.Text.UTF8Encoding $false
$credit = "# Source: Echap stalkerware-indicators (https://github.com/AssoEchap/stalkerware-indicators), CC BY 4.0. Built $((Get-Date).ToString('yyyy-MM-dd'))."

function ConvertTo-Token([string] $text) {
    $token = $text -replace '[^A-Za-z0-9._-]', ''
    if (-not $token) { $token = 'Unknown' }
    return $token
}

# Reads Echap's YAML (a list of apps with "name", "type", "packages" and "certificates") line by line.
function Read-EchapApps([string] $path) {
    $apps = New-Object 'System.Collections.Generic.List[object]'
    $current = $null
    $key = $null
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path $path).Path)) {
        if ($line -match '^- name:\s*(.+?)\s*$') {
            $current = [pscustomobject]@{ Name = $Matches[1].Trim("'", '"'); Type = 'stalkerware'; Packages = New-Object 'System.Collections.Generic.List[string]'; Certificates = New-Object 'System.Collections.Generic.List[string]' }
            $apps.Add($current); $key = $null; continue
        }
        if (-not $current) { continue }
        if ($line -match '^  ([a-z_0-9]+):\s*(.*?)\s*$') {
            $key = $Matches[1]
            if ($key -eq 'type' -and $Matches[2]) { $current.Type = $Matches[2].Trim("'", '"') }
            continue
        }
        if ($line -match '^  - (.+?)\s*$') {
            $value = $Matches[1].Trim("'", '"')
            if ($key -eq 'packages') { $current.Packages.Add($value) }
            elseif ($key -eq 'certificates') { $current.Certificates.Add($value) }
        }
    }
    return $apps
}

# ---- File signatures (.hashdb) ----------------------------------------------------------------------

$watchPackages = New-Object 'System.Collections.Generic.HashSet[string]'
$apps = @()
# Watchware first: apps listed in both files keep the milder watchware classification.
if ($Watchware) { $apps += Read-EchapApps $Watchware }
if ($Ioc) { $apps += Read-EchapApps $Ioc }
foreach ($app in $apps | Where-Object { $_.Type -eq 'watchware' }) { foreach ($p in $app.Packages) { [void] $watchPackages.Add($p) } }

$header = $null
$seen = @{}
$lines = New-Object 'System.Collections.Generic.List[string]'
$skipped = 0
foreach ($row in Import-Csv -LiteralPath (Resolve-Path $Samples).Path) {
    if (-not $header) { $header = $row.PSObject.Properties.Name -join ',' }
    $sha = "$($row.SHA256)".Trim().ToLowerInvariant()
    if ($sha -notmatch '^[0-9a-f]{64}$') { $skipped++; continue }
    if ($seen.ContainsKey($sha)) { continue }
    $kind = if ($watchPackages.Contains("$($row.'Package Name')".Trim())) { 'Watchware' } else { 'Stalkerware' }
    $name = "Android.$kind.$(ConvertTo-Token $row.App)"
    if ($name.Length -gt 128) { $name = $name.Substring(0, 128) }
    $seen[$sha] = $true
    $lines.Add("sha256:$sha $name pua")
}
if ($header -notmatch '^SHA256,Package Name') { throw "Unexpected samples.csv columns: $header" }

$out = @('# kshatriya-hashdb v1', $credit) + ($lines | Sort-Object)
[System.IO.File]::WriteAllText($Output, (($out -join "`n") + "`n"), $utf8)
Write-Host "Wrote $($lines.Count) file signatures to $Output ($skipped rows skipped)."

# ---- App indicators (.appblock) ---------------------------------------------------------------------

if ($AppBlockOutput) {
    $packagePattern = '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$'
    # Public AOSP keys (testkey, platform, shared, media): any build signed with them would match.
    $publicKeys = @('61ed377e85d386a8dfee6b864bd85b0bfaa5af81', '27196e386b875e76adf700e7ea84e4c6eee33dfa', '5b368cff2da2686996bc95eac190eaa4f5630fe5', 'b79df4a82e90b57ea76525ab7037ab238a42f5d3')
    $owner = @{}
    $entries = New-Object 'System.Collections.Generic.List[string]'
    $left = 0
    foreach ($app in $apps) {
        $kind = if ($app.Type -eq 'watchware') { 'Watchware' } else { 'Stalkerware' }
        $category = if ($kind -eq 'Watchware') { 'suspicious' } else { 'pua' }
        $name = "Android.$kind.$(ConvertTo-Token $app.Name)"
        if ($name.Length -gt 128) { $name = $name.Substring(0, 128) }
        $candidates = @()
        foreach ($p in $app.Packages) {
            if ($p.Length -le 255 -and $p -match $packagePattern) { $candidates += , @('package', $p) } else { $left++ }
        }
        foreach ($c in $app.Certificates) {
            $hex = ($c -replace '[:\s]', '').ToLowerInvariant()
            if ($hex -match '^[0-9a-f]{40}$' -and $publicKeys -notcontains $hex) { $candidates += , @('cert-sha1', $hex) }
            elseif ($hex -match '^[0-9a-f]{64}$') { $candidates += , @('cert-sha256', $hex) }
            else { $left++ }
        }
        foreach ($candidate in $candidates) {
            $id = "$($candidate[0]) $($candidate[1])"
            if ($owner.ContainsKey($id)) {
                if ($owner[$id] -ne $name) { $left++; Write-Warning "$id is listed for both $($owner[$id]) and $name; kept the first." }
                continue
            }
            $owner[$id] = $name
            $entries.Add("$id $name $category")
        }
    }
    $out = @('# kshatriya-appblock v1', $credit) + ($entries | Sort-Object)
    [System.IO.File]::WriteAllText($AppBlockOutput, (($out -join "`n") + "`n"), $utf8)
    $packages = @($entries | Where-Object { $_ -like 'package *' }).Count
    Write-Host "Wrote $($entries.Count) app indicators ($packages package names, $($entries.Count - $packages) certificates) for $($apps.Count) apps to $AppBlockOutput ($left entries left out)."
}
