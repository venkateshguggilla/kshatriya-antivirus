#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a Sentinel release folder and zip: service, sandboxed worker, CLI and desktop app.

.DESCRIPTION
    Publishes self-contained win-x64 binaries (no separate .NET installation needed) into
    artifacts/Sentinel-<version>-win-x64, adds the licence files and a dependency inventory, optionally
    Authenticode-signs every Sentinel binary, writes SHA256SUMS.txt and zips the folder.

    Signing happens only when a certificate is supplied, through parameters or the environment variables
    SENTINEL_SIGN_PFX (path to a .pfx) and SENTINEL_SIGN_PASSWORD. Without one, the release is clearly
    marked UNSIGNED. No certificate or private key is ever stored in the repository.

.EXAMPLE
    ./scripts/Get-YaraX.ps1
    ./scripts/Build-Release.ps1
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [string] $CertificatePath = $env:SENTINEL_SIGN_PFX,
    [string] $CertificatePassword = $env:SENTINEL_SIGN_PASSWORD,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
[xml] $props = Get-Content (Join-Path $repo 'Directory.Build.props')
$version = ($props.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
$name = "Sentinel-$version-win-x64"
$folder = Join-Path $OutputDirectory $name

if (-not (Test-Path (Join-Path $repo 'native/yara-x/win-x64/yara_x_capi.dll'))) {
    throw 'YARA-X library missing. Run ./scripts/Get-YaraX.ps1 first.'
}

if (Test-Path $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
New-Item -ItemType Directory -Force -Path $folder | Out-Null

foreach ($project in 'src/Sentinel.Service', 'src/Sentinel.Cli', 'src/Sentinel.App') {
    dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=false -o $folder --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
}

Get-ChildItem $folder -File | Where-Object { $_.Extension -in '.pdb', '.xml' } | Remove-Item
foreach ($doc in 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'README.md', 'SECURITY.md') {
    if (Test-Path (Join-Path $repo $doc)) { Copy-Item (Join-Path $repo $doc) $folder }
}

# Dependency inventory (NuGet packages, including transitive ones, of every shipped project).
$inventory = foreach ($project in 'src/Sentinel.Service', 'src/Sentinel.Cli', 'src/Sentinel.App') {
    $json = dotnet list (Join-Path $repo $project) package --include-transitive --format json | ConvertFrom-Json
    foreach ($p in $json.projects.frameworks.topLevelPackages + $json.projects.frameworks.transitivePackages) {
        if ($p) { [pscustomobject]@{ id = $p.id; version = $p.resolvedVersion } }
    }
}
$inventory = @($inventory | Sort-Object id, version -Unique)
$yara = Get-Content (Join-Path $repo 'scripts/Get-YaraX.ps1') -Raw
$yaraVersion = if ($yara -match "\`$Version\s*=\s*'([^']+)'") { $Matches[1] } else { 'see scripts/Get-YaraX.ps1' }
[ordered]@{
    product   = 'Sentinel'
    version   = $version
    packages  = $inventory
    native    = @([ordered]@{ id = 'yara-x (yara_x_capi.dll)'; version = $yaraVersion; license = 'BSD-3-Clause' })
} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $folder 'dependencies.json') -Encoding utf8

$ours = Get-ChildItem $folder -File | Where-Object { $_.Name -like 'Sentinel*' -or $_.Name -eq 'sentinel.exe' } | Where-Object { $_.Extension -in '.exe', '.dll' }
$signed = $false
if ($CertificatePath) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found (install the Windows SDK).' }
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $CertificatePath /p $CertificatePassword $ours.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
    $signed = $true
}

Set-Content (Join-Path $folder 'RELEASE.txt') -Encoding utf8 -Value @"
Sentinel $version (win-x64) - prototype. Not a replacement for Microsoft Defender; keep Defender on.
Binaries: $(if ($signed) { 'Authenticode-signed' } else { 'UNSIGNED (no signing certificate was supplied for this build)' })
Install (administrator, PowerShell 7): ./Install-SentinelService.ps1 -FromRelease <this folder>
Verify: every file is listed with its SHA-256 in SHA256SUMS.txt.
"@
Copy-Item (Join-Path $repo 'scripts/Install-SentinelService.ps1'), (Join-Path $repo 'scripts/Uninstall-SentinelService.ps1') $folder

$sums = Get-ChildItem $folder -File -Recurse | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($folder.Length + 1)
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
}
Set-Content (Join-Path $folder 'SHA256SUMS.txt') -Value $sums -Encoding utf8

$zip = Join-Path $OutputDirectory "$name.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content "$zip.sha256" -Value "$zipHash  $name.zip" -Encoding utf8

Write-Host "Built $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MiB), $(if ($signed) { 'signed' } else { 'UNSIGNED' }). SHA-256 $zipHash"
