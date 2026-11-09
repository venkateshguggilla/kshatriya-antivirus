#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a Kshatriya release folder and zip: service, sandboxed worker, CLI and desktop app.

.DESCRIPTION
    Publishes self-contained win-x64 binaries (no separate .NET installation needed) into
    artifacts/Kshatriya-<version>-win-x64, adds the licence files and a dependency inventory, writes
    SHA256SUMS.txt and zips the folder.

    Two stages, so that an external signing service can sign in between (the release workflow uses
    SignPath, ADR 0014): -Stage Build publishes the folder; -Stage Package writes RELEASE.txt, the
    checksums and the zip for whatever is in the folder then. -Stage All (default) does both.

    Whether the release is signed is decided by checking every Kshatriya binary's Authenticode signature,
    not by how it was produced. -RequireSignature refuses to package unless all of them are validly signed.
    A local .pfx (a test certificate; publicly trusted code-signing keys must stay on hardware and cannot be
    exported) can be applied with -CertificatePath or KSHATRIYA_SIGN_PFX / KSHATRIYA_SIGN_PASSWORD. No
    certificate or private key is ever stored in the repository.

.EXAMPLE
    ./scripts/Get-YaraX.ps1
    ./scripts/Build-Release.ps1
.EXAMPLE
    ./scripts/Build-Release.ps1 -Stage Build
    # ... binaries signed externally and copied back into the folder ...
    ./scripts/Build-Release.ps1 -Stage Package -RequireSignature
#>
[CmdletBinding()]
param(
    # Defaults to <repo>/artifacts (resolved below: Windows PowerShell 5.1 leaves $PSScriptRoot empty here).
    [string] $OutputDirectory,
    [ValidateSet('All', 'Build', 'Package')]
    [string] $Stage = 'All',
    [switch] $RequireSignature,
    [string] $CertificatePath = $env:KSHATRIYA_SIGN_PFX,
    [string] $CertificatePassword = $env:KSHATRIYA_SIGN_PASSWORD,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'artifacts' }
[xml] $props = Get-Content (Join-Path $repo 'Directory.Build.props')
$version = ($props.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
$name = "Kshatriya-$version-win-x64"
$folder = Join-Path $OutputDirectory $name

if ($Stage -ne 'Package') {
if (-not (Test-Path (Join-Path $repo 'native/yara-x/win-x64/yara_x_capi.dll'))) {
    throw 'YARA-X library missing. Run ./scripts/Get-YaraX.ps1 first.'
}

if (Test-Path $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
New-Item -ItemType Directory -Force -Path $folder | Out-Null

foreach ($project in 'src/Kshatriya.Service', 'src/Kshatriya.Cli', 'src/Kshatriya.App', 'src/Kshatriya.BrowserHost') {
    dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=false -o $folder --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
}

Get-ChildItem $folder -File | Where-Object { $_.Extension -in '.pdb', '.xml' } | Remove-Item
foreach ($doc in 'LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.md', 'README.md', 'SECURITY.md') {
    if (Test-Path (Join-Path $repo $doc)) { Copy-Item (Join-Path $repo $doc) $folder }
}

# Dependency inventory (NuGet packages, including transitive ones, of every shipped project).
$inventory = foreach ($project in 'src/Kshatriya.Service', 'src/Kshatriya.Cli', 'src/Kshatriya.App', 'src/Kshatriya.BrowserHost') {
    $json = dotnet list (Join-Path $repo $project) package --include-transitive --format json | ConvertFrom-Json
    foreach ($p in $json.projects.frameworks.topLevelPackages + $json.projects.frameworks.transitivePackages) {
        if ($p) { [pscustomobject]@{ id = $p.id; version = $p.resolvedVersion } }
    }
}
$inventory = @($inventory | Sort-Object id, version -Unique)
$yara = Get-Content (Join-Path $repo 'scripts/Get-YaraX.ps1') -Raw
$yaraVersion = if ($yara -match "\`$Version\s*=\s*'([^']+)'") { $Matches[1] } else { 'see scripts/Get-YaraX.ps1' }
[ordered]@{
    product   = 'Kshatriya'
    version   = $version
    packages  = $inventory
    native    = @([ordered]@{ id = 'yara-x (yara_x_capi.dll)'; version = $yaraVersion; license = 'BSD-3-Clause' })
} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $folder 'dependencies.json') -Encoding utf8
# Browser extension (ADR 0018), loaded unpacked from the install folder.
Copy-Item (Join-Path $repo 'extension') (Join-Path $folder 'browser-extension') -Recurse
Copy-Item (Join-Path $repo 'scripts/Install-KshatriyaService.ps1'), (Join-Path $repo 'scripts/Uninstall-KshatriyaService.ps1') $folder

if ($Stage -eq 'Build') {
    Write-Host "Built $folder (not packaged; sign the Kshatriya binaries, then run -Stage Package)."
    return
}
}

if (-not (Test-Path (Join-Path $folder 'Kshatriya.Service.exe'))) {
    throw "No built release in $folder. Run -Stage Build first."
}

$ours = @(Get-ChildItem $folder -File | Where-Object { $_.Name -like 'Kshatriya*' -or $_.Name -like 'kshatriya.*' } | Where-Object { $_.Extension -in '.exe', '.dll' })
if ($CertificatePath) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found (install the Windows SDK).' }
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $CertificatePath /p $CertificatePassword $ours.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
}

# Signed means every Kshatriya binary carries a valid Authenticode signature right now.
$unsigned = @($ours | Where-Object { (Get-AuthenticodeSignature -LiteralPath $_.FullName).Status -ne 'Valid' })
$signed = $ours.Count -gt 0 -and $unsigned.Count -eq 0
if ($RequireSignature -and -not $signed) {
    throw "Refusing to package: $($unsigned.Count) of $($ours.Count) Kshatriya binaries are not validly signed ($(($unsigned.Name | Select-Object -First 5) -join ', '))."
}

$signer = if ($signed) { (Get-AuthenticodeSignature -LiteralPath $ours[0].FullName).SignerCertificate.Subject } else { $null }
Set-Content (Join-Path $folder 'RELEASE.txt') -Encoding utf8 -Value @"
Kshatriya Antivirus $version (win-x64) - prototype. Not a replacement for Microsoft Defender; keep Defender on.
Binaries: $(if ($signed) { "Authenticode-signed ($signer)" } else { 'UNSIGNED (no signature was applied to this build)' })
Install (administrator, Windows PowerShell 5.1 or later): ./Install-KshatriyaService.ps1 -FromRelease <this folder>
Verify: every file is listed with its SHA-256 in SHA256SUMS.txt.
Licence: Apache License 2.0 (LICENSE, NOTICE); third-party components: THIRD-PARTY-NOTICES.md.
"@

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
