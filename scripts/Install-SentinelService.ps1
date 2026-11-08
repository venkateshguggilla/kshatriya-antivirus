#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Sentinel prototype service (SentinelService) from a local build.

.DESCRIPTION
    Publishes the service, the sandboxed scan worker and the CLI into "%ProgramFiles%\Sentinel"
    (writable only by administrators), registers SentinelService to run as LocalSystem with
    automatic (delayed) start and restart-on-failure, and starts it.

    Sentinel runs alongside Microsoft Defender (companion mode, ADR 0002). This script does not
    change any Defender or Windows security setting and adds no exclusions.

    This is a prototype. Review docs/threat-model.md before installing on a machine you depend on.

.PARAMETER InstallDirectory
    Target directory. Defaults to "$env:ProgramFiles\Sentinel".

.PARAMETER FromRelease
    Install from a release folder made by scripts/Build-Release.ps1 instead of building from source.
    Every file is checked against the folder's SHA256SUMS.txt first; any mismatch, missing or unlisted
    binary aborts the installation.

.PARAMETER RequireSignature
    With -FromRelease: also require a valid Authenticode signature on every Sentinel executable and library.

.EXAMPLE
    ./scripts/Get-YaraX.ps1
    ./scripts/Install-SentinelService.ps1
    sentinel status
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'Sentinel'),
    [string] $FromRelease,
    [switch] $RequireSignature
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelService'
$repo = Split-Path -Parent $PSScriptRoot

if (-not $FromRelease -and -not (Test-Path (Join-Path $repo 'native/yara-x/win-x64/yara_x_capi.dll'))) {
    throw 'YARA-X library missing. Run ./scripts/Get-YaraX.ps1 first.'
}

function Test-Release([string] $folder) {
    $sumsFile = Join-Path $folder 'SHA256SUMS.txt'
    if (-not (Test-Path $sumsFile)) { throw "No SHA256SUMS.txt in $folder." }
    $listed = @{}
    foreach ($line in Get-Content $sumsFile) {
        if ($line -match '^([0-9a-f]{64})  (.+)$') { $listed[$Matches[2]] = $Matches[1] }
    }
    foreach ($entry in $listed.GetEnumerator()) {
        $file = Join-Path $folder $entry.Key
        if (-not (Test-Path -LiteralPath $file)) { throw "Release file missing: $($entry.Key)" }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw "Checksum mismatch: $($entry.Key)" }
    }
    $unlisted = Get-ChildItem $folder -File -Recurse | Where-Object { $_.Extension -in '.exe', '.dll' } |
        Where-Object { -not $listed.ContainsKey($_.FullName.Substring((Resolve-Path $folder).Path.TrimEnd('\').Length + 1)) }
    if ($unlisted) { throw "Unlisted binaries in the release folder: $($unlisted.Name -join ', ')" }
    if ($RequireSignature) {
        foreach ($binary in Get-ChildItem $folder -File | Where-Object { ($_.Name -like 'Sentinel*' -or $_.Name -eq 'sentinel.exe') -and $_.Extension -in '.exe', '.dll' }) {
            $signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
            if ($signature.Status -ne 'Valid') { throw "$($binary.Name) is not validly signed ($($signature.Status))." }
        }
    }
    Write-Host "Verified $($listed.Count) files against SHA256SUMS.txt$(if ($RequireSignature) { ' and their signatures' })."
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "$serviceName is already installed. Run ./scripts/Uninstall-SentinelService.ps1 first."
}

$staging = if ($FromRelease) { (Resolve-Path $FromRelease).Path } else { Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-publish-$([guid]::NewGuid().ToString('N'))" }
try {
    if ($FromRelease) {
        Test-Release $staging
    }
    else {
        foreach ($project in 'src/Sentinel.Service', 'src/Sentinel.Cli', 'src/Sentinel.App') {
            dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained false -o $staging
            if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
        }
    }

    if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Copy Sentinel binaries')) {
        # Program Files inherits an ACL that only lets administrators and SYSTEM write, so the
        # service binary and the worker cannot be replaced by a standard user.
        New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
        Copy-Item -Path (Join-Path $staging '*') -Destination $InstallDirectory -Recurse -Force
    }
}
finally {
    if (-not $FromRelease) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
}

$app = Join-Path $InstallDirectory 'Sentinel.App.exe'
if ((Test-Path $app) -and $PSCmdlet.ShouldProcess('Start menu', 'Add Sentinel shortcut')) {
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Sentinel.lnk'))
    $shortcut.TargetPath = $app
    $shortcut.Description = 'Sentinel (prototype) - runs alongside Microsoft Defender'
    $shortcut.Save()
}

$binary = Join-Path $InstallDirectory 'Sentinel.Service.exe'
if ($PSCmdlet.ShouldProcess($serviceName, 'Register and start service')) {
    New-Service -Name $serviceName `
        -BinaryPathName "`"$binary`"" `
        -DisplayName 'Sentinel (prototype)' `
        -Description 'Sentinel prototype scanner service. Runs alongside Microsoft Defender; scanning is read-only; files change only through opt-in quarantine.' `
        -StartupType Automatic | Out-Null
    # Delayed automatic start (New-Service only offers it from PowerShell 6, so set it with sc.exe).
    sc.exe config $serviceName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed ($LASTEXITCODE)." }

    # Restart after a crash (5 s, 30 s, then every 5 minutes); reset the failure count after a day.
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/300000 | Out-Null
    # Give the service its own SID so its resources can be ACLed to it specifically.
    sc.exe sidtype $serviceName unrestricted | Out-Null

    Start-Service -Name $serviceName
    Write-Host "Installed $serviceName to $InstallDirectory. Check it with: & '$InstallDirectory\sentinel.exe' status"
}
