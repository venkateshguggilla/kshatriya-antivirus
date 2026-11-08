#Requires -Version 7.0
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

.EXAMPLE
    ./scripts/Get-YaraX.ps1
    ./scripts/Install-SentinelService.ps1
    sentinel status
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'Sentinel')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelService'
$repo = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path (Join-Path $repo 'native/yara-x/win-x64/yara_x_capi.dll'))) {
    throw 'YARA-X library missing. Run ./scripts/Get-YaraX.ps1 first.'
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "$serviceName is already installed. Run ./scripts/Uninstall-SentinelService.ps1 first."
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-publish-$([guid]::NewGuid().ToString('N'))"
try {
    foreach ($project in 'src/Sentinel.Service', 'src/Sentinel.Cli') {
        dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained false -o $staging
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
    }

    if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Copy Sentinel binaries')) {
        # Program Files inherits an ACL that only lets administrators and SYSTEM write, so the
        # service binary and the worker cannot be replaced by a standard user.
        New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
        Copy-Item -Path (Join-Path $staging '*') -Destination $InstallDirectory -Recurse -Force
    }
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}

$binary = Join-Path $InstallDirectory 'Sentinel.Service.exe'
if ($PSCmdlet.ShouldProcess($serviceName, 'Register and start service')) {
    New-Service -Name $serviceName `
        -BinaryPathName "`"$binary`"" `
        -DisplayName 'Sentinel (prototype)' `
        -Description 'Sentinel prototype scanner service. Runs alongside Microsoft Defender; read-only scanning.' `
        -StartupType AutomaticDelayedStart | Out-Null

    # Restart after a crash (5 s, 30 s, then every 5 minutes); reset the failure count after a day.
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/300000 | Out-Null
    # Give the service its own SID so its resources can be ACLed to it specifically.
    sc.exe sidtype $serviceName unrestricted | Out-Null

    Start-Service -Name $serviceName
    Write-Host "Installed $serviceName to $InstallDirectory. Check it with: & '$InstallDirectory\sentinel.exe' status"
}
