#Requires -Version 7.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the Sentinel prototype service.

.DESCRIPTION
    Stops SentinelService, deletes the service registration and, unless -KeepFiles is given, removes
    the installed binaries. Configuration and reports in %ProgramData%\Sentinel are kept unless
    -RemoveData is given.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'Sentinel'),
    [switch] $KeepFiles,
    [switch] $RemoveData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelService'

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($serviceName, 'Stop and delete service')) {
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
    }
}

if (-not $KeepFiles -and (Test-Path $InstallDirectory)) {
    if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Remove binaries')) {
        Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
    }
}

$data = Join-Path $env:ProgramData 'Sentinel'
if ($RemoveData -and (Test-Path $data)) {
    if ($PSCmdlet.ShouldProcess($data, 'Remove configuration and reports')) {
        Remove-Item -LiteralPath $data -Recurse -Force
    }
}
