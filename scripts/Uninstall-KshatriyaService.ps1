#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the Kshatriya prototype service.

.DESCRIPTION
    Stops KshatriyaService, deletes the service registration and, unless -KeepFiles is given, removes
    the installed binaries. Configuration and reports in %ProgramData%\Kshatriya are kept unless
    -RemoveData is given.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'Kshatriya'),
    [switch] $KeepFiles,
    [switch] $RemoveData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'KshatriyaService'

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($serviceName, 'Stop and delete service')) {
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
    }
}

$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Kshatriya Antivirus.lnk'
if ((Test-Path $shortcut) -and $PSCmdlet.ShouldProcess($shortcut, 'Remove Start menu shortcut')) {
    Remove-Item -LiteralPath $shortcut -Force
}

if (-not $KeepFiles -and (Test-Path $InstallDirectory)) {
    if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Remove binaries')) {
        Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
    }
}

$data = Join-Path $env:ProgramData 'Kshatriya'
if ($RemoveData -and (Test-Path $data)) {
    if ($PSCmdlet.ShouldProcess($data, 'Remove configuration and reports')) {
        Remove-Item -LiteralPath $data -Recurse -Force
    }
}
