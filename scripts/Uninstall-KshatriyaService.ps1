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

foreach ($shortcut in (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Kshatriya Antivirus.lnk'),
                      (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Kshatriya Antivirus.lnk')) {
    if ((Test-Path $shortcut) -and $PSCmdlet.ShouldProcess($shortcut, 'Remove shortcut')) {
        Remove-Item -LiteralPath $shortcut -Force
    }
}

if ($PSCmdlet.ShouldProcess('Explorer context menu', 'Remove "Scan with Kshatriya Antivirus"')) {
    foreach ($class in '*', 'Directory', 'Drive') {
        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree("SOFTWARE\Classes\$class\shell\KshatriyaScan", $false)
    }
}

if (-not $KeepFiles -and (Test-Path $InstallDirectory)) {
    # The desktop app runs in the notification area of signed-in users and keeps its files open. Close
    # only Kshatriya's own app processes started from this install folder, so the files can be removed.
    $installed = [System.IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\') + '\'
    $apps = @(Get-Process -Name 'Kshatriya.App' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($installed, [StringComparison]::OrdinalIgnoreCase) })
    if ($apps.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($apps.Count) running Kshatriya Antivirus app window(s)", 'Close')) {
        $apps | Stop-Process -Force
        $apps | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }

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
