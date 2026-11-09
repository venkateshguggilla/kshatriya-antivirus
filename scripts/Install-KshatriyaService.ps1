#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Kshatriya prototype service (KshatriyaService) from a local build.

.DESCRIPTION
    Publishes the service, the sandboxed scan worker and the CLI into "%ProgramFiles%\Kshatriya"
    (writable only by administrators), registers KshatriyaService to run as LocalSystem with
    automatic (delayed) start and restart-on-failure, and starts it.

    Kshatriya runs alongside Microsoft Defender (companion mode, ADR 0002). This script does not
    change any Defender or Windows security setting and adds no exclusions.

    This is a prototype. Review docs/threat-model.md before installing on a machine you depend on.

.PARAMETER InstallDirectory
    Target directory. Defaults to "$env:ProgramFiles\Kshatriya".

.PARAMETER FromRelease
    Install from a release folder made by scripts/Build-Release.ps1 instead of building from source.
    Every file is checked against the folder's SHA256SUMS.txt first; any mismatch, missing or unlisted
    binary aborts the installation.

.PARAMETER RequireSignature
    With -FromRelease: also require a valid Authenticode signature on every Kshatriya executable and library.

.EXAMPLE
    ./scripts/Get-YaraX.ps1
    ./scripts/Install-KshatriyaService.ps1
    kshatriya status
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'Kshatriya'),
    [string] $FromRelease,
    [switch] $RequireSignature
)

$ErrorActionPreference = 'Stop'
$serviceName = 'KshatriyaService'
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
        foreach ($binary in Get-ChildItem $folder -File | Where-Object { ($_.Name -like 'Kshatriya*' -or $_.Name -eq 'kshatriya.exe') -and $_.Extension -in '.exe', '.dll' }) {
            $signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
            if ($signature.Status -ne 'Valid') { throw "$($binary.Name) is not validly signed ($($signature.Status))." }
        }
    }
    Write-Host "Verified $($listed.Count) files against SHA256SUMS.txt$(if ($RequireSignature) { ' and their signatures' })."
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "$serviceName is already installed. Run ./scripts/Uninstall-KshatriyaService.ps1 first."
}

$staging = if ($FromRelease) { (Resolve-Path $FromRelease).Path } else { Join-Path ([System.IO.Path]::GetTempPath()) "kshatriya-publish-$([guid]::NewGuid().ToString('N'))" }
try {
    if ($FromRelease) {
        Test-Release $staging
    }
    else {
        foreach ($project in 'src/Kshatriya.Service', 'src/Kshatriya.Cli', 'src/Kshatriya.App', 'src/Kshatriya.BrowserHost') {
            dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained false -o $staging
            if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
        }
        Copy-Item (Join-Path $repo 'extension') (Join-Path $staging 'browser-extension') -Recurse
    }

    if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Copy Kshatriya binaries')) {
        # Program Files inherits an ACL that only lets administrators and SYSTEM write, so the
        # service binary and the worker cannot be replaced by a standard user.
        New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
        Copy-Item -Path (Join-Path $staging '*') -Destination $InstallDirectory -Recurse -Force
    }
}
finally {
    if (-not $FromRelease) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
}

$app = Join-Path $InstallDirectory 'Kshatriya.App.exe'
if ((Test-Path $app) -and $PSCmdlet.ShouldProcess('Start menu', 'Add Kshatriya shortcut')) {
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Kshatriya Antivirus.lnk'))
    $shortcut.TargetPath = $app
    $shortcut.Description = 'Kshatriya Antivirus (prototype) - runs alongside Microsoft Defender'
    $shortcut.Save()
}

# Desktop shortcut for every user (the Public desktop).
if ((Test-Path $app) -and $PSCmdlet.ShouldProcess('Desktop', 'Add Kshatriya Antivirus shortcut')) {
    $desktop = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Kshatriya Antivirus.lnk'))
    $desktop.TargetPath = $app
    $desktop.Description = 'Kshatriya Antivirus (prototype) - runs alongside Microsoft Defender'
    $desktop.Save()
}

# Explorer right-click "Scan with Kshatriya Antivirus" for files, folders and drives (on Windows 11 it is
# under "Show more options"). Each item opens its own scan window; the service scans with the user's rights.
if ((Test-Path $app) -and $PSCmdlet.ShouldProcess('Explorer context menu', 'Add "Scan with Kshatriya Antivirus"')) {
    foreach ($class in '*', 'Directory', 'Drive') {
        # .NET registry API: PowerShell registry paths would treat '*' as a wildcard.
        $verb = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SOFTWARE\Classes\$class\shell\KshatriyaScan")
        try {
            $verb.SetValue('MUIVerb', 'Scan with Kshatriya Antivirus')
            $verb.SetValue('Icon', "`"$app`"")
            $command = $verb.CreateSubKey('command')
            try { $command.SetValue('', "`"$app`" --scan `"%1`"") } finally { $command.Dispose() }
        }
        finally { $verb.Dispose() }
    }
}

# Browser extension helper (ADR 0018): register the native messaging host for Edge and Chrome, so the
# Kshatriya extension - and only that extension ID - can ask the service to scan finished downloads. The
# manifest lives in the install folder, which only administrators can change.
$browserHost = Join-Path $InstallDirectory 'Kshatriya.BrowserHost.exe'
if ((Test-Path $browserHost) -and $PSCmdlet.ShouldProcess('Edge and Chrome', 'Register the Kshatriya browser helper')) {
    $hostManifest = Join-Path $InstallDirectory 'browser-host.json'
    $json = [ordered]@{
        name            = 'com.kshatriya.browser_host'
        description     = 'Kshatriya Antivirus browser helper: scans finished downloads through the Kshatriya service'
        path            = $browserHost
        type            = 'stdio'
        allowed_origins = @('chrome-extension://lkkpcdfabgihmnhfdmhoellokaobmdah/')
    } | ConvertTo-Json
    # UTF-8 without a byte-order mark.
    [System.IO.File]::WriteAllText($hostManifest, $json, (New-Object System.Text.UTF8Encoding $false))
    foreach ($browserKey in 'SOFTWARE\Google\Chrome\NativeMessagingHosts\com.kshatriya.browser_host',
                            'SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.kshatriya.browser_host') {
        $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($browserKey)
        try { $key.SetValue('', $hostManifest) } finally { $key.Dispose() }
    }
    Write-Host "Browser extension: open edge://extensions or chrome://extensions, turn on Developer mode, choose 'Load unpacked' and select $(Join-Path $InstallDirectory 'browser-extension')."
}

# Start the app in the notification area at sign-in, for every user, so findings from real-time protection
# are shown as notifications. Each user can turn it off in Task Manager > Startup apps, or turn off
# notifications from the tray icon.
if ((Test-Path $app) -and $PSCmdlet.ShouldProcess('Startup folder', 'Start Kshatriya Antivirus in the notification area at sign-in')) {
    $startup = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Kshatriya Antivirus.lnk'))
    $startup.TargetPath = $app
    $startup.Arguments = '--background'
    $startup.Description = 'Kshatriya Antivirus notifications (notification area)'
    $startup.Save()
}

$binary = Join-Path $InstallDirectory 'Kshatriya.Service.exe'
if ($PSCmdlet.ShouldProcess($serviceName, 'Register and start service')) {
    New-Service -Name $serviceName `
        -BinaryPathName "`"$binary`"" `
        -DisplayName 'Kshatriya Antivirus (prototype)' `
        -Description 'Kshatriya Antivirus prototype scanner service. Runs alongside Microsoft Defender; scanning is read-only; files change only through opt-in quarantine.' `
        -StartupType Automatic | Out-Null
    # Delayed automatic start (New-Service only offers it from PowerShell 6, so set it with sc.exe).
    sc.exe config $serviceName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed ($LASTEXITCODE)." }

    # Restart after a crash (5 s, 30 s, then every 5 minutes); reset the failure count after a day.
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/300000 | Out-Null
    # Apply them also when the service stops itself with an error (for example a failed start).
    sc.exe failureflag $serviceName 1 | Out-Null
    # Give the service its own SID so its resources can be ACLed to it specifically.
    sc.exe sidtype $serviceName unrestricted | Out-Null

    Start-Service -Name $serviceName
    Write-Host "Installed $serviceName to $InstallDirectory. Check it with: & '$InstallDirectory\kshatriya.exe' status"
}
