#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the browser extension's blocklist (extension/rules/blocklist.json) from domain lists.

.DESCRIPTION
    Reads one or more local text files with one entry per line: a domain ("bad.example"), a hosts-file
    line ("0.0.0.0 bad.example") or a URL ("http://bad.example/x"). Comments (#) and blank lines are
    ignored. Domains are lower-cased, validated, de-duplicated and capped at 30,000, then written as
    declarativeNetRequest blocking rules of up to 1,000 domains each. The test domain
    blocktest.kshatriya.invalid is always kept so the block page can be checked.

    Use only lists you are licensed to redistribute with this Apache-2.0 project (ADR 0018). The script
    never downloads anything; fetch the list yourself under its terms.

.PARAMETER Source
    One or more list files.

.PARAMETER SourceName
    Name of the list shown in the extension popup, for example "URLhaus (abuse.ch)".

.EXAMPLE
    ./scripts/Build-BrowserBlocklist.ps1 -Source C:\lists\hostfile.txt -SourceName 'My list'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Source,
    [Parameter(Mandatory)] [string] $SourceName,
    [string] $Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'extension/rules')
)

$ErrorActionPreference = 'Stop'
$maxDomains = 30000
$perRule = 1000
$testDomain = 'blocktest.kshatriya.invalid'
$domainPattern = '^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$'
$never = @('localhost', 'localhost.localdomain', 'local', 'broadcasthost', '0.0.0.0')

$domains = New-Object 'System.Collections.Generic.HashSet[string]'
[void] $domains.Add($testDomain)
$rejected = 0
foreach ($file in $Source) {
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path $file).Path)) {
        $entry = ($line -replace '#.*$', '').Trim()
        if (-not $entry) { continue }
        $parts = $entry -split '\s+'
        $candidate = if ($parts.Count -ge 2 -and $parts[0] -match '^(0\.0\.0\.0|127\.0\.0\.1|::1?)$') { $parts[1] } else { $parts[0] }
        if ($candidate -match '^[a-z][a-z0-9+.-]*://') {
            try { $candidate = ([Uri] $candidate).Host } catch { $rejected++; continue }
        }
        $candidate = $candidate.ToLowerInvariant().TrimEnd('.')
        if ($never -contains $candidate -or $candidate -notmatch $domainPattern) { $rejected++; continue }
        if ($domains.Count -ge $maxDomains) { Write-Warning "Stopped at $maxDomains domains."; break }
        [void] $domains.Add($candidate)
    }
}

$sorted = @($domains | Sort-Object)
$types = @('main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'other')
$rules = for ($i = 0; $i -lt $sorted.Count; $i += $perRule) {
    $chunk = $sorted[$i..([Math]::Min($i + $perRule, $sorted.Count) - 1)]
    [ordered]@{
        id        = [int]($i / $perRule) + 1
        priority  = 1
        action    = [ordered]@{ type = 'block' }
        condition = [ordered]@{ requestDomains = @($chunk); resourceTypes = $types }
    }
}

$utf8 = New-Object System.Text.UTF8Encoding $false
New-Item -ItemType Directory -Force -Path $Output | Out-Null
[System.IO.File]::WriteAllText((Join-Path $Output 'blocklist.json'), (ConvertTo-Json @($rules) -Depth 5), $utf8)
$info = [ordered]@{
    source  = $SourceName
    built   = (Get-Date).ToString('yyyy-MM-dd')
    domains = $sorted.Count
    note    = 'Includes the test entry blocktest.kshatriya.invalid.'
}
[System.IO.File]::WriteAllText((Join-Path $Output 'blocklist-info.json'), (ConvertTo-Json $info), $utf8)
Write-Host "Wrote $($sorted.Count) domains in $(@($rules).Count) rules to $Output ($rejected lines skipped). Reload the extension to use them."
