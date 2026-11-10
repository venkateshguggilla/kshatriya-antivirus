#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a browser blocklist from domain lists: the extension's built-in ruleset, or a .webblock file for
    a signed content package (ADR 0019).

.DESCRIPTION
    Reads one or more local text files with one entry per line: a domain ("bad.example"), a hosts-file
    line ("0.0.0.0 bad.example") or a URL ("http://bad.example/x"). Comments (#) and blank lines are
    ignored. Domains are lower-cased, validated, de-duplicated and capped at -MaxDomains, then written as
    declarativeNetRequest blocking rules of up to 1,000 domains each. The test domain
    blocktest.kshatriya.invalid is always kept so the block page can be checked.

    With -Format webblock the domains are written as a web blocklist ("# kshatriya-webblock v1", one domain
    per line, no test domain) to the file -Output names. Sign it into a package with
    "kshatriya-content pack ... phishing.webblock" and import that package into the service; the extension
    then fetches it through the native host, with no extension update needed.

    Use only lists you are licensed to redistribute with this Apache-2.0 project (ADR 0018). The script
    never downloads anything; fetch the list yourself under its terms.

.PARAMETER Source
    One or more list files.

.PARAMETER SourceName
    Name of the list shown in the extension popup, for example "URLhaus (abuse.ch)".

.PARAMETER Format
    "ruleset" (default) writes extension/rules; "webblock" writes one .webblock file.

.PARAMETER MaxDomains
    Most domains to keep. Ruleset: at most 30,000 (default). Webblock: up to 500,000 (default 100,000);
    the extension fetches the list in pages (ADR 0019).

.EXAMPLE
    ./scripts/Build-BrowserBlocklist.ps1 -Source C:\lists\hostfile.txt -SourceName 'My list'

.EXAMPLE
    ./scripts/Build-BrowserBlocklist.ps1 -Source C:\lists\phish.txt -SourceName 'My list' -Format webblock -Output C:\build\phishing.webblock
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Source,
    [Parameter(Mandatory)] [string] $SourceName,
    [ValidateSet('ruleset', 'webblock')] [string] $Format = 'ruleset',
    [ValidateRange(1, 500000)] [int] $MaxDomains = 0,
    [string] $Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'extension/rules')
)

$ErrorActionPreference = 'Stop'
$maxDomains = if ($MaxDomains -gt 0) { $MaxDomains } elseif ($Format -eq 'webblock') { 100000 } else { 30000 }
if ($Format -eq 'ruleset' -and $maxDomains -gt 30000) { throw 'The built-in ruleset holds at most 30,000 domains.' }
$perRule = 1000
$testDomain = 'blocktest.kshatriya.invalid'
$domainPattern = '^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$'
$never = @('localhost', 'localhost.localdomain', 'local', 'broadcasthost', '0.0.0.0')

# Shared platforms and public suffixes that must never be listed, nor any parent of them (listing a domain
# blocks its subdomains). The service refuses signed lists that contain one; here they are dropped.
$protectedFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Kshatriya.Updates/protected-domains.txt'
$protected = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($line in [System.IO.File]::ReadLines($protectedFile)) {
    $p = $line.Trim()
    if (-not $p -or $p.StartsWith('#')) { continue }
    $labels = $p.Split('.')
    for ($i = 0; $i -lt $labels.Count; $i++) { [void] $protected.Add(($labels[$i..($labels.Count - 1)] -join '.')) }
}

$domains = New-Object 'System.Collections.Generic.HashSet[string]'
$rejected = 0
$protectedDropped = New-Object 'System.Collections.Generic.List[string]'
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
        if ($protected.Contains($candidate)) { $protectedDropped.Add($candidate); continue }
        [void] $domains.Add($candidate)
    }
}

if ($protectedDropped.Count -gt 0) {
    Write-Warning "Dropped $($protectedDropped.Count) protected shared-platform domain(s): $(($protectedDropped | Select-Object -Unique) -join ', ')"
}

# Over the limit: keep a sample ordered by SHA-256 of each domain. Unlike the first N lines, this is not
# biased by how the source is sorted, and it stays mostly the same when the source changes.
# Signed lists are also limited to 16 Mi characters in total (Kshatriya.Updates.WebBlockList).
$room = if ($Format -eq 'ruleset') { $maxDomains - 1 } else { $maxDomains }
$maxChars = 16 * 1024 * 1024
$selected = @($domains)
$chars = ($selected | Measure-Object -Property Length -Sum).Sum
if ($selected.Count -gt $room -or $chars -gt $maxChars) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $ordered = $selected | Sort-Object { [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($_))) }
    $selected = New-Object 'System.Collections.Generic.List[string]'
    $chars = 0
    foreach ($domain in $ordered) {
        if ($selected.Count -ge $room -or $chars + $domain.Length -gt $maxChars) { break }
        $selected.Add($domain)
        $chars += $domain.Length
    }
    $selected = @($selected)
    Write-Warning "The sources hold $($domains.Count) domains; kept a sample of $($selected.Count) (limits: $room domains, $maxChars characters)."
}
if ($Format -eq 'ruleset') { $selected += $testDomain }

$sorted = @($selected | Sort-Object)
$utf8 = New-Object System.Text.UTF8Encoding $false
if ($Format -eq 'webblock') {
    if ([System.IO.Path]::GetExtension($Output) -ne '.webblock') { throw "-Output must name a .webblock file when -Format is webblock." }
    $lines = @('# kshatriya-webblock v1', "# source: $SourceName, built $((Get-Date).ToString('yyyy-MM-dd'))") + $sorted
    [System.IO.File]::WriteAllText($Output, (($lines -join "`n") + "`n"), $utf8)
    Write-Host "Wrote $($sorted.Count) domains to $Output ($rejected lines skipped). Sign it with kshatriya-content pack."
    return
}

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
