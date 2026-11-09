#Requires -Version 5.1
<#
.SYNOPSIS
    Release gates: a scanning performance budget and a false-positive check on benign Windows files.

.DESCRIPTION
    1. Performance: scans a generated tree of small benign files with the default sandboxed workers and
       fails if throughput is below -MinFilesPerSecond or if anything is not scanned or flagged.
    2. False positives: scans -BenignPaths (default: %SystemRoot%\System32) and fails on any detected or
       suspicious item. Items not scanned for policy or access reasons are reported, not failed.
    Writes a summary to -SummaryPath. Budgets are deliberately conservative so they hold on CI runners;
    they are regression tripwires, not performance claims.

.EXAMPLE
    dotnet build src/Kshatriya.Cli -c Release
    ./scripts/Test-ReleaseGates.ps1
#>
[CmdletBinding()]
param(
    [string] $Kshatriya = (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Kshatriya.Cli/bin/Release/net10.0-windows/kshatriya.exe'),
    [int] $Files = 5000,
    [double] $MinFilesPerSecond = 500,
    [string[]] $BenignPaths = @((Join-Path $env:SystemRoot 'System32')),
    [string] $SummaryPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/release-gates.json')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Kshatriya)) { throw "kshatriya.exe not found at $Kshatriya (build src/Kshatriya.Cli in Release first)." }
$failures = New-Object System.Collections.Generic.List[string]

function Invoke-Scan([string[]] $arguments) {
    $output = & $Kshatriya @arguments
    $code = $LASTEXITCODE
    if ($code -in 3, 4) { throw "kshatriya failed (exit $code) for: $($arguments -join ' ')" }
    return ($output -join "`n" | ConvertFrom-Json)
}

# 1. Performance budget
$tree = Join-Path ([System.IO.Path]::GetTempPath()) "kshatriya-gate-$([guid]::NewGuid().ToString('N'))"
& (Join-Path $PSScriptRoot 'New-PerfTree.ps1') -Path $tree -Files $Files | Out-Null
try {
    $null = Invoke-Scan @('scan', $tree, '--json', '--quiet') # warm-up (workers, file cache)
    $perf = Invoke-Scan @('scan', $tree, '--json')
}
finally {
    Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue
}

$seconds = [math]::Max($perf.durationMs / 1000.0, 0.001)
$rate = [math]::Round($perf.summary.filesScanned / $seconds)
if ($perf.summary.filesScanned -ne $Files) { $failures.Add("performance: scanned $($perf.summary.filesScanned) of $Files files") }
if ($perf.summary.detected + $perf.summary.suspicious + $perf.summary.notScanned -gt 0) { $failures.Add('performance: generated benign files were flagged or not scanned') }
if ($rate -lt $MinFilesPerSecond) { $failures.Add("performance: $rate files/s is below the budget of $MinFilesPerSecond files/s") }
Write-Host "Performance: $($perf.summary.filesScanned) files in $([math]::Round($seconds, 2)) s = $rate files/s (budget >= $MinFilesPerSecond)"

# 2. False positives on benign system files
$fp = Invoke-Scan (@('scan') + $BenignPaths + @('--json', '--archive-depth', '1'))
$flagged = @($fp.items | Where-Object { $_.status -in 'detected', 'suspicious' })
$notScanned = @($fp.items | Where-Object { $_.status -eq 'notScanned' } | Group-Object reason | ForEach-Object { "$($_.Name)=$($_.Count)" })
foreach ($item in $flagged) {
    $failures.Add("false positive: $($item.status) $($item.path) [$(($item.detections | ForEach-Object { $_.name }) -join ', ')]")
}
Write-Host "False positives: $($fp.summary.filesScanned) benign files scanned, $($flagged.Count) flagged; not scanned: $(if ($notScanned) { $notScanned -join ', ' } else { 'none' })"

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $SummaryPath) | Out-Null
[ordered]@{
    timeUtc           = [DateTime]::UtcNow.ToString('o')
    performance       = [ordered]@{ files = $perf.summary.filesScanned; seconds = $seconds; filesPerSecond = $rate; budget = $MinFilesPerSecond }
    falsePositives    = [ordered]@{ paths = $BenignPaths; filesScanned = $fp.summary.filesScanned; flagged = $flagged.Count; notScanned = $notScanned }
    failures          = $failures
} | ConvertTo-Json -Depth 4 | Set-Content $SummaryPath -Encoding utf8

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "GATE FAILED: $_" }
    exit 1
}

Write-Host 'All release gates passed.'
exit 0
