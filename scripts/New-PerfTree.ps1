<#
.SYNOPSIS
  Creates a synthetic tree of small benign files for scanner performance baselines.
.EXAMPLE
  ./scripts/New-PerfTree.ps1 -Path $env:TEMP\kshatriya-perf -Files 50000
  dotnet run -c Release --project src/Kshatriya.Cli -- scan $env:TEMP\kshatriya-perf --quiet
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Path,
    [int] $Files = 50000,
    [int] $FilesPerDirectory = 250,
    [int] $MinBytes = 512,
    [int] $MaxBytes = 16384
)

$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Path) { throw "Refusing to write into existing path '$Path'." }
New-Item -ItemType Directory -Path $Path | Out-Null

$rng = [System.Random]::new(20261108)
for ($i = 0; $i -lt $Files; $i++) {
    $dir = Join-Path $Path ('d{0:D4}' -f [int][math]::Floor($i / $FilesPerDirectory))
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $bytes = [byte[]]::new($rng.Next($MinBytes, $MaxBytes))
    $rng.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes((Join-Path $dir ('f{0:D6}.bin' -f $i)), $bytes)
}
Write-Host "Created $Files files under $Path"
