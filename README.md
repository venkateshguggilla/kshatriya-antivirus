# Sentinel

> **Status: Milestone 1, a read-only prototype.** Sentinel is an early-stage, defensive Windows security project. It is **not** a replacement for Microsoft Defender or any commercial antivirus product, and makes no claim of equivalent protection. Keep Microsoft Defender enabled.

"Sentinel" is a working name and will change before any release.

## What works today (M1)

- `sentinel scan <path>...` — on-demand, **read-only** scan of files and folders
  - SHA-256 hash signatures (built-in EICAR test signature, plus your own databases via `--signatures`)
  - Never follows symbolic links, junctions or other reparse points inside a tree (they are reported as skipped)
  - Never reads cloud placeholders (OneDrive "online-only" files) so it cannot trigger downloads
  - Supports paths longer than 260 characters
  - Per-file size limit and time limit; locked, denied, oversized or timed-out files are reported as **not scanned**, never silently ignored
  - Text output for people, versioned JSON output for tools ([schema](docs/schemas/scan-report.v1.schema.json))
- `sentinel scan --stdin` — scan piped data (useful for the EICAR test string without writing it to disk)

Sentinel M1 **never modifies, moves or deletes files**. Quarantine arrives in a later milestone.

## Build and test

Requirements: Windows 10 22H2 or Windows 11, .NET SDK 10.0.100 or later (pinned in [global.json](global.json)).

```powershell
dotnet build Sentinel.slnx
dotnet test Sentinel.slnx
dotnet run --project src/Sentinel.Cli -- scan C:\path\to\folder
```

### CLI

```text
sentinel scan <path>... [--json] [--output <file>] [--include-clean] [--signatures <file>]...
                        [--max-file-size <MiB>] [--timeout <seconds>] [--parallelism <n>] [--quiet]
sentinel scan --stdin [--name <label>] [options]
sentinel version | help
```

| Exit code | Meaning |
|---|---|
| 0 | Everything in scope was scanned; nothing detected |
| 1 | At least one detection (takes precedence over 2) |
| 2 | Nothing detected, but some items could not be scanned, or the scan was cancelled |
| 3 | Invalid command line |
| 4 | Fatal error (for example an invalid signature database) |

Items skipped **by policy** (links, cloud placeholders) are listed but do not make a scan incomplete.

### Hash database format (v1)

UTF-8 text. The header line is required; any malformed line rejects the whole file (fail closed).

```text
# sentinel-hashdb v1
# comments start with '#'
sha256:<64 hex characters> <Name> [malware|pua|suspicious|test]
```

Databases are not yet cryptographically signed; signed content updates are planned for milestone 6.

### Testing with EICAR

Microsoft Defender will (correctly) quarantine an EICAR file written to disk, and this project never adds Defender exclusions. Tests therefore assemble the EICAR string in memory, and file-based tests use a harmless custom signature (the hash of generated random bytes). To try the CLI by hand, pipe the string into `sentinel scan --stdin`.

## Performance baseline (M1)

Measured 2026-11-08 with `scripts/New-PerfTree.ps1` (50,000 files, 512 B–16 KiB, 404 MiB total), Release build, Intel Core i9-9980HK (16 logical CPUs), default settings:

| Run | Time | Throughput |
|---|---|---|
| Warm file cache (3 runs) | 1.00–1.06 s | ≈ 47,000–50,000 files/s |

The tree had just been written, so these are **warm-cache** numbers; cold-cache throughput will be lower and has not been measured yet. M1 acceptance threshold: ≥ 200 files/s.

## Repository layout

| Path | Purpose |
|---|---|
| `src/Sentinel.Core` | Scan result model (items, detections, reports, limits) |
| `src/Sentinel.Engines.Abstractions` | `IDetectionEngine` extension point |
| `src/Sentinel.Engines.Hash` | SHA-256 signature engine and database parser |
| `src/Sentinel.Scanning` | Safe enumerator, read-only opener, scan pipeline |
| `src/Sentinel.Cli` | `sentinel` command-line tool |
| `tests/` | xUnit tests (shared helpers in `tests/Shared`) |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [ADRs](docs/adr), [schemas](docs/schemas) |
| `scripts/` | Developer scripts (performance tree generator) |

## Roadmap

See [docs/architecture.md](docs/architecture.md#roadmap). Next: M2 adds YARA-X rules, PE heuristics, Authenticode checks and archive scanning.

## Security

See [SECURITY.md](SECURITY.md). Do not commit live malware to this repository.
