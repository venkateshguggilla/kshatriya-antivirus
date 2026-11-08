# Sentinel

> **Status: Milestone 2, a read-only prototype.** Sentinel is an early-stage, defensive Windows security project. It is **not** a replacement for Microsoft Defender or any commercial antivirus product, and makes no claim of equivalent protection. Keep Microsoft Defender enabled.

"Sentinel" is a working name and will change before any release.

## What works today (M1–M2)

- `sentinel scan <path>...` — on-demand, **read-only** scan of files and folders
  - **Hash engine:** SHA-256 signatures (built-in EICAR test signature, plus your own databases via `--signatures`)
  - **YARA engine:** YARA-X rules (one built-in test rule, plus your own via `--rules`; `include` is disabled)
  - **PE heuristics:** static indicators such as packer section names, high-entropy code, writable+executable sections, odd entry points and injection API sets. Results are only ever **suspicious**, never "malware", and validly signed files are not scored
  - **Authenticode trust:** embedded and catalog signatures are verified offline (no revocation or network lookups) and shown per executable
  - **Archives:** ZIP-based files (`.zip`, `.docx`, `.jar`, …) are expanded in memory up to 3 levels deep, with limits on entries, sizes and compression ratio; findings show the path inside the archive
  - Never follows symbolic links, junctions or other reparse points inside a tree (they are reported as skipped)
  - Never reads cloud placeholders (OneDrive "online-only" files) so it cannot trigger downloads
  - Supports paths longer than 260 characters
  - Per-file size limit and time limit; locked, denied, oversized or timed-out files are reported as **not scanned**, never silently ignored
  - Text output for people, versioned JSON output for tools ([schema v2](docs/schemas/scan-report.v2.schema.json); [v1](docs/schemas/scan-report.v1.schema.json) is kept for reference)
- `sentinel scan --stdin` — scan piped data (useful for the EICAR test string without writing it to disk)

Sentinel **never modifies, moves or deletes files**. Quarantine arrives in a later milestone.

## Build and test

Requirements: Windows 10 22H2 or Windows 11 (x64), .NET SDK 10.0.100 or later (pinned in [global.json](global.json)).

```powershell
./scripts/Get-YaraX.ps1          # once: downloads the hash-pinned YARA-X library into native/ (not committed)
dotnet build Sentinel.slnx
dotnet test Sentinel.slnx
dotnet run --project src/Sentinel.Cli -- scan C:\path\to\folder
```

### CLI

```text
sentinel scan <path>... [--json] [--output <file>] [--include-clean] [--signatures <file>]... [--rules <file>]...
                        [--no-heuristics] [--archive-depth <n>] [--max-file-size <MiB>] [--timeout <seconds>]
                        [--parallelism <n>] [--quiet]
sentinel scan --stdin [--name <label>] [options]
sentinel version | help
```

| Exit code | Meaning |
|---|---|
| 0 | Everything in scope was scanned; nothing detected |
| 1 | At least one confirmed detection (takes precedence over 5 and 2) |
| 5 | No confirmed detections, but at least one **suspicious** (heuristic) finding (takes precedence over 2) |
| 2 | Nothing found, but some items could not be scanned or were only partially scanned, or the scan was cancelled |
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

### YARA rule metadata

Sentinel reads these optional `meta:` fields: `name` (detection name), `category` (`malware`, `pua`, `suspicious`, `test`; default `suspicious`), `confidence` (`low`, `medium`, `high`; default `medium`) and `description`. A rule without a category is treated as suspicious, never as confirmed malware. Third-party rule sets must pass the licence review in [ADR 0003](docs/adr/0003-dependency-licensing.md) before being bundled.

### Testing with EICAR

Microsoft Defender will (correctly) quarantine an EICAR file written to disk, and this project never adds Defender exclusions. Tests therefore assemble the EICAR string in memory, and file-based tests use a harmless custom signature (the hash of generated random bytes). To try the CLI by hand, pipe the string into `sentinel scan --stdin`.

## Performance baseline (M1)

Measured 2026-11-08 with `scripts/New-PerfTree.ps1` (50,000 files, 512 B–16 KiB, 404 MiB total), Release build, Intel Core i9-9980HK (16 logical CPUs), default settings:

| Run | Time | Throughput |
|---|---|---|
| M1, hash engine only, warm cache (3 runs) | 1.00–1.06 s | ≈ 47,000–50,000 files/s |
| M2, hash + YARA + PE heuristics + trust, warm cache (2 runs) | 1.33–1.34 s | ≈ 37,000 files/s |

The tree had just been written, so these are **warm-cache** numbers; cold-cache throughput will be lower and has not been measured yet. M1 acceptance threshold: ≥ 200 files/s.

## False-positive and robustness checks (M2)

Measured 2026-11-08 on the development machine (Release build, default limits, `--archive-depth 1`) over `C:\Windows\System32` and `C:\Program Files`:

| Measure | Result |
|---|---|
| Files scanned | 117,541 (28.3 GB); 285 not scanned (271 access denied, 11 archive entry limit in large `.jar` files, 3 over the size limit) |
| Executables with a trust check | 23,505: 22,084 validly signed (15,002 embedded, 7,082 catalog), 1,420 unsigned, 1 invalid (Windows' own `Get-AuthenticodeSignature` also reports a hash mismatch for that file) |
| Suspicious with default settings | **0** (0.000%) |
| Suspicious when signed files are also scored (`--heuristics-include-signed`) | **1 of 23,505 executables (0.004%)**: a signed, genuinely UPX-packed tool, which the heuristics correctly describe as packed |
| Time | 208 s cold cache, 80 s warm |

Limits of this evidence: one machine's files, mostly signed vendor software, and only 1,420 unsigned executables. A broader benign corpus and a labelled malware set are needed before heuristic quality can be claimed.

Mutation fuzzing (`tools/Sentinel.Fuzz`, unguided, seed 20261108): **1,000,000 iterations each** for the PE parser and heuristics (103 s), ZIP expansion (23 s) and the hash-database parser (4 s), with **0 failures**. CI runs 100,000 iterations per parser.

## Repository layout

| Path | Purpose |
|---|---|
| `src/Sentinel.Core` | Scan result model (items, detections, reports, limits) |
| `src/Sentinel.Engines.Abstractions` | `IDetectionEngine` extension point |
| `src/Sentinel.Engines.Hash` | SHA-256 signature engine and database parser |
| `src/Sentinel.Engines.Yara` | YARA-X engine (P/Invoke), built-in rules |
| `src/Sentinel.Engines.Pe` | Bounds-checked PE parser and static heuristics |
| `src/Sentinel.Scanning` | Safe enumerator, read-only opener, Authenticode trust, ZIP expansion, scan pipeline |
| `src/Sentinel.Cli` | `sentinel` command-line tool |
| `tests/` | xUnit tests (shared helpers in `tests/Shared`) |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [ADRs](docs/adr), [schemas](docs/schemas) |
| `tools/Sentinel.Fuzz` | Mutation fuzz harness for the parsers |
| `scripts/` | Developer scripts (YARA-X fetch with hash pinning, performance tree generator) |

## Roadmap

See [docs/architecture.md](docs/architecture.md#roadmap). Next: M3 adds the Windows service, sandboxed scan workers and authenticated IPC.

## Security

See [SECURITY.md](SECURITY.md). Do not commit live malware to this repository.
