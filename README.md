# Sentinel

> **Status: Milestone 3, a read-only prototype.** Sentinel is an early-stage, defensive Windows security project. It is **not** a replacement for Microsoft Defender or any commercial antivirus product, and makes no claim of equivalent protection. Keep Microsoft Defender enabled.

"Sentinel" is a working name and will change before any release.

## What works today (M1–M3)

- `sentinel scan <path>...`: on-demand, **read-only** scan of files and folders
  - **Sandboxed parsing (M3):** file contents are analysed in separate worker processes. Each worker runs on a restricted token with the account SID deny-only and low integrity, inside a Job Object (one process, memory cap, killed with its parent) with process mitigations. Workers cannot write your files, start programs or read files private to your account. A crashed or hung worker is replaced and the item is reported as not scanned. `--no-sandbox` turns this off for development only.
  - **Hash engine:** SHA-256 signatures (built-in EICAR test signature, plus your own databases via `--signatures`)
  - **YARA engine:** YARA-X rules (one built-in test rule, plus your own via `--rules`; `include` is disabled)
  - **PE heuristics:** static indicators such as packer section names, high-entropy code, writable+executable sections, odd entry points and injection API sets. Results are only ever **suspicious**, never "malware", and validly signed files are not scored
  - **Authenticode trust:** embedded and catalog signatures are verified offline (no revocation or network lookups) and shown per executable
  - **Archives:** ZIP-based files (`.zip`, `.docx`, `.jar`, …) are expanded in memory up to 3 levels deep, with limits on entries, sizes and compression ratio; findings show the path inside the archive
  - Never follows symbolic links, junctions or other reparse points inside a tree (they are reported as skipped)
  - Never reads cloud placeholders (OneDrive "online-only" files), so it cannot trigger downloads
  - Supports paths longer than 260 characters
  - Per-file size limit and time limit; locked, denied, oversized or timed-out files are reported as **not scanned**, never silently ignored
  - Text output for people, versioned JSON output for tools ([schema v2](docs/schemas/scan-report.v2.schema.json))
- `sentinel scan --stdin`: scans piped data (useful for the EICAR test string without writing it to disk)
- **Windows service (M3):** `Sentinel.Service` runs as LocalSystem with a shared worker pool, a verdict cache for unchanged clean files and scheduled scans
  - `sentinel scan --service <path>` asks the service to scan. The service scans **with your own access rights** (pipe impersonation), so it can't be used to read files you can't read.
  - `sentinel status` shows the engines, workers, cache, schedules and active scans.
  - The client verifies that the pipe really belongs to the installed service before sending anything.

Sentinel **never modifies, moves or deletes files**. Quarantine arrives in a later milestone.

## Build and test

Requirements: Windows 10 22H2 or Windows 11 (x64), .NET SDK 10.0.100 or later (pinned in [global.json](global.json)).

```powershell
./scripts/Get-YaraX.ps1          # once: downloads the hash-pinned YARA-X library into native/ (not committed)
dotnet build Sentinel.slnx
dotnet test Sentinel.slnx
dotnet run --project src/Sentinel.Cli -- scan C:\path\to\folder
```

### Trying the service without installing it

```powershell
dotnet run --project src/Sentinel.Service -- --dev     # runs as you, on a per-user pipe; data in %LOCALAPPDATA%\Sentinel\dev
dotnet run --project src/Sentinel.Cli -- status --dev
dotnet run --project src/Sentinel.Cli -- scan --service --dev C:\Users\me\Downloads
```

`scripts/Install-SentinelService.ps1` (administrator) publishes to `%ProgramFiles%\Sentinel` and registers `SentinelService` as LocalSystem; `scripts/Uninstall-SentinelService.ps1` removes it. Neither script touches Defender or any security setting. Neither has been run on the development machine yet, and the installed (LocalSystem) configuration has not been tested end to end.

### Service configuration

Optional `%ProgramData%\Sentinel\config\service.json` (development: `%LOCALAPPDATA%\Sentinel\dev\config\service.json`). Unknown fields or invalid values reject the whole file, and the service refuses the file, and any signature or rule file it names, unless only SYSTEM/Administrators can change it.

```json
{
  "schemaVersion": 1,
  "workers": 4,
  "signatureFiles": ["C:\\ProgramData\\Sentinel\\signatures\\extra.hashdb"],
  "ruleFiles": [],
  "maxFileSizeMiB": 256,
  "maxConcurrentScans": 2,
  "reportRetention": 30,
  "scheduledScans": [
    { "name": "weekly-users", "days": ["sunday"], "time": "03:00", "paths": ["C:\\Users"] }
  ]
}
```

Scheduled scans run in local time and skip the verdict cache. Their reports (schema v2) are written to `reports\`. A run missed while the machine was off happens once the service is running again; a new schedule waits for its first occurrence.

### CLI

```text
sentinel scan <path>... [--json] [--output <file>] [--include-clean] [--signatures <file>]... [--rules <file>]...
                        [--no-heuristics] [--archive-depth <n>] [--max-file-size <MiB>] [--timeout <seconds>]
                        [--parallelism <n>] [--no-sandbox] [--quiet]
sentinel scan --stdin [--name <label>] [options]
sentinel scan --service [--dev] <path>... [--json] [--output <file>] [--include-clean] [--quiet]
sentinel status [--dev]
sentinel version | help
```

| Exit code | Meaning |
|---|---|
| 0 | Everything in scope was scanned; nothing detected |
| 1 | At least one confirmed detection (takes precedence over 5 and 2) |
| 5 | No confirmed detections, but at least one **suspicious** (heuristic) finding (takes precedence over 2) |
| 2 | Nothing found, but some items could not be scanned or were only partially scanned, or the scan was cancelled |
| 3 | Invalid command line |
| 4 | Fatal error (for example an invalid signature database, workers that cannot be started, or an unreachable service) |

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

## Performance

Measured 2026-11-08 with `scripts/New-PerfTree.ps1` (50,000 files, 512 B–16 KiB, 404 MiB total), Release build, Intel Core i9-9980HK (16 logical CPUs), default settings, warm file cache:

| Run | Time | Throughput |
|---|---|---|
| M1, hash engine only (3 runs) | 1.00–1.06 s | ≈ 47,000–50,000 files/s |
| M2/M3, all engines in-process (`--no-sandbox`, 4 runs) | 1.33–1.42 s | ≈ 35,000–37,000 files/s |
| M3, all engines in sandboxed workers (default, 3 runs) | 3.22–3.80 s | ≈ 13,000–15,500 files/s |

Isolation costs about 2.3× on many tiny files: each item crosses a pipe to a worker. An early version starved the thread pool because .NET anonymous pipes do synchronous I/O (about 10,500 files/s); switching the broker side to overlapped named pipes fixed it. On large real-world files the cost disappears: the false-positive corpus below took 71 s sandboxed versus 80 s in-process (both warm). These are warm-cache numbers; M1's acceptance threshold was ≥ 200 files/s.

Verdict cache (service, `--dev`, `C:\Windows\System32\drivers`, 684 files, 116 MiB): first scan 1.76 s, repeat scan 0.01 s (684 cache hits). Files changed in the last 2 seconds are never cached.

## False-positive and robustness checks

Measured on the development machine (Release build, default limits, `--archive-depth 1`) over `C:\Windows\System32` and `C:\Program Files`:

| Measure | M2 (in-process) | M3 (sandboxed workers) |
|---|---|---|
| Files scanned | 117,541 (28.3 GB) | 117,541 (28.3 GB) |
| Not scanned | 285 (271 access denied, 11 archive entry limit in large `.jar` files, 3 over the size limit) | the same 285 |
| Suspicious with default settings | **0** | **0** |
| Worker crashes or engine errors | n/a | **0** |
| Time | 208 s cold, 80 s warm | 71 s warm |

M2 trust results (unchanged): 23,505 executables; 22,084 validly signed (15,002 embedded, 7,082 catalog), 1,420 unsigned, 1 invalid (Windows' own `Get-AuthenticodeSignature` also reports a hash mismatch for it). With signed files also scored (`--heuristics-include-signed`), 1 of 23,505 executables (0.004%) was flagged: a signed, genuinely UPX-packed tool.

Limits of this evidence: one machine's files, mostly signed vendor software, and only 1,420 unsigned executables. A broader benign corpus and a labelled malware set are needed before heuristic quality can be claimed.

Mutation fuzzing (`tools/Sentinel.Fuzz`, unguided, seed 20261108), **1,000,000 iterations each, 0 failures**:

| Target | Time |
|---|---|
| PE parser and heuristics | 103 s |
| ZIP expansion | 23 s |
| Hash-database parser | 4 s |
| IPC frames and DTOs (M3) | 9.5 s |
| JSON report reader (M3) | 14.6 s |

CI runs 100,000 iterations per target.

Sandbox properties verified by tests with real worker processes: low integrity; writes to the user's files denied; child processes blocked; files private to the account unreadable; memory cap enforced; a crash or hang mid-item recovered; diagnostics refused without test hooks. One residual is also stated as a test: world-readable files remain readable from inside the sandbox ([threat model](docs/threat-model.md#residual-risks-m3)).

## Repository layout

| Path | Purpose |
|---|---|
| `src/Sentinel.Core` | Scan result model, wire names, JSON report reader/writer |
| `src/Sentinel.Engines.Abstractions` | `IDetectionEngine` extension point |
| `src/Sentinel.Engines.Hash` | SHA-256 signature engine and database parser |
| `src/Sentinel.Engines.Yara` | YARA-X engine (P/Invoke), built-in rules |
| `src/Sentinel.Engines.Pe` | Bounds-checked PE parser and static heuristics |
| `src/Sentinel.Scanning` | Safe enumerator, read-only opener, Authenticode trust, ZIP expansion, analyzers, verdict cache, scan pipeline |
| `src/Sentinel.Protocol` | Framing and strict DTOs for the worker and service pipes |
| `src/Sentinel.Runtime` | Sandbox launcher, worker pool, engine setup, authenticated service client |
| `src/Sentinel.Worker` | Sandboxed scan worker process |
| `src/Sentinel.Service` | Windows service: pipe server, scan coordinator, scheduler |
| `src/Sentinel.Cli` | `sentinel` command-line tool |
| `tests/` | xUnit tests (shared helpers in `tests/Shared`) |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [ADRs](docs/adr), [schemas](docs/schemas) |
| `tools/Sentinel.Fuzz` | Mutation fuzz harness for the parsers |
| `scripts/` | YARA-X fetch (hash-pinned), performance tree generator, service install/uninstall |

## Roadmap

See [docs/architecture.md](docs/architecture.md#roadmap). Next: M4 adds the encrypted quarantine, handle-based removal and restore, exclusions and an audit log.

## Security

See [SECURITY.md](SECURITY.md). Do not commit live malware to this repository.
