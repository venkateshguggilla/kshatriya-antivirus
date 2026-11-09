# Sentinel

> **Status: Milestone 12 prototype (roadmap M1–M12 complete as prototypes).** Sentinel is an early-stage, defensive Windows security project. It is **not** a replacement for Microsoft Defender or any commercial antivirus product, and makes no claim of equivalent protection. Keep Microsoft Defender enabled.

"Sentinel" is a working name and will change before any release.

## What works today (M1–M12)

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
  - Text output for people, versioned JSON output for tools ([schema v4](docs/schemas/scan-report.v4.schema.json))
- `sentinel scan --stdin`: scans piped data (useful for the EICAR test string without writing it to disk)
- **Windows service (M3):** `Sentinel.Service` runs as LocalSystem with a shared worker pool, a verdict cache for unchanged clean files and scheduled scans
  - `sentinel scan --service <path>` asks the service to scan. The service scans **with your own access rights** (pipe impersonation), so it can't be used to read files you can't read.
  - `sentinel status` shows the engines, workers, cache, schedules and active scans.
  - The client verifies that the pipe really belongs to the installed service before sending anything.

- **Quarantine (M4), opt-in:** `scan --quarantine` moves confirmed, high-confidence detections (category malware or test, confidence high) into an encrypted vault. Suspicious (heuristic) and PUA findings are only reported. `sentinel quarantine add <file>` quarantines a file by hand.
  - The file is removed only through the same handle that was verified: opened without following links and shared for reading only, checked (regular file, one hard link, ≤ 1 GiB), re-hashed while it is encrypted into the vault, and deleted only after the vault copy is on disk. If anything fails (the file changed, is locked, is a running program, …) the file is left where it was and the report says why.
  - The vault uses AES-256-GCM with a DPAPI-protected key; the service's vault is readable only by SYSTEM and Administrators.
  - `sentinel quarantine restore <id> [--to <path>]` never overwrites an existing file, verifies the content and marks the restored file as downloaded from the internet. `quarantine list` and `quarantine delete <id>` manage the vault.
  - Running programs are **not** stopped; quarantining one fails with `inUse`.
- **Exclusions (M4):** folders, files or SHA-256 values that Sentinel does not scan. Excluded items still appear in every report (`skipped`, reason `excluded`). Drive roots and the Windows directory cannot be excluded. Exclusions apply to Sentinel only and never to Microsoft Defender.
- **Audit log (M4):** every quarantine, restore, delete and exclusion change (including refused attempts) is recorded in a hash-chained log; `sentinel audit` shows it and checks the chain. This makes edits detectable but cannot stop an administrator from rewriting the whole file.
- With the **service**, quarantine and restore act with your own access rights (you can only quarantine files you could delete). Restoring files, managing exclusions and reading the audit log require an elevated administrator.

- **Desktop app (M5):** `Sentinel.App.exe` (WPF, Fluent theme, light/dark/high contrast) with Dashboard (service, engines, workers, schedules, quarantine count, audit status and the Windows antivirus state), Scan (folders, progress, results, opt-in quarantine), Quarantine (restore, restore to, delete), Exclusions, History (audit log with integrity check) and About. It talks only to the service (`Sentinel.App.exe --dev` for a development service) and offers "Restart as administrator" for admin-only actions. Keyboard and screen-reader friendly; no formal accessibility audit yet.

- **Signed content updates (M6):** `sentinel update import <package.sntu> --service` (administrator) installs signature and rule updates. Packages are signed with ECDSA P-256; the service checks the signature before reading the manifest, verifies every file hash, refuses older packages (anti-rollback) and expired ones, and only switches once a fresh sandboxed worker pool has loaded the new content. `status` and the app show the active update and warn when it has expired. `tools/Sentinel.ContentTool` (`sentinel-content keygen|pack|verify`) creates keys and packages. **No production signing key exists yet:** add your own public key to `contentKeys` in `service.json`.

- **Real-time monitoring (M7, opt-in, user mode):** with a `realTime` section in `service.json` the service watches folders for new and changed files, scans the image of every program that starts (WMI process-start events) and scans removable drives when they are attached. Findings appear in `sentinel detections --service`, the app's Detections page and the event log; with `"action": "quarantine"` high-confidence detections are quarantined. **It scans shortly after the fact and cannot block a file or program before it runs**, and it never terminates processes.

- **Ransomware behaviour detection (M8, alert only):** with real-time monitoring on, Sentinel raises *suspicious* alerts when many existing files are rewritten or renamed in a short time and the results look encrypted, when ransom-note-like files appear, when a program runs a command that deletes shadow copies or disables recovery, and (opt-in) when a hidden decoy file in a chosen folder is touched. Alerts name recently started programs from user-writable folders as possible sources. **Nothing is stopped or quarantined automatically.** The app shows whether Defender's Controlled folder access (which can block) is on, and recommends it; Sentinel never changes it.

- **Optional machine-learning scoring (M9, off by default):** an `ml` engine scores PE files with a JSON model (logistic regression or gradient-boosted trees over 296 EMBER-style features), evaluated in pure C# inside the sandboxed workers. Results are only ever *suspicious*. **No model is shipped**: use `scan --model <file.model.json>` to evaluate one locally, or deliver it in a signed content package and set `"machineLearning": true` in `service.json`. No detection-quality claim is made.

- **Network protection (M10, opt-in):** with `"networkProtection": true` the service turns IP blocklists from signed content packages (`*.netblock`) into Windows Filtering Platform filters that block outbound connections to those addresses. The filters live in a dynamic session, so they disappear if the service stops (it never strands the machine offline), and broad or local ranges are refused. **IP only** (no domain or URL filtering); no blocklist is published by this project.

- **Release packaging (M11):** `./scripts/Build-Release.ps1` builds a self-contained `Sentinel-<version>-win-x64.zip` (service, worker, CLI, app) with `SHA256SUMS.txt`, a dependency inventory and the licence files. Binaries are Authenticode-signed only when a certificate is supplied; otherwise the release is marked **UNSIGNED**. `Install-SentinelService.ps1 -FromRelease <folder> [-RequireSignature]` verifies every file before installing. The zip and install script are the chosen installer; there is deliberately no MSI/MSIX ([ADR 0013](docs/adr/0013-packaging-and-signing.md)). Automatic product updates are not built yet (they need certificate and hosting decisions).

- **Release hardening (M12):** every push runs a dependency vulnerability audit and release gates (a performance budget through the sandboxed workers, and a false-positive check that fails on any finding in `C:\Windows\System32`); parsers are fuzzed nightly at 1,000,000 iterations each, and the PE, ZIP and content-package parsers also with coverage guidance. [SECURITY.md](SECURITY.md) describes private reporting and response targets. The [release checklist](docs/release-checklist.md) lists what is still missing before a beta label, and records a first real-time cost measurement on one machine (watching `C:\Users`: about 0.1% CPU idle, under 1% during heavy file churn, about 300 MB for the service and workers). That's one machine, not a budget.

Scans without `--quarantine` (and the service without quarantine requests or schedules) **never modify, move or delete files**.

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
    { "name": "weekly-users", "days": ["sunday"], "time": "03:00", "paths": ["C:\\Users"], "action": "report" }
  ],
  "realTime": {
    "paths": ["C:\\Users"], "action": "report", "processes": true, "removableMedia": true, "debounceSeconds": 2,
    "ransomware": { "threshold": 40, "windowSeconds": 30, "canaryFolders": ["C:\\Users\\me\\Documents"] }
  },
  "contentKeys": ["<base64 public key from sentinel-content keygen>"]
}
```

Scheduled scans run in local time and skip the verdict cache. Add `"action": "quarantine"` to a schedule to quarantine high-confidence detections (default `"report"`). Reports (schema v4) are written to `reports\`. Persistent exclusions live in `config\exclusions.json` and are managed with `sentinel exclusions ... --service`; the quarantine vault is `quarantine\` and the audit log `audit\`. A run missed while the machine was off happens once the service is running again; a new schedule waits for its first occurrence.

### CLI

```text
sentinel scan <path>... [--quarantine] [--exclude <path>]... [--json] [--output <file>] [--include-clean]
                        [--signatures <file>]... [--rules <file>]... [--no-heuristics] [--archive-depth <n>]
                        [--max-file-size <MiB>] [--timeout <seconds>] [--parallelism <n>] [--no-sandbox] [--quiet]
sentinel scan --stdin [--name <label>] [options]
sentinel scan --service [--dev] <path>... [--quarantine] [--json] [--output <file>] [--include-clean] [--quiet]
sentinel status [--dev]
sentinel quarantine list | add <file> | restore <id> [--to <path>] | delete <id>   [--service [--dev]]
sentinel exclusions list | add <path|sha256:...> | remove <path|sha256:...>   --service [--dev]
sentinel audit [--last <n>] [--service [--dev]]
sentinel update import <package.sntu> --service [--dev]
sentinel detections [--last <n>] --service [--dev]
sentinel version | help
```

| Exit code | Meaning |
|---|---|
| 0 | Everything in scope was scanned; nothing detected |
| 1 | At least one confirmed detection, whether or not it was quarantined (takes precedence over 5 and 2) |
| 5 | No confirmed detections, but at least one **suspicious** (heuristic) finding (takes precedence over 2) |
| 2 | Nothing found, but some items could not be scanned or were only partially scanned, or the scan was cancelled |
| 3 | Invalid command line |
| 4 | Fatal error (for example an invalid signature database, workers that cannot be started, or an unreachable service), or a failed quarantine/restore/delete command or audit integrity check |

Items skipped **by policy** (links, cloud placeholders, exclusions) are listed but do not make a scan incomplete.

Files that Windows refuses to open because Microsoft Defender (or another security product) has detected them are reported as not scanned with the reason `blockedBySecurityProduct`. That is expected in companion mode: Defender acted first, and Sentinel never asks for a Defender exclusion.

Without `--service`, quarantine uses a per-user vault and audit log in `%LOCALAPPDATA%\Sentinel\local`.

### Hash database format (v1)

UTF-8 text. The header line is required; any malformed line rejects the whole file (fail closed).

```text
# sentinel-hashdb v1
# comments start with '#'
sha256:<64 hex characters> <Name> [malware|pua|suspicious|test]
```

Hash databases given directly with `--signatures` or in `service.json` are trusted by their file permissions; updates delivered as `.sntu` packages are signed (see above).

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
| JSON report reader (M3; v3 seed with actions in M4) | 15.6 s |
| Content packages (M6) | 113 s |
| ML model files (M9) | 14 s |

CI runs 100,000 iterations per target.

Coverage-guided fuzzing (`tools/Sentinel.CoverageFuzz`: SharpFuzz edge instrumentation, in-process AFL-style loop, seed 20261109), **5 minutes per target, 0 failures**:

| Target | Executions | Edges (seeds → end) | Corpus |
|---|---|---|---|
| PE parser, heuristics and ML features | 3.0 M (10,024/s) | 431 → 574 | 199 |
| ZIP expansion through the scan pipeline | 5.6 M (18,518/s) | 229 → 292 | 51 |
| Content-package container | 4.3 M (14,261/s) | 173 → 208 | 20 |

Coverage levels off within the first minute (the PE target reached 567 edges after 20 s), so longer runs mostly re-check the same paths. The content target almost never passes the signature check, so the signed manifest parser is covered by unit tests rather than by this fuzzer.

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
| `src/Sentinel.Response` | Quarantine manager, encrypted vault, hash-chained audit log, quarantine responder |
| `src/Sentinel.Updates` | Signed content package format, verification and creation |
| `src/Sentinel.Service` | Windows service: pipe server, scan coordinator, scheduler, exclusion store |
| `src/Sentinel.App` | WPF desktop app (client of the service) |
| `src/Sentinel.Cli` | `sentinel` command-line tool |
| `tests/` | xUnit tests (shared helpers in `tests/Shared`) |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [ADRs](docs/adr), [schemas](docs/schemas) |
| `tools/Sentinel.ContentTool` | `sentinel-content`: signing keys and content packages |
| `tools/Sentinel.Fuzz` | Mutation fuzz harness for the parsers |
| `tools/Sentinel.CoverageFuzz` | Coverage-guided fuzzing (SharpFuzz instrumentation) of the PE, ZIP and content-package parsers |
| `scripts/` | YARA-X fetch (hash-pinned), performance tree generator, service install/uninstall |

## Roadmap

See [docs/architecture.md](docs/architecture.md#roadmap). All planned user-mode milestones (M1–M12) exist as prototypes. What a beta would still need is listed in the [release checklist](docs/release-checklist.md). The optional kernel minifilter (M13+) stays out of scope until the user-mode design has been reviewed.

## Security

See [SECURITY.md](SECURITY.md). Do not commit live malware to this repository.

## Code signing policy

Releases are not signed yet. Signing through SignPath Foundation has been applied for or is planned
([ADR 0014](docs/adr/0014-open-source-licence-and-code-signing.md)). Once it is approved:

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

- Committers and reviewers: [repository members](https://github.com/venkateshguggilla/sentinel-antivirus/graphs/contributors)
- Approvers: [repository owner](https://github.com/venkateshguggilla)

Only binaries built by this repository's GitHub Actions release workflow from a tagged commit are signed, and
each signing request is approved by hand. See [docs/code-signing-policy.md](docs/code-signing-policy.md).

### Privacy

This program will not transfer any information to other networked systems unless specifically requested by
the user or the person installing or operating it. Scanning, quarantine, real-time monitoring and reports
all stay on the device. Content updates are imported from files you supply; nothing is downloaded
automatically.

## Licence

Sentinel is licensed under the [Apache License, Version 2.0](LICENSE). Third-party components keep their own
licences, listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
