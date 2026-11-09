# Release checklist and readiness (M12)

Kshatriya is a **prototype**. This page separates what is checked automatically today from what is still
missing before anyone should call a build "beta", let alone production.

## Checked on every push (CI)

- Zero-warning Release build; all unit, integration and sandbox tests, including elevated-only paths
  (WMI process events, WFP block/unblock) that the CI runner executes as administrator.
- Hung tests fail after 5 minutes and are named (`--blame-hang-timeout`).
- Dependency vulnerability audit (`dotnet list package --vulnerable --include-transitive`).
- Release gates (`scripts/Test-ReleaseGates.ps1`):
  - performance budget: 5,000 small files through the sandboxed workers at ≥ 500 files/s (a tripwire,
    not a claim; the development machine measured 7,474 files/s);
  - false positives: every file in `%SystemRoot%\System32` scanned with archives (depth 1); any
    detected or suspicious item fails the build.
- Mutation fuzzing, 100,000 iterations per parser; nightly 1,000,000 per parser with a fresh seed, plus
  coverage-guided fuzzing of the PE, ZIP and content-package parsers.

## Before each release

1. `./scripts/Get-YaraX.ps1`, then `./scripts/Build-Release.ps1` (signed if a certificate is available).
2. Confirm `RELEASE.txt` says signed or UNSIGNED as intended; verify the zip's `.sha256`.
3. Run `./scripts/Test-ReleaseGates.ps1 -BenignPaths C:\Windows\System32, "C:\Program Files"` on a
   clean reference machine and keep `artifacts/release-gates.json` with the release.
4. Install on a clean VM with `Install-KshatriyaService.ps1 -FromRelease <folder> -RequireSignature`;
   run `kshatriya status`, a scan, a quarantine/restore cycle and `kshatriya audit`; uninstall.
5. Review `docs/threat-model.md` for changes since the last release and update the README's honest
   limitations.

## Not done: required before a beta label

- [ ] Install and run the LocalSystem service end to end on clean Windows 10 22H2 and Windows 11 VMs.
      Done once on a Windows 10 22H2 development machine (2026-11-09): install, `status`, service scan,
      quarantine, refused and elevated restore, audit chain. It found three defects, all fixed (workers
      could not start under LocalSystem, the scripts needed PowerShell 7, refused audit reads were not
      audited). Clean VMs and Windows 11 are still to do.
- [ ] Code-signing certificate and signed releases. (Installer decided: zip + install script, ADR 0013.)
      Route decided: Apache-2.0 and free signing through SignPath Foundation (ADR 0014). Done: licence,
      NOTICE, code signing policy and privacy statement, two-stage release script with `-RequireSignature`,
      SignPath step in the release workflow (inactive until configured), history checked for secrets (none).
      Owner: make the repository public, publish a first release, apply to SignPath, configure it.
- [ ] Production content signing key, key-custody process and a first signed content release (ADR 0008).
- [ ] A broader benign corpus (many machines and installers) and a labelled malware set run in an
      isolated lab, with false-positive and detection rates published.
- [ ] Independent security review of the service pipe, sandbox and response component; external
      penetration test.
- [ ] Measured performance budgets on reference hardware (CPU, memory, disk I/O during real-time
      monitoring), including the cost of watching `C:\Users`. **First measurement only** (2026-11-09,
      build 73d9cf1, one developer machine: i9-9980HK 8 cores/16 threads, 64 GB, Apple SSD, Windows 10 22H2,
      Defender on; `C:\Users` watched, about 675,000 files; processes and removable media on; report only).
      Service and workers summed, 60 s per phase from performance counters; CPU is a share of the whole
      machine:

      | Phase | CPU avg (max) | Private working set avg (max) | Disk read / write avg |
      |---|---|---|---|
      | Idle (normal desktop and browser activity) | 0.09% (0.6%) | 280 MB (299 MB) | 1.1 / 0.4 MB/s |
      | File churn: 2,506 writes of 4–256 KB random data | 0.84% (1.7%) | 329 MB (554 MB) | 16.1 / 5.4 MB/s |
      | Program starts: 266 `cmd.exe` launches | 0.10% (1.4%) | 100 MB (129 MB) | 2.0 / 0.6 MB/s |

      The queue stayed under 10 entries in every phase. Not yet measured: a full rescan after lost
      events (it runs in its own lane on one worker and took over 30 minutes for all of `C:\Users`
      before the lane fix), slower disks, and other machines. The first install measured far worse
      (about 2% CPU and 8–67 MB/s of reads continuously) because of two real-time defects fixed in edb8ff9
      and 73d9cf1 ([ADR 0009 amendment](adr/0009-user-mode-real-time-monitoring.md)).
- [ ] Accessibility audit of the app with screen readers (Narrator, NVDA) and keyboard-only use.
- [x] Coverage-guided fuzzing for the PE, ZIP and package parsers (`tools/Kshatriya.CoverageFuzz`, nightly 10 minutes each with a carried-over corpus). Not yet: the signed manifest past signature verification, and the text/JSON parsers.
- [ ] A staffed false-positive response and content-revocation process.

Production status would additionally require independent lab testing and, to act as a primary
antivirus, Microsoft Virus Initiative membership. None of that is claimed.
