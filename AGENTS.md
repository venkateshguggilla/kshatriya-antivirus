# Instructions for coding agents and contributors

## Product rules (non-negotiable)

1. Defensive only: no stealth, evasion, credential theft, exploit delivery, or monitoring without the device owner's consent.
2. Never disable, weaken, or add exclusions to Microsoft Defender or other Windows security controls. Sentinel runs in **companion mode** alongside Defender ([ADR 0002](docs/adr/0002-defender-companion-mode.md)).
3. Never claim production readiness or parity with commercial antivirus without evidence. Label work as prototype, beta, or production honestly.
4. Never commit live malware. Use the in-memory EICAR helper (`tests/Shared/TestData.cs`) and generated benign files.
5. Dependencies must be MIT/BSD/Apache-2.0 compatible; no GPL linking ([ADR 0003](docs/adr/0003-dependency-licensing.md)).
6. Kernel-mode code is out of scope until the user-mode design is complete and reviewed.

## Engineering rules

- Setup: run `./scripts/Get-YaraX.ps1` once (downloads the hash-pinned YARA-X DLL into the git-ignored `native/` folder).
- Build: `dotnet build Sentinel.slnx` must have **zero warnings** (warnings are errors). Test: `dotnet test Sentinel.slnx`.
- Fuzz: `dotnet run -c Release --project tools/Sentinel.Fuzz -- all 1000000` before changing a parser.
- Package versions live only in `Directory.Packages.props`.
- Code that handles files must open them through `SafeFileOpener` / `SafeFileEnumerator`: never follow reparse points, never read cloud placeholders, always enforce size and time limits, and report every item that was not scanned.
- Scanning code is read-only. Anything that changes user files belongs in `Sentinel.Response`, must act on the same handle it verified, must keep a verified copy before removing anything, and must be reversible ([ADR 0006](docs/adr/0006-quarantine-and-response.md)).
- Only `malware`/`test` detections with `high` confidence may be actioned automatically, and only when the user asked for it. Never terminate processes or schedule reboot-time deletion without a reviewed design.
- Service operations that weaken protection (restore, exclusions) or reveal other users' data (audit log, others' quarantine items) require an elevated administrator and must write an audit record, including on refusal.
- Engines implement `IDetectionEngine` and must be pure: no file system, network, or global state access.
- Untrusted content is parsed only inside `Sentinel.Worker` (sandboxed). The broker (CLI/service) opens files and streams bytes; never give a worker a path to open, and never weaken the worker token, job limits or mitigations ([ADR 0005](docs/adr/0005-service-sandbox-ipc.md)). Sandbox properties are covered by `SandboxTests`; keep them passing.
- The service must act on a client's behalf only while impersonating that client, accept only local absolute paths, and identify clients only through the pipe, never from message contents.
- Every message read from a pipe is untrusted: enforce frame limits before allocating, deserialize strictly, and treat any violation as a reason to drop the connection.
- Logging in the service uses the source-generated `Log` class with stable event IDs.
- Heuristic engines report `DetectionCategory.Suspicious` only. Confirmed categories (`malware`, `pua`) come from exact signatures or rules with explicit metadata.
- Synthetic test executables come from `tests/Shared/PeBuilder.cs`; never commit real binaries.
- Public report formats are versioned (`docs/schemas`). Map enum values to wire names explicitly; never serialize enum member names directly.
- Content updates are accepted only as signed `.sntu` packages ([ADR 0008](docs/adr/0008-signed-content-updates.md)): never parse a manifest before its signature is verified, never weaken anti-rollback or expiry checks, never commit private signing keys.
- Record significant design decisions as ADRs in `docs/adr`.
