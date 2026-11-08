# Instructions for coding agents and contributors

## Product rules (non-negotiable)

1. Defensive only: no stealth, evasion, credential theft, exploit delivery, or monitoring without the device owner's consent.
2. Never disable, weaken, or add exclusions to Microsoft Defender or other Windows security controls. Sentinel runs in **companion mode** alongside Defender ([ADR 0002](docs/adr/0002-defender-companion-mode.md)).
3. Never claim production readiness or parity with commercial antivirus without evidence. Label work as prototype, beta, or production honestly.
4. Never commit live malware. Use the in-memory EICAR helper (`tests/Shared/TestData.cs`) and generated benign files.
5. Dependencies must be MIT/BSD/Apache-2.0 compatible; no GPL linking ([ADR 0003](docs/adr/0003-dependency-licensing.md)).
6. Kernel-mode code is out of scope until the user-mode design is complete and reviewed.

## Engineering rules

- Build: `dotnet build Sentinel.slnx` must have **zero warnings** (warnings are errors). Test: `dotnet test Sentinel.slnx`.
- Package versions live only in `Directory.Packages.props`.
- Code that handles files must open them through `SafeFileOpener` / `SafeFileEnumerator`: never follow reparse points, never read cloud placeholders, always enforce size and time limits, and report every item that was not scanned.
- Scanning code is read-only. Anything that changes user files belongs in the (future) response/quarantine component, must act on the same handle it verified, and must be reversible.
- Engines implement `IDetectionEngine` and must be pure: no file system, network, or global state access.
- Public report formats are versioned (`docs/schemas`). Map enum values to wire names explicitly; never serialize enum member names directly.
- Record significant design decisions as ADRs in `docs/adr`.
