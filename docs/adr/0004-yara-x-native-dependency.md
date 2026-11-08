# ADR 0004: YARA-X as the pattern-rule engine, consumed as a hash-pinned native library

- Status: Accepted (2026-11-08)

## Context

Milestone 2 needs pattern rules (strings, byte patterns, conditions). YARA is the de facto rule language. The classic C implementation is in maintenance mode; VirusTotal's Rust rewrite, YARA-X, receives new development and is licensed BSD-3-Clause (compatible with [ADR 0003](0003-dependency-licensing.md)). YARA-X publishes a prebuilt C API library for Windows x64 on its GitHub releases page, with SHA-256 digests. The development machine has no Rust toolchain.

## Decision

- Use **YARA-X 1.22.1** (`yara-x-capi-v1.22.1-x86_64-pc-windows-msvc.zip`, SHA-256 `f52c2105e52696461de5f4aa6df50051994855ceee069015d566d7c6eb321217`) through P/Invoke.
  - 1.22.1 was chosen over the newer 1.23.0 (released three days earlier) to avoid adopting a brand-new release.
- Do **not** commit the DLL. `scripts/Get-YaraX.ps1` downloads the pinned archive, refuses to continue on a hash mismatch, and extracts `yara_x_capi.dll`, `yara_x.h` and the licence into `native/yara-x/win-x64/` (git-ignored). CI runs the same script.
- Compile rules with `YRX_DISABLE_INCLUDES` so rule files cannot read other files.
- Every concurrent scan rents its own native scanner; compiled rules are shared (supported by the C API).
- If the DLL is missing, the CLI warns and scans without YARA; if the user passed `--rules`, it fails (exit 4) rather than silently ignoring them.

## Consequences

- The upstream DLL is **not Authenticode-signed**; the pinned hash is the integrity control in development. Before any release (M11) we must either sign the redistributed DLL as part of our package or build it from source in CI.
- Only Windows x64 is supported for YARA until an ARM64 build is added.
- Upgrading YARA-X means updating the version and hash in the script, the version constant in `YaraEngine`, and re-running tests.
- Native code runs in-process. A crash inside YARA-X would take down the scanner; process isolation of scan workers (M3) contains this.
