# ADR 0001: Technology stack

- Status: Accepted (2026-11-08)

## Context

Kshatriya is a Windows-first security suite. Its engines parse hostile files, it needs reliable background services, deep Win32 integration, a native-feeling accessible UI, and long-term maintainability by a small team.

## Decision

| Layer | Choice |
|---|---|
| Service, scan coordinator, engines, CLI | C# on .NET 10 (LTS) |
| Windows service hosting | `Microsoft.Extensions.Hosting.WindowsServices` / `BackgroundService` (M3) |
| PE parsing | `System.Reflection.PortableExecutable` first; AsmResolver if needed (M2) |
| Pattern rules | YARA-X (BSD-3-Clause) through its C API (M2) |
| Local storage | SQLite (`Microsoft.Data.Sqlite`) (M3+) |
| Local ML | LightGBM-trained model exported to ONNX, run with ONNX Runtime (M9) |
| UI | WinUI 3 / Windows App SDK, Fluent design (M5); WPF with the .NET Fluent theme is the fallback |
| IPC | gRPC over named pipes (M3) |
| Native code | C++ only where required: AMSI provider DLL, future minifilter |
| Installer | WiX MSI (M11) |
| Tests | xUnit; fuzzing with SharpFuzz from M2 |

## Rationale

- **Memory safety where it matters most.** Engines parse attacker-controlled content; a memory-safe runtime removes a whole class of exploitable bugs in the most-attacked code.
- **Productivity and maintainability.** One primary language across service, engines, CLI and UI; strong Win32 interop (`LibraryImport`), async I/O, ETW libraries.
- **Already available** on the development machine (.NET SDK 10.0.403, VS Build Tools 2022, Windows SDK 10.0.26100).

## Alternatives considered

- **C++ throughout**: best raw performance and the conventional vendor choice, but memory-unsafe parsers of hostile input and slower iteration. Kept only for the driver and the AMSI DLL.
- **Rust core with a C# UI**: memory-safe and fast, but adds a second toolchain and an FFI boundary everywhere. Revisit for specific hot engines if profiling justifies it.
- **Electron or web UI**: rejected; too heavy for a resident security app and a larger attack surface.
- **MSIX installer**: services require restricted capabilities and drivers are not supported, so MSI is the safer long-term choice.

## Consequences

- The .NET runtime is a dependency of the product (self-contained deployment is an option at packaging time).
- YARA-X requires a native DLL built or obtained per architecture (risk tracked for M2: no Rust toolchain is installed yet).
