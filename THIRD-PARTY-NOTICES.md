# Third-party notices

Licensing policy: only permissive licenses (MIT, BSD, Apache-2.0, or similar) may be used. GPL/LGPL/AGPL components must not be linked into Kshatriya. See [ADR 0003](docs/adr/0003-dependency-licensing.md).

## Shipped components

| Component | Version | License | Notes |
|---|---|---|---|
| .NET runtime and base class libraries | 10.0 | MIT, © .NET Foundation and contributors | |
| System.Management and its dependency System.CodeDom | 10.0.14 | MIT, © .NET Foundation and contributors | Process-start events for real-time monitoring (`Kshatriya.Service`). |
| Microsoft.Extensions.Hosting.WindowsServices and its dependencies (Microsoft.Extensions.Hosting, Configuration, DependencyInjection, Logging including EventLog, Options, Primitives, FileProviders; System.Diagnostics.EventLog; System.ServiceProcess.ServiceController) | 10.0.14 | MIT, © .NET Foundation and contributors | Service host only (`Kshatriya.Service`). |
| YARA-X C API (`yara_x_capi.dll`) | 1.22.1 | BSD-3-Clause, © The YARA-X Authors | Fetched by `scripts/Get-YaraX.ps1` with a pinned SHA-256; not committed. Upstream binary is not Authenticode-signed. Licence text is saved next to the DLL. See [ADR 0004](docs/adr/0004-yara-x-native-dependency.md). |

## Development and test-only components (not shipped)

| Package | License |
|---|---|
| xunit, xunit.runner.visualstudio | Apache-2.0 |
| Microsoft.NET.Test.Sdk | MIT |
| coverlet.collector | MIT |
| NJsonSchema | MIT |
| SharpFuzz, SharpFuzz.Common, dnlib (coverage instrumentation for `tools/Kshatriya.CoverageFuzz`) | MIT |

## Data

| Item | Notes |
|---|---|
| EICAR test file signature | Industry-standard harmless test file defined by EICAR. Only its SHA-256 hash is embedded. |
