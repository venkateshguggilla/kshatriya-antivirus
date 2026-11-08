# Third-party notices

Licensing policy: only permissive licenses (MIT, BSD, Apache-2.0, or similar) may be used. GPL/LGPL/AGPL components must not be linked into Sentinel. See [ADR 0003](docs/adr/0003-dependency-licensing.md).

## Shipped components

The M1 product (`src/`) depends only on the .NET runtime and base class libraries (MIT, © .NET Foundation and contributors).

## Development and test-only components (not shipped)

| Package | License |
|---|---|
| xunit, xunit.runner.visualstudio | Apache-2.0 |
| Microsoft.NET.Test.Sdk | MIT |
| coverlet.collector | MIT |
| NJsonSchema | MIT |

## Data

| Item | Notes |
|---|---|
| EICAR test file signature | Industry-standard harmless test file defined by EICAR. Only its SHA-256 hash is embedded. |
