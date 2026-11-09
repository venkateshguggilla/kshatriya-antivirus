# ADR 0003: Dependency and data licensing

- Status: Accepted (2026-11-08)

## Decision

- Shipped code may depend only on permissively licensed components (MIT, BSD, Apache-2.0, or equivalent). No GPL, LGPL or AGPL code is linked into Sentinel. This rules out `libclamav` (GPLv2).
- Development and test-only dependencies follow the same rule so the repository can be relicensed freely.
- Threat-intelligence content (hash lists, YARA rules, reputation feeds) is reviewed for licence terms before it is bundled or redistributed; the review result is recorded in `THIRD-PARTY-NOTICES.md`.
- All dependency versions are centrally pinned in `Directory.Packages.props`.

## Rationale

The licensing model of the product is not final. A permissive-only policy keeps proprietary, open-source and dual-licence options open. (Settled on 2026-11-09: Sentinel is Apache-2.0, see [ADR 0014](0014-open-source-licence-and-code-signing.md).)

## Consequences

- Signature and rule content must come from sources whose terms allow redistribution, or be authored by the project.
- Each new dependency's licence is checked before it is added, including for test-only packages.
