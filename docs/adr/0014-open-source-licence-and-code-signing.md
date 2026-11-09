# ADR 0014: Open-source licence (Apache-2.0) and code signing through SignPath Foundation

- Status: licence accepted by the owner on 2026-11-09. Signing pending: the repository is still private
  and the project has not applied to SignPath Foundation yet.
- Date: 2026-11-09

## Context

Releases are unsigned (ADR 0013 left the certificate to the owner). Checked against Microsoft's code
signing guidance (August 2026) and SignPath Foundation's terms on 2026-11-09:

- Publicly trusted code-signing keys must be kept on hardware (CA/Browser Forum, since June 2023), so the
  old `.pfx` path in the release script cannot work with a real certificate.
- Azure Artifact Signing (about $9.99/month) is open to individuals only in the US and Canada. OV
  certificates cost about $150–300 a year, and certificates now last at most 460 days.
- EV certificates no longer skip SmartScreen reputation (since 2024). Any certificate builds reputation
  over time.
- SignPath Foundation signs qualifying open-source projects for free. It requires an OSI-approved licence
  for every component, builds from source on a trusted build system, manual approval of each signing
  request, MFA, named team roles, product name and version metadata, and a code signing policy and privacy
  statement on the project's home page. Antivirus software is allowed: only finding or exploiting
  vulnerabilities and getting around security measures are excluded.

The owner wants Kshatriya to be open source with free signing.

## Decision

1. **Licence: Apache-2.0** for all Kshatriya code (`LICENSE` is the official text; `NOTICE` added). It is
   compatible with every dependency (MIT, BSD, Apache-2.0; ADR 0003), includes a patent grant, and keeps
   the project name out of the licence (trademark rights are not granted).
2. **Signing: SignPath Foundation** through the GitHub Actions release workflow. The workflow builds and
   tests, uploads the unsigned folder, submits it to SignPath, waits for a project approver to approve the
   request by hand, puts the signed binaries back, and packages with `-RequireSignature`. Signing is only
   counted as done when every Kshatriya binary has a valid Authenticode signature. Only Kshatriya's own
   binaries are signed (`.signpath/artifact-configuration.xml`); third-party files are never re-signed.
   Until SignPath is configured the workflow builds an UNSIGNED release, labelled as such.
3. `Build-Release.ps1` has two stages (`Build`, `Package`) so the checksums cover the signed files. Its
   `.pfx` option remains for local test certificates only.
4. The policy and privacy statement are in the README and [docs/code-signing-policy.md](../code-signing-policy.md).

## Owner actions (not automated)

- Make the GitHub repository public. Commit metadata includes the author's email address, which becomes
  public too; rewriting history to a no-reply address would change every commit id.
- Product name: renamed from "Sentinel" to **Kshatriya Antivirus** on 2026-11-09, before any public
  release, because "Sentinel" is used by existing security products (Microsoft Sentinel, SentinelOne). Everything
  was renamed: code namespaces, projects, executables (`kshatriya.exe`), the Windows service
  (`KshatriyaService`), folders (`%ProgramFiles%\Kshatriya`, `%ProgramData%\Kshatriya`) and format identifiers
  (`.kstu` content packages, `KSTU`/`KSTQ` magic). Nothing was released under the old name, so the old formats
  are not read. A web search found no antivirus product with this name; no formal trademark search was done.
  The GitHub repository was renamed from `sentinel-antivirus` to `kshatriya-antivirus` the same day (GitHub
  redirects old links).
- Publish a first release, then apply at signpath.org. After acceptance, create the SignPath project,
  signing policy (product name and version restrictions) and artifact configuration. Then set the
  repository variable `SIGNPATH_ORGANIZATION_ID` (and optionally `SIGNPATH_PROJECT_SLUG`,
  `SIGNPATH_POLICY_SLUG`, `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`) and the secret `SIGNPATH_API_TOKEN`.
- Turn on MFA for every team member.

## Consequences

- Anyone may use, modify and redistribute Kshatriya, including commercially. Versions already released stay
  Apache-2.0 even if the licence changes later.
- Signed releases depend on SignPath Foundation accepting the project, at its discretion and without an
  appeal. The fallback is an OV certificate on a hardware token or cloud HSM (`-Stage Build`, sign,
  `-Stage Package -RequireSignature`).
- Signing does not remove SmartScreen warnings for new files; it lets reputation build for the publisher.
- ADR 0003's statement that the licensing model was not final is settled by this ADR.
