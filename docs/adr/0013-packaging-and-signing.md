# ADR 0013: Release packaging, signing pipeline and product updates

- Status: accepted (M11). Installer technology decided by the owner on 2026-11-09: keep the zip and
  install script. Product auto-update still awaits owner decisions. The signing part is superseded by
  [ADR 0014](0014-open-source-licence-and-code-signing.md) (Apache-2.0, SignPath Foundation; no `.pfx`
  secrets in CI).
- Date: 2026-11-09

## Context

The roadmap item was "WiX MSI packaging, signing pipeline, product updater". Three parts need decisions
or assets that only the project owner can provide:

1. **Installer technology.** WiX v4+ is licensed under MS-RL, and WiX v6 asks commercial users to pay an
   Open Source Maintenance Fee. Both sit outside the plain MIT/BSD/Apache policy of
   [ADR 0003](0003-dependency-licensing.md) for a proprietary product. MSIX can package services only with
   restricted capabilities that need Microsoft approval.
2. **A code-signing certificate** (and ideally an EV or Azure Trusted Signing identity).
3. **Where updates are hosted**, and who holds the release-signing key.

## Decision (what is built now)

- `scripts/Build-Release.ps1` publishes the service, worker, CLI and desktop app **self-contained** for
  win-x64 into one folder. It adds the licence files, a dependency inventory (`dependencies.json`: NuGet
  packages, including transitive ones, plus the pinned YARA-X DLL), `RELEASE.txt` and `SHA256SUMS.txt`
  for every file, then zips it and writes the zip's SHA-256.
- **Signing is optional and explicit.** With a certificate (`SENTINEL_SIGN_PFX` / `SENTINEL_SIGN_PASSWORD`,
  or the CI secrets `SIGNING_CERT_PFX_BASE64` / `SIGNING_CERT_PASSWORD`) every Sentinel binary is signed
  with SHA-256 and an RFC 3161 timestamp. Without one, the release says **UNSIGNED** in `RELEASE.txt` and
  in the build output. No certificate or key is stored in the repository.
- `Install-SentinelService.ps1 -FromRelease <folder>` verifies every file against `SHA256SUMS.txt`,
  refuses missing, modified or unlisted binaries, and with `-RequireSignature` also requires valid
  Authenticode signatures. It adds a Start-menu shortcut for the app; uninstall removes it.
- `.github/workflows/release.yml` builds, tests and packages on version tags or on demand, and uploads
  the zip as a workflow artifact. It publishes nothing publicly.

## Installer decision (owner, 2026-11-09)

The project owner chose to **keep the self-contained zip plus `Install-SentinelService.ps1`** as the
only installer, and not to adopt WiX or MSIX for now.

- Why: it keeps every build dependency within [ADR 0003](0003-dependency-licensing.md) (no MS-RL toolset,
  no maintenance fee) and avoids MSIX restricted capabilities. The script already verifies checksums
  and, with `-RequireSignature`, Authenticode signatures before installing.
- Consequences: installing requires an elevated PowerShell session; there is no Add/Remove Programs
  entry, repair, or Group Policy/Intune MSI deployment. Uninstall is `Uninstall-SentinelService.ps1`.
- Revisit when managed (enterprise) deployment is needed, or when an installer toolset with a
  compatible licence is available.

## Not built (needs the owner)

- Product auto-update: the signed-package machinery of [ADR 0008](0008-signed-content-updates.md) can verify
  a release manifest (version, zip SHA-256, anti-rollback), but hosting, the release key and the
  replace-running-service procedure need decisions first.
- The release zip is integrity-checked by checksums only. Without a signing certificate it has no
  publisher authenticity.
