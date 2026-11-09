# Code signing policy

Status: **releases are not signed yet.** This policy describes how they will be signed once the project
is accepted by SignPath Foundation ([ADR 0014](adr/0014-open-source-licence-and-code-signing.md)).

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## Team roles

| Role | Who | Responsibility |
|---|---|---|
| Committers and reviewers | [repository members](https://github.com/venkateshguggilla/sentinel-antivirus/graphs/contributors) | Write and review changes; changes from non-members are reviewed before merging |
| Approvers | [repository owner](https://github.com/venkateshguggilla) | Approve each signing request in SignPath by hand |

Everyone in these roles uses multi-factor authentication for GitHub and SignPath.

## What is signed

- Only Sentinel's own binaries (`Sentinel.*.exe`, `Sentinel.*.dll`, `sentinel.exe`, `sentinel.dll`), as listed
  in [.signpath/artifact-configuration.xml](../.signpath/artifact-configuration.xml). Third-party files (the
  .NET runtime, `yara_x_capi.dll`) are shipped as published by their authors and never re-signed.
- Only builds made by the repository's [release workflow](../.github/workflows/release.yml) on GitHub
  Actions, from source in this repository, after the full build (warnings are errors) and test suite pass.
- Every signed binary has product name `Sentinel` and the release's product version; the signing policy
  enforces both.
- Each signing request is approved manually. The workflow then refuses to package the release unless every
  Sentinel binary has a valid signature, writes the checksums of the signed files and builds the zip.

Nothing is signed from a developer machine, and no certificate or private key exists in the repository or
on build runners: the key stays in SignPath's hardware security module.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by
the user or the person installing or operating it. Scanning, quarantine, real-time monitoring and reports
all stay on the device. Content updates are imported from files the operator supplies; nothing is
downloaded automatically. Signature checks run with revocation and network retrieval turned off.

## Reporting misuse

If you find a signed Sentinel binary that does something this policy or the README does not describe,
report it as described in [SECURITY.md](../SECURITY.md), and to SignPath Foundation.
