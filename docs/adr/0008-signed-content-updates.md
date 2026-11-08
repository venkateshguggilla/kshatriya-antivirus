# ADR 0008: Signed content updates with anti-rollback and expiry

- Status: accepted (M6)
- Date: 2026-11-08

## Context

Signature and rule content must change far more often than the product. A content update path is
also an attractive attack surface: a forged package could blind the scanner or flood it with false
positives, a replayed old package could undo protection (rollback), and an attacker who blocks updates
can keep a device on stale content (freeze). The product is offline-first ([ADR 0001](0001-technology-stack.md)).

## Decision

- **Package (`.sntu`):** `"SNTU" | version | manifest JSON | signature JSON | file bytes`, every length
  bounded before allocation (manifest 64 KiB, signature 4 KiB, 64 files, 128 MiB per file, 256 MiB total).
  A custom framing instead of ZIP keeps the parser small and fuzzable (`Sentinel.Fuzz content`).
- **Signature:** ECDSA P-256 / SHA-256 (IEEE P1363) over the exact manifest bytes, from .NET's built-in
  cryptography (no new dependency). It is verified **before** the manifest is parsed. Key ids are the
  first 16 hex digits of SHA-256(SubjectPublicKeyInfo).
- **Manifest:** schema 1, channel, `sequence`, `createdUtc`, `expiresUtc`, and per file a safe name
  (`.hashdb` or `.yar`), kind, size and SHA-256. Every file must match its hash; the sizes must account
  for every byte.
- **Anti-rollback:** a package must have a sequence greater than the highest ever installed (kept in
  `content/state.json`, written with a protected ACL).
- **Freeze protection:** expired packages are refused at import. Installed content that has since
  expired keeps being used (better than nothing) but `status` and the app flag it as expired.
- **Activation:** the service stages the package, starts a **new sandboxed worker pool** with the new
  content (so the engines, inside the sandbox, must accept it), waits until no scan runs, swaps pools and
  clears the verdict cache. Any failure leaves the current content active.
- **At start** the active package is re-verified (signature and hashes). If verification fails the
  service still starts with built-in and configured content and reports the problem.
- **Trust roots:** `ContentTrust.ProductionKeys` is **empty**: no production signing key has been
  provisioned. Administrators can trust their own keys via `contentKeys` in the protected
  `service.json`. `tools/Sentinel.ContentTool` (`sentinel-content`) creates keys and packages; private
  keys stay with the publisher and are git-ignored.
- **Who:** importing (`sentinel update import <file> --service`) requires an elevated administrator on
  the installed service and is audited. The service reads the package file while impersonating the caller.

## Consequences

- Offline import only; fetching from a static CDN is left to the product updater milestone (M11), which
  can reuse the same package verification.
- No key rotation or revocation yet beyond editing `contentKeys`. A threshold or delegated-role scheme
  (as in TUF) is future work.
- No content is published by this project yet; the built-in EICAR signature and test rule remain the
  only shipped content.
