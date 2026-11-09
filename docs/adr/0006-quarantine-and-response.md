# ADR 0006: Quarantine, restore, exclusions and audit log

- Status: accepted (M4)
- Date: 2026-11-08

## Context

Until M3 Kshatriya only reported. Milestone 4 adds the first component that changes user files.
A mistake here destroys data, and a mistake in authorization turns the LocalSystem service into a
tool for deleting or planting files, so the design favours "leave the file alone and say why" over
"try harder".

## Decision

### Separate response component

- `Kshatriya.Response` holds everything that writes: the vault, the quarantine manager, the audit log.
  `ScanRunner` stays read-only and calls an optional `IItemResponder` for detected files **after**
  its own read-only handle is closed.
- Only confirmed, high-confidence detections are actioned automatically: category `malware` or
  `test`, confidence `high` (exact hash signatures, or YARA rules that declare both explicitly).
  `suspicious` (heuristics) and `pua` findings are reported only. Quarantine during a scan is
  opt-in (`--quarantine`, request action `quarantine`, schedule `"action": "quarantine"`).

### Handle-based removal

1. Open the file with `GENERIC_READ | DELETE`, `FILE_SHARE_READ` only, and
   `FILE_FLAG_OPEN_REPARSE_POINT`. Nobody can write, rename or delete it while we hold the handle.
2. Check the handle: not a directory, not a reparse point or cloud placeholder, exactly one hard link,
   within the size limit (1 GiB).
3. Encrypt the content into the vault through that handle, hashing it on the way. If the SHA-256
   differs from what the scan saw, discard the vault copy and stop (`changed`).
4. Only after the vault copy is flushed, mark **the same handle** for deletion
   (`FileDispositionInfoEx`: delete, POSIX semantics, ignore read-only; classic disposition as fallback).
5. If marking fails (for example a running program, `inUse`), delete the vault copy; the file stays.

Running programs are not terminated and removal is not scheduled for reboot: both need a stronger
design (process attribution, admin consent) and are left to M7/M8.

### Encrypted vault

- AES-256-GCM in authenticated 1 MiB chunks; each chunk's additional data binds the item header, the
  chunk index and a final-chunk flag, so truncation, reordering, appending and swapping items are
  detected. The per-item key is HKDF-SHA256(vault key, salt = item id).
- The 256-bit vault key is random and protected with DPAPI for the account that owns the vault
  (LocalSystem for the service, the user for the CLI's local vault).
- Vault and audit directories get an explicit, non-inherited ACL: SYSTEM + Administrators
  (service) or SYSTEM + the user (CLI, development service). Users cannot read the service vault.
- The purpose of encryption is to keep quarantined content **inert** (it cannot be run, opened by
  accident or re-detected while stored), not to hide it from administrators.

### Restore

- Creates the target with `CREATE_NEW` (never overwrites), writes and verifies the SHA-256, and
  deletes a partial file through the handle that created it if anything fails.
- The restored file gets `Zone.Identifier` (zone 3, internet) so Windows SmartScreen and Office
  Protected View still treat it with caution. Original ACLs and alternate data streams are not restored.

### Service authorization

All file access runs **impersonating the client**: a user can quarantine only files they could delete,
and a restore lands only where they could write. Only vault and audit access revert to the service
identity. On the installed service:

| Operation | Who |
|---|---|
| Scan with quarantine, manual quarantine | any local user (their own rights) |
| List / delete quarantine items | own items; elevated administrators: all |
| Restore | elevated administrator |
| View or change exclusions | elevated administrator |
| Read the audit log | elevated administrator |

"Elevated administrator" means the impersonation token has the Administrators group enabled (UAC
filtered tokens do not). A development service serves only its own user and does not require it.
Refused operations are audited.

### Exclusions

- Full paths (a file, or a folder and everything below it, on path-segment boundaries) and exact
  SHA-256 values. No wildcards. Drive roots and the Windows directory are refused.
- Excluded items are still reported (`skipped`, reason `excluded`) and do not make a scan incomplete.
- Exclusions apply to Kshatriya only. Nothing in Kshatriya adds Defender exclusions ([ADR 0002](0002-defender-companion-mode.md)).

### Audit log

JSON Lines, `{"entry":{...},"hash":"<sha256 of the entry text>"}`, each entry naming the previous
hash, flushed per append and serialised across processes with a lock file. Rotates once at 8 MiB.
It is **tamper-evident**, not tamper-proof: an administrator can rewrite the whole file. Shipping
records off the machine (Windows Event Log forwarding) is future work.

### Report format

Scan report schema v3 adds the `excluded` reason, a per-item `action` object and `quarantined` /
`quarantineFailed` counters. Readers accept v2 and v3. Service protocol version 2.

## Consequences

- No file is removed without a verified, durable, decryptable copy; the failure mode is "file left in place".
- Running malware is reported (`inUse`), not stopped. Hard-linked files are refused rather than half-removed.
- Quarantine keeps items until deleted; there is no automatic retention yet.
- The production authorization rules are covered by tests that run either branch depending on whether
  the test process is elevated; the installed LocalSystem configuration is still not tested end to end.
