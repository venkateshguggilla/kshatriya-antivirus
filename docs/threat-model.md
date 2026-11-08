# Threat model (draft, M2)

Scope: the M1–M2 command-line scanner, plus threats that later milestones must design for. Reviewed at every milestone.

## Assets

- Integrity of the user's files (the scanner must never damage them)
- Correctness of verdicts (missed detections and false positives)
- Integrity of signature content
- Availability of the user's machine (the scanner must not hang or exhaust it)

## Trust boundaries

| Boundary | M1 | Later |
|---|---|---|
| Scanned file content → engines | Untrusted input parsed in memory-safe C# | Parsed only in sandboxed workers (M3) |
| File system namespace → scanner | Untrusted (links, placeholders, races) | Same, plus a SYSTEM-privileged service |
| Signature databases → engine | Trusted by path; strict parser, fail closed | Signed manifests with rollback protection (M6) |
| UI ↔ service | n/a | Authenticated, authorised named-pipe IPC (M3) |

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation | Status |
|---|---|---|---|
| T1 | Link or junction redirects the scan outside the requested scope, or into an infinite loop (Tampering/DoS) | Reparse points are never followed inside a tree; directory identities are tracked; an explicitly named root link is resolved once | M1 ✔ |
| T2 | File swapped for a link between enumeration and open (race) | Open with `FILE_FLAG_OPEN_REPARSE_POINT`, then re-check the handle's attributes; read only through that handle | M1 ✔ |
| T3 | Scan triggers mass cloud downloads (DoS, privacy) | Offline / recall-on-open / recall-on-data-access files are skipped before opening, and re-checked after | M1 ✔ |
| T4 | Huge or slow files exhaust time or memory (DoS) | Per-item size limit and timeout; streaming hash; bounded parallelism and channel | M1 ✔ |
| T5 | Scanner blocks or corrupts user files (Tampering) | Read-only access, share-all mode, no writes; test asserts files are unchanged after a scan | M1 ✔ |
| T6 | Malformed signature database half-loads or misbehaves | Strict v1 parser; any malformed line rejects the whole file | M1 ✔ (signing in M6) |
| T7 | Faulty engine crashes or hangs the scan (DoS) | Exceptions are contained per item; cancellation-based timeouts | M1 ✔ (process isolation in M3) |
| T8 | Silent incompleteness gives false assurance (Repudiation) | Every unscanned item is reported with a reason; exit code 2; `complete` flag in JSON | M1 ✔ |
| T9 | Malicious content exploits a parser (Elevation) | PE, ZIP and hash-database parsers are memory-safe C# with explicit bounds checks; 1M-iteration mutation fuzzing per parser; YARA-X (Rust) runs in-process for now; sandboxed low-integrity workers with Job Object limits in M3 | M2 partial, M3 |
| T10 | Archive bombs and path traversal from archive entry names | Per-item depth (3), entry (10,000), entry-size (64 MiB), total-size (256 MiB) and ratio (200:1) limits; decompression is metered, declared sizes are not trusted; extraction is in memory only; entry names are display-only and sanitised | M2 ✔ |
| T16 | Compromised third-party native library (supply chain) | YARA-X DLL fetched from the official release and verified against a pinned SHA-256; not committed; to be signed or built from source before release | M2 ✔ (signing M11) |
| T17 | Signed malware abuses the "skip heuristics for signed files" rule | Hash and YARA engines still scan signed files; trust is verified offline through the scanned handle; invalid signatures are not trusted; the trade-off is documented | Accepted trade-off |
| T18 | Trust verification triggers network access (privacy, hangs) | WinVerifyTrust runs with revocation checks off and cache-only URL retrieval | M2 ✔ |
| T11 | Local malware spoofs the UI or service over IPC (Spoofing/Elevation) | Pipe access list, verification of both ends, admin-only weakening operations, audit | M3 |
| T12 | Quarantine or restore abused to move or delete arbitrary files | Act on the verified handle only; re-validate restore paths; SYSTEM-only vault | M4 |
| T13 | Update tampering, rollback or freeze attacks | Ed25519-signed manifests, monotonic versions, expiry, offline root key | M6 |
| T14 | Admin-level malware stops Sentinel (Tampering) | Out of scope without PPL/ELAM (requires MVI); we detect and report "protection off" rather than claim tamper-proofing | Accepted limitation |
| T15 | False positive leads to data loss | Heuristic/ML verdicts never delete; quarantine is reversible; extra checks for OS and trusted-signed files | M4 |

## Known M1 limitations

- Reading a file may update its last-access time if the volume has last-access updates enabled. Content, size, attributes and write times are never changed.
- Directory-cycle detection by identity is defence in depth: because links are never followed, M1 cannot be led into a cycle. No test constructs a true cycle (NTFS does not allow directory hard links).
- Hash databases and rule files are not yet signed.
- The ZIP central directory is read by `System.IO.Compression` before entry limits apply; its size is bounded by the per-file size limit (256 MiB) but not otherwise capped.
- YARA scans hold the whole file in memory (up to the size limit); many large files in parallel can use significant memory.
- Mutation fuzzing is unguided; coverage-guided fuzzing is future work.
