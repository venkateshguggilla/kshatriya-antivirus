# Threat model (draft, M3)

Scope: the M1–M3 scanner, service and workers, plus threats that later milestones must design for. Reviewed at every milestone.

## Assets

- Integrity of the user's files (the scanner must never damage them)
- Confidentiality of files the requesting user cannot read (the service runs as LocalSystem)
- Correctness of verdicts (missed detections and false positives)
- Integrity of signature content and service configuration
- Availability of the user's machine (the scanner must not hang or exhaust it)

## Trust boundaries

| Boundary | Today (M3) | Later |
|---|---|---|
| Scanned file content → engines | Parsed only in sandboxed workers: restricted token, account SID deny-only, low integrity, Job Object, mitigations | AppContainer or dedicated low-privilege account (stronger read barrier) |
| File system namespace → broker | Untrusted (links, placeholders, races); opened with the caller's own rights | Same |
| Client process → service (pipe) | Caller identified by impersonation; scans run impersonated; local paths only | Admin-only operations for anything that weakens protection (M4/M5) |
| Service → client (pipe) | Client checks the server PID against the SCM before sending anything | Signed binaries checked too (M11) |
| Configuration and signature files → service | Refused unless owned and writable only by SYSTEM/Administrators/TrustedInstaller | Signed manifests with rollback protection (M6) |

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation | Status |
|---|---|---|---|
| T1 | A link or junction redirects the scan outside the requested scope, or into an infinite loop (Tampering/DoS) | Reparse points are never followed inside a tree; directory identities are tracked; an explicitly named root link is resolved once | M1 ✔ |
| T2 | A file is swapped for a link between enumeration and open (race) | Open with `FILE_FLAG_OPEN_REPARSE_POINT`, then re-check the handle's attributes; read only through that handle | M1 ✔ |
| T3 | The scan triggers mass cloud downloads (DoS, privacy) | Offline, recall-on-open and recall-on-data-access files are skipped before opening and re-checked after | M1 ✔ |
| T4 | Huge or slow files exhaust time or memory (DoS) | Per-item size limit and timeout; streaming hash; bounded parallelism; per-worker memory cap | M1 ✔ / M3 ✔ |
| T5 | The scanner blocks or corrupts user files (Tampering) | Read-only access, share-all mode, no writes; a test asserts files are unchanged after a scan | M1 ✔ |
| T6 | A malformed signature database half-loads or misbehaves | Strict v1 parser; any malformed line rejects the whole file | M1 ✔ (signing in M6) |
| T7 | A faulty engine crashes or hangs the scan (DoS) | Exceptions contained per item; a crashed, over-memory or hung worker is killed at the item deadline and replaced, and the item is reported `engineError`/`timeout` | M3 ✔ |
| T8 | Silent incompleteness gives false assurance (Repudiation) | Every unscanned item is reported with a reason; exit code 2; `complete` flag in JSON | M1 ✔ |
| T9 | Malicious content exploits a parser (Elevation) | Memory-safe C# parsers with bounds checks; 1M-iteration mutation fuzzing per parser; **all engines and archive expansion run in sandboxed workers** that cannot write user files, start processes, read files private to the account, or use UI; the broker refuses workers that are not low integrity | M3 ✔ (see residual risks) |
| T10 | Archive bombs and path traversal from archive entry names | Per-item depth, entry, size and ratio limits; metered decompression; in-memory only; entry names are display-only and sanitised | M2 ✔ |
| T11 | Local malware spoofs the service to a client, or a client to the service (Spoofing) | Client checks the pipe server PID against the SCM before writing; first-instance claim; Authenticated Users lack `CREATE_PIPE_INSTANCE`; the caller's identity comes only from impersonation | M3 ✔ |
| T12 | Quarantine or restore is abused to move or delete arbitrary files | Act on the verified handle only; re-validate restore paths; SYSTEM-only vault | M4 |
| T13 | Update tampering, rollback or freeze attacks | Ed25519-signed manifests, monotonic versions, expiry, offline root key | M6 |
| T14 | Admin-level malware stops Sentinel (Tampering) | Out of scope without PPL/ELAM (requires MVI); we report "protection off" rather than claim tamper-proofing | Accepted limitation |
| T15 | A false positive leads to data loss | Heuristic and ML verdicts never delete; quarantine is reversible; extra checks for OS and trusted-signed files | M4 |
| T16 | Compromised third-party native library (supply chain) | YARA-X DLL fetched from the official release and verified against a pinned SHA-256; not committed | M2 ✔ (signing M11) |
| T17 | Signed malware abuses the "skip heuristics for signed files" rule | Hash and YARA engines still scan signed files; trust is verified offline through the scanned handle | Accepted trade-off |
| T18 | Trust verification triggers network access (privacy, hangs) | WinVerifyTrust runs with revocation checks off and cache-only URL retrieval | M2 ✔ |
| T19 | Confused deputy: a standard user asks the SYSTEM service to scan, and so read, files they cannot read (Information disclosure) | Each client scan runs impersonating the caller; the cache is consulted only after the file was opened with the caller's rights; Identification-only clients are refused | M3 ✔ |
| T20 | The service is pointed at network shares or device namespaces on a caller's behalf | Only fully qualified local drive paths; UNC, `\\?\`, device paths, ADS and wildcards refused; 64 paths per request | M3 ✔ |
| T21 | A standard user edits service configuration or adds signature/rule files to change what SYSTEM scans | Protected ACL on `%ProgramData%\Sentinel`; settings and signature/rule files refused unless owned and writable only by SYSTEM/Administrators/TrustedInstaller; strict settings parser | M3 ✔ |
| T22 | A client floods the service (DoS) | Frame size limits before allocation; capped concurrent scans (`busy`); a fixed number of listeners | M3 ✔ (per-user quotas later) |
| T23 | A stale verdict-cache entry hides a modified file | Only complete clean results cached; key = file ID + size + last-write + change time + engine fingerprint; files changed in the last 2 s never cached; scheduled scans bypass the cache | M3 ✔ (see residual risks) |
| T24 | Code-loading environment variables reach the worker | Startup-hook and profiler variables stripped; diagnostics IPC disabled; extension points and non-system fonts blocked by mitigation policy | M3 ✔ |
| T25 | A malicious pipe server impersonates the client | The client writes nothing before verifying the server, and impersonation needs data to have been read | M3 ✔ |

## Residual risks (M3)

- **Workers can still read world-readable files.** The worker's account SID is deny-only, so files private to the account (user profile, SYSTEM-only data) are unreadable. Files that Users or Everyone may read remain readable. A test (`Worker_can_still_read_world_readable_files`) documents this. AppContainer or a dedicated account is the planned fix.
- **WinVerifyTrust parses PE files in the broker** (the service, as SYSTEM). It is Windows code, but it reads attacker-controlled input with full privileges.
- **Verdict cache vs. timestamp forgery.** A process that can write a file can also restore its timestamps (including the change time, via native APIs), making a modified file look unchanged until the next scheduled scan or cache reset. A USN-journal-based cache key is future work.
- The service authorizes per user, not per client binary. Today that grants nothing beyond the user's own rights; it must be revisited before operations that weaken protection exist.

## Known limitations

- Reading a file may update its last-access time if the volume has last-access updates enabled. Content, size, attributes and write times are never changed.
- Directory-cycle detection by identity is defence in depth: because links are never followed, the scanner cannot be led into a cycle.
- Hash databases and rule files are not yet signed.
- The ZIP central directory is read by `System.IO.Compression` before entry limits apply; its size is bounded by the per-file size limit.
- Workers hold an item fully in memory (bounded by the size limit and the job memory cap).
- Mutation fuzzing is unguided; coverage-guided fuzzing is future work.
- The service has been exercised in development mode (as the current user) by automated tests. Installing it as LocalSystem is scripted (`scripts/Install-SentinelService.ps1`) but was not run on the development machine.
