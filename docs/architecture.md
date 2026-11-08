# Architecture

This document describes the target architecture and what exists today. Planned parts are marked **(planned)**.

## Principles

- **Companion to Microsoft Defender**, never a replacement that turns it off ([ADR 0002](adr/0002-defender-companion-mode.md)).
- **User mode first.** A kernel minifilter is an optional, late phase.
- **Hostile input is parsed only in memory-safe code, inside sandboxed worker processes** (M3). The process that opens files never parses their contents beyond the SHA-256 and the Windows signature check.
- **Scanning is read-only.** Changing user files is the job of a separate, auditable, reversible response component.
- **Nothing is silently skipped.** Every item is clean, detected, skipped by policy (with reason), or not scanned (with reason).
- **Offline first.** Cloud features are opt-in and send hashes only.

## Target component diagram

```
 UI (WPF app, user) ──named pipe, both ends verified──► Service (LocalSystem)
                                                              ├─ Scan Coordinator ─► Sandboxed scan workers
                                                              │                      └─ Engines: Hash · YARA-X · PE · Archive · ML
                                                              ├─ Monitors: file activity · ETW process start · ransomware · WFP
                                                              ├─ Quarantine vault · audit log · SQLite store
                                                              └─ Updater (signed manifests, anti-rollback) ──► static CDN
 Defender stays ON · optional minifilter driver = final phase
```

## What exists (M1–M5)

`Sentinel.App.exe` (M5) is a WPF client of the same pipe: it never touches scanned files itself.

```
sentinel.exe (Sentinel.Cli) ─────────────┐        Sentinel.Service.exe (LocalSystem, or --dev as the user)
  scan <paths>      local broker         │          ├─ PipeServer  \\.\pipe\Sentinel.Service.v1
  scan --service ───────────── named pipe ─────────►│    caller identified by impersonation; scans run AS the caller
  status, quarantine, client checks server PID = SCM│  ├─ ScanCoordinator (shared worker pool, verdict cache, exclusions, scan cap)
  exclusions, audit                                 │  ├─ Scheduler (local-time schedules, reports, catch-up, optional quarantine)
                                                    │  ├─ Response: QuarantineManager · encrypted vault · audit log · ExclusionStore
                                                    │  ├─ RealTimeMonitor (opt-in): FileSystemWatcher · WMI process start · removable
                                                    │       drives → debounced background scans (shared pool, cache, exclusions)
                                                    │       └─ RansomwareDetector: behaviour alerts (suspicious only, no action)
                                                    │  ├─ NetworkProtection (opt-in): WFP block filters (ALE connect, dynamic session)
                                                    │  └─ ContentStore: signed .sntu packages (ECDSA P-256), anti-rollback, expiry;
                                                    │       new content → new sandboxed pool → swapped between scans
        broker (CLI or service)
          └─ ScanRunner (Sentinel.Scanning)
               ├─ SafeFileEnumerator  → never follows reparse points; skips cloud placeholders; long paths; exclusions
               ├─ SafeFileOpener      → read-only, share-all, OPEN_REPARSE_POINT; handle attributes re-checked
               ├─ VerdictCache        → unchanged clean files (file ID + size + write/change times + engine fingerprint)
               ├─ SHA-256 · AuthenticodeTrustProvider (WinVerifyTrust on the open handle, offline)
               └─ IContentAnalyzer
                    ├─ WorkerPoolAnalyzer (default) ── bytes over overlapped pipes ──► Sentinel.Worker.exe ×N
                    │                                   restricted token · account SID deny-only · low integrity
                    │                                   Job Object (1 process, memory cap, kill on close, UI limits)
                    │                                   mitigations (no child processes, no extension points, ...)
                    │                                     └─ InProcessAnalyzer (+ MlEngine when a model is enabled)
                    └─ InProcessAnalyzer (--no-sandbox, development only)
                          ├─ HashEngine · YaraEngine · PeHeuristicEngine   (IDetectionEngine)
                          └─ ZipExpander (metered, per-item budget, every engine on every entry)
               └─ IItemResponder (optional, Sentinel.Response) → QuarantineResponder for detected files
                    open share-read + DELETE, no reparse → verify links/size → encrypt into vault while
                    re-hashing → mark the same handle for deletion → audit
```

See [ADR 0006](adr/0006-quarantine-and-response.md) for quarantine, restore, exclusions and the audit log.

See [ADR 0005](adr/0005-service-sandbox-ipc.md) for the service, sandbox and IPC decisions.

### Verdict aggregation

- Any detection whose category is not `suspicious` → item status `detected`.
- Only `suspicious` findings (PE heuristics, rules without a category) → status `suspicious`. Never auto-actioned.
- Findings found before a timeout or archive limit are kept; the item is marked partial (`incomplete: true`).
- Validly signed executables are not scored by PE heuristics (hash and YARA still apply).

### Extension point

```csharp
public interface IDetectionEngine
{
    EngineDescriptor Descriptor { get; }   // id, version, content version
    ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken ct);
}
```

Engines receive an already-open, read-only, seekable stream plus its SHA-256. They must not touch the file system or network and must honour cancellation (the pipeline enforces per-item time limits through the token). An engine that throws marks the item `notScanned/engineError`; it never stops the scan.

Engines and (future) protection modules are compiled in and shipped signed. Third-party plug-in loading is intentionally not supported.

### Result model

| Status | Meaning | Counts as incomplete |
|---|---|---|
| `clean` | Every engine ran; nothing found | no |
| `detected` | At least one detection | no |
| `skipped` | Not opened by policy: `reparsePoint`, `cloudPlaceholder`, `loopDetected` | no |
| `suspicious` | Only heuristic findings | partial findings only |
| `skipped` (`excluded`) | Matched a path or SHA-256 exclusion (M4) | no |
| `notScanned` | Should have been scanned but wasn't: `tooLarge`, `timeout`, `accessDenied`, `locked`, `notFound`, `ioError`, `engineError`, `archiveLimit`, `archiveEncrypted`, `archiveError` | **yes** |

Detections carry a category (`malware`, `pua`, `suspicious`, `test`) and a confidence (`low`, `medium`, `high`). Only `malware`/`test` detections with `high` confidence are quarantined automatically, and only when quarantine was requested (M4). Items carry the action taken (`quarantined` with a vault id, or `failed` with a reason).

## Communication between clients and the service (M3)

- Length-prefixed frames over a named pipe, with strict JSON headers and limits checked before
  allocation. The handshake carries a protocol version, and a mismatch is refused.
- Pipe ACL: SYSTEM and Administrators full control; Authenticated Users read/write but **not**
  `FILE_CREATE_PIPE_INSTANCE`; network logons denied. The first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`.
- The **client verifies the server before sending anything**: the pipe server's PID must be the
  PID that the SCM reports for `SentinelService` (development: same user).
- The **service identifies the client only via impersonation** and runs that client's scans
  impersonated, so a caller can scan only what it can read. Clients therefore connect at the
  Impersonation level; Identification-only clients are refused.
- Accepted paths: fully qualified local drive paths only (no UNC, device, `\\?\`, ADS or wildcards).
- Operations that weaken protection (restore, exclusions) and reading the audit log or other users'
  quarantine items require an elevated administrator (M4). Every attempt, including refusals, is audited.
  Quarantine and restore touch files only while impersonating the caller.
- Not yet built: verifying the *client binary* (image path and signer). Authorization is per user,
  because every operation today grants only what the caller already has.

## Roadmap

Labels: **P** prototype/educational · **B** beta for trusted testers. Nothing here is production-grade; that would also require independent lab testing, a staffed threat-intelligence pipeline, false-positive response processes and, for primary-AV status, Microsoft Virus Initiative membership.

| # | Milestone | Label |
|---|---|---|
| M1 | Foundation + read-only scanner CLI ✔ | P |
| M2 | YARA-X rules, PE heuristics, Authenticode checks, archive scanning with limits ✔ | P |
| M3 | Windows service, sandboxed scan workers, authenticated IPC, scheduler, verdict cache ✔ | P |
| M4 | Encrypted quarantine, handle-based removal, restore, exclusions, audit log ✔ | P |
| M5 | Desktop app (WPF + Fluent, [ADR 0007](adr/0007-desktop-app-wpf.md)): dashboard, scan, quarantine, exclusions, history; accessibility ✔ (updates page with M6) | P |
| M6 | Signed content updates with rollback/freeze protection, offline import ✔ ([ADR 0008](adr/0008-signed-content-updates.md)) | P |
| M7 | User-mode real-time monitoring (file activity, process start, removable media) ✔ ([ADR 0009](adr/0009-user-mode-real-time-monitoring.md)); detects after the fact, cannot block | P |
| M8 | Ransomware behaviour detection (mass modification, ransom notes, recovery tampering, opt-in decoys), alert only ✔ ([ADR 0010](adr/0010-ransomware-behaviour-detection.md)) | P |
| M9 | Optional local ML scoring (EMBER-style `pe-v1` features, JSON tree/logistic models in pure C#, no native runtime), off by default, no model shipped ✔ ([ADR 0011](adr/0011-local-ml-scoring.md)) | P |
| M10 | Network protection: IP blocklists from signed content as WFP filters in a dynamic session (fail open) ✔ ([ADR 0012](adr/0012-network-protection-wfp.md)) | P |
| M11 | Release packaging (self-contained zip, checksums, dependency inventory), optional signing pipeline, verified install ✔; zip + script chosen as the installer; product auto-update pending owner decisions ([ADR 0013](adr/0013-packaging-and-signing.md)) | P |
| M12 | Release hardening: CI release gates (performance budget, System32 false-positive check), dependency audit, nightly fuzzing, disclosure process ✔ ([release checklist](release-checklist.md)) | P |
| M13+ | Optional kernel minifilter (Microsoft Scanner sample model) | P |
