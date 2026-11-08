# Architecture

This document describes the target architecture and what exists today. Planned parts are marked **(planned)**.

## Principles

- **Companion to Microsoft Defender**, never a replacement that turns it off ([ADR 0002](adr/0002-defender-companion-mode.md)).
- **User mode first.** A kernel minifilter is an optional, late phase.
- **Hostile input is parsed only in memory-safe code**, and (from M3) only inside sandboxed worker processes.
- **Scanning is read-only.** Changing user files is the job of a separate, auditable, reversible response component.
- **Nothing is silently skipped.** Every item is clean, detected, skipped by policy (with reason), or not scanned (with reason).
- **Offline first.** Cloud features are opt-in and send hashes only.

## Target component diagram

```
 UI (WinUI 3, user) ──gRPC/named pipe, both ends verified──► Service (LocalSystem)        (planned M3/M5)
                                                              ├─ Scan Coordinator ─► Sandboxed scan workers
                                                              │                      └─ Engines: Hash · YARA-X · PE · Archive · ML
                                                              ├─ Monitors: file activity · ETW process start · ransomware · WFP
                                                              ├─ Quarantine vault · audit log · SQLite store
                                                              └─ Updater (signed manifests, anti-rollback) ──► static CDN
 Defender stays ON · optional minifilter driver = final phase
```

## What exists (M1–M2)

```
sentinel.exe (Sentinel.Cli)
  └─ ScanRunner (Sentinel.Scanning)
       ├─ SafeFileEnumerator  → walks targets; never follows reparse points; skips cloud placeholders;
       │                        long paths; directory identity tracking; reports unreadable directories
       ├─ SafeFileOpener      → CreateFileW(GENERIC_READ, share all, OPEN_REPARSE_POINT); re-checks the
       │                        handle's attributes to close enumeration→open races
       ├─ SHA-256 (streamed, size- and time-limited)
       ├─ AuthenticodeTrustProvider → WinVerifyTrust on the open handle: embedded, then catalog; offline
       ├─ IDetectionEngine[]
       │    ├─ HashEngine          (Sentinel.Engines.Hash)  exact SHA-256 signatures
       │    ├─ YaraEngine          (Sentinel.Engines.Yara)  YARA-X rules via C API, includes disabled
       │    └─ PeHeuristicEngine   (Sentinel.Engines.Pe)    static PE indicators → "suspicious" only
       └─ ZipExpander         → in-memory, metered expansion of ZIP-based containers under a per-item
                                budget; every engine runs on every entry; findings carry the entry path
```

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
| `notScanned` | Should have been scanned but wasn't: `tooLarge`, `timeout`, `accessDenied`, `locked`, `notFound`, `ioError`, `engineError`, `archiveLimit`, `archiveEncrypted`, `archiveError` | **yes** |

Detections carry a category (`malware`, `pua`, `suspicious`, `test`) and a confidence (`low`, `medium`, `high`). Only high-confidence detections may ever drive automatic actions (from M4).

## Planned communication between UI and service (M3)

- gRPC over a named pipe. The access list grants SYSTEM full control and interactive users connect rights, denies network logons, and grants nobody else `FILE_CREATE_PIPE_INSTANCE`.
- Service verifies the client (`GetNamedPipeClientProcessId` → image path in install directory → Authenticode signer). Client verifies the server (`GetNamedPipeServerProcessId` → our signed service running as SYSTEM) and connects at the Identification impersonation level.
- Operations that weaken protection (disable real-time, add exclusion, restore a detected file, change update source) require an elevated administrator token and are audited.
- Protocol version handshake; protobuf evolution rules; the service supports N and N-1.

## Roadmap

Labels: **P** prototype/educational · **B** beta for trusted testers. Nothing here is production-grade; that would also require independent lab testing, a staffed threat-intelligence pipeline, false-positive response processes and, for primary-AV status, Microsoft Virus Initiative membership.

| # | Milestone | Label |
|---|---|---|
| M1 | Foundation + read-only scanner CLI ✔ | P |
| M2 | YARA-X rules, PE heuristics, Authenticode checks, archive scanning with limits ✔ | P |
| M3 | Windows service, sandboxed scan workers, authenticated IPC, scheduler, verdict cache | P |
| M4 | Encrypted quarantine, handle-based removal, restore, exclusions, audit log | P |
| M5 | WinUI 3 app: dashboard, scan, detections, quarantine, protection, updates, settings; accessibility | P→B |
| M6 | Signed content updates with rollback/freeze protection, offline import | B |
| M7 | User-mode real-time monitoring (file activity, ETW process start, removable media) | B |
| M8 | Ransomware behaviour protection | B |
| M9 | Optional local ML (EMBER-style features, ONNX), off by default | P |
| M10 | Web/network protection via WFP user-mode filters | B |
| M11 | WiX MSI packaging, signing pipeline, product updater | B |
| M12 | Release hardening: fuzzing, performance budgets, false-positive corpus, disclosure process | B |
| M13+ | Optional kernel minifilter (Microsoft Scanner sample model) | P |
