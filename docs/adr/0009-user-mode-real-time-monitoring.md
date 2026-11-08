# ADR 0009: User-mode real-time monitoring

- Status: accepted (M7)
- Date: 2026-11-08

## Context

On-demand and scheduled scans leave long gaps. M7 adds monitoring **without** kernel code
(AGENTS rule 6: no kernel mode until the user-mode design is complete and reviewed). User mode cannot
intercept an open or an execution, so this milestone *detects soon after*; it does not *prevent*.

## Decision

- **File activity:** `FileSystemWatcher` (ReadDirectoryChangesW) on configured folders, recursive.
  Created, changed and renamed paths are debounced (2 s quiet period by default) and scanned in batches.
  Locked files are retried with exponential backoff (5 attempts). When notifications are lost (buffer
  overflow, folder removed) the whole watched root is queued for a rescan, so lost events cost time,
  not coverage. The queue is bounded (10,000 paths). The service's own data folder is never monitored.
- **Process start:** WMI `Win32_ProcessStartTrace` (backed by kernel process events; administrator or
  SYSTEM only) via `System.Management` (MIT). The image path comes from `QueryFullProcessImageName`;
  a process that exits before it can be opened is missed. Images are scanned and findings reported.
  **Processes are never terminated.** TraceEvent was considered and rejected because its package ships
  non-MIT native binaries ([ADR 0003](0003-dependency-licensing.md)).
- **Removable media:** removable drives are detected by polling (3 s) and scanned once when they
  appear. Nothing on them is opened beyond reading for the scan; nothing is executed.
- **Scanning:** as the service identity, through `ScanCoordinator.ScanBackgroundAsync`: the shared
  sandboxed pool, the verdict cache and current exclusions, one batch at a time, not counted against user
  scan capacity. Content updates wait for the running batch before swapping pools.
- **Action:** report by default; `"action": "quarantine"` quarantines high-confidence detections (same
  rules as [ADR 0006](0006-quarantine-and-response.md)).
- **History:** findings from user scans, schedules and real-time monitoring go into a bounded in-memory
  history (500). Administrators see all; other users see entries under their own profile folder.
- **Opt-in:** enabled only when `service.json` has a `realTime` section (default folders: `%SystemDrive%\Users`).

## Consequences

- Malware can run before the scan of its file finishes. This is stated in the app, the README and the
  threat model. Blocking requires a minifilter (M13+, optional) or a different OS facility.
- Watching `C:\Users` recursively sees a lot of churn; the debounce, cache and batch size bound the
  cost, but no performance budget has been measured yet (M12).
- The history does not survive a restart; reports and the event log remain the durable record.
- No user notification (toast) yet; findings appear in the app, `sentinel detections` and the event log.
