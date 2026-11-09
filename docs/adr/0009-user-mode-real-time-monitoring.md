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
  cost. A first measurement on one machine is in the [release checklist](../release-checklist.md); no budget is set yet.
- The history does not survive a restart; reports and the event log remain the durable record.
- Findings appear in the app, `kshatriya detections` and the event log, and since ADR 0015 as desktop notifications from the app's notification-area icon.

## Amendment (2026-11-09): folder events and scan lanes

The first install with `C:\Users` watched (on the owner's own machine) showed real-time scanning never
went idle. Two defects, both fixed:

- **Folder change events.** Windows reports a folder as changed whenever an entry inside it changes. The
  monitor queued that folder, and queued folders are scanned recursively, so every write in a busy folder
  rescanned the whole folder (about 5 million scans in an hour). `Changed` events for folders are now
  ignored, because the entry has its own event. Created folders are still scanned in full, since a folder
  moved in raises no events for its files. Folder changes no longer count toward the ransomware
  mass-change heuristic.
- **One lane.** A full folder scan (a folder moved in, a removable drive, a rescan after lost events)
  ran in the same one-batch-at-a-time lane as file events. A large one held up every new file and
  started program for as long as it ran; once, the whole of `C:\Users` was scanned in a single batch
  for over 30 minutes while the file queue grew. The trigger could not be identified from the logs,
  which only record warnings. Whole folders now have their own lane (one batch, one worker), so file
  events keep being scanned. Status counts scanned items as they finish. A folder scan still running
  after a minute is logged as event 7002, naming each folder and why it was queued. A file batch that
  takes over 10 s is logged as event 7003. Content updates wait for both lanes.

## Amendment (2026-11-09): targeted recovery after lost notifications

When notifications for a watched root are lost, the monitor reads the NTFS change journal (USN journal)
of that volume instead of rescanning everything. It reads from a checkpoint taken 30–60 seconds before
the loss (checkpoints rotate every 30 s) and queues only the paths that changed: files that still exist
under their recorded name, and folders that were created or moved in (scanned in full in the folder
lane, because their files raise no records). Each recovery is logged as event 7000 with the number of
paths queued.

- **Fallback:** the previous full rescan of the root, logged with the reason. This happens without
  administrator or SYSTEM rights (opening a volume needs them), on non-NTFS drives, when the journal
  was recreated or its entries were overwritten, or when more than 5,000 paths changed.
- **Reading the journal:** only metadata is read. Parent folders are opened by file id with
  attribute access only and without following reparse points, to rebuild paths. File contents are
  opened later by the normal scan through `SafeFileOpener`, and paths outside the watched root or in the
  service data folder are dropped.
- **Parser:** journal records come from the kernel, but the parser (`UsnRecords`) is bounds-checked
  anyway, unit-tested with malformed records and fuzzed (`Kshatriya.Fuzz usn`).
- **Limits:** the 30-second margin assumes notifications are lost within seconds of being raised, which
  matches how a buffer overflow happens. Only 64-bit file ids (NTFS) are handled; ReFS falls back to
  the full rescan.
