# ADR 0017: Scanning files up to 10 GiB (read-only mapped sections)

- Status: accepted (owner asked for a 10 GB default on 2026-11-09)
- Date: 2026-11-09

## Context

The per-file limit was 256 MiB, and could not go above 1 GiB. A file was streamed to a sandboxed worker in
one pipe message, the worker held it in memory, and each engine copied it again into a byte array. The
message size (about 1 GiB), the worker's private-memory cap (1.5 GB, ADR 0005) and .NET byte arrays
(2 GiB) all stood in the way of larger files. A quick scan on the owner's machine listed installers, ISO
images and videos as "not scanned: too large".

## Decision

1. **Files are mapped, not copied.** The broker (service, or CLI) still opens the file through
   `SafeFileOpener` and hashes it as a stream. For analysis it creates a **read-only section** from that
   handle (`CreateFileMapping`, `PAGE_READONLY`). It confirms that the file still has the length that
   was hashed, then duplicates the section into the worker with **`FILE_MAP_READ` as the only access
   right**. The worker maps a view, checks that the view covers the stated length, scans, unmaps and
   closes the handle. The worker still never receives a path. Its restricted token, low integrity, job
   object and mitigations are unchanged (the sandbox tests still pass). Mapped pages are file-backed, so
   they do not count against the worker's private-memory cap.
2. **Engines read in place.** `ScanSubject.Memory` (`ContentMemory`: start pointer and length) is set
   for mapped content. YARA-X scans the whole view through its pointer, with no size limit from .NET. The
   PE heuristic and ML engines read a span of the view; they only examine files up to 64 MiB, as before.
   Archives are expanded from a stream over the view. Without a mapping, engines read the stream, which
   works up to 2 GiB.
3. **Limits.** `maxFileSizeMiB` defaults to **10240 (10 GiB)** and may be set up to 65536 (64 GiB). Content
   that is not a file (standard input) is still held in memory and sent in a message, so it stays
   limited to 1 GiB. If a file of 1 GiB or less cannot be mapped (some network or virtual file systems),
   it is streamed as before. Larger unmappable files are reported as not scanned.
4. **Time.** The per-item limit is 60 s plus 30 s per GiB (a 10 GiB file gets 6 minutes). The YARA-X timeout
   grows the same way (its base plus one second per 32 MiB).
5. Worker protocol 3: `AnalyzeDto.Section` (handle value); a request with a section carries no bytes.

## Consequences

- Large installers, disk images and archives are scanned instead of being listed as too large. On the
  owner's machine a 3 GiB test file with a marker at 2.5 GiB is detected through the sandbox in about 15 s.
  Videos and ISOs are still read in full by hashing and YARA, so scans of folders with many large media
  files take longer.
- While a section exists, other programs cannot truncate the file being scanned (Windows refuses to
  shrink a file below a mapped size). This lasts only for the scan of that file.
- If a mapped file becomes unreadable mid-scan (for example a removable drive is pulled out), the read
  faults inside the worker. The worker dies, is replaced, and the item is reported as not scanned. The
  scan continues.
- Quarantine still holds files only up to its own 1 GiB limit (ADR 0006). A larger confirmed detection is
  reported with "not quarantined: too large".
