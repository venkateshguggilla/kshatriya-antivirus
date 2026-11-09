# ADR 0016: Quick, full, drive and custom scans

- Status: accepted
- Date: 2026-11-09

## Context

Kshatriya scanned only the paths a user typed or picked. Antivirus products usually offer a **quick
scan** (where malware starts from or lands), a **full scan** (everything), a **drive scan** (for example a
USB stick) and a **custom scan**, plus "Scan with ..." in Explorer's right-click menu. A quick scan needs
targets that change all the time (startup entries, running processes), more of them than the service's
limit of 64 paths per request, and the same logic for scheduled scans.

## Decision

1. **Targets in one place.** `Kshatriya.Scanning.Targets.ScanTargets` builds them. Gathering (registry,
   processes, drives) is kept apart from selection (command-line parsing, de-duplication, the profile
   rule), so the selection is unit-tested with fake file systems.
   - **Quick:** in each covered profile, `Downloads`, `Desktop`, `AppData\Local\Temp` and the per-user
     Startup folder; the all-users Startup folder; `%SystemRoot%\Temp` for administrators and schedules;
     the programs named by the HKLM and per-user `Run`/`RunOnce` keys (including WOW6432Node) and by
     Winlogon `Shell`/`Userinit`; the image of every Win32 service; and the executable of every running
     process. Command lines are resolved to files: quotes, environment variables, unquoted paths with
     spaces, a missing `.exe`, `\SystemRoot\` and `\??\` prefixes, bare names in System32, and the DLL
     run by `rundll32`/`regsvr32`. Scheduled tasks are not covered yet: their definitions need
     administrator rights to read.
   - **Full:** the root of every ready fixed drive.
   - **Drive:** a drive root as a custom path (`E:\`), so removable drives work too.
2. **Protocol 8.** `ScanRequestDto.Kind` is `custom` (default), `quick` or `full`; quick and full requests
   carry no paths, and the service determines the targets. Protocol 7 clients are refused by the
   exact-version handshake, as before.
3. **Privacy.** For a quick scan a user starts, the service gathers the targets as itself but keeps only
   system locations and the caller's own profile (the `Public` profile is shared); nothing inside another
   user's profile is scanned or named. Every file is still opened while impersonating the caller, so a
   full scan by a standard user reports protected files as not scanned (access denied). Running the app or
   CLI as an elevated administrator covers more.
4. **Schedules.** `"scan": "quick" | "full"` (no `"paths"`). The targets are resolved each time the schedule
   runs, as the service, covering all profiles, and the verdict cache is skipped as for every schedule.
5. **App and Explorer.** The Scan page offers Quick scan, Full scan, a drive picker (ready fixed and
   removable drives) and the custom list; at most 2,000 result rows are shown, findings first. The
   installer registers "Scan with Kshatriya Antivirus" for files, folders and drives
   (`Kshatriya.App.exe --scan "%1"`); each opens its own scan window, separate from the tray instance.
   Uninstall removes the entries.
6. The CLI gets `--quick` and `--full`, with or without `--service`.

## Consequences

- A full scan of a system drive takes a long time (on the owner's machine a quick scan took about 35 s for
  57,000 files; a full scan covers several hundred thousand). It keeps running while the app sits in the
  notification area; closing the app cancels it.
- Not covered: boot-time scans and memory scans, which need kernel components (out of scope until the
  user-mode design is reviewed); scheduled tasks, WMI subscriptions and browser extensions as
  persistence locations.
- On Windows 11 the Explorer entry appears under "Show more options" (the classic menu). Adding it to the
  new menu needs a packaged app with a shell extension, which ADR 0013 decided against.

## Amendment (2026-11-09): external drives and a desktop shortcut

- **External drive scan** (`"kind": "external"`, CLI `--external`, schedules `"scan": "external"`): every connected external drive. A drive is external when Windows marks it removable or its storage bus (from `IOCTL_STORAGE_QUERY_PROPERTY`, which needs no access rights) is USB, SD/MMC or FireWire. Without this, USB hard disks and SSDs, which Windows reports as fixed, were treated as internal. A user scan with no external drive gets "No external drive is connected"; a schedule with none records "nothing to scan" and waits for its next occurrence. Protocol 9.
- **Real-time removable-media monitoring** uses the same rule, so a USB hard disk or SSD is scanned when it is attached, not only USB sticks.
- **App:** an "External drives" button, drive labels showing internal or external with the device name (for example "External drive (USB) SanDisk Ultra"), and a notification when an external drive is plugged in (checked every 3 seconds). If real-time protection scans new drives, the notification says it is being scanned; otherwise clicking it scans that drive. Drives connected when the app starts are not announced.
- **Desktop shortcut** for all users (Public desktop), removed on uninstall.
