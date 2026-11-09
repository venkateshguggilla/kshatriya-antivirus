# ADR 0010: Ransomware behaviour detection (user mode, alert only)

- Status: accepted (M8)
- Date: 2026-11-08

## Context

Signatures miss new ransomware. Behaviour gives earlier warning, but in user mode file events carry no
process identity, and Kshatriya may not terminate processes without a reviewed design (AGENTS.md).
Microsoft Defender already offers real blocking for protected folders (Controlled folder access).

## Decision

`RansomwareDetector` runs inside real-time monitoring ([ADR 0009](0009-user-mode-real-time-monitoring.md))
and raises **suspicious** behaviour findings only:

| Signal | Rule |
|---|---|
| Mass modification | ≥ threshold (default 40) distinct **existing** files changed, renamed or deleted within the window (default 30 s), confirmed by renames to unfamiliar extensions (≥ half) or encrypted-looking samples (≥ half of up to 12 sampled files with entropy ≥ 7.5 bits/byte). Writes to files created within the window (downloads, unzip, builds) do not count. |
| Ransom note | A new `.txt/.html/.hta/.url/.rtf` file whose name combines a threat word (decrypt, ransom, restore, recover, encrypted) with an instruction word (files, readme, how, instruction, help). |
| Recovery tampering | A started command that deletes shadow copies or backups or disables recovery (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit … recoveryenabled no`, `wbadmin delete catalog/systemstatebackup`, `Win32_ShadowCopy` deletion). |
| Decoy touched (opt-in) | A hidden decoy in a configured folder is changed, renamed or deleted. Decoys are recreated within seconds. |

- Alerts are cooled down per signal and location (5 minutes), logged as critical (event 8000), added to
  the detections history and counted in status. They list programs started from user-writable folders
  in the last 10 minutes as **possible** sources.
- **No automatic action:** nothing is terminated, blocked or quarantined because of a behaviour alert.
- Content entropy is computed in the service from the first 4 KiB, read through `SafeFileOpener`
  (no parsing; same class of operation as hashing).
- The app shows Defender's Controlled folder access state (read-only, WMI `MSFT_MpPreference`) and
  recommends turning it on. Kshatriya never changes it.
- Decoys are opt-in (`ransomware.canaryFolders`, inside real-time paths) because they create files in
  user folders.

## Consequences

- This warns; it does not stop encryption in progress. Stopping needs process attribution (ETW file I/O
  or a minifilter) and a reviewed termination design.
- Thresholds are untuned guesses: no ransomware corpus has been run against them. False positives are
  possible (for example bulk encryption by a legitimate tool, or mass renames); they are reported as
  suspicious only.
