# ADR 0022: Security posture checks and consented hardening

- Status: accepted (owner choice, 2026-11-21)
- Date: 2026-11-21
- Research: [attack-surface review](../research/attack-surface-review-2026-11.md)

## Context

The owner asked for protection against the common ways a PC is compromised, a check of the LAN connection,
a password before apps are installed, and the same ideas on Android. The research shows that most realistic
wins need no new engine: Windows already enforces strong controls in the kernel (UAC, Defender attack surface
reduction rules, the firewall), but they are often off or weakened. A user-mode companion cannot block a
process start or a file open without a driver (out of scope, AGENTS rule 6), and must never terminate
processes without a reviewed design. So Kshatriya **checks** the machine and, **with an administrator's
consent**, switches on Windows' own controls.

The owner chose (2026-11-21): install protection through the Windows password prompt, a LAN check, a Defender
and ASR health check, a startup-programs watch and an Android security check. The USB lock and the Kshatriya
password are in [ADR 0023](0023-removable-drive-lock.md).

## Decision

### Checks ("Security check")

A new pure library, `Kshatriya.Posture`, defines checks and evaluates them from snapshots; it reads nothing
itself, so every rule is unit tested. The service collects the snapshots (registry, WMI, IP Helper) as
LocalSystem and evaluates them on request. Each check has a stable id, an area, a state (`ok`, `info`,
`attention`, `risk`, `unknown`), a title, a detail line and optionally a fix id.

| Area | Checks |
|---|---|
| Defender | Real-time protection, tamper protection, signature age, cloud protection, each recommended ASR rule's state |
| Installs | UAC on (`EnableLUA`), admin prompt (`ConsentPromptBehaviorAdmin`), secure desktop, `AlwaysInstallElevated` (machine and the caller's own profile), Administrator protection (Windows 11, reported only) |
| USB | AutoRun for removable drives (`NoDriveTypeAutoRun`), the ASR USB rule, the removable-drive lock (ADR 0023) |
| Network | Firewall per profile, network category, SMBv1, listening ports with their programs, Remote Desktop and NLA, LLMNR, NetBIOS, DNS servers, hosts file entries, router admin page over plain HTTP, gateway hardware address and DNS changes |
| Startup | Run/RunOnce keys, startup folders, auto-start services, scheduled tasks, WMI event subscriptions |

- **Read-only.** Checks only read. The router check opens one TCP connection to the default gateway on port 80
  with a 1-second timeout; nothing else leaves the machine, and no login is ever attempted.
- **Wi-Fi security** needs the user's location consent, which a service cannot get. The desktop app reads it
  for the connected network (open, WEP or TKIP is `risk`).
- **Changes over time.** The service keeps a baseline (`posture-baseline.json` in its data folder: default
  gateway hardware address per network, DNS servers, startup entries). A new startup entry, a changed gateway
  hardware address on the same network or a changed DNS server is reported as a **suspicious** finding in the
  detection history and notified by the app. These are heuristics: they never trigger an action
  (AGENTS: heuristics report suspicious only). The program behind a new startup entry is scanned.
- **Privacy.** Any user may run the check. Other users' startup entries and `AlwaysInstallElevated` values
  are included only for an elevated administrator.

### Fixes (consented hardening)

| Fix id | Change | Undo |
|---|---|---|
| `uac.credentialPrompt` | `ConsentPromptBehaviorAdmin=1`, `PromptOnSecureDesktop=1`: administrators type their password for every install or change that needs admin rights | previous values |
| `msi.alwaysInstallElevated` | `AlwaysInstallElevated=0` (machine policy) | previous value |
| `autorun.removable` | `NoDriveTypeAutoRun` gains bit `0x04` (machine policy) | previous value or absence |
| `network.llmnr` | `EnableMulticast=0` (DNS client policy) | previous value or absence |
| `asr.<rule>` | Defender ASR rule set to audit, then (second step) block, through `MSFT_MpPreference` | previous state of that rule |

- **Strengthen only.** Every fix makes a Windows control stricter. No fix ever turns a control off, and no
  code path touches Defender exclusions or ASR exclusions (AGENTS rule 2). Undo only returns a value
  Kshatriya itself changed to what it was before.
- **Administrator and audit.** Applying or undoing a fix requires an elevated administrator and writes an
  audit record, including on refusal and failure (`hardeningApply`, `hardeningUndo`).
- **Reversible.** Before a change the service records the previous value (or its absence) in
  `hardening.json` (SYSTEM and Administrators only). Undo restores exactly that. If the value was changed
  by someone else since, undo refuses rather than overwrite it.
- **Managed machines.** If a value is set by domain Group Policy or MDM, the service reports it and refuses
  to change it.
- **Install protection.** Windows only prompts for installers that need admin rights; installers that write
  only to the user's own profile are not covered, and the app says so. App Control for Business would cover
  them but can break software, so it needs its own ADR. Administrator protection (Windows 11) needs a
  restart and has known incompatibilities; it is reported with instructions, not switched on by Kshatriya.
- **ASR rules offered:** USB (`b2b3f03d-…`), LSASS credential theft (`9e6c4e1f-…`), Office child processes
  (`d4f940ab-…`), Office executable content (`3b576869-…`), WMI persistence (`e6db77e5-…`), email executable
  content (`be9ba2d9-…`), script-launched downloads (`d3e037e1-…`), vulnerable signed drivers (`56a863a9-…`),
  obfuscated scripts (`5beb7efe-…`, needs cloud protection) and advanced ransomware protection
  (`c1db55ab-…`, needs cloud protection). States: 0 off, 1 block, 2 audit, 6 warn. Audit comes first so the
  user can see what a rule would have blocked before choosing block.

### Protocol and clients

- Service protocol 12: `PostureQuery`/`PostureReply` and `HardeningRequest` (fix id, apply or undo, ASR mode)
  answered with `OperationReply`.
- CLI: `kshatriya check [--json]`, `kshatriya harden <fix> [--undo] [--block]`.
- Desktop app: the Protection page gains a Security check section grouped by area, with a Fix button per
  fixable item (the app elevates on request, as for restore) and Undo for applied fixes. Home lists `risk`
  items as recommendations through the shared status model.

### Android

Kshatriya on Android is an ordinary app: it cannot block installs or USB transfers without being device owner
(factory reset and provisioning), which a consumer app must not require. It **checks** instead: USB debugging,
developer options, screen lock, apps that can install other apps, and (Android 16) Advanced Protection Mode.
Each result explains how to change the setting in Android's own Settings. A managed "family device" build
would need its own ADR.

## Consequences

- Kshatriya can tell a user, in one place, which Windows protections are off and switch most of them on.
- A machine with no admin rights gets a report but no fixes.
- ASR rules can block legitimate tools; audit first, undo always available.
- Posture checks run on demand and on the existing status refresh (every 6 hours for the baseline); they
  add no permanent background load beyond the existing IP Helper change notifications.
- Router, gateway and DNS alerts can be false positives (new router, VPN). They are suspicious only.
