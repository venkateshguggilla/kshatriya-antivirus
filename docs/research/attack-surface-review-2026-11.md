# Attack surface review: how Windows PCs get compromised, and what a user-mode companion can do (November 2026)

Input for future feature work and ADRs. Sources were retrieved on 2026-11-21. Kshatriya runs in user mode as a
LocalSystem service next to Microsoft Defender ([ADR 0002](../adr/0002-defender-companion-mode.md)). Nothing here
proposes disabling, weakening or excluding anything from Defender or any other Windows security control
([AGENTS.md](../../AGENTS.md), rule 2), and kernel-mode code stays out of scope (rule 6).

How to read the labels:

- **Verified**: we fetched and read the primary page during this review.
- **Reference**: a primary page (Microsoft Learn, MITRE, Android developers, CISA, NIST) that we linked from
  known documentation but did not re-open during this review. Check it before quoting it in an ADR.
- **Snippet**: the fact comes from a search engine's extract of the named page. Lower confidence.
- **Recommendation**: our own opinion. It is not a sourced fact.

Unlabelled MITRE ATT&CK links in section 1 are **Reference**.

What a companion can do is graded on four levels throughout:

- **Detect**: observe and report an event (Kshatriya's existing monitoring, scanning and alerts).
- **Audit**: read a configuration and report a weakness, read-only.
- **Harden (consent)**: make a change that *strengthens* Windows, only after the user asks, as an elevated
  administrator, written to the audit log, and reversible (the same rules ADR 0006 applies to file changes).
- **Nothing**: not realistically possible in user mode. **Kernel** marks things that would need a driver.

## 1. Catalogue of compromise paths, by ATT&CK tactic

### 1.1 Initial access

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| Phishing attachments | [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | SmartScreen and Mark-of-the-Web ([SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/), Reference); ASR "Block executable content from email client and webmail" ([ASR reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference), Verified) | Detect (scan new downloads, already done). Audit SmartScreen state. Harden (consent): turn on ASR rules. |
| Phishing links | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | SmartScreen; Defender network protection ([network protection](https://learn.microsoft.com/en-us/defender-endpoint/network-protection), Reference) | Detect: signed web blocklist and extension (ADR 0018/0019). Audit network protection state. |
| Malicious Office macros | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Office blocks macros in files from the internet by default ([internet macros blocked](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked), Reference); ASR "Block Win32 API calls from Office macros", "Block all Office applications from creating child processes" (Verified, ASR reference) | Detect (YARA rules on documents). Harden (consent): ASR rules. |
| Drive-by downloads, browser exploits | [T1189](https://attack.mitre.org/techniques/T1189/), [T1203](https://attack.mitre.org/techniques/T1203/) | SmartScreen; Exploit protection ([exploit protection](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection), Reference); patching | Detect (download scans). Audit: browser and OS patch level against CISA KEV ([KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), Reference). |
| Malicious USB: AutoRun | [T1091](https://attack.mitre.org/techniques/T1091/) | `NoDriveTypeAutoRun` / AutoPlay policies ([AutoRun registry](https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg), Verified) | Audit. Harden (consent). See 3a. |
| Malicious USB: LNK and lure files | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | ASR "Block untrusted and unsigned processes that run from USB" (Verified, ASR reference) | Detect (USB auto-scan, already done). Harden (consent): ASR rule. |
| BadUSB / HID keystroke injection | [T1200](https://attack.mitre.org/techniques/T1200/) | Device installation restrictions ([manage device installation](https://learn.microsoft.com/en-us/windows/client-management/client-tools/manage-device-installation-with-group-policy), Verified) | Detect: "new keyboard connected" alert. Harden is risky (see 3a). Real blocking of injected keystrokes: **Kernel**. |
| Rogue installers, trojanised software | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Smart App Control, App Control for Business, UAC (see 3b) | Detect (scan installers). Audit SAC state. Harden (consent): see 3b. |
| Supply chain | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Code signing, SmartScreen reputation, App Control | Detect only when a signature or rule exists. Mostly nothing. |
| Exposed RDP/SMB, brute force | [T1133](https://attack.mitre.org/techniques/T1133/), [T1110](https://attack.mitre.org/techniques/T1110/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Windows Firewall, NLA, account lockout ([lockout threshold](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold), Reference) | Audit (section 4). Detect: failed-logon bursts in the Security log (event 4625, [event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625), Reference). |
| Unpatched software exploits | [T1190](https://attack.mitre.org/techniques/T1190/), [T1203](https://attack.mitre.org/techniques/T1203/) | Windows Update; Exploit protection | Audit: last update install, pending reboot. CISA ranks known-exploited flaws first (KEV, Reference). |

### 1.2 Execution

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | AMSI ([AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal), Reference); script block logging ([about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows), Reference); App Control script enforcement (Verified, [feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)) | Detect: process-start command lines (already WMI). Audit: script block logging off. Harden (consent): turn logging on. |
| VBScript/JScript droppers | [T1059.005](https://attack.mitre.org/techniques/T1059/005/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | ASR "Block JavaScript or VBScript from launching downloaded executable content" (Verified) | Harden (consent): ASR rule. |
| MSHTA and other LOLBins | [T1218.005](https://attack.mitre.org/techniques/T1218/005/), [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | App Control "recommended block rules"; ASR "Block use of copied or impersonated system tools" (Verified) | Detect: suspicious parent/child chains (heuristic, Suspicious only). Blocking before start: **Kernel** (see 3b). |

### 1.3 Persistence

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| Run/RunOnce keys, Startup folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | None preventive; Defender scans | Detect: enumerate and diff autostart entries, scan their targets. Report changes. |
| Scheduled tasks | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | None preventive | Detect: enumerate tasks (Task Scheduler API), diff, scan actions. |
| Services | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Service creation needs admin | Detect: diff services, scan binaries. |
| WMI event subscriptions | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | ASR "Block persistence through WMI event subscription" (Verified; a "standard protection" rule) | Detect: list `__EventConsumer`/`__FilterToConsumerBinding` in `root\subscription`. Harden (consent): ASR rule. |

**Recommendation:** an "autostart inventory" with change alerts is a high-value, purely read-only feature. Remediation
of an entry belongs in `Kshatriya.Response` with backup and restore, never silent deletion.

### 1.4 Privilege escalation

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| Kernel/driver exploits, vulnerable drivers | [T1068](https://attack.mitre.org/techniques/T1068/) | Memory integrity (HVCI) ([HVCI](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity), Reference); vulnerable driver blocklist ([driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), Reference); ASR "Block abuse of exploited vulnerable signed drivers" (Verified) | Audit: HVCI and blocklist state. Harden (consent): ASR rule. Blocking driver loads: **Kernel** (Windows does it). |
| UAC bypass | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | UAC level; Administrator protection (see 3b) | Audit: `EnableLUA`, `ConsentPromptBehaviorAdmin` (Verified, [UAC settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)). |
| `AlwaysInstallElevated` MSI abuse | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Leave policy off ([AlwaysInstallElevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated), Reference) | Audit: flag if set. Harden (consent): clear it. |

### 1.5 Defence evasion

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| Tampering with Defender, adding exclusions | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Tamper Protection ([tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection), Reference) | Audit: read `Get-MpComputerStatus` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), Reference) and `Get-MpPreference` for real-time protection off, tamper protection off, new exclusions. Alert loudly. Kshatriya never changes Defender exclusions. |
| Disabling the firewall | [T1562.004](https://attack.mitre.org/techniques/T1562/004/) | Windows Firewall | Audit (section 4). Harden (consent): re-enable a profile. |
| Reboot into Safe Mode to evade | [T1562.009](https://attack.mitre.org/techniques/T1562/009/) | ASR "Block rebooting machine in Safe Mode" (Verified) | Harden (consent): ASR rule. |

### 1.6 Credential access

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| LSASS memory dumping | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSA protection ([LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection), Reference); Credential Guard (Enterprise/Education only, Verified, [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)); ASR LSASS rule, which the ASR reference says adds nothing if LSA protection is on (Verified) | Audit: `RunAsPPL`, Credential Guard state. Harden (consent): ASR rule on Pro/Home. |
| Browser credential theft | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | None specific | Detect (signatures). Mostly nothing. |
| LLMNR/NBT-NS poisoning | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Turn off multicast name resolution; disable NetBIOS over TCP/IP (section 4) | Audit. Harden (consent). |

### 1.7 Lateral movement and LAN attacks

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| SMB/admin shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Firewall; SMB signing ([SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing), Reference) | Audit: listening 445, share list, signing. |
| SMBv1 exploits (EternalBlue class) | [T1210](https://attack.mitre.org/techniques/T1210/) | Remove SMBv1 ([detect/disable SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3), Reference) | Audit. Harden (consent): disable feature (needs restart). |
| RDP | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | NLA, firewall scope | Audit (section 4). |
| ARP spoofing | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | None on a home LAN (switch features only) | Detect: gateway MAC change (heuristic, Suspicious). Prevent: **Nothing** in user mode. |
| Rogue Wi-Fi / evil twin | [T1557.004](https://attack.mitre.org/techniques/T1557/004/) (Verified) | WPA3, profile hygiene; guidance in [NIST SP 800-153](https://csrc.nist.gov/pubs/sp/800/153/final) (Reference) | Audit: open/WEP/WPA2-TKIP network in use. |
| DNS hijack via router or hosts file | CISA [ED 19-01](https://www.cisa.gov/news-events/directives/ed-19-01-mitigate-dns-infrastructure-tampering) on DNS tampering (Reference) | Defender detects hosts hijacks as `SettingsModifier:Win32/HostsFileHijack` ([encyclopedia](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=SettingsModifier:Win32/HostsFileHijack), Reference) | Detect: DNS server changes, hosts file diffs. Router internals: **Nothing** (see 4.10). |

### 1.8 Impact

| Path | ATT&CK | Windows built-in control | Companion role |
| --- | --- | --- | --- |
| Ransomware | [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/) | Controlled folder access ([CFA](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders), Reference); ASR "Use advanced protection against ransomware" (Verified); backups per [CISA #StopRansomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) (Reference) | Detect (ADR 0010, Suspicious only). Detect `vssadmin delete shadows`-style commands at process start. Audit CFA. Harden (consent): CFA, ASR. |
| Wipers | [T1485](https://attack.mitre.org/techniques/T1485/), [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | Raw disk writes need admin; CFA | Detect (behaviour). Blocking raw writes: **Kernel**. |
| Bootkits, firmware | [T1542.003](https://attack.mitre.org/techniques/T1542/003/), [T1542.001](https://attack.mitre.org/techniques/T1542/001/) | Secure Boot, Measured Boot, BitLocker ([BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/), Reference) | Audit: `Confirm-SecureBootUEFI` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi), Reference), BitLocker status. Firmware integrity: **Nothing/Kernel**. |

NIST's malware prevention guide puts the same weight on configuration hardening and user awareness as on
antivirus ([SP 800-83r1](https://csrc.nist.gov/pubs/sp/800/83/r1/final), Reference). That supports an "audit and
harden with consent" pillar next to scanning.

### 1.9 A note on Defender-dependent controls

ASR rules "are a Microsoft Defender Antivirus feature that's available on any edition of Windows that includes
Microsoft Defender Antivirus (for example, Windows 11 Home)". They can be set locally with PowerShell or Group
Policy, without Defender for Endpoint (Verified, ASR reference). Most rules list "Microsoft Defender Antivirus" as a
dependency, and several also need cloud protection (Verified). Kshatriya's companion mode keeps Defender as the
active antivirus, so these rules stay available. That makes switching them on (with consent, in Audit mode first)
the cheapest big win for a companion app.

## 2. What user mode cannot do (summary)

- **Block a process before it starts.** WMI `Win32_ProcessStartTrace` and ETW report a process after it was
  created. Only a kernel callback registered with `PsSetCreateProcessNotifyRoutineEx` runs during creation
  (Verified, [DDI page](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)).
  Its `PS_CREATE_NOTIFY_INFO.CreationStatus` field lets a driver fail the creation
  ([struct](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info),
  Reference). Registration fails unless the image has `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (Verified). In user
  mode the only remaining response is termination, which AGENTS.md forbids.
- **Block opening a file on a USB drive until something happens.** That needs a file-system minifilter
  ([filter manager concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts),
  Reference): **Kernel**.
- **Stop injected HID keystrokes, ARP spoofing or firmware writes.** **Kernel** or network hardware.

**Recommendation:** the way around this is to *configure Windows' own kernel-enforced controls* (ASR, App Control,
Smart App Control, Removable Storage Access, device installation restrictions, UAC). Each change must be opt-in,
audited, reversible and strengthening. That keeps Kshatriya in user mode and within ADR 0002.

## 3. Deep dive: the owner's three requested features

### 3a. Block running or opening files on USB drives until the user enters a password

**Mechanisms Microsoft documents:**

1. **Removable Storage Access policies (Verified,
   [ADMX_RemovableStorage CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-removablestorage)).**
   - "Removable Disks: Deny execute access", "Deny read access" and "Deny write access" are the values `Deny_Execute`,
     `Deny_Read` and `Deny_Write` under
     `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`. The
     same policies exist for the current user under HKCU.
   - "All Removable Storage classes: Deny all access" sits at the `RemovableStorageDevices` key and "takes
     precedence over any individual removable storage policy settings".
   - Editions listed: Pro, Enterprise, Education, IoT Enterprise. Home is not listed.
   - **Timing:** the companion "Set time (in seconds) to force reboot" policy says: "If no reboot is forced, the
     access right doesn't take effect until the operating system is restarted." The policies are **per storage
     class, not per device**.
   - **Recommendation:** whether a direct registry write takes effect on the next mount without a restart is not
     documented. We must test it on Windows 10 22H2 and Windows 11 24H2/25H2 before promising anything.
2. **AutoRun/AutoPlay (Verified,
   [AutoRun registry](https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg)).** `NoDriveTypeAutoRun`
   bit `0x04` disables AutoRun for removable drives. Microsoft says "You must restart Windows Explorer before the
   changes take effect", and that applications should not change these values "as there is no way to reliably
   restore them". AutoRun.inf launching from USB sticks was already curtailed by
   [KB971029](https://support.microsoft.com/kb/971029) (Reference). This is an *audit* item, plus a harden-with-consent
   option that records the previous value. On its own it is not a password gate.
3. **ASR "Block untrusted and unsigned processes that run from USB"** (GUID `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`,
   Verified).
   - It blocks unsigned or untrusted `.exe`, `.dll` and `.scr` files from running from USB drives and SD cards. It
     does *not* block copying, but it blocks the copied files from running from disk.
   - Available on any edition with Defender Antivirus. It can be set locally with `Add-MpPreference
     -AttackSurfaceReductionRules_Ids … -AttackSurfaceReductionRules_Actions Enabled|AuditMode|Warn`
     ([configure ASR](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure),
     Reference).
   - It is a policy, not a per-device switch. Signed malware and documents are not covered.
4. **Defender Device Control (Verified,
   [overview](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview)).**
   - Per-device read/write/execute rules matched on VID_PID, serial number and similar properties. Needs anti-malware
     client 4.18.2103.3 or later and runs on Windows 10/11 (not servers). Policy can be deployed by Group Policy.
   - It applies only to devices that "create a disk (such as `E:`)", plus portable devices, CD/DVD and printers.
   - It is a Defender for Endpoint feature. The page we read does not say whether it is supported without a Defender
     for Endpoint licence or onboarding. Treat it as an enterprise option, not a consumer one.
5. **Device installation restrictions (Verified,
   [manage device installation](https://learn.microsoft.com/en-us/windows/client-management/client-tools/manage-device-installation-with-group-policy)).**
   - Prevent installation by device ID, instance ID or setup class. Applies to the whole machine, with an optional
     "Allow administrators to override" exemption.
   - "All 'Prevent' policies can apply the block functionality to already installed devices". Microsoft warns that
     doing this retroactively for crucial classes "could render the machine useless". The walkthroughs check the
     result after a restart.
   - For BadUSB: blocking the keyboard/HID class would also block the user's own keyboard. An allowlist by instance
     ID is fragile, and a malicious device can present a legitimate-looking ID.
   - **Recommendation:** a "lock new keyboards" mode is too risky to ship as a default.

**Can a LocalSystem service toggle these per device at runtime?** Partly, with gaps:

- LocalSystem *can* write the HKLM policy values and call `Add-MpPreference`. On a domain-joined or
  Intune-managed PC, Group Policy or MDM refresh may overwrite local values. Kshatriya should detect managed policy
  and refuse to fight it.
- Removable Storage Access is per class, and its documented activation is a restart, so it is not a per-device gate.
- Per device, a service can *disable the device node* with `CM_Disable_DevNode`
  ([cfgmgr32](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode),
  Reference) after an arrival notification from `CM_Register_Notification`
  ([cfgmgr32](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_register_notification),
  Reference). It can re-enable the node after the user authenticates. **Limitation:** the volume is mounted and
  usable for a short window before the service reacts. That makes it a convenience lock, not a security boundary.
  Closing the window needs a minifilter (**Kernel**).
- The "password" must be the user's Windows credential or Windows Hello. Use `UserConsentVerifier`
  ([WinRT](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier), Reference)
  or a UAC elevation from the desktop app. Kshatriya must never invent its own password store.
- A built-in "password before opening" already exists: **BitLocker To Go** encrypts the drive itself, and Windows can
  deny writes to removable drives that are not BitLocker-protected (BitLocker,
  [configure](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure),
  Reference).

**Recommendation for 3a:** ship in this order:

1. Audit AutoRun, the ASR USB rule and the Removable Storage policies.
2. One-click, consented, reversible "USB hardening": the ASR USB rule in Audit mode, then Block; AutoRun off for
   removable drives.
3. Keep the existing auto-scan on arrival, with clear "not yet scanned" status.
4. An optional "lock removable drives until I approve" mode using device-node disable, labelled honestly as a race-prone
   convenience feature. Only after testing.

A true block-until-password is not possible in user mode.

### 3b. Require a password before installing apps

- **UAC, standard accounts (Verified,
  [UAC settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)).**
  - The default for standard users is "Prompt for credentials". `ConsentPromptBehaviorUser` = 3; 1 shows the
    credential prompt on the secure desktop.
  - Installer detection (`EnableInstallerDetection`) is listed as enabled by default on Home only.
  - **Recommendation:** running daily as a standard user is the strongest built-in "password to install" for
    anything that needs elevation.
- **UAC, admin accounts (Verified, same page).** `ConsentPromptBehaviorAdmin` = 5 by default (consent for
  non-Windows binaries). Value **1 = "Prompt for credentials on the secure desktop"** makes an admin type a password
  for every elevation. The values live under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. This is
  a clean harden-with-consent change.
- **Administrator protection (Verified,
  [overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)).**
  - Windows 11 only (Home, Pro, Enterprise, Education). Available with KB5120998 (August 2026), off by default.
  - It requires Windows Hello authentication for each elevation, gives no auto-elevation, and uses an isolated admin
    token. A restart is required.
  - It is enabled by the policy "User Account Control: Configure type of Admin Approval Mode".
  - Known incompatibilities: Hyper-V hosts, LAPS-managed devices, some apps.
  - **Recommendation:** offer it on Windows 11 as the preferred option, with the incompatibility list shown before
    the user agrees.
- **Gap:** UAC only gates installers that elevate. Per-user installers that write to `%LOCALAPPDATA%` never trigger
  UAC. Blocking those needs an application control policy.
- **App Control for Business / WDAC (Verified,
  [feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)).**
  - "App Control PowerShell cmdlets aren't available on Home edition, but policies are effective on all editions."
  - It enforces `.exe`, `.dll`, `.msi` and scripts. Policies are device-wide, and it can be deployed by script
    ([script deployment](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script),
    Reference).
  - **Recommendation:** a badly built policy can block needed software or drivers. We would ship only Microsoft's
    templates, Audit mode first, and a tested rollback.
- **AppLocker (Verified, same page).** "Policies are supported on all editions Windows 10 version 2004 and newer with
  KB 5024351". It supports per-user rules, which WDAC does not. Microsoft's ASR page lists AppLocker as a protection
  for older systems, and App Control is the strategic option (Verified, ASR reference).
- **Smart App Control (Verified,
  [overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)).**
  - Blocks "Malware, Potentially Unwanted Apps (PUA), and unknown, unsigned code". It runs in evaluation or
    enforcement mode, and its state shows in Windows Security > App & browser control.
  - Snippet: Microsoft says that since the April 2026 Windows 11 25H2 update it can be turned on without a clean
    install ([SAC FAQ](https://support.microsoft.com/windows/smart-app-control-faq-285ea03d-fa88-4d56-882e-6698afdb7003)).
  - It does not ask for a password. It blocks by reputation. Companion role: audit and explain.
- **"Choose where to get apps" (Verified,
  [SmartScreen CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen)).**
  - `EnableAppInstallControl`: 1 = Store only, 3 = warn before installing apps from outside the Store. Group Policy
    "Configure App Install Control", registry value `ConfigureAppInstallControlEnabled`.
  - Editions: Pro and above.
  - It "will block installation only while the device is online". Offline blocking also needs
    `EnableSmartScreenInShell` and `PreventOverrideForFilesInShell`.
- **Windows Installer policies (Reference).** `DisableMSI` can stop Windows Installer for non-managed apps
  ([DisableMSI](https://learn.microsoft.com/en-us/windows/win32/msi/disablemsi)). `AlwaysInstallElevated` makes every
  MSI install with system rights when set in both HKLM and HKCU
  ([AlwaysInstallElevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)), and MITRE
  records attackers abusing it ([T1218.007](https://attack.mitre.org/techniques/T1218/007/)). Audit: flag it as high
  risk. `DisableMSI` breaks updates of legitimate apps, so do not offer it to consumers.
- **Why Kshatriya cannot simply intercept installs:** see section 2. By the time WMI reports `setup.exe`, it is
  already running, and the only response is termination, which is forbidden. Windows' own engines (UAC, App Control,
  AppLocker, SAC) enforce in the kernel. Kshatriya can configure them but cannot replace them.

**Recommendation for 3b:**

- Offer an "Install protection" card with three consented options: a standard daily account (guidance), the UAC
  credential prompt for admins (`ConsentPromptBehaviorAdmin=1`), and Administrator protection on Windows 11.
- Add the warn-mode App Install Control on Pro.
- Audit `AlwaysInstallElevated`.
- Keep App Control for a later, separately reviewed ADR.

### 3c. Android: blocking app installs or USB file transfer without root

- **User restrictions need device owner or profile owner rights.**
  - `DISALLOW_USB_FILE_TRANSFER` (API 18) "can only be set by a device owner or a profile owner on the primary
    user's profile or a profile owner of an organization-owned managed profile". When a device owner sets it, "it
    applies globally" (Verified,
    [UserManager](https://developer.android.com/reference/android/os/UserManager)).
  - `DISALLOW_INSTALL_APPS` (API 18) "also prevents device owners and profile owners installing apps".
  - `DISALLOW_INSTALL_UNKNOWN_SOURCES` (API 18) and `DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY` (API 29) control the
    unknown-sources setting. Unknown sources exclude adb and trusted app stores.
  - `DISALLOW_DEBUGGING_FEATURES` and `DISALLOW_MOUNT_PHYSICAL_MEDIA` cover USB debugging and external media.
  - All are set through `DevicePolicyManager.addUserRestriction` and cleared with `clearUserRestriction` (Verified,
    UserManager and [dedicated devices cookbook](https://developer.android.com/work/dpc/dedicated-devices/cookbook)).
    An ordinary app is not an admin, so it cannot call them.
- **Becoming device owner (Verified, cookbook).**
  - The development path is `adb shell dpm set-device-owner` on a device with no accounts. For customers, Google
    points to other enrolment methods and recommends QR-code enrolment.
  - The documented provisioning flows run during setup of a new or factory-reset device
    ([provisioning](https://developers.google.com/android/work/play/emm-api/prov-devices), Reference).
  - That is not acceptable for a consumer antivirus on an already set-up personal phone.
- **Legacy device admin is deprecated.** Snippet: Google deprecated device admin for enterprise use in Android 9.
  From Android 10, deprecated policies throw `SecurityException` for apps targeting API 29
  ([deprecation](https://developers.google.com/android/work/device-admin-deprecation)).
- **"Password before install" as device owner.** It *would* be technically possible: keep `DISALLOW_INSTALL_APPS` set,
  and clear it briefly after `BiometricPrompt`/device-credential authentication
  ([BiometricPrompt](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt),
  Reference). Only on a fully managed device, though.
- **What a normal app can do:**
  - Detect new installs and scan them (already part of ADR 0020).
  - Check the device's own protections. Android 16 Advanced Protection Mode blocks app sideloading and disables WEP
    and 2G. An app can query it with `QUERY_ADVANCED_PROTECTION_MODE` and `AdvancedProtectionManager` (Verified,
    [AAPM](https://developer.android.com/privacy-and-security/advanced-protection-mode)).
  - Guide the user to the per-app "Install unknown apps" setting and Play Protect.
- **Google Play policy limits (Reference).**
  - `QUERY_ALL_PACKAGES` is allowed only for permitted uses, and antivirus is among them
    ([package visibility policy](https://support.google.com/googleplay/android-developer/answer/10158779)).
  - Using the Accessibility API to intercept installer screens would breach the AccessibilityService policy
    ([policy](https://support.google.com/googleplay/android-developer/answer/10964491)).
  - Installing other apps without the user's consent is prohibited (Verified,
    [Device and Network Abuse](https://support.google.com/googleplay/android-developer/answer/16273414)).
- **USB file transfer** cannot be blocked by a normal app. Android itself requires the phone to be unlocked and the
  user to choose file transfer in USB preferences
  ([Android help](https://support.google.com/android/answer/9064445), Reference).

**Recommendation for 3c:**

- Do not ship a device-owner mode in the consumer app.
- Offer audit: unknown-sources grants per app, USB debugging on (readable from `Settings.Global.ADB_ENABLED`,
  [Settings.Global](https://developer.android.com/reference/android/provider/Settings.Global#ADB_ENABLED),
  Reference), AAPM state, Play Protect guidance.
- A separate, opt-in "managed family device" build could use QR provisioning later, under its own ADR.

## 4. Read-only LAN and network checks

All of these are reads. None sends traffic beyond the local gateway, and none tries a login.
[NIST SP 800-124r2](https://csrc.nist.gov/pubs/sp/800/124/r2/final) (Reference) covers the mobile equivalents.

| # | Check | Documented API / cmdlet | Finding to report |
| --- | --- | --- | --- |
| 4.1 | Firewall profile state | `Get-NetFirewallProfile` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile), Reference); COM `INetFwPolicy2` ([API](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2), Reference) | Any profile disabled; default inbound action Allow. |
| 4.2 | Network category | `Get-NetConnectionProfile` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile), Reference) | Public Wi-Fi marked Private (file sharing exposed). |
| 4.3 | SMBv1 | `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`, `Get-SmbServerConfiguration` (detect/disable SMBv1, Reference) | SMBv1 installed or enabled. |
| 4.4 | Listening ports and owners | `GetExtendedTcpTable`/`GetExtendedUdpTable` with owner PID ([API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable), Reference); `Get-NetTCPConnection -State Listen` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection), Reference) | Unexpected listeners on 0.0.0.0, mapped to a process and signer; flag 445, 3389, 5985 when the firewall allows them. |
| 4.5 | RDP and NLA | `fDenyTSConnections` under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`; `Win32_TSGeneralSetting.UserAuthenticationRequired` ([WMI](https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting), Reference) | RDP on without NLA; RDP allowed on Public profile. |
| 4.6 | LLMNR and NetBIOS | Policy `EnableMulticast` under `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` ([ADMX_DnsClient](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient), Reference); `Win32_NetworkAdapterConfiguration.TcpipNetbiosOptions` ([WMI](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration), Reference). Microsoft's networking team is ramping both down in favour of mDNS ([blog](https://techcommunity.microsoft.com/blog/networkingblog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/3290816), Reference) | LLMNR or NetBIOS on (T1557.001 exposure). Harden (consent). |
| 4.7 | Wi-Fi security | WinRT `ConnectionProfile.NetworkSecuritySettings` (`NetworkAuthenticationType`, `NetworkEncryptionType`) ([API](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.networksecuritysettings), Reference); `WlanQueryInterface` | Open, WEP or WPA/TKIP network. **Limitation (Verified):** `WlanQueryInterface` with `wlan_intf_opcode_current_connection` returns `ERROR_ACCESS_DENIED` without precise-location consent, and the consent prompt appears only for processes in the user's context ([Wi-Fi location changes](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)). Do this check in the desktop app, not the service, and test the WinRT path. |
| 4.8 | Gateway MAC changes (ARP spoofing signs) | `GetIpNetTable2` ([API](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2), Reference) / `Get-NetNeighbor` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netneighbor), Reference); default route from `Get-NetRoute` | Gateway MAC changed on the same SSID/network, or two IPs sharing the gateway MAC. Suspicious only: router replacements cause false positives. |
| 4.9 | DNS server changes | `Get-DnsClientServerAddress` ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress), Reference); `NotifyIpInterfaceChange` ([API](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange), Reference) | Statically set or DHCP-supplied resolver changed to an unknown public address. |
| 4.9b | Hosts file tampering | Read `%SystemRoot%\System32\drivers\etc\hosts` through `SafeFileOpener`; Defender's `HostsFileHijack` detection shows the threat is real (Reference) | Entries redirecting banks, update or security domains. Restore via `Kshatriya.Response` with backup. |
| 4.10 | Router admin exposure | Local only: TCP connect to the gateway on 80/443/8080 to see whether an admin page answers on the LAN. Internet-side exposure and router firmware cannot be judged from inside. Point users to CISA's SOHO guidance ([Secure by Design alert](https://www.cisa.gov/resources-tools/resources/secure-design-alert-security-design-improvements-soho-device-manufacturers), Reference) | "Your router's admin page is reachable over plain HTTP." Never try default passwords. |

**Recommendation:**

- Run these as a "Network check" scan type in the service, except Wi-Fi security, which runs in the user's app.
- Results use the existing finding categories, with posture findings separate from malware findings.
- Gateway-MAC and DNS-change alerts are Suspicious heuristics and never trigger automatic action.

## 5. Prioritised feature table

Priority: P1 = next milestone, P2 = later, P3 = research only.

| Feature idea | Threat addressed | Windows control used | Edition | Risk / limitation | Priority |
| --- | --- | --- | --- | --- | --- |
| Defender health audit (real-time, tamper protection, new exclusions, signature age) | T1562.001 | `Get-MpComputerStatus`, `Get-MpPreference` | All with Defender | Read-only; Kshatriya must never edit exclusions | P1 |
| ASR rules audit + consented enablement (Audit mode, then Block) | Macros, LOLBins, USB, WMI persistence, LSASS, ransomware | Defender ASR via `Add-MpPreference` | All with Defender AV active (Home included) | False positives; some rules need cloud protection; MDM may override | P1 |
| USB hardening pack (ASR USB rule, AutoRun off for removable drives) | T1091, T1204.002 | ASR, `NoDriveTypeAutoRun` | All (ASR); AutoRun registry all | Not a password gate; Explorer restart for AutoRun | P1 |
| Network check (firewall, profile, SMBv1, listeners, RDP/NLA, LLMNR/NetBIOS, DNS, hosts) | T1021, T1210, T1557.001, DNS hijack | Firewall, SMB, DNS client APIs | All | Read-only; hardening steps need restart in some cases (SMBv1) | P1 |
| Autostart inventory with change alerts | T1547.001, T1053.005, T1543.003, T1546.003 | Registry, Task Scheduler, SCM, WMI | All | Noise from updaters; remediation through Response only | P1 |
| Install protection: UAC credential prompt for admins | Rogue installers needing elevation | `ConsentPromptBehaviorAdmin=1` | All | Per-user installers bypass UAC; user friction | P1 |
| Install protection: Administrator protection | Same, plus silent elevation | UAC "type of Admin Approval Mode" | Windows 11 with KB5120998 | Restart; Hyper-V/LAPS/app incompatibilities | P2 |
| `AlwaysInstallElevated` audit and fix | T1218.007 | MSI policy | All | None significant | P1 |
| App Install Control (warn mode) | Trojanised downloads | SmartScreen `EnableAppInstallControl=3` | Pro+ | Online only unless SmartScreen shell policies set | P2 |
| Smart App Control status and explanation | Unknown or unsigned apps | SAC | Windows 11 | Cannot be configured by policy for consumers; audit only | P2 |
| Wi-Fi security warning (open/WEP/TKIP) | T1557.004, sniffing | WinRT network security settings | All | Location-consent limits on WLAN APIs | P2 |
| Gateway MAC / DNS change alert | T1557.002, DNS hijack | IP Helper notifications | All | False positives (router swap, VPN); Suspicious only | P2 |
| Boot integrity audit (Secure Boot, BitLocker, HVCI, driver blocklist) | T1542, T1068 | Secure Boot, BitLocker, VBS | All (BitLocker encryption Pro+) | Read-only; turning HVCI on can break drivers | P2 |
| Removable Storage Access deny-execute (class-wide) | USB malware | `RemovableStorageDevices` policies | Pro+ | Per class, documented as effective after restart; untested for live toggling | P2 |
| "Lock removable drives until approved" (device-node disable + Windows Hello) | USB malware, data theft | `CM_Disable_DevNode`, `UserConsentVerifier` | All | Race window before disable; convenience, not a boundary; real gate needs **Kernel** minifilter | P3 |
| New-keyboard alert (BadUSB) | T1200 | Device interface notifications | All | Detection only; blocking HID class can lock out the user | P2 alert, P3 blocking |
| App Control for Business templates | Unknown executables and scripts | WDAC | Policies on all editions; cmdlets not on Home | High breakage risk; needs its own ADR, Audit mode, rollback | P3 |
| Android posture audit (unknown-sources grants, ADB on, AAPM state) | Sideloaded malware | Android settings, AAPM API | Android (AAPM: 16+) | Cannot block without device owner | P2 |
| Android device-owner "family" build | App installs, USB transfer | `DevicePolicyManager` user restrictions | Factory-reset + QR provisioning | Not suitable for consumers; separate ADR | P3 |

## 6. Conclusions

1. The biggest realistic wins need no new engine. **Audit what is weak and, with consent, switch on Windows' own
   kernel-enforced controls**: ASR rules (Home included, while Defender is active), the UAC credential prompt or
   Administrator protection, the network posture fixes, and AutoRun.
2. **3a:** a true "block USB until password" cannot be built in user mode. The documented class-wide policies are
   effective after a restart, Defender Device Control is an enterprise feature, and device-node disabling leaves a race
   window. A minifilter would be needed, and kernel code is out of scope.
3. **3b:** a password before *elevated* installs is fully achievable with built-in UAC settings or Administrator
   protection. Per-user installs need App Control or AppLocker, which are effective on all current editions but risky
   to author. Kshatriya cannot intercept a process start without a driver, and terminating processes is forbidden.
4. **3c:** on Android, blocking installs or USB transfer needs device owner (factory reset plus provisioning) or a
   managed profile. A consumer Play app can only audit, guide, and rely on Play Protect and Advanced Protection Mode.
5. Every hardening action must follow the same rules as quarantine: an elevated administrator, an audit record
   (including on refusal), the previous value stored, one-click undo, and no change that weakens any Windows security
   control.
