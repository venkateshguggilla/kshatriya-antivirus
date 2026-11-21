# ADR 0023: Removable-drive lock and the Kshatriya password

- Status: accepted (owner choice, 2026-11-21); prototype
- Date: 2026-11-21
- Research: [attack-surface review, section 3a](../research/attack-surface-review-2026-11.md#3a-block-running-or-opening-files-on-usb-drives-until-the-user-enters-a-password)

## Context

The owner asked that every USB drive be blocked from running or opening anything when it is connected, until
someone enters a password chosen when Kshatriya was installed.

A true block (nothing on the drive can be read until the password is entered) needs a file-system minifilter
driver, and kernel code is out of scope (AGENTS rule 6). Windows' Removable Storage Access policies work per
storage class, not per drive, and take effect after a restart, so they cannot unlock one drive on demand.
Defender Device Control can target one device but is an enterprise feature. The research therefore offered
two parts, and the owner chose both:

1. **USB hardening** through Windows' own controls ([ADR 0022](0022-security-posture-and-hardening.md)): the
   ASR rule "Block untrusted and unsigned processes that run from USB" and AutoRun off for removable drives.
   These are enforced by Windows itself and close the most common USB attack (running a program from the
   drive).
2. **An approve lock**: Kshatriya disables each newly connected USB drive and enables it again when the
   password is entered. The owner chose a separate Kshatriya password rather than the Windows sign-in.

## Decision

### The lock

- **Opt-in.** Off until an elevated administrator turns it on (`kshatriya lock on` or the Protection page).
  Turning it on requires a Kshatriya password to exist.
- **Detection.** The service registers for disk device-interface arrivals (`CM_Register_Notification`,
  `GUID_DEVINTERFACE_DISK`), so it reacts within milliseconds instead of the 3-second removable-drive poll.
- **Which disks.** A disk is locked only if one of its ancestor device nodes is enumerated by `USB` (this
  covers USB mass storage and UAS drives, including USB hard disks). Never locked: the disk that holds the
  Windows volume, the boot volume or the Kshatriya program or data folder, and anything that is not a disk.
  Keyboards, mice and other USB devices are never touched; blocking them could lock the user out.
- **How.** `CM_Disable_DevNode` with `CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK` on the disk's device node:
  the drive's volumes disappear. **Not persistent** (no `CM_DISABLE_PERSIST`): after a restart or a re-plug
  the device starts enabled and is locked again, so a crash or uninstall can never strand a disabled device.
  When the service stops normally it enables the drives it locked.
  If the disk is in use, Windows vetoes a polite disable. The lock then retries every second for 30 seconds
  (state `locking`), because programs that read disk details (temperature monitors, indexers, antivirus) often
  hold a new disk open briefly; after that the drive is reported as "could not be locked" (`couldNotLock`) and
  the app always notifies the user. The program that vetoed is named from the Kernel-PnP event 225 in the
  System log (file name only). The lock never forces a disable.
- **When the service starts** with the lock on, USB disks already connected are left alone (they may hold
  open files) and listed as "connected before the lock started".
- **Unlock.** The app shows the locked drive (name, size) and asks for the Kshatriya password. The service
  checks it, enables the device node and remembers the device as approved until it is removed. The existing
  removable-drive scan then scans it as usual.
- **Honest limit.** A drive is mounted and usable for a short moment (typically well under a second) before
  the service disables it. In that moment AutoRun (off) and the ASR USB rule are the protection. The app and
  the README call this a convenience lock, not a security boundary, and recommend the USB hardening fixes.

### The Kshatriya password

- **Set at installation.** `Install-KshatriyaService.ps1` asks for it (twice, hidden input) unless
  `-NoLockPassword` is given, and hands it to the service over the pipe as an elevated administrator. It can
  be set later with `kshatriya password set`.
- **Storage.** Only a hash is stored: PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt, 32-byte
  output (`lock.json` in the service data folder, SYSTEM and Administrators only, written through
  `SecureStorage`). Comparison is constant-time. The password itself is never logged, audited or written
  anywhere; it is cleared from memory as soon as it is hashed.
- **Rules.** At least 8 characters. After 5 wrong attempts in a row, each further attempt waits 30 seconds,
  doubling up to 15 minutes. The delay is service-wide (reconnecting does not reset it) and resets after a
  correct password.
- **Who may do what.** Unlocking a drive needs the Kshatriya password and nothing else: it only returns the
  drive to Windows' normal behaviour, which is never weaker than Windows without Kshatriya. Turning the lock
  off, setting the password the first time and resetting a forgotten password need an elevated administrator
  (AGENTS: operations that weaken protection). Changing the password as a non-administrator needs the
  current password.
- **Audit.** Every unlock (succeeded or wrong password), lock on/off and password change is audited
  (`deviceUnlock`, `deviceLockOn`, `deviceLockOff`, `passwordSet`), including refusals.

### App installs

The owner's request for a password before installing apps is met by Windows' own prompt
([ADR 0022](0022-security-posture-and-hardening.md), fix `uac.credentialPrompt`): Kshatriya cannot stop a
program from starting without a driver, and must not terminate processes. The Kshatriya password is not used
for installs.

### Protocol and clients

- Service protocol 12: `DeviceLockQuery`/`DeviceLockReply` (lock state and locked drives; any user),
  `DeviceUnlock` (device id and password), `DeviceLockConfigure` (on/off; administrator) and `PasswordSet`
  (new password and, when not an administrator, the current one). Password frames are size-limited like every
  frame and the password field is never echoed back.
- CLI: `kshatriya lock status|on|off|unlock <id>`, `kshatriya password set` (reads the password from the
  console without echo, or from standard input with `--stdin`).
- Desktop app: a notification "USB drive locked" opens an unlock dialog with a password box. The Protection
  page shows the lock switch and the password action.

## Implementation notes (2026-11-21)

- Built: `LockSettings` (password hash, attempt delay), `DriveLock` (arrivals, approvals, sweep of unplugged
  drives), `WindowsDeviceControl` (cfgmgr32), pipe handlers with audit, CLI `lock`/`password`, the installer
  prompt, and the app's Protection section plus an on-top unlock prompt while the lock is on.
- Tested with a fake device layer; a read-only test lists this machine's real disks and checks that the
  Windows disk is marked protected.
- First live test (2026-11-21, owner's PC): the service saw the stick arrive within milliseconds, but the
  disable was vetoed by a temperature-monitor program that opens every new disk (LibreHardwareMonitor based),
  and the app said nothing because it only prompted for locked drives. Fixed: retries for 30 seconds, the
  vetoing program is named, and a drive the lock gave up on is always notified.

## Consequences

- USB drives need the password before Windows mounts them for use, on top of Windows' own USB protections.
- A forgotten password means an administrator must reset it; there is no recovery question.
- The disable is visible in Device Manager while the drive is locked.
- Locked drives that are unplugged are forgotten; approvals do not survive a service restart.
- Real protection against a malicious USB device that types keystrokes (BadUSB) is not provided; a later
  release could alert when a new keyboard appears.
