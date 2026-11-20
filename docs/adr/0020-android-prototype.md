# ADR 0020: Android version (prototype)

- Status: accepted (owner asked for an Android version and chose .NET for Android on 2026-11-19)
- Date: 2026-11-19

## Context

Kshatriya is a Windows product: a service, a sandboxed scan worker, a desktop app and a browser
extension. Android isolates every app in its own sandbox, so most of that design does not carry over.
An Android security app cannot watch other apps' files, intercept file opens, terminate apps or install
browser extensions, and it must not require root.

Platform facts this design relies on (checked 2026-11-19):

- Google Play's package visibility policy allows broad visibility of installed apps
  (`QUERY_ALL_PACKAGES`) for "antivirus apps", when it is central to the app's purpose.
- Play's "All files access" policy (`MANAGE_EXTERNAL_STORAGE`) lists anti-virus apps as a permitted use.
- Since Android 8.0, apps cannot receive `ACTION_PACKAGE_ADDED` or `ACTION_PACKAGE_REPLACED` through
  manifest receivers; they are not among the exempt broadcasts (Android developer documentation,
  "Implicit broadcast exceptions").
- `VpnService` lets an app filter traffic after the user consents; only one VPN can run at a time and
  Android shows a permanent notification while it runs.

## Decision

1. **A prototype app, `src/Kshatriya.Android`, in .NET for Android** (plain Android views, no MAUI). It
   reuses the shared libraries unchanged: `Kshatriya.Core`, `Kshatriya.Engines.Abstractions`,
   `Kshatriya.Engines.Hash` and `Kshatriya.Updates`, which now targets `net10.0` (it used nothing
   Windows-specific). Platform-independent logic lives in `src/Kshatriya.Mobile` (`net10.0`), so it is
   tested on every CI run without an Android device.
2. **Companion to Google Play Protect,** as Kshatriya is to Microsoft Defender (ADR 0002): it never
   asks the user to turn Play Protect or any Android security setting off.
3. **What it scans, by exact SHA-256 only.** The hash engine compares whole files against the built-in
   signatures (the EICAR test file) and signatures from signed content packages (ADR 0008):
   - installed apps: each app's base APK and split APKs, read through `ApplicationInfo`;
   - files and folders the user picks through the system file picker (Storage Access Framework), so the
     first version needs no all-files access.
   Files are read as streams with a size limit (512 MiB per file) and every item not scanned is reported
   with its reason, as on Windows. **No file format is parsed** (not even an APK's ZIP structure), so
   the Android app adds no parser that untrusted content reaches; the sandboxed-worker rule (ADR 0005)
   has nothing to isolate yet. YARA rules and APK/DEX analysis would need that design first.
4. **New and updated apps** are found by a periodic `JobScheduler` job (about every 15 minutes, the
   platform minimum, persisted across restarts) that asks `PackageManager.getChangedPackages` for the
   apps changed since the last sequence number, scans them, and notifies on a finding. A first scan
   records the starting point.
5. **Report only.** A finding shows the app or file and what matched. For an app, "Review app" opens
   Android's app details screen, where the user can uninstall it; Kshatriya removes nothing itself and
   asks for no uninstall permission.
6. **Signed content on the device.** The user imports a `.kstu` package with the file picker. It is
   verified exactly as on Windows (signature before parsing, hashes, expiry, anti-rollback against the
   highest sequence installed, kept in app-private storage). Trusted keys are `ContentTrust.ProductionKeys`
   (still empty) plus public keys the user adds from a file, after a confirmation that names the key id.
   A trusted key can only add signatures and lists; it cannot turn protection off.
7. **Permissions:** `QUERY_ALL_PACKAGES` (installed apps), `POST_NOTIFICATIONS` (findings, Android 13+)
   and `RECEIVE_BOOT_COMPLETED` (the persisted job). No internet, storage, VPN or accessibility permission.
8. **Not in the first version:** web protection (a local `VpnService` filter using the ADR 0019 lists, off
   by default because of the one-VPN limit), all-files scanning, Play Store publishing and signing.

## Consequences

- Detection on Android is exactly as strong as the signature lists. With only the EICAR signature
  shipped, the app is plumbing until signed content with real APK hashes is chosen and imported.
- No real-time protection: new apps are checked within roughly 15 minutes of installation, and files only
  when the user scans them.
- The Android build needs the .NET `android` workload; the main solution and CI job stay free of it, and a
  separate CI job builds the Android app.
