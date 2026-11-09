# ADR 0015: Desktop notifications for background findings

- Status: accepted
- Date: 2026-11-09

## Context

Real-time monitoring, behaviour alerts and scheduled scans run in the service as LocalSystem, in session 0.
A service cannot show anything on a user's desktop, and until now findings appeared only in the app's
Detections page, `kshatriya detections` and the event log, so a finding made while the user was working went
unseen (ADR 0009 listed this as a gap).

Options considered for showing a notification from the per-user desktop app:

- **Windows App SDK app notifications**: rejected for the same reason as WinUI 3 in ADR 0007 (its packages
  require accepting proprietary licence terms).
- **Toasts through the Windows Runtime projection** (`Windows.UI.Notifications`, optionally via a community
  helper package): workable, but an unpackaged app needs an AppUserModelID registered on a Start-menu
  shortcut and a Windows SDK-specific target framework, which is more moving parts than this needs.
- **A notification-area icon** (`System.Windows.Forms.NotifyIcon`, part of the MIT-licensed .NET desktop
  pack): its balloon tips are shown by Windows 10 and 11 as ordinary toast notifications, it needs no
  registration, and it gives the app a natural place to keep running.

## Decision

1. The desktop app gets a **notification-area icon** with Open, "Show notifications" (on by default, saved per
   user in `%LocalAppData%\Kshatriya\app-settings.json`) and Exit. Closing the window hides it to the
   notification area; Exit closes the app (protection continues in the service). One instance runs per
   session; starting it again brings the existing window up.
2. The app **polls** the service's recent findings every 15 seconds over the existing authenticated pipe,
   with no protocol change. It announces only findings that are **newer than its first successful poll** and
   come from **background sources** (real-time file, process and removable-drive scans, behaviour alerts,
   scheduled scans). Scans the user started show their results already. Several new findings become one
   notification. Clicking it opens the Detections page.
3. The service already limits what a non-administrator sees to findings under their own profile folder,
   so each user is told only about their own files.
4. The installer adds an all-users **Startup** shortcut (`Kshatriya.App.exe --background`), so the app starts
   in the notification area at sign-in. Users can disable it in Task Manager (Startup apps) or turn
   notifications off from the icon. Uninstall removes the shortcut and closes Kshatriya's own app processes
   started from the install folder before removing files.

## Consequences

- A notification can lag a finding by up to about 15 seconds, and nothing is shown while no user is
  signed in or the app has been exited. Findings are always kept in the service history, the event log and
  reports, so notifications are a convenience, not the record.
- The service keeps its findings history in memory (500 entries); if more than that arrive between two polls,
  the oldest are not announced individually (the count is still shown).
- No new dependency: Windows Forms ships with the .NET Windows desktop runtime the app already uses.
