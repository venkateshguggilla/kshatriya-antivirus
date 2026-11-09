# ADR 0007: Desktop app on WPF with the .NET Fluent theme

- Status: accepted (M5)
- Date: 2026-11-08

## Context

[ADR 0001](0001-technology-stack.md) named WinUI 3 (Windows App SDK) for the UI, with WPF and the .NET
Fluent theme as the fallback. When M5 started, the `Microsoft.WindowsAppSDK` 2.6.5 NuGet package was
checked against [ADR 0003](0003-dependency-licensing.md): it ships under the *Microsoft Software
License Terms for Windows App SDK* (`requireLicenseAcceptance=true`, proprietary, with an arbitration
clause), not MIT/BSD/Apache-2.0. Unpackaged deployment also needs the Windows App Runtime or a
self-contained copy of it.

## Decision

Build `Kshatriya.App` on **WPF (.NET 10)** with the in-box Fluent theme
(`PresentationFramework.Fluent`). WPF is part of the MIT-licensed .NET runtime, adds no package
dependency, follows the system light/dark and high-contrast settings through the Fluent theme, and has
a mature UI Automation implementation.

- The app is a **client of the service only**. It never opens, parses or changes scanned files itself;
  every operation goes over the authenticated pipe ([ADR 0005](0005-service-sandbox-ipc.md)), so the
  service's authorization (impersonation, administrator checks, audit) applies unchanged.
- It runs `asInvoker`. Elevation is requested only when the user presses "Restart as administrator".
- MVVM without third-party frameworks; view models depend on `IServiceGateway`, `IDialogs` and
  `IAppHost`, so they are unit-tested with fakes, and a test renders every page's real XAML.
- Windows antivirus health is read (only read) from Windows Security Center
  (`WscGetSecurityProviderHealth`) to remind people to keep Defender on.
- Accessibility: headings via `AutomationProperties.HeadingLevel`, names/help text on controls, live
  regions for progress and results, errors labelled in text (not colour only), full keyboard navigation.

## Consequences

- No new dependency or licence to accept. Revisit WinUI 3 only if its licence or packaging fits ADR 0003.
- Not yet done: notifications/tray icon, localization, a formal accessibility audit with screen readers.

## Amendment (2026-11-09): visual redesign and design system

- **Design system** in `Views/Theme.xaml`: Fluent theme brushes only, so light, dark and high-contrast themes keep working. Text styles: page title, lead, section title, caption. Surfaces: a panel with a hairline border, and a banner coloured by a `Tone` (success, caution, critical, neutral). Status colours carry meaning only and always come with an icon shape and text. Icons are Segoe Fluent Icons with a Segoe MDL2 Assets fallback, so the same code points work on Windows 10 and 11. Spacing is on a 4 px grid.
- **Shell:** a brand mark (the shield in the user's accent colour) and icon-plus-title navigation, with an accent marker on the current page. Below 900 px the navigation becomes an icon rail (titles stay as tooltips and accessible names) and page margins tighten.
- **Dashboard:** one verdict ("All checks passed", "Attention needed", "Kshatriya is not running") with Quick scan next to it, then one list of checks with a status icon each. Technical details sit in an expander.
- **Scan:** one "choose a scan" list (quick, full, external drives, one drive, custom) and a single Scan now button. Each choice's own options sit below it rather than inside the radio button, so every control keeps its own focus and name. Progress appears in its own panel; results get a toned banner and status icons in the table.
- **List pages:** actions in a toolbar above the list, an empty state instead of an empty table, and a loading bar in the page header while refreshing. "Delete permanently" uses a danger style.
- **Accessibility:** headings levels 1 and 2, names on icon-only controls, live regions for verdicts and results, Fluent's focus visuals kept, theme brushes for contrast, and loading bars that stop animating when Windows animations are turned off.
- `tests/Kshatriya.App.Tests/UiSnapshots.cs` renders every page with sample data at desktop and narrow sizes when `KSHATRIYA_UI_SNAPSHOTS` names a folder, for design review.
