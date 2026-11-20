# ADR 0021: UI and app-layer redesign for desktop and Android

- Status: accepted (2026-11-20). The owner chose to build all eight slices below, in order. Nothing is
  implemented yet.
- Date: 2026-11-20
- Research: [UI and UX review of security apps](../research/ui-ux-review-2026-11.md)
- Mockups (sample data only): [Kshatriya UI redesign mockups](https://claude.ai/artifact/KCQ7Yeby76HnAmeAzDWxm5)
  (private to the owner until shared)

## Context

**Desktop app ([ADR 0007](0007-desktop-app-wpf.md)).** The app has seven flat pages: Dashboard, Scan,
Detections, Quarantine, Exclusions, History (audit) and About.

- The verdict is worked out inside `DashboardViewModel`, mixed with display strings.
- `Pages.cs` holds every view model (about 840 lines).
- The running scan belongs to `ScanViewModel`, so nothing outside the Scan page knows a scan is running.
- Pages talk to each other through ad-hoc events (`QuickScanRequested`).
- Three places poll the service on their own: the dashboard retry, `DetectionWatcher` for notifications
  ([ADR 0015](0015-desktop-notifications.md)) and each page's refresh.
- One thing appears in three places: a finding is listed under Detections, then under Quarantine once it is
  quarantined, and the action under History.

**Android app ([ADR 0020](0020-android-prototype.md)).** It is a single screen: a stack of seven buttons
over a plain list, on the platform theme.

- Results live only in memory.
- There is no onboarding, so the notification permission is requested on first launch with no context.
- Navigation and state are not separated from the `Activity`.

**What other products and platforms do.** The research shows a shared convention:

- Windows Security, ESET and Android's Security & privacy page all use one status in two to four plain
  states, with a short list of causes and an action for each.
- Protection history is one filterable record.
- Critical alerts are always shown; informational ones can be turned off.

It also shows practices to avoid: upselling, housekeeping counted as issues, alerts repeated until people
stop reading them, and nagging after a permission is denied.

**Rules that still apply.** These come from AGENTS.md and the ADRs above:

- companion mode;
- report-only heuristics;
- automatic action only for high-confidence `malware`/`test` detections, and only when the user asked;
- operations that weaken protection need an administrator and are audited;
- the app is only a client of the service;
- no GPL dependencies.

## Decision

### 1. One status model, shared by both apps

A new platform-neutral library, `src/Kshatriya.Presentation` (`net10.0`, no UI types), referenced by
`Kshatriya.App` and `Kshatriya.Mobile`. Its CI tests run on every build.

- `ProtectionLevel` has five values:
  - `Checking`
  - `Protected`
  - `AttentionRecommended`
  - `ActionNeeded`
  - `NotRunning` (with a *starting* variant)
- `StatusItem` has:
  - a stable id;
  - an area;
  - a level;
  - a title and detail (plain language);
  - an optional `ActionId` (a fixed set such as `review-finding`, `check-updates`, `open-windows-security`,
    `restart-elevated`, `setup-browser-extension`);
  - whether it can be dismissed.
- `StatusEvaluator.Evaluate(inputs) → StatusSnapshot` is a pure function. Its inputs are the service status,
  Windows Security Center health and unresolved findings on desktop, and content state, last scan and
  findings on Android. The snapshot holds the overall level, one headline, and items ordered by level then
  priority.

The rules, in priority order:

| Level | Shown when | Example action |
| --- | --- | --- |
| NotRunning | Service unreachable (desktop). "Starting" while the delayed start runs. | none / wait |
| ActionNeeded | A confirmed detection (`malware`, `pua`, `test`) is not quarantined or kept. Audit chain check failed. Windows antivirus off or out of date. | Review, Open Windows Security |
| AttentionRecommended | A suspicious finding is waiting for review. Signatures expired or expire within 7 days. Real-time monitoring off. Items not scanned in the last user scan for access reasons. | Review, Check for updates |
| Protected | None of the above. | Quick scan |

- **Optional features never lower the level.** For example, a browser extension that is not set up, decoy
  files that are off, or controlled folder access that is off. They show as neutral "Not set up" rows on the
  Protection page.
- **Dismissing an item mutes it but keeps the fact visible.** A dismissed recommendation no longer counts
  toward the level and is no longer notified, but stays visible on the Protection page or in History. This
  matches how Windows Security treats a dismissed warning.
- **Keeping a suspicious file is not an exclusion.** "Keep file" is a per-user acknowledgement stored by the
  app (by SHA-256 and path). It never changes service settings. An exclusion still goes through the
  administrator-only, audited Exclusions operation.
- **Text, icon shape and colour together.** Every level has its own icon shape (check, triangle, octagon,
  dash) and text as well as a colour. The colours meet WCAG 2.2 contrast in light, dark and high-contrast
  themes.

### 2. Desktop information architecture

The left navigation follows the NavigationView pattern: expanded from 1008 px, an icon rail from 641 px,
minimal below. It has five task areas and two footer items:

| Page | Contents | Replaces |
| --- | --- | --- |
| Home | Status hero (headline, one primary action), "Needs your attention" (at most 3 items with actions), protection tiles, last and next scan | Dashboard |
| Scan | Choose a scan (quick, full, external drives, custom); live progress; results with findings grouped by what the user must do; "not scanned" grouped by reason, each with a fix | Scan |
| Protection | Each protection layer with its state; changes marked "(administrator)"; a read-only Windows Security section | Dashboard rows, part of About |
| History | One filterable record: Needs decision, Quarantined, Allowed, Actions log (audit, administrator). List and detail pane with actions in the pane | Detections, Quarantine, History |
| Updates | Content version, expiry, channel, import a signed package, update history | Dashboard row |
| Settings (footer) | Notifications by category, start at sign-in, browser extension copy, Exclusions (administrator) | Exclusions, tray toggles |
| Help and about (footer) | Version, limitations, companion-mode statement, licences | About |

Rules for the shell:

- A running scan shows a dot on the Scan item and a slim strip at the top of any other page.
- The History item shows a count badge only for items that need a decision.
- Closing the window still hides it to the notification area (ADR 0015). The tray icon gets a small status
  overlay for each level, and its menu gains "Quick scan" and a status line.

### 3. Desktop app-layer architecture

The app keeps WPF, the Fluent theme and MVVM without a third-party framework (ADR 0007). It adds a few
app-level services so pages stop owning shared state:

- **`StatusStore`.** One poller of the service (status and recent findings, every 15 s while visible or in
  the tray, plus on demand). It publishes an immutable `AppSnapshot` and the `StatusSnapshot` from §1. Home,
  the navigation badges, the tray icon and notifications subscribe to it. `DetectionWatcher`'s separate poll
  is folded into it, with no protocol change.
- **`ScanSession`.** The app-level owner of the current user scan, as a state machine: `Idle → Running →
  Completed | Cancelled | Failed`. It holds progress, counters and the result report. The Scan page, the
  shell strip and the tray all bind to it.
  - Navigating away no longer hides a scan.
  - "Scan finished" is notified only when the window is hidden.
  - Closing the app still cancels the scan (ADR 0016).
- **`INavigator`** with typed routes (`Home`, `Scan`, `ScanResults`, `History(filter, id)`, …). It replaces
  events between view models and is how a notification click opens the right item.
- **`NotificationPolicy`** (pure, in `Kshatriya.Presentation`).
  - **Critical, always shown:** background findings, the service stopping, audit failure.
  - **Informational, can be turned off by category:** scan finished while hidden, update installed,
    external drive scanned.
  - **Never:** "all clear" or promotional notifications.
  - Several findings still merge into one notification.
- **Code layout.**
  - One view model file per page under `ViewModels/`.
  - Page templates split into one resource dictionary per page.
  - Shared controls (status hero, status row, finding card, filter chips) as styles or templates in
    `Views/Controls`.
  - `UiSnapshots` covers every page in every status level.
- **Visual details.**
  - Accent colour from `SystemColors` through `DynamicResource`.
  - The Mica backdrop only where the Fluent theme provides it on Windows 11; Windows 10 keeps solid
    surfaces.
  - No new package.

**Not in scope here.** Changing real-time or schedule settings from the app needs new administrator-only,
audited service operations and its own ADR. Until then the Protection page shows the state and says which
settings file an administrator edits.

### 4. Android information architecture and look

- **Material 3.**
  - A navigation bar with four destinations: Home, Apps, History, Settings.
  - Home: status hero, "Scan apps now", "Scan files" and "Scan a folder" cards, and signatures and Play
    Protect cards.
  - Apps: search, filter chips (Needs review, All, Not checked, Recent) and one row per app.
  - Selecting a finding opens a bottom sheet: what matched, how strong the evidence is, "Review in Android
    settings" and "Keep this app".
  - History: findings and scans, persisted.
  - Settings: automatic updates, trusted keys, import a package, notifications, about.
- **Onboarding in three steps.**
  1. What Kshatriya does and that nothing leaves the phone.
  2. Notifications, explained just before Android's own prompt. "Not now" is respected, and there is no
     repeated asking.
  3. Optional automatic updates, which states what is sent (ADR 0020, point 12).
- **Stalkerware findings** (Echap list, ADR 0020 points 9 and 10) carry safety wording: removing the app may
  alert whoever installed it, with a link to safety advice before the removal action. Package-name-only
  matches stay worded as weak evidence.
- **Notification channels:** "Findings" (high importance) and "Scans and updates" (low, can be turned off).
- **Platform behaviour.** Edge-to-edge layout and AndroidX predictive back, ready for target SDK 35 and 36.
  Material You dynamic colour on Android 12 and later for surfaces only. Status colours stay fixed and keep
  their icon shapes.
- **Expressive styling, sparingly.** The large shaped status hero and empty states only. Lists, buttons and
  text stay standard, following Google's own caution that expressive design is not right for every product.

### 5. Android app-layer architecture

- **Single activity with unidirectional data flow.**
  - Screen states (`HomeState`, `AppsState`, `HistoryState`, `OnboardingState`) are immutable records
    built by pure reducers in `Kshatriya.Mobile`, so they are unit-tested on CI without a device.
  - The `Activity` and fragments only render state and send intents (`ScanApps`, `PickFiles`,
    `KeepApp(id)`, …) to a `MobileController`.
  - The controller runs the existing `MobileScanner`, `ContentUpdateChecker` and `MobileContentStore` off
    the UI thread.
  - This follows the UI-layer pattern in Android's architecture guide (state holders, UDF). We did not
    re-fetch that page for this ADR.
- **Persisted findings.** A bounded, app-private findings store (JSON, at most 1,000 entries, a damaged
  file is discarded, as for the hash cache). It feeds History, the Apps "Needs review" filter and the Home
  status. "Keep this app" is stored there by package and certificate. It never changes a list or
  protection.
- **Views stay XML layouts.** Jetpack Compose is not practical from .NET for Android. Material Components
  for Android and AndroidX come in through their .NET binding packages, versioned in
  `Directory.Packages.props`.
  - **Before adding them, check their licences against [ADR 0003](0003-dependency-licensing.md).** We
    believe the binding packages are MIT and the Java libraries Apache-2.0, but have not checked.
  - **If they do not qualify,** fall back to platform widgets with Kshatriya's own Material 3-style
    resources.
- **Scanning in the background** stays on `JobScheduler`. A long user-started scan that must survive
  leaving the app would need a `dataSync` foreground service (Android 14+ type, 6 h per 24 h when targeting
  Android 15). That is not part of this ADR.

## Consequences

- Both apps describe protection in the same words and levels, decided in one tested library, and the
  desktop verdict logic moves out of the view model.
- The desktop gains a few app-level services but no dependency. Pages get smaller and stop polling on their
  own.
- Moving three pages into History changes where users find things. The tray menu and notifications link
  straight to the right filter.
- The Android app may gain AndroidX and Material dependencies (after the licence check) and gets a larger
  APK.
- Nothing changes in the service, the protocol, the sandbox or any detection or response rule. "Keep file"
  and "Keep this app" are acknowledgements made in the app only.
- The mockups are proposals with sample data. Visual details will change during implementation, and every
  slice keeps the zero-warning build, the tests and the UI snapshots green.

## Suggested slices (each one commit or a few)

1. `Kshatriya.Presentation`: status model, evaluator and notification policy, with tests. Desktop Home uses
   it.
2. Desktop shell: the new navigation and pages, split `Pages.cs` and `Pages.xaml`.
3. Desktop `ScanSession`: progress and results redesign.
4. Desktop unified History (Detections, Quarantine and Audit).
5. Desktop `StatusStore`: tray status overlay and notification categories.
6. Android: UDF state and persisted findings in `Kshatriya.Mobile`, with tests.
7. Android: Material 3 navigation, Home, Apps and finding sheet, onboarding (after the licence check).
8. Android: edge-to-edge, predictive back, notification channels.

## Implementation notes

- **Slice 1 (2026-11-20):** `Kshatriya.Presentation` with the status model, `DesktopStatusEvaluator` and
  `NotificationPolicy`. Home's verdict and "Needs your attention" come from the evaluator. Findings are not
  yet inputs: they need the review actions of slice 4.
- **Slice 2 (2026-11-20):** the navigation shows Home, Scan, Protection, History and Updates, with Settings
  and Help and about at the bottom. A dot marks Scan while a scan runs. As steps towards the full design:
  - History holds the existing Detections, Quarantine and Actions log pages as tabs until slice 4 merges
    them.
  - Protection shows the service's state read-only and names the settings file an administrator edits.
  - Updates installs a chosen `.kstu` through the existing, signature-checked service import.
  - Settings carries the notification-area preferences (kept in step with the tray menu), the browser
    extension and Exclusions.
  - A page shown inside another page gets a level-2 heading.
  - View models and page templates are one file per page.
- **Slice 3 (2026-11-21):** `ScanSession` owns the user's scan and its live counters and outcome.
  - While a scan runs on another page, the shell shows a strip with a View button.
  - A scan that ends while the window is hidden is notified through `NotificationPolicy`.
  - Results group findings into "Needs your decision" (suspicious) and "Threats" cards. Items that were not
    scanned are grouped by reason with what to do, and the full table moves into an expander.
  - The last scan's access-denied count feeds Home's status.
