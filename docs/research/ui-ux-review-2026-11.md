# UI and UX review of security apps (November 2026)

Input for [ADR 0021](../adr/0021-ui-architecture-redesign.md). Sources were retrieved on 2026-11-20. Only
patterns are taken from other products. Kshatriya does not copy their names, artwork or exact layouts.

How to read the labels:

- **Verified**: we fetched and read the primary page (vendor help, platform documentation).
- **Snippet**: the fact comes from a search engine's extract of the named primary page, which we did not
  open. Treat it as lower confidence and check it before quoting.
- **Secondary**: a review, news report or forum post.
- **Recommendation**: our own opinion. It is not a sourced fact.

Some pages could not be fetched: help.malwarebytes.com (HTTP 403), the Material 3 Expressive pages on
m3.material.io (404 or empty) and fluent2.microsoft.design (landing page only). Facts from those sites are
snippets at best.

## 1. Product by product

### Windows Security / Microsoft Defender (Windows 10 and 11)

- **Layout and navigation (verified).** The app is a hub of protection areas: Virus & threat protection,
  Account protection, Firewall & network protection, App & browser control, Device security, Device
  performance & health, Family options and Protection history
  ([overview](https://support.microsoft.com/windows/security/windows-security/windows-security-app-overview)).
  Explorer has a "Scan with Microsoft Defender" entry, which Windows 11 puts under "Show more options"
  ([stay protected](https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963)).
- **Status (verified).** There are three states:
  - green: "sufficiently protected and there aren't any recommended actions";
  - yellow: "a safety recommendation for you";
  - red: "something that needs your immediate attention".

  The source is the overview page above. A snippet adds that dismissing a Secure Boot warning resets the
  badge and pauses notifications, but the status text stays visible
  ([Secure Boot status, 2026](https://support.microsoft.com/en-us/servicing/os/secure-boot/2026/03/secure-boot-certificate-update-status-in-the-windows-security-app)).
- **Scans (verified).** Quick, Full, Custom, and an offline scan that restarts the PC and scans before
  Windows loads. The page also shows the last scan time, duration and number of files
  ([virus & threat protection](https://support.microsoft.com/en-us/windows/virus-and-threat-protection-in-the-windows-security-app-1362f4cd-d71a-b52a-0b66-c2820032b65e)).
  If the user turns real-time protection off, it turns itself back on after a short time (same page).
- **Results (verified).** Protection history lists events as expandable cards, colour-coded red or yellow,
  and keeps them for two weeks. Viewing threat details needs administrator rights.
  - Labels say what has already happened: "Threat found - action needed", "Threat quarantined", "Threat
    blocked", "Remediation incomplete", "An important service is off".
  - Actions: Quarantine (recommended "if you're not sure"), Allow on device (with a warning), Remove and
    Restore.

  Source: [protection history](https://support.microsoft.com/windows/protection-history-f1e5fd95-09b4-46d1-b8c7-1059a1e09708).
- **Notifications (snippet).** Informational notifications can be turned off by category. Notifications
  about problems that need immediate action are always shown
  ([notifications](https://support.microsoft.com/en-us/topic/6a59ce6a-e1e0-4795-b080-ba92d49644b2)).
- **Defender app for individuals (verified).** Only its VPN feature ended, on 28 Feb 2025; device protection
  and threat alerts continue
  ([end of VPN](https://support.microsoft.com/en-au/topic/end-of-support-privacy-protection-vpn-in-microsoft-defender-for-individuals-8b503da5-732a-4472-833a-e2ddca53036a)).
  We found no primary notice that the whole consumer app is retired.

**Recommendation:** adopt Microsoft's three states, labels that say what already happened, and the split
between critical and informational notifications. These are the conventions Windows users already know, and
Kshatriya runs next to this very app.

### Google Play Protect and Android's Security & privacy page

- **Play Protect (verified).**
  - Where to find it: Play Store > profile > Play Protect > settings. There are two toggles: scan apps, and
    improve harmful app detection
    ([help](https://support.google.com/googleplay/answer/2812853?hl=en)).
  - How it scans: a light daily scan plus a full scan the user can start, offline blocking of well-known
    harmful apps, and code-level scanning of apps it has not seen. Code-level scanning uploads the app, so
    it needs the user's consent
    ([client protections](https://developers.google.com/android/play-protect/client-protections)).
  - How it responds: the most harmful apps are removed. Less harmful ones are *disabled*, which keeps their
    data and lets the user re-enable or remove the app (same page).
  - Dialogs use plain verbs, for example "Play Protect hasn't seen this app before" with "Scan app" and
    "Don't install app"
    ([warnings](https://developers.google.com/android/play-protect/warning-dev-guidance)).
- **Live Threat Detection (snippet).** It started rolling out to Pixel 6 and later in November 2024. It uses
  on-device analysis, and its first focus is stalkerware
  ([I/O 2024](https://security.googleblog.com/2024/05/io-2024-whats-new-in-android-security.html)).
- **Security & privacy hub (verified).** On Android 13 and later, the page opens with "Looks good." or
  "Device is at risk", followed by alerts and recommendations. The sections are app security, device lock,
  accounts, system updates, device finders, privacy and more
  ([help](https://support.google.com/android/answer/13985942?hl=en)).

**Recommendation:** match the platform's wording (one plain status line, then a short list of
recommendations) and Play Protect's graded and consent-first behaviour. Kshatriya already reports only and
leaves removal to Android's own app page.

### Third-party products

| Product | What we found (label) | Recommendation |
| --- | --- | --- |
| ESET | Green "You are protected", yellow "Attention required", red "Security alert". The state is shown in both the main window and the tray icon (verified, [ESET KB2248](https://support.eset.com/en/kb2248-why-does-my-protection-status-change-color-and-what-does-each-color-mean)). An alert box explains the cause (snippet, [help](https://help.eset.com/eis/19/en-US/idh_page_status.html)). | Show the same status in the tray icon and the window. |
| Norton | "You Are Protected"; any other state shows an alert with a "Fix Now" button. Quick Scan sits under a Scans tile (snippet, [Norton](https://support.norton.com/sp/en/aa/norton-360/current/solutions/v71537759)). Users complain about persistent upgrade pop-ups (secondary, [forum](https://community.norton.com/t/ads-and-scareware-are-a-complete-disgrace-as-part-of-a-security-software/524174)). | Pair each problem with one fix. Never put marketing in the status area. |
| Malwarebytes | A real-time protection card with a switch per layer. A tray menu can toggle layers and start a scan. Detection History has Restore and Delete. The Android app explains each permission it asks for (snippets; the help site refused fetching: [layers](https://help.malwarebytes.com/hc/en-us/articles/31589448817563), [Android](https://help.malwarebytes.com/hc/en-us/articles/31589249159963)). | Show protection per layer. Explain every permission in context. |
| Bitdefender | A status area, contextual recommendations with action buttons, and quick actions. Recommendation pop-ups can be turned off (snippet, user guides several years old, [mobile guide](https://www.bitdefender.com/content/dam/bitdefender/solutions/user-guide/bitdefender-mobile-security-for-android_user-guide-EN.pdf)). | Recommendations are useful when each has an action and a way to dismiss it. |
| Avast / AVG | Smart Scan mixes malware with housekeeping (outdated software, weak passwords). "Resolve All" walks through each issue, and some fixes need Premium (snippet, [Avast help](https://help.avast.com/en/av_abs/17/smartscan.html)). Reviewers criticise the upselling (secondary, [ITPro](https://www.itpro.com/antivirus/33115/avast-free-antivirus-review-capable-but-annoying)). | Do not inflate issue counts with non-security items. |
| Kaspersky | On Mac: a sidebar, a Scan window with Quick and Full scans, and a Reports window (snippet, [Mac help](https://support.kaspersky.com/help/Kaspersky/Mac24/en-US/58162.htm)). We could not retrieve the Windows layout. | None (not enough evidence). |
| Lookout | Its consumer business was sold to F-Secure; the deal closed in June 2023 (snippet, [Business Wire](https://www.businesswire.com/news/home/20230601005323/en)). | Not a current reference point. |

### Practices that hurt users

- **Which? (2023).** It found steep renewal price rises, cancelling auto-renew framed as losing "continuous
  protection", pre-ticked basket add-ons, and AVG pop-ups pushing paid extras (verified,
  [Which?](https://www.which.co.uk/news/article/revealed-the-traps-antivirus-companies-use-to-get-you-to-overpay-aX6PA5f1922s)).
- **FTC and Avast (2024).** The FTC's final order bans Avast from selling browsing data for advertising
  (snippet, [FTC](https://www.ftc.gov/news-events/news/press-releases/2024/06/ftc-finalizes-order-avast-banning-it-selling-or-licensing-web-browsing-data-advertising-requiring-it)).
- **Warning habituation.** Responses to a security warning drop after people have seen it once or twice.
  Habituation to routine notifications also carries over to security warnings unless those look different
  (snippets, [Vance et al., MISQ 42(2)](https://misq.umn.edu/pub/skin/frontend/default/misq/pdf/V42I2/14124_RA_VanceJenkinsAbstract.pdf),
  [MISQ 49(4)](https://aisel.aisnet.org/misq/vol49/iss4/10)).

**Recommendation:** Kshatriya is open source and non-commercial, so it can be the calm product. That means
no upsell surfaces, no "all clear" notifications, no housekeeping counted as issues, and a critical alert
that looks clearly different from informational messages.

## 2. Platform guidance and trends (2025–2026)

### Windows (verified)

- **NavigationView.** Use a left pane for 5 to 10 top-level categories. The pane adapts by window width:
  minimal up to 640 px, compact from 641 to 1007 px, expanded from 1008 px. Content margins are 12 px in
  minimal mode and 24 px otherwise
  ([NavigationView](https://learn.microsoft.com/en-us/windows/apps/design/controls/navigationview)).
- **WPF Fluent theme.** `ThemeMode` can be Light, Dark or System; setting it from code is experimental
  (WPF0001). Accent colours come from `SystemColors.AccentColor*` through `DynamicResource`
  ([WPF .NET 9](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/whats-new/net90)).
- **Mica.** It is meant for long-lived windows. On Windows 10, or when transparency or battery saver is
  on, it falls back to a solid colour ([Mica](https://learn.microsoft.com/en-us/windows/apps/design/style/mica)).
- **Notifications.** They "should not be noisy". Send non-urgent ones silently to Notification Center,
  respect focus sessions, open the app at the item the notification is about, show progress for long
  operations, and remove notifications that are out of date
  ([notification guidance](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/app-notifications/app-notifications-ux-guidance)).

### Android (verified unless noted)

- **Edge-to-edge** is enforced for apps that target SDK 35, and the opt-out is gone at API 36
  ([edge-to-edge](https://developer.android.com/develop/ui/views/layout/edge-to-edge),
  [Android 16 changes](https://developer.android.com/about/versions/16/behavior-changes-16)).
- **Predictive back** is the default at API 36, and `onBackPressed` is no longer called. Use AndroidX
  `OnBackPressedCallback` ([predictive back](https://developer.android.com/guide/navigation/custom-back/predictive-back-gesture)).
- **Notifications.**
  - Android 13 and later need `POST_NOTIFICATIONS`. Ask in context after a user action, and show a
    rationale only when the system says to
    ([notification permission](https://developer.android.com/develop/ui/views/notifications/notification-permission)).
  - Google calls persistent nagging after a denial "not respectful"
    ([requesting permissions](https://developer.android.com/training/permissions/requesting)).
  - Use one notification channel per kind of notification
    ([channels](https://developer.android.com/develop/ui/views/notifications/channels)).
- **Background work.**
  - From Android 14 a foreground service must declare its type. The `dataSync` type covers local file
    processing ([service types](https://developer.android.com/develop/background-work/services/fgs/service-types)).
  - For apps targeting Android 15, `dataSync` may run 6 hours in 24 while in the background
    ([timeout](https://developer.android.com/develop/background-work/services/fgs/timeout)).
- **Material 3 Expressive.** Google's research post reports key elements found up to 4× faster in its
  studies. It also warns that expressive design is "not a one-size-fits-all solution", that removing text
  labels hurt usability, and that some participants preferred calmer versions
  ([Google Design](https://design.google/library/expressive-material-design-google-research)). The
  component list (button groups, loading indicator, toolbars) is snippet-level.

### Accessibility

- **WCAG 2.2** adds, among others:
  - 2.4.11 Focus Not Obscured;
  - 2.5.7 Dragging Movements;
  - 2.5.8 Target Size (Minimum) of 24 × 24 CSS px;
  - 3.2.6 Consistent Help;
  - 3.3.8 Accessible Authentication.

  Source: [W3C](https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/).

## 3. Trends worth adopting (recommendations)

1. **One overall status with three levels**, each with its own icon shape and text, not colour alone. Every
   state other than "protected" lists its causes, and each cause has one action.
2. **Calm by default.** Critical alerts are always shown; informational ones can be turned off by category
   (Windows settings, Android channels). There are no "all clear" notifications and no marketing.
3. **History as the single record.** Findings, quarantine and actions go in one filterable list with
   reversible actions and labels that say what happened.
4. **Graded, consent-first responses.** Report first; act automatically only on high-confidence detections
   the user opted into; leave removing apps to the platform.
5. **Platform-native look.** Fluent on Windows (NavigationView behaviour, accent colours, Mica only as an
   enhancement on Windows 11). Material 3 on Android, with expressive styling used sparingly in a security
   context: a calm status hero, expressive shapes only for the main status and empty states.
6. **Explain permissions in context**, and degrade gracefully when one is denied.
7. **Scans that keep running** when the user moves to another page, with visible progress and a summary
   when they finish. The summary always includes the items that were not scanned (a Kshatriya rule already).
8. **Safety-aware wording for stalkerware.** Removing a monitoring app can alert the person who installed
   it, so the finding offers safety advice before suggesting removal. This is our recommendation, prompted
   by Google's own focus on stalkerware.
