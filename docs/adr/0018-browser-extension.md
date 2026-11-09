# ADR 0018: Browser extension for Edge and Chrome (prototype)

- Status: accepted (owner asked for browser extensions for internet security on 2026-11-10)
- Date: 2026-11-10

## Context

Most malware and phishing reaches people through the browser. Edge (Microsoft Defender SmartScreen) and
Chrome (Google Safe Browsing) already block many dangerous sites and downloads. Kshatriya should add to
that protection, as it does alongside Microsoft Defender (ADR 0002), and never ask anyone to turn it off.

Platform facts this design relies on (Chrome for Developers documentation, checked 2026-11-10):

- Manifest V3 extensions block requests with `declarativeNetRequest`. The browser evaluates the rules;
  the extension never sees the traffic. At least 30,000 rules in enabled static rulesets are guaranteed,
  plus 30,000 dynamic and 5,000 session rules.
- An extension can talk to a local program through native messaging. Windows finds the program's
  manifest through `HKLM` or `HKCU` `SOFTWARE\Google\Chrome\NativeMessagingHosts\<name>` (Edge:
  `SOFTWARE\Microsoft\Edge\NativeMessagingHosts\<name>`). Only extensions listed in the manifest's
  `allowed_origins` may start it. Messages are a 32-bit native-order length and UTF-8 JSON; at most 1 MB
  from the program, 64 MiB to it.
- The Google Safe Browsing API is for non-commercial use only (commercial use needs Web Risk).
- The URLhaus feeds (abuse.ch) now need an account key and are offered under fair-use terms, with paid
  access for commercial needs.

## Decision

1. **One Manifest V3 extension** (`extension/`) for Edge and Chrome. The manifest carries a public `key`,
   so the unpacked extension always has the ID `lkkpcdfabgihmnhfdmhoellokaobmdah`. The private key was
   not kept: it is not needed to load the extension, and store builds get IDs from the stores, which are
   then added to the host's `allowed_origins`.
2. **Blocking known dangerous sites with local lists.** A static `declarativeNetRequest` ruleset blocks
   top-level navigation and sub-resources to listed domains. The browser enforces it, so no URL leaves
   the device. When a page load is blocked by one of our domains, the tab shows Kshatriya's warning page
   with "Go back" and "Continue anyway". Continuing adds a session rule that allows that site in that tab
   only, until the browser restarts.
3. **The default list holds only a test domain** (`blocktest.kshatriya.invalid`). No list with a licence
   compatible with redistribution under Apache-2.0 has been chosen yet; that is an open owner decision.
   `scripts/Build-BrowserBlocklist.ps1` turns a domain or hosts file the owner is entitled to use into a
   ruleset (capped at 30,000 domains). A list baked into the extension goes stale; delivering lists
   through signed content packages (ADR 0008) via the service is the planned follow-up.
4. **Download scanning through Kshatriya.** When a download completes, the extension sends its path to
   the native host `com.kshatriya.browser_host` (`Kshatriya.BrowserHost.exe`). The host is a broker: it
   reads nothing from the file, checks that the path is a local, fully qualified path to an existing
   file (not a folder, not UNC or device paths), and asks the service to scan it as the signed-in user,
   exactly like Explorer's "Scan with Kshatriya". Results are report-only; the extension never deletes or
   quarantines. The host enforces a 64 KiB request limit before allocating, parses requests strictly, and
   handles one request per launch.
5. **Look-alike warnings, never blocks.** Before and after navigation the extension checks the host name
   locally for imitation of well-known brands: digit and letter swaps (`paypa1`), one-letter typos,
   a brand's domain used as a subdomain of another site, and internationalised names that mix Latin with
   Cyrillic or Greek letters. A match shows a badge on the toolbar icon and one notification per site per
   browser session. These are heuristics, so they are labelled as possible imitation, matching the rule
   that heuristics only ever report "suspicious".
6. **What the extension does not do:** read page contents or keystrokes, inject scripts into pages, send
   browsing history or URLs anywhere, inspect encrypted traffic, block ads, or change browser security
   settings. Its permissions are fixed in a test (`declarativeNetRequest`, `webNavigation`, `downloads`,
   `nativeMessaging`, `notifications`, `storage`), and it has no host permissions.
7. **Installation (prototype).** The installer copies the extension to
   `%ProgramFiles%\Kshatriya\browser-extension` and registers the native host for Edge and Chrome under
   `HKLM`. The user loads the extension with "Load unpacked" in developer mode. Kshatriya does not
   force-install it through browser policy. Store publishing is an owner decision.

## Consequences

- Download scanning works only while the service runs; otherwise the popup and a single notification
  say so. Large downloads take as long as any scan of that file.
- `webNavigation` makes the browser show a "read your browsing history" permission warning. The URLs
  stay inside the extension; this is stated in the extension description and popup.
- Without a chosen blocklist, site blocking is plumbing plus a test entry. The README says so.
- The extension logic is plain JavaScript without a build step or dependencies; its tests run with
  `node --test tests/extension` in CI.
