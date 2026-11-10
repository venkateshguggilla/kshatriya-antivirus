# ADR 0019: Web blocklists delivered through signed content

- Status: accepted (follow-up planned in ADR 0018, point 3; owner said "continue" on 2026-11-10)
- Date: 2026-11-10

## Context

The browser extension (ADR 0018) blocks dangerous sites with a static ruleset baked into the extension.
A baked-in list goes stale between releases, and changing it means reloading the extension. Kshatriya
already delivers signatures, rules and IP blocklists in signed `.kstu` packages (ADR 0008, ADR 0012), with
signature checks before parsing, anti-rollback and expiry.

Platform facts this design relies on (Chrome for Developers, `chrome.declarativeNetRequest`, checked
2026-11-10): an extension can add, remove and replace **dynamic rules** at run time with
`updateDynamicRules`, and they persist across browser restarts and extension updates. Chrome 121 and later
guarantee 30,000 "safe" dynamic rules (block and allow rules are safe); earlier versions allow 5,000
dynamic and session rules together. The limits count rules, not domains: the documentation sets no limit
on the domains in one rule's `requestDomains`, which also matches subdomains. Native-messaging messages
from the host to the extension are limited to 1 MB. `storage.local` holds 10 MB without the
`unlimitedStorage` permission.

## Decision

1. **A new content kind, `*.webblock`.** It starts with `# kshatriya-webblock v1` and lists one domain
   per line (`#` comment lines allowed). A domain covers its subdomains. Entries must be lower-case ASCII
   host names (internationalised names in their `xn--` form), with at least two labels and a non-numeric
   last label. That refuses IP addresses, single labels, wildcards, URLs and paths. Any invalid line
   rejects the whole list, and so the whole package at import (`contentInvalid`), as with `.netblock`.
   At most 500,000 domains and 16 Mi characters across all lists in a package. `kshatriya-content pack`
   checks the lists before signing.
2. **The service serves the list to anyone.** The active package's web blocklist is held in memory and
   replaced atomically when a new package is activated. A pipe message (`WebBlocklistQuery`, protocol
   version 11) returns one **page** of it to any local client, without impersonation: it is published
   content, the same for every user, and reveals nothing about anyone. The client gives an offset and a
   byte budget (at most 900,000, counting each domain as its length plus 3 for JSON quotes and comma);
   the reply carries the package sequence, the total, the offset and the next offset. A package without a
   `.webblock` file means an empty list. The latest package wins, as with `.netblock`.
3. **The native host relays it page by page.** The request `{"v":1,"type":"blocklist","offset":n}`
   returns `{sequence, total, offset, next, domains}`, one page of at most 900,000 bytes of domains, so
   every reply fits in one native message (tested with the shortest and longest domains). The host
   re-checks every domain, the limits and that the page is consistent, and refuses to pass on anything
   malformed (`blocklist-failed`). It still opens no files.
4. **The extension installs it as dynamic rules.** At browser start, on install, at most every 6 hours
   while the service worker runs, and when the popup opens (at most every 10 minutes), the extension
   asks the host for the first page. When its sequence, total and the number of installed rules match
   what is installed it stops there; otherwise it fetches every page, refusing pages that are
   inconsistent or whose sequence or total changes mid-fetch, and replaces its dynamic rules in one
   `updateDynamicRules` call (1,000 domains per rule, so at most 500 rules). Any failure leaves the
   installed rules in place. The list is not stored a second time (it can exceed `storage.local`): the
   warning page and "Continue anyway" read the domains back from the installed rules. No new permission
   is needed.
5. **Measured in Edge before raising the limit (2026-11-10).** Microsoft Edge (headless, this project's
   development PC), a throwaway profile, a test extension installing 1,000 domains per rule, then 15 loads
   of a local page with 30 sub-resources:

   | Domains | Rules | Install (once) | Read rules back | Page load (median) | Edge private memory | Listed domain blocked |
   |---|---|---|---|---|---|---|
   | 0 | 0 | — | — | 256 ms / 203 ms (two runs) | 534 MB / 557 MB | — |
   | 30,000 | 30 | 0.67 s | 0.03 s | 193 ms | 529 MB | yes |
   | 100,000 | 100 | 0.73 s | 0.12 s | 251 ms | 496 MB | yes |
   | 200,000 | 200 | 0.84 s | 0.24 s | 145 ms | 542 MB | yes |
   | 386,091 | 387 | 1.47 s | 0.45 s | 81 ms | 549 MB | yes |

   Page loads and memory show no trend beyond the run-to-run noise of the two empty runs. Not measured:
   Google Chrome (not installed on that PC), browser start-up with the rules in place (headless Edge
   does not reload a command-line extension after a restart), and slower PCs.
6. **Source: Phishing.Database (MIT).** On 2026-11-10 the owner chose
   [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (`phishing-domains-ACTIVE.txt`,
   MIT). Other candidates were rejected: URLhaus terms forbid derivative works and charge for commercial
   use, Phishing Army has no licence and defers to upstream terms, Hagezi is GPL (ADR 0003), and The Block
   List Project's Unlicense covers data it copies from GPL lists. The list is not committed; the owner
   builds packages with `scripts/Build-BrowserBlocklist.ps1 -Format webblock` and signs them with their
   own key. The source held 392,178 active domains (386,091 after validation and the protected-domain
   check). The first package, before paging, held a 28,878-domain sample; with paging the whole list
   fits. Over `-MaxDomains` (default 100,000, at most 500,000) the script keeps a sample ordered by
   SHA-256 of each domain, which is not biased by the source's alphabetical order. Lists only cover
   phishing; Microsoft Defender SmartScreen and Google Safe Browsing remain the main protection.
7. **Protected domains.** A listed domain blocks its subdomains, so listing a shared platform would block
   many legitimate sites. The source listed `sites.google.com` and `bit.ly`. `protected-domains.txt` (in
   `Kshatriya.Updates`, embedded) names shared hosting and document platforms, URL shorteners, sign-in
   services and two-part public suffixes. The build script drops them; the service, and the host, refuse
   any list that contains one of them or a parent of one. Sites hosted on those platforms
   (`evil.github.io`) may still be listed.

## Consequences

- Updating the site list no longer needs an extension release: an administrator imports a signed package
  and every browser picks it up within hours, or immediately when its popup opens.
- A full list of about 390,000 domains takes about 13 pages, each a separate start of the native host and
  connection to the service, but only when the list has changed.
- Old clients and a new service (or the reverse) refuse each other at the protocol-version check. They
  are installed together, so this only matters for hand-mixed builds.
- No production signing key exists yet (ADR 0008), so in practice only packages signed with an
  administrator's own key can carry lists.
- The extension trusts the host to relay what the service holds; the signature is checked by the service,
  not the extension. The host and extension still validate every domain, so a compromised list can only
  block sites. It can never allow one, run code or read pages.
