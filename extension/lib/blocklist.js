// Fetching the dangerous-site list from Kshatriya one page at a time (ADR 0019). Pure: the caller passes
// askPage(offset), which returns a validated host reply (see messages.js parseReply).

import { MAX_BLOCKED_DOMAINS } from './messages.js';

/** Upper bound on pages, so a misbehaving host cannot keep the extension asking forever. */
export const MAX_PAGES = 1000;

/**
 * Collects every page. Returns { ok: true, sequence, domains }, { ok: true, unchanged: true } when
 * isUnchanged(firstPage) says the installed list is current, or the first failure ({ ok: false, ... }).
 * The list must not change while it is fetched (same sequence and total on every page).
 */
export async function fetchBlocklist(askPage, isUnchanged = () => false) {
  const bad = (message) => ({ ok: false, error: 'bad-reply', message });
  const domains = [];
  let first = null;
  let offset = 0;
  for (let pages = 0; pages < MAX_PAGES; pages++) {
    const page = await askPage(offset);
    if (!page.ok) return page;
    if (page.offset !== offset || page.next !== offset + page.domains.length || page.next > page.total) {
      return bad('The Kshatriya helper sent an inconsistent page of the blocklist.');
    }
    if (page.total > MAX_BLOCKED_DOMAINS) return bad('The blocklist is larger than the extension accepts.');
    if (first === null) {
      first = page;
      if (isUnchanged(page)) return { ok: true, unchanged: true };
    } else if (page.sequence !== first.sequence || page.total !== first.total) {
      return { ok: false, error: 'changed', message: 'The blocklist changed while it was being fetched.' };
    }
    for (const domain of page.domains) domains.push(domain);
    if (page.next === page.total) return { ok: true, sequence: first.sequence, domains };
    if (page.domains.length === 0) return bad('The Kshatriya helper sent an empty page of the blocklist.');
    offset = page.next;
  }
  return bad('The blocklist has too many pages.');
}
