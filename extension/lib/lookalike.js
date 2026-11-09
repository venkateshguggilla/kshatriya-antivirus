// Local look-alike checks for host names (ADR 0018). Heuristics: results are warnings, never blocks.

import { isIpAddress, registrableDomain } from './domains.js';
import { decodeLabel } from './punycode.js';

/** Brand name -> display name. The registrable label equal to the brand is never flagged. */
export const BRANDS = new Map([
  ['paypal', 'PayPal'], ['google', 'Google'], ['microsoft', 'Microsoft'], ['microsoftonline', 'Microsoft'],
  ['apple', 'Apple'], ['icloud', 'iCloud'], ['amazon', 'Amazon'], ['facebook', 'Facebook'],
  ['instagram', 'Instagram'], ['whatsapp', 'WhatsApp'], ['netflix', 'Netflix'], ['linkedin', 'LinkedIn'],
  ['outlook', 'Outlook'], ['github', 'GitHub'], ['dropbox', 'Dropbox'], ['wellsfargo', 'Wells Fargo'],
  ['bankofamerica', 'Bank of America'], ['hdfcbank', 'HDFC Bank'], ['icicibank', 'ICICI Bank'],
  ['onlinesbi', 'State Bank of India'], ['paytm', 'Paytm'], ['flipkart', 'Flipkart'], ['yahoo', 'Yahoo'],
  ['ebay', 'eBay'], ['adobe', 'Adobe'], ['binance', 'Binance'], ['coinbase', 'Coinbase'],
  ['steampowered', 'Steam'], ['steamcommunity', 'Steam'], ['discord', 'Discord'],
]);

/** Real sites whose names contain a brand plus something else. */
const OFFICIAL = new Set([
  'google-analytics.com', 'googleapis.com', 'googleusercontent.com', 'googlevideo.com', 'paypal-community.com',
  'paypalobjects.com', 'microsoft365.com', 'facebookmail.com', 'amazonaws.com', 'amazon-adsystem.com',
  'githubusercontent.com', 'githubassets.com', 'discordapp.com', 'discordapp.net', 'icloud-content.com',
  'adobelogin.com', 'linkedinmobileapp.com',
]);

/** Brands long enough that a one-letter difference is unlikely to be a different real word. */
const MIN_TYPO_LENGTH = 6;

/** Cyrillic and Greek letters that look like Latin ones. */
const CONFUSABLES = new Map(Object.entries({
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ӏ: 'l', һ: 'h',
  ԛ: 'q', ԝ: 'w', ο: 'o', α: 'a', ν: 'v', ι: 'i', κ: 'k', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ε: 'e',
}));

const DIGIT_SWAPS = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' };

/** How a label would read if digits and letter pairs that imitate letters were the letters. */
export function skeleton(label) {
  let text = '';
  for (const ch of label) text += CONFUSABLES.get(ch) ?? DIGIT_SWAPS[ch] ?? ch;
  return text.replace(/-/g, '').replace(/rn/g, 'm').replace(/vv/g, 'w');
}

/** Levenshtein distance, stopping early once it exceeds max. */
export function editDistance(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost);
      rowMin = Math.min(rowMin, current[j]);
    }
    if (rowMin > max) return max + 1;
    previous = current;
  }
  return previous[b.length];
}

const isLatinLetter = (ch) => /[a-z]/i.test(ch);
const isCyrillicOrGreek = (ch) => /[Ͱ-ϿЀ-ӿԀ-ԯ]/u.test(ch);

/** A decoded label that mixes Latin with Cyrillic/Greek, or is made only of Latin look-alikes. */
function isDeceptiveUnicode(text) {
  const letters = [...text].filter((ch) => /\p{L}/u.test(ch));
  const foreign = letters.filter(isCyrillicOrGreek);
  if (foreign.length === 0) return false;
  if (letters.some(isLatinLetter)) return true;
  return foreign.every((ch) => CONFUSABLES.has(ch));
}

function brandFor(text) {
  return BRANDS.has(text) ? text : null;
}

/**
 * Checks a lower-case host name. Returns null, or { kind, brand } where kind is
 * "imitation" (digit/letter swaps), "typo" (one letter off), "brand-in-name" (brand plus words),
 * "subdomain" (brand.com placed in front of another site) or "unicode" (mixed or look-alike scripts).
 */
export function checkHost(host) {
  if (typeof host !== 'string' || host.length === 0 || isIpAddress(host)) return null;
  const registrable = registrableDomain(host);
  if (OFFICIAL.has(registrable)) return null;
  const label = registrable.split('.')[0];

  // Internationalised labels anywhere in the name.
  for (const part of host.split('.')) {
    if (!part.startsWith('xn--')) continue;
    const decoded = decodeLabel(part.slice(4));
    if (decoded && isDeceptiveUnicode(decoded)) {
      return { kind: 'unicode', brand: BRANDS.get(brandFor(skeleton(decoded))) ?? null };
    }
  }

  if (BRANDS.has(label)) return null;

  const swapped = skeleton(label);
  if (BRANDS.has(swapped)) return { kind: 'imitation', brand: BRANDS.get(swapped) };

  for (const [brand, name] of BRANDS) {
    if (brand.length >= MIN_TYPO_LENGTH && editDistance(label, brand, 1) === 1) return { kind: 'typo', brand: name };
  }

  for (const token of label.split('-')) {
    if (label.includes('-') && BRANDS.has(token)) return { kind: 'brand-in-name', brand: BRANDS.get(token) };
  }

  const labels = host.split('.');
  const prefix = labels.slice(0, labels.length - registrable.split('.').length);
  for (let i = 0; i < prefix.length - 1; i++) {
    if (BRANDS.has(prefix[i]) && ['com', 'net', 'org', 'co', 'in'].includes(prefix[i + 1])) {
      return { kind: 'subdomain', brand: BRANDS.get(prefix[i]) };
    }
  }
  return null;
}

/** A short explanation for the notification and the popup. */
export function describeLookalike(result, host) {
  const who = result.brand ?? 'another site';
  switch (result.kind) {
    case 'imitation':
      return `${host} swaps letters or digits to look like ${who}.`;
    case 'typo':
      return `${host} is one letter away from ${who}.`;
    case 'brand-in-name':
      return `${host} uses the name ${who} but isn't ${who}'s own site.`;
    case 'subdomain':
      return `${host} puts ${who}'s address in front of a different site.`;
    case 'unicode':
      return `${host} uses letters from other alphabets that can imitate ${who}.`;
    default:
      return `${host} may be imitating ${who}.`;
  }
}
