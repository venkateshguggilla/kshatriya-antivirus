// Host-name helpers shared by the background worker and the tests. Pure functions only.

/** Two-part public suffixes common enough to matter for the look-alike check (not a full list). */
const TWO_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'net.in', 'org.in', 'gov.in',
  'ac.in', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'co.nz', 'co.za', 'com.sg', 'com.cn', 'com.tr',
  'com.hk', 'com.tw', 'co.kr', 'com.ar', 'co.id', 'com.my', 'com.ph', 'com.pk', 'com.sa', 'com.eg',
]);

/** The lower-case host name of an http(s) URL, without a trailing dot; null for anything else. */
export function hostOf(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  return host.length > 0 ? host : null;
}

/** True for IPv4 and bracketed IPv6 literals, which have no registrable domain. */
export function isIpAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
}

/** The registrable domain ("example.co.uk" for "www.example.co.uk"), approximated without the full PSL. */
export function registrableDomain(host) {
  if (isIpAddress(host)) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return TWO_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

/** The listed domain that covers host (itself or a parent domain), or null. */
export function matchListedDomain(domains, host) {
  let candidate = host;
  while (candidate) {
    if (domains.has(candidate)) return candidate;
    const dot = candidate.indexOf('.');
    if (dot < 0) return null;
    candidate = candidate.slice(dot + 1);
  }
  return null;
}

/** All requestDomains of the blocking rules in a declarativeNetRequest ruleset. */
export function domainsFromRules(rules) {
  const domains = new Set();
  if (!Array.isArray(rules)) return domains;
  for (const rule of rules) {
    if (rule?.action?.type !== 'block') continue;
    for (const domain of rule?.condition?.requestDomains ?? []) {
      if (typeof domain === 'string') domains.add(domain.toLowerCase());
    }
  }
  return domains;
}
