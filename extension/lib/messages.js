// Messages to and from the native host com.kshatriya.browser_host
// (schema: docs/schemas/browser-host.v1.schema.json). Replies are validated before use.

export const HOST_NAME = 'com.kshatriya.browser_host';

const STATUSES = new Set(['clean', 'detected', 'suspicious', 'skipped', 'notScanned']);
const CATEGORIES = new Set(['malware', 'pua', 'suspicious', 'test']);
const CONFIDENCES = new Set(['low', 'medium', 'high']);
const REPLY_KEYS = new Set(['v', 'type', 'ok', 'serviceVersion', 'status', 'reason', 'detections', 'error', 'message', 'sequence', 'total', 'offset', 'next', 'domains']);
export const MAX_BLOCKED_DOMAINS = 500000;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** A lower-case ASCII host name with at least two labels whose last label is not numeric (as the service checks). */
export function isBlockableDomain(domain) {
  if (typeof domain !== 'string' || domain.length === 0 || domain.length > 253) return false;
  const labels = domain.split('.');
  return labels.length >= 2 && labels.every((label) => LABEL.test(label)) && !/^\d+$/.test(labels[labels.length - 1]);
}

/** A scan request for a local drive path such as C:\Users\me\Downloads\setup.exe, or null. */
export function scanRequest(path) {
  if (typeof path !== 'string' || !/^[A-Za-z]:\\/.test(path) || path.length > 32767) return null;
  return { v: 1, type: 'scan', path };
}

export const statusRequest = () => ({ v: 1, type: 'status' });

/** Asks for one page of the dangerous-site list from Kshatriya's signed content updates (ADR 0019). */
export const blocklistRequest = (offset = 0) => ({ v: 1, type: 'blocklist', offset });

const text = (value) => typeof value === 'string' && value.length <= 200;

/** Validates a host reply; anything unexpected becomes { ok: false, error: 'bad-reply' }. */
export function parseReply(reply, expectedType) {
  const bad = { ok: false, error: 'bad-reply', message: 'The Kshatriya helper sent an unexpected reply.' };
  if (!reply || typeof reply !== 'object' || Array.isArray(reply) || reply.v !== 1) return bad;
  if (Object.keys(reply).some((key) => !REPLY_KEYS.has(key))) return bad;
  if (reply.ok === false) {
    return text(reply.error) && text(reply.message) ? { ok: false, error: reply.error, message: reply.message } : bad;
  }
  if (reply.ok !== true || reply.type !== expectedType) return bad;
  if (expectedType === 'status') {
    return text(reply.serviceVersion) ? { ok: true, serviceVersion: reply.serviceVersion } : bad;
  }
  if (expectedType === 'blocklist') {
    const { sequence, total, offset, next, domains } = reply;
    const count = (n) => Number.isSafeInteger(n) && n >= 0;
    if (![sequence, total, offset, next].every(count) || total > MAX_BLOCKED_DOMAINS) return bad;
    if (!Array.isArray(domains) || domains.length > MAX_BLOCKED_DOMAINS || !domains.every(isBlockableDomain)) return bad;
    return { ok: true, sequence, total, offset, next, domains };
  }
  if (!STATUSES.has(reply.status) || !Array.isArray(reply.detections) || reply.detections.length > 10) return bad;
  if (reply.reason !== undefined && !text(reply.reason)) return bad;
  for (const d of reply.detections) {
    if (!d || !text(d.name) || !CATEGORIES.has(d.category) || !CONFIDENCES.has(d.confidence)) return bad;
  }
  return { ok: true, status: reply.status, reason: reply.reason ?? null, detections: reply.detections };
}

const REASONS = {
  tooLarge: "it's larger than the scan size limit",
  timeout: 'the scan took too long',
  accessDenied: "your account can't read it",
  locked: 'another program has it open',
  notFound: 'it was moved or deleted before the scan',
  blockedBySecurityProduct: 'Microsoft Defender or another security product blocked it',
  excluded: 'it matches one of your Kshatriya exclusions',
  cloudPlaceholder: "it's an online-only cloud file",
  reparsePoint: "it's a link to another location",
};

const CATEGORY_TEXT = { malware: 'malware', pua: 'a potentially unwanted app', suspicious: 'suspicious', test: 'a test file' };

/** Notification text for a finished download scan. level: ok | warn | danger | info. */
export function describeScan(fileName, result) {
  if (!result.ok) {
    if (result.error === 'service-unavailable') {
      return { level: 'info', title: "Couldn't scan download", message: `${fileName}: the Kshatriya service isn't running.` };
    }
    if (result.error === 'host-missing') {
      return { level: 'info', title: "Couldn't scan download", message: 'The Kshatriya helper is not installed. Reinstall Kshatriya Antivirus.' };
    }
    return { level: 'info', title: "Couldn't scan download", message: `${fileName}: ${result.message}` };
  }
  switch (result.status) {
    case 'clean':
      return { level: 'ok', title: 'Download scanned', message: `${fileName}: no threats found.` };
    case 'detected': {
      const first = result.detections[0];
      const what = first ? `${first.name} (${CATEGORY_TEXT[first.category]})` : 'a threat';
      return { level: 'danger', title: 'Threat found in download', message: `${fileName}: ${what}. Don't open it; review it in Kshatriya Antivirus.` };
    }
    case 'suspicious':
      return { level: 'warn', title: 'Suspicious download', message: `${fileName} looks suspicious. Open it only if you trust where it came from.` };
    default: {
      const why = REASONS[result.reason] ?? 'it could not be read';
      return { level: 'info', title: 'Download not scanned', message: `${fileName} wasn't scanned because ${why}.` };
    }
  }
}

/** The file name part of a Windows path. */
export function baseName(path) {
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1] || String(path);
}
