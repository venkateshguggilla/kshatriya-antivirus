// Kshatriya browser extension service worker (ADR 0018).
// - Blocked sites: the browser enforces rules/blocklist.json; this worker only swaps the browser's
//   "blocked" error page for Kshatriya's warning page and handles "Continue anyway".
// - Downloads: finished downloads are sent to the Kshatriya service through the native host (report only).
// - Look-alike sites: checked locally; a badge and one notification per site per browser session.
// Nothing in this file sends URLs or browsing data off the device.

import { domainsFromRules, hostOf, matchListedDomain } from './lib/domains.js';
import { checkHost, describeLookalike } from './lib/lookalike.js';
import { HOST_NAME, baseName, describeScan, parseReply, scanRequest, statusRequest } from './lib/messages.js';

const DEFAULT_SETTINGS = { scanDownloads: true, lookalikeWarnings: true };
const MAX_RECENT = 20;
const ALLOW_RULE_PRIORITY = 100;
const ICON = 'icons/icon-128.png';

let blockedDomains = null;

async function getBlockedDomains() {
  if (!blockedDomains) {
    const response = await fetch(chrome.runtime.getURL('rules/blocklist.json'));
    blockedDomains = domainsFromRules(await response.json());
  }
  return blockedDomains;
}

async function getSettings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

/** Recent activity lives in session storage: it is cleared when the browser closes. */
async function remember(entry) {
  const { recent = [] } = await chrome.storage.session.get('recent');
  recent.unshift({ ...entry, time: Date.now() });
  await chrome.storage.session.set({ recent: recent.slice(0, MAX_RECENT) });
}

function notify(id, title, message) {
  chrome.notifications.create(id, { type: 'basic', iconUrl: ICON, title, message, priority: 1 });
}

/** One request to the native host over a port (a port keeps this worker alive during long scans). */
function askHost(message, expectedType) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };
    let port;
    try {
      port = chrome.runtime.connectNative(HOST_NAME);
    } catch {
      finish({ ok: false, error: 'host-missing', message: 'The Kshatriya helper is not installed.' });
      return;
    }
    port.onMessage.addListener((reply) => {
      finish(parseReply(reply, expectedType));
      port.disconnect();
    });
    port.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError?.message ?? '';
      finish(
        /not found|forbidden/i.test(error)
          ? { ok: false, error: 'host-missing', message: 'The Kshatriya helper is not installed.' }
          : { ok: false, error: 'host-failed', message: 'The Kshatriya helper stopped unexpectedly.' },
      );
    });
    port.postMessage(message);
  });
}

// ---- Blocked sites ---------------------------------------------------------------------------

chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const host = hostOf(details.url);
  if (!host) return;

  if (details.error === 'net::ERR_BLOCKED_BY_CLIENT') {
    const listed = matchListedDomain(await getBlockedDomains(), host);
    if (!listed) return; // blocked by another extension
    await remember({ kind: 'block', host });
    const page = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(details.url)}`);
    await chrome.tabs.update(details.tabId, { url: page });
    return;
  }

  await checkLookalike(details.tabId, host);
});

async function allowSite(url, tabId) {
  const host = hostOf(url);
  if (!host || !matchListedDomain(await getBlockedDomains(), host)) return false;
  const rules = await chrome.declarativeNetRequest.getSessionRules();
  const id = rules.reduce((max, rule) => Math.max(max, rule.id), 0) + 1;
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [{
      id,
      priority: ALLOW_RULE_PRIORITY,
      action: { type: 'allow' },
      condition: { requestDomains: [host], tabIds: [tabId] },
    }],
  });
  await remember({ kind: 'allowed', host });
  await chrome.tabs.update(tabId, { url });
  return true;
}

// ---- Look-alike sites ------------------------------------------------------------------------

async function checkLookalike(tabId, host) {
  if (!(await getSettings()).lookalikeWarnings) return;
  const result = checkHost(host);
  if (!result) return;

  await chrome.action.setBadgeBackgroundColor({ tabId, color: '#B45309' });
  await chrome.action.setBadgeText({ tabId, text: '!' });
  await chrome.action.setTitle({ tabId, title: `Kshatriya: ${describeLookalike(result, host)}` });

  const { warned = [] } = await chrome.storage.session.get('warned');
  if (warned.includes(host)) return;
  await chrome.storage.session.set({ warned: [...warned, host].slice(-200) });
  await remember({ kind: 'lookalike', host, brand: result.brand });
  notify(`lookalike:${host}`, 'This site may be an imitation', `${describeLookalike(result, host)} Don't enter passwords or payment details unless you're sure.`);
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const host = hostOf(details.url);
  if (host) await checkLookalike(details.tabId, host);
});

// ---- Downloads -------------------------------------------------------------------------------

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state?.current !== 'complete') return;
  if (!(await getSettings()).scanDownloads) return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !item.exists) return;

  const request = scanRequest(item.filename);
  if (!request) return;
  const name = baseName(item.filename);
  const result = await askHost(request, 'scan');
  const text = describeScan(name, result);

  if (!result.ok) {
    // Say once per browser session that scanning is unavailable, not for every download.
    const { hostProblemShown } = await chrome.storage.session.get('hostProblemShown');
    await remember({ kind: 'scan', file: name, level: 'info', summary: text.message });
    if (hostProblemShown) return;
    await chrome.storage.session.set({ hostProblemShown: true });
  } else {
    await remember({ kind: 'scan', file: name, level: text.level, summary: text.message });
  }
  notify(`download:${delta.id}`, text.title, text.message);
});

// ---- Messages from the extension's own pages -------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  const fromPage = (page) => typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(page));

  if (message?.type === 'allow-site' && fromPage('blocked.html') && sender.tab?.id !== undefined) {
    allowSite(String(message.url), sender.tab.id).then((ok) => sendResponse({ ok }));
    return true;
  }
  if (message?.type === 'popup-state' && fromPage('popup.html')) {
    Promise.all([
      getSettings(),
      chrome.storage.session.get('recent'),
      askHost(statusRequest(), 'status'),
      getBlockedDomains(),
      fetch(chrome.runtime.getURL('rules/blocklist-info.json')).then((r) => r.json()).catch(() => null),
    ]).then(([settings, { recent = [] }, status, domains, info]) =>
      sendResponse({ settings, recent, status, listedDomains: domains.size, blocklist: info }));
    return true;
  }
  if (message?.type === 'set-setting' && fromPage('popup.html') && message.key in DEFAULT_SETTINGS) {
    chrome.storage.local.set({ [message.key]: Boolean(message.value) }).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
