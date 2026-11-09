import { hostOf } from './lib/domains.js';

const target = new URLSearchParams(location.search).get('url') ?? '';
const host = hostOf(target);

document.getElementById('host').textContent = host ?? 'This site';

document.getElementById('back').addEventListener('click', async () => {
  // The blocked page never loaded, so going back returns to the page the user came from.
  if (history.length > 1) {
    history.back();
    return;
  }
  const tab = await chrome.tabs.getCurrent();
  if (tab?.id !== undefined) await chrome.tabs.remove(tab.id);
});

document.getElementById('details').addEventListener('click', () => {
  document.getElementById('continue-box').style.display = 'block';
});

document.getElementById('continue').addEventListener('click', async () => {
  if (!host) return;
  await chrome.runtime.sendMessage({ type: 'allow-site', url: target });
});
