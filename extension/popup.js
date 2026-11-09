const statusEl = document.getElementById('status');
const blocklistEl = document.getElementById('blocklist');
const recentEl = document.getElementById('recent');

function pill(level, text) {
  const span = document.createElement('span');
  span.className = `pill ${level}`;
  span.textContent = text;
  return span;
}

function describe(entry) {
  switch (entry.kind) {
    case 'block':
      return ['danger', `Blocked ${entry.host}`];
    case 'allowed':
      return ['warn', `You allowed ${entry.host} in one tab`];
    case 'lookalike':
      return ['warn', `${entry.host} may imitate ${entry.brand ?? 'another site'}`];
    case 'scan':
      return [entry.level === 'ok' ? 'ok' : entry.level, entry.summary];
    default:
      return ['info', ''];
  }
}

function render(state) {
  statusEl.replaceChildren(
    state.status.ok
      ? pill('ok', `Connected to Kshatriya ${state.status.serviceVersion}`)
      : pill('warn', state.status.error === 'host-missing'
        ? 'Kshatriya helper not installed: downloads are not scanned'
        : "Kshatriya service isn't running: downloads are not scanned"),
  );

  const info = state.blocklist;
  blocklistEl.textContent = info && info.source !== 'test'
    ? `Blocklist: ${state.listedDomains} sites from ${info.source}, built ${info.built}.`
    : 'Blocklist: test entry only. No list of dangerous sites has been added yet.';

  for (const key of ['scanDownloads', 'lookalikeWarnings']) {
    const box = document.getElementById(key);
    box.checked = Boolean(state.settings[key]);
    box.onchange = () => chrome.runtime.sendMessage({ type: 'set-setting', key, value: box.checked });
  }

  if (state.recent.length > 0) {
    recentEl.replaceChildren(...state.recent.map((entry) => {
      const [level, text] = describe(entry);
      const li = document.createElement('li');
      li.append(pill(level, new Date(entry.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })), ' ', text);
      return li;
    }));
  }
}

chrome.runtime.sendMessage({ type: 'popup-state' }).then(render);
