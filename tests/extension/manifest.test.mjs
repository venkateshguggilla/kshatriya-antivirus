// Guards the extension's permissions and packaging decisions (ADR 0018).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const root = new URL('../../extension/', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const manifest = JSON.parse(read('manifest.json'));

/** Chrome's extension ID: the first 128 bits of SHA-256 of the public key, as letters a-p. */
function extensionId(base64Key) {
  const hash = createHash('sha256').update(Buffer.from(base64Key, 'base64')).digest();
  return [...hash.subarray(0, 16)].map((b) => String.fromCharCode(97 + (b >> 4), 97 + (b & 15))).join('');
}

test('permissions are exactly the reviewed set, with no host access or page scripts', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(
    [...manifest.permissions].sort(),
    ['declarativeNetRequest', 'downloads', 'nativeMessaging', 'notifications', 'storage', 'webNavigation'],
  );
  for (const key of ['host_permissions', 'optional_permissions', 'optional_host_permissions', 'content_scripts', 'web_accessible_resources', 'externally_connectable']) {
    assert.equal(manifest[key], undefined, key);
  }
});

test('the pinned extension ID is the one the installer allows', () => {
  const id = extensionId(manifest.key);
  assert.equal(id, 'lkkpcdfabgihmnhfdmhoellokaobmdah');
  const installer = readFileSync(new URL('../../scripts/Install-KshatriyaService.ps1', import.meta.url), 'utf8');
  assert.match(installer, new RegExp(`chrome-extension://${id}/`));
});

test('every file the manifest names exists', () => {
  const files = [
    manifest.background.service_worker, manifest.action.default_popup,
    ...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon),
    ...manifest.declarative_net_request.rule_resources.map((r) => r.path),
  ];
  for (const file of files) assert.doesNotThrow(() => readFileSync(new URL(file, root)), file);
});

test('the blocklist is a valid blocking ruleset within the guaranteed limits', () => {
  const rules = JSON.parse(read('rules/blocklist.json'));
  const info = JSON.parse(read('rules/blocklist-info.json'));
  const ids = new Set(rules.map((r) => r.id));
  assert.equal(ids.size, rules.length);
  assert.ok(rules.length <= 30000);
  let domains = 0;
  for (const rule of rules) {
    assert.ok(Number.isInteger(rule.id) && rule.id > 0);
    assert.equal(rule.action.type, 'block');
    assert.ok(rule.condition.resourceTypes.includes('main_frame'));
    for (const domain of rule.condition.requestDomains) {
      assert.match(domain, /^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
      domains++;
    }
  }
  assert.ok(domains <= 30000);
  assert.equal(info.domains, domains);
  assert.ok(rules.some((r) => r.condition.requestDomains.includes('blocktest.kshatriya.invalid')), 'test entry kept');
});

test('pages load scripts from files only (Manifest V3 forbids inline script)', () => {
  for (const page of ['popup.html', 'blocked.html']) {
    const html = read(page);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, page);
    assert.doesNotMatch(html, /\son[a-z]+=/i, page);
  }
});
