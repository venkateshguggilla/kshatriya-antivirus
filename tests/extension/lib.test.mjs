// Run with: node --test tests/extension
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { domainToUnicode } from 'node:url';
import { domainsFromRules, hostOf, matchListedDomain, registrableDomain } from '../../extension/lib/domains.js';
import { checkHost, describeLookalike, editDistance, skeleton } from '../../extension/lib/lookalike.js';
import { baseName, describeScan, parseReply, scanRequest } from '../../extension/lib/messages.js';
import { decodeLabel, hostToUnicode } from '../../extension/lib/punycode.js';

test('hostOf keeps only http(s) host names', () => {
  assert.equal(hostOf('https://WWW.Example.com./path?q=1'), 'www.example.com');
  assert.equal(hostOf('http://192.168.1.1:8080/'), '192.168.1.1');
  assert.equal(hostOf('chrome://settings'), null);
  assert.equal(hostOf('file:///C:/x.html'), null);
  assert.equal(hostOf('not a url'), null);
});

test('registrable domains handle common two-part suffixes', () => {
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(registrableDomain('www.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('a listed domain also covers its subdomains, not look-alike parents', () => {
  const listed = domainsFromRules([
    { action: { type: 'block' }, condition: { requestDomains: ['bad.example'] } },
    { action: { type: 'allow' }, condition: { requestDomains: ['good.example'] } },
  ]);
  assert.deepEqual([...listed], ['bad.example']);
  assert.equal(matchListedDomain(listed, 'bad.example'), 'bad.example');
  assert.equal(matchListedDomain(listed, 'x.y.bad.example'), 'bad.example');
  assert.equal(matchListedDomain(listed, 'notbad.example'), null);
  assert.equal(matchListedDomain(listed, 'good.example'), null);
});

test('punycode decoding matches the platform decoder', () => {
  for (const host of ['xn--mnchen-3ya.de', 'xn--pple-43d.com', 'xn--80ak6aa92e.com', 'xn--n3h.com', 'xn--fiqs8s.cn']) {
    assert.equal(hostToUnicode(host), domainToUnicode(host), host);
  }
  assert.equal(decodeLabel('!!!'), null);
  assert.equal(decodeLabel(''), null);
});

test('skeleton and edit distance', () => {
  assert.equal(skeleton('paypa1'), 'paypal');
  assert.equal(skeleton('rnicrosoft'), 'microsoft');
  assert.equal(skeleton('g00gle'), 'google');
  assert.equal(editDistance('gooogle', 'google'), 1);
  assert.equal(editDistance('google', 'google'), 0);
  assert.equal(editDistance('amazon', 'facebook', 2), 3);
});

test('look-alike names are flagged with the brand they imitate', () => {
  const cases = {
    'paypa1.com': ['imitation', 'PayPal'],
    'www.rnicrosoft.com': ['imitation', 'Microsoft'],
    'gooogle.com': ['typo', 'Google'],
    'amaz0n.co.uk': ['imitation', 'Amazon'],
    'paypal-login.com': ['brand-in-name', 'PayPal'],
    'paypal.com.account-check.xyz': ['subdomain', 'PayPal'],
    'xn--pple-43d.com': ['unicode', 'Apple'],
    'xn--80ak6aa92e.com': ['unicode', 'Apple'],
  };
  for (const [host, [kind, brand]] of Object.entries(cases)) {
    assert.deepEqual(checkHost(host), { kind, brand }, host);
  }
});

test('real sites and ordinary names are not flagged', () => {
  for (const host of [
    'paypal.com', 'www.google.com', 'google.co.in', 'mail.google.com', 'login.microsoftonline.com',
    'google-analytics.com', 'someone.github.io', 'github.com', 'apply.com', 'example.com',
    'xn--mnchen-3ya.de', 'xn--fiqs8s.cn', '192.168.1.1', 'localhost', 'onlinesbi.sbi',
  ]) {
    assert.equal(checkHost(host), null, host);
  }
});

test('look-alike descriptions name the host and the brand', () => {
  const text = describeLookalike({ kind: 'imitation', brand: 'PayPal' }, 'paypa1.com');
  assert.match(text, /paypa1\.com/);
  assert.match(text, /PayPal/);
});

test('scan requests only carry local drive paths', () => {
  assert.deepEqual(scanRequest('C:\\Users\\a\\Downloads\\x.exe'), { v: 1, type: 'scan', path: 'C:\\Users\\a\\Downloads\\x.exe' });
  assert.equal(scanRequest('\\\\server\\share\\x.exe'), null);
  assert.equal(scanRequest('x.exe'), null);
  assert.equal(scanRequest(42), null);
});

test('host replies are validated strictly', () => {
  const clean = { v: 1, type: 'scan', ok: true, status: 'clean', detections: [] };
  assert.deepEqual(parseReply(clean, 'scan'), { ok: true, status: 'clean', reason: null, detections: [] });
  assert.equal(parseReply({ ...clean, extra: 1 }, 'scan').error, 'bad-reply');
  assert.equal(parseReply({ ...clean, status: 'infected' }, 'scan').error, 'bad-reply');
  assert.equal(parseReply({ ...clean, v: 2 }, 'scan').error, 'bad-reply');
  assert.equal(parseReply(clean, 'status').error, 'bad-reply');
  assert.equal(parseReply({ ...clean, detections: [{ name: 'x', category: 'virus', confidence: 'high' }] }, 'scan').error, 'bad-reply');
  assert.deepEqual(parseReply({ v: 1, type: 'status', ok: true, serviceVersion: '0.12.0' }, 'status'), { ok: true, serviceVersion: '0.12.0' });
  assert.deepEqual(
    parseReply({ v: 1, type: 'scan', ok: false, error: 'service-unavailable', message: 'down' }, 'scan'),
    { ok: false, error: 'service-unavailable', message: 'down' },
  );
  assert.equal(parseReply(null, 'scan').error, 'bad-reply');
});

test('scan results become plain notifications', () => {
  const detected = describeScan('x.exe', {
    ok: true, status: 'detected', reason: null,
    detections: [{ name: 'EICAR-Test-File', category: 'test', confidence: 'high' }],
  });
  assert.equal(detected.level, 'danger');
  assert.match(detected.message, /EICAR-Test-File \(a test file\)/);
  assert.equal(describeScan('x.exe', { ok: true, status: 'clean', detections: [] }).level, 'ok');
  assert.match(describeScan('x.iso', { ok: true, status: 'notScanned', reason: 'tooLarge', detections: [] }).message, /larger than the scan size limit/);
  assert.match(describeScan('x.exe', { ok: false, error: 'service-unavailable', message: '' }).message, /isn't running/);
  assert.equal(baseName('C:\\Users\\a\\Downloads\\setup.exe'), 'setup.exe');
});
