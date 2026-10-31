const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const source = readFileSync(join(__dirname, '../internal/hub/web/research-tracker.js'), 'utf8');
function tracker() {
  const calls = [];
  const context = { window: {}, navigator: {}, location: { origin: 'https://website.example', pathname: '/public' },
    crypto: { randomUUID: () => '01234567-89ab-4def-89ab-0123456789ab' }, URL, Date,
    fetch: async (...args) => { calls.push(args); return { ok: true, json: async () => ({ stored: true }) }; } };
  vm.runInNewContext(source, context);
  return { sdk: context.window.kodeblueAnalytics, context, calls };
}
test('collection requires explicit permission and respects privacy signals', async () => {
  const { sdk, context, calls } = tracker();
  assert.equal(await sdk.track('pageview'), false);
  assert.equal(sdk.start({ site: 'website', permitted: () => false }), true);
  assert.equal(await sdk.track('pageview'), false);
  sdk.start({ site: 'website', permitted: () => true });
  context.navigator.globalPrivacyControl = true;
  assert.equal(await sdk.track('pageview'), false);
  context.navigator.globalPrivacyControl = false; context.navigator.doNotTrack = '1';
  assert.equal(await sdk.track('pageview'), false);
  assert.equal(calls.length, 0);
});
test('bounded schema excludes arbitrary properties and never persists an identity', async () => {
  const { sdk, calls } = tracker();
  sdk.start({ site: 'website', permitted: () => true });
  assert.equal(calls.length, 0); // Configuring alone never sends telemetry.
  assert.equal(await sdk.track('interaction', 'email_address'), false);
  assert.equal(await sdk.track('performance', 'lcp', Infinity), false);
  assert.equal(await sdk.track('interaction', 'contact_click'), true);
  const [url, request] = calls[0];
  assert.equal(url, 'https://website.example/collect/research/website');
  assert.equal(request.credentials, 'omit');
  const event = JSON.parse(request.body).events[0];
  assert.deepEqual(Object.keys(event).sort(), ['at', 'id', 'kind', 'name', 'path']);
  sdk.stop(); assert.equal(await sdk.track('pageview'), false);
  assert.equal(calls.length, 1);
});
test('no insecure collector or credential-bearing endpoint', () => {
  const { sdk } = tracker();
  for (const endpoint of ['http://remote.example/collect', 'https://user:pass@remote.example/collect', 'https://remote.example/collect?token=secret']) {
    assert.equal(sdk.start({ site: 'website', endpoint, permitted: () => true }), false);
  }
});
