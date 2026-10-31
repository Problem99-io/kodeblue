// Run with: node --test tests/hub-ui.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../internal/hub/web/app.js'), 'utf8').replace(/route\(\);\s*$/, '');
function runtime() {
  const ctx = vm.createContext({ document: { getElementById: () => null, addEventListener() {}, querySelector: () => null },
    window: { addEventListener() {} }, location: { hash: '#/settings', hostname: '127.0.0.1' },
    history: { replaceState() {} }, localStorage: { getItem: () => null },
    navigator: {platform: "Mac"}, setInterval() {}, setTimeout() {}, clearInterval() {}, clearTimeout() {}, TextEncoder, console });
  vm.runInContext(source, ctx);
  // Render-only tree: no browser, network, credentials or server mutations.
  vm.runInContext(`h = (tag, attrs, ...children) => ({ tag, attrs: attrs || {}, children: children.flat(Infinity).filter(x => x != null && x !== false), isConnected: true });
    sync = (body, node) => { globalThis.rendered = node; };`, ctx);
  return { ctx, run: (code) => vm.runInContext(code, ctx) };
}
test('missing settings never become null prices or disabled booleans', () => {
  const {run} = runtime();
  for (const kind of ['usd','bool','number']) for (const value of ['null','undefined','""']) assert.equal(run(`fmtTuning({kind:"${kind}"}, ${value})`), '');
  assert.equal(run('fmtTuning({kind:"usd"}, 0)'), '$0');
  assert.equal(run('fmtTuning({kind:"bool"}, "false")'), 'no');
  assert.equal(run('fmtTuning({kind:"bool"}, "true")'), 'yes');
});
test('a server without an inventory is not described as fully monitored', async () => {
  const {run,ctx} = runtime();
  run('api = async () => [];');
  await run('vServices({id:"test"}, {dataset:{}})');
  const text = JSON.stringify(ctx.rendered);
  assert.match(text, /Awaiting inventory/);
  assert.doesNotMatch(text, /every check covered/);
});
test('accepted vulnerabilities are labeled separately from fixed issues', async () => {
  const {run,ctx} = runtime();
  run(`api = async (method,path) => path.includes('/service') ? [] : [{data:{id:'v1',status:'accepted',service:'web'}}];
    vulnTable = () => h('div', null, 'details');`);
  await run('vServices({id:"test"}, {dataset:{}})');
  assert.match(JSON.stringify(ctx.rendered), /1 risks accepted \(not fixed\)/);
});
test('new case cannot send without an enrolled server', async () => {
  const {run} = runtime();
  run(`P.st = {isNew:true}; P.newSrv = {value:''}; P.comp = {setNote:(text) => globalThis.note=text}; api = () => {throw Error('unexpected request')};`);
  await run('sendMessage("Investigate")');
  assert.equal(run('note'), 'Connect a server first.');
});
test('messages disabled by server policy cannot be sent', async () => {
  const {run} = runtime();
  run(`P.st = {isNew:true}; P.newSrv = {value:'s1'}; S.servers = [{id:'s1',enrolled:true,status:{accepts_messages:false}}];
    P.comp = {setNote:(text) => globalThis.note=text}; api = () => {throw Error('unexpected request')};`);
  await run('sendMessage("Investigate")');
  assert.match(run('note'), /cannot receive messages/);
});
test('save feedback clears only the corresponding dirty form', () => {
  const {run} = runtime();
  run(`globalThis.a=statusLine(); globalThis.b=statusLine(); a.say('Unsaved changes'); b.say('Unsaved changes'); a.say('Saved','ok');`);
  assert.equal(run('dirtyForms.size'), 1);
  assert.equal(run('dirtyForms.has(b.el)'), true);
});
test('staying on unsaved settings preserves its dirty state', async () => {
  const {run} = runtime();
  run(`dirtyForms.add({isConnected:true}); location.hash='#/'; ask=async()=>false;`);
  await run('route()');
  assert.equal(run('dirtyForms.size'), 1);
  assert.equal(run('currentHash'), '#/settings');
});
test('approval impact explains irreversible consequences', () => {
  const {run} = runtime();
  assert.match(run('actionImpact("kill_process")'), /cannot be undone/);
  assert.match(run('actionImpact("lock_user")'), /does not restore/);
});
test('sign-out cancellation preserves unsaved settings and session', async () => {
  const {run} = runtime();
  run(`dirtyForms.add({isConnected:true}); S.me={name:'admin'}; ask=async()=>false; api=()=>{throw Error('unexpected logout')};`);
  await run('logout()');
  assert.equal(run('dirtyForms.size'),1);
  assert.equal(run('S.me.name'),'admin');
});
test('confirmed sign-out clears dirty forms and session', async () => {
  const {run} = runtime();
  run(`dirtyForms.add({isConnected:true}); S.me={name:'admin'}; ask=async()=>true; api=async()=>{}; renderLogin=()=>{};`);
  await run('logout()');
  assert.equal(run('dirtyForms.size'),0);
  assert.equal(run('S.me'),null);
});
test('first-use board disables archives and tolerates a missing redraw handler', async () => {
  const {run} = runtime();
  run(`const originalH=h; h=(...args)=>{const el=originalH(...args);el.appendChild=x=>el.children.push(x);el.setAttribute=(k,v)=>el.attrs[k]=v;return el;};
    ic=()=>null; onboarding=()=>h('div',null,'setup'); S.servers=[]; S.redrawBoard=null; globalThis.main=h('main'); main.append=(...xs)=>main.children.push(...xs);`);
  await run('vBoard({},main,null)');
  assert.equal(run('main.children[0].children.find(x=>x.attrs?.class?.includes("arch-t")).attrs.disabled'),true);
  run('main.children[0].children.find(x=>x.attrs?.class?.includes("arch-t")).attrs.on.click()');
});
test('a message is not blocked when the server list could not load', async () => {
  const {run} = runtime();
  run(`P.st = {isNew:true}; P.newSrv = {value:'s1'}; S.servers = []; P.key = 'k'; P.comp = {setNote:(text) => globalThis.note=text, send:{}};
    api = async (method, path) => { globalThis.sent = path; throw Object.assign(Error('offline'), {status: 0}); };`);
  await run('sendMessage("Investigate").catch(() => {})');
  assert.equal(run('sent'), '/api/servers/s1/messages');
});
test('the fleet settings form does not claim values come from a server', () => {
  const {run} = runtime();
  run(`globalThis.tf = tuningForm([{key:'budget', kind:'usd', group:'Budget', label:'Daily budget'}], {budget:'5'});`);
  const label = (reported) => run(`tf.paint(() => "each server's own", ${reported}); (function find(n) { if (n && n.attrs && /frow-now/.test(n.attrs.class || '')) return n; for (const c of (n && n.children) || []) { const r = find(c); if (r) return r; } })(tf.el).textContent`);
  assert.equal(label('null'), '');
  assert.equal(label('{}'), 'Not reported');
  assert.equal(label('{budget:"3"}'), 'Running: $3');
});
test('notification empty states cover Slack and Telegram', async () => {
  const {run} = runtime();
  run(`api = async (m, path) => path.endsWith('/telegram') ? {configured:true} : {configured:false};`);
  assert.equal(await run('deliveryConfigured()'), true);
  run(`api = async () => ({configured:false});`);
  assert.equal(await run('deliveryConfigured()'), false);
  run(`api = async () => { throw Error('forbidden'); };`);
  assert.equal(await run('deliveryConfigured()'), null);
});
