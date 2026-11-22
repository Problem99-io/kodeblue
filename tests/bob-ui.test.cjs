const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../internal/hub/web/bob.js'), 'utf8');
function runtime(handler) {
  const timers = new Map(); let timerId = 0;
  const ctx = vm.createContext({ encodeURIComponent,
    setTimeout: (fn) => { timers.set(++timerId, fn); return timerId; }, clearTimeout: (id) => timers.delete(id),
    S: { servers: [{ id: 's1', enrolled: true, status: { accepts_bob: true, accepts_messages: true } }] },
    enc: encodeURIComponent, parseHash: () => ({}), taskHash: (_, srv, id) => `#/t/${srv}/${id}`,
    when: () => 'now', usd: (v) => `$${v}`, api: handler, toast: () => {},
  });
  vm.runInContext(`
    globalThis.elements = [];
    function h(tag, attrs, ...kids) {
      const node = { tag, attrs:attrs || {}, kids:kids.flat().filter(x => x != null), value:'', disabled:!!attrs?.disabled,
        events:{}, isConnected:true, append(...xs){this.kids.push(...xs.filter(x => x != null));},
        addEventListener(name, fn){this.events[name]=fn;}, focus(){} };
      elements.push(node); return node;
    }
    function clear(node){node.kids=[];return node;}
    function md(text){return h('div',null,text);}
    function modal(title,body,footer,onClose){ globalThis.dialog={title,body,footer,isConnected:true,
      close(){this.isConnected=false;onClose();}};return dialog;}
  `,ctx);
  vm.runInContext(source,ctx);
  const run = (s) => vm.runInContext(s,ctx);
  return { ctx, run, timers };
}
const report = `{id:7,title:'Unconfirmed access'}`;

test('unsupported or disabled servers do not offer an action-capable fallback', async () => {
  let calls = 0; const {run} = runtime(async () => {calls++;});
  run('S.servers[0].status.accepts_bob=false');
  await run(`askBob('s1',${report})`);
  assert.equal(calls,0);
  assert.equal(run(`bobButton('s1',${report}).disabled`),true);
});
test('opening an empty Bob conversation sends one explanation to the dedicated endpoint', async () => {
  const requests=[];let sent=false;
  const {run,timers}=runtime(async(method,url,body)=>{
    requests.push({method,url,body});
    if(method==='POST'){sent=true;return {};}
    return sent?[{id:1,command:'bob',conversation_id:'c_bob',status:'queued',author:'Alice',body:'Explain'}]:[];
  });
  await run(`askBob('s1',${report})`);
  const posts=requests.filter(r=>r.method==='POST');assert.equal(posts.length,1);
  assert.equal(posts[0].url,'/api/servers/s1/bob');assert.equal(posts[0].body.incident_id,7);
  assert.equal(posts[0].body.conversation_id,'');assert.equal(posts[0].body.body,'Please explain this report.');
  assert.equal(timers.size,1,'only one poll should be scheduled');
  run('dialog.close()');assert.equal(timers.size,0);
});
test('existing history opens without another billed explanation and follows the Bob conversation', async () => {
  const requests=[];
  const {run}=runtime(async(method,url,body)=>{
    requests.push({method,url,body});
    return method==='POST'?{}:[{id:1,command:'bob',conversation_id:'c_bob',status:'done',author:'Alice',body:'Explain',reply:'The report is inconclusive.'}];
  });
  await run(`askBob('s1',${report})`);
  assert.equal(requests.filter(r=>r.method==='POST').length,0);
  await run(`elements.find(e=>e.tag==='textarea').value='Was anything blocked?';elements.find(e=>e.tag==='textarea').events.input();dialog.footer[1].events.click()`);
  const post=requests.find(r=>r.method==='POST');assert.equal(post.url,'/api/servers/s1/bob');assert.equal(post.body.conversation_id,'c_bob');
});
test('a failed initial history request never sends a question', async () => {
  let posts=0;const {run}=runtime(async(method)=>{if(method==='POST')posts++;throw Error('offline');});
  await run(`askBob('s1',${report})`);assert.equal(posts,0);
  assert.match(run(`elements.find(e=>e.attrs.role==='status').textContent`),/Could not load/);
});
test('uncertain delivery preserves the draft and requires refreshing before retry', async () => {
  let posts=0;const {run}=runtime(async(method)=>{if(method==='POST'){posts++;throw Error('connection lost');}return [];});
  await run(`askBob('s1',${report})`);
  assert.equal(posts,1);assert.match(run(`elements.find(e=>e.tag==='textarea').value`),/explain this report/);
  assert.equal(run('dialog.footer[1].disabled'),true);
  await run('dialog.footer[1].events.click()');assert.equal(posts,1);
});
test('Bob history excludes operator sessions and selects the latest Bob conversation', () => {
  const {run}=runtime(async()=>[]);
  assert.equal(run(`bobConversation([{id:1,command:'',conversation_id:'c_operator'},{id:2,command:'bob',conversation_id:'c_old'},{id:3,command:'bob',conversation_id:'c_new'}]).id`),'c_new');
  assert.equal(run(`bobConversation([{id:1,command:'bob',conversation_id:'c_old'},{id:2,command:'bob',conversation_id:'c_new'}]).messages.length`),1);
});

test('a dialog removed by sign-out does not continue polling', async () => {
  let requests=0;
  const {run,timers}=runtime(async()=>{requests++;return [{id:1,command:'bob',conversation_id:'c_bob',status:'queued',author:'Alice',body:'Explain'}];});
  await run(`askBob('s1',${report})`);
  const before=requests;run('dialog.isConnected=false');
  await [...timers.values()][0]();
  assert.equal(requests,before);
});

test('closing while history is loading cannot trigger an explanation', async () => {
  let finish,posts=0;
  const {run}=runtime(async(method)=>{if(method==='POST'){posts++;return {};}return new Promise(resolve=>{finish=resolve;});});
  const opening=run(`askBob('s1',${report})`);
  run('dialog.close()');finish([]);await opening;
  assert.equal(posts,0);
});

test('sign-out cleanup releases the dialog and its poll timer', async () => {
  const {run,timers}=runtime(async()=>[{id:1,command:'bob',conversation_id:'c_bob',status:'queued',author:'Alice',body:'Explain'}]);
  await run(`askBob('s1',${report})`);
  assert.equal(timers.size,1);run('closeBob()');
  assert.equal(run('bobDialog'),null);assert.equal(timers.size,0);
});
