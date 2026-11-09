// Offline contract/interaction checks: node verify.mjs. No dependencies or sockets.
import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import { setTimeout as wait } from 'node:timers/promises';

const media = new EventTarget(); media.matches = false;
globalThis.window = { matchMedia: () => media };
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.document = new EventTarget(); document.hidden = false;
const { createSeed, createMock } = await import('./js/mock.js');
const store = await import('./js/store.js');
const { age, freshness, milestones } = await import('./js/ui.js');
const fixture = createSeed();
store.seed(fixture);
let passed = 0;
async function check(name, run) { await run(); console.log(`PASS ${name}`); passed++; }
const exactKeys = (object, keys) => assert.deepEqual(Object.keys(object).sort(), keys.split(' ').sort());
const until = async predicate => {
  for (let i = 0; i < 500; i++) { if (predicate()) return; await wait(5); }
  throw new Error('Timed out waiting for an asynchronous state transition');
};

await check('Exact wire schemas and representative states', () => {
  fixture.initiatives.forEach(item => {
    exactKeys(item, 'id initiative state milestones_done milestones_total pct owner ticket milestones next_step next_eta full_eta note updated estimate_by');
    assert.match(item.estimate_by, /^(main|owner .+)$/);
    if (item.pct !== null) {
      const parts = milestones(item.milestones);
      assert.equal(parts.length, item.milestones_total);
      assert.equal(parts.filter(part => part.done).length, item.milestones_done);
      assert.equal(item.pct, item.milestones_done / item.milestones_total * 100);
    } else assert.equal(item.milestones_done, null);
  });
  assert.equal(new Set(fixture.initiatives.map(item => item.state)).size, 7);
  fixture.owners.forEach(owner => {
    exactKeys(owner, 'agent_id runtime type ticket task state last_item initiative_id');
    exactKeys(owner.last_item, 'at event note');
    assert.ok(['claude', 'codex'].includes(owner.runtime));
  });
  assert.equal(new Set(fixture.owners.map(owner => owner.state)).size, 4);
  fixture.events.forEach(event => {
    exactKeys(event, 'schema id ts kind source actor subject summary severity');
    exactKeys(event.actor, 'runtime session agent');
    exactKeys(event.subject, 'repo branch ticket initiative');
    assert.equal(event.schema, 'mc.event/1');
    assert.ok(store.KINDS[event.kind]);
  });
  fixture.messages.forEach(message => exactKeys(message, 'id from text ts status to'));
  assert.deepEqual(new Set(fixture.sources.map(source => source.state)), new Set(['ok','stale','error']));
});

await check('Age boundaries, future timestamps, and milestone parsing', () => {
  const now = Date.now(), at = seconds => new Date(now - seconds * 1000).toISOString();
  assert.equal(age(at(0), now), 'just now');
  assert.equal(age(at(-10), now), 'just now');
  assert.equal(age(at(240), now), '4 m ago');
  assert.equal(freshness(at(299), now), 'fresh');
  assert.equal(freshness(at(300), now), 'warm');
  assert.equal(freshness(at(1800), now), 'stale');
  assert.deepEqual(milestones('Done: One · Not yet: Two'), [{done:true,text:'One'},{done:false,text:'Two'}]);
});

await check('Event deduplication, pause buffering, filtering, bounded retention', () => {
  const original = store.getState().events[0];
  store.ingestEvent(original);
  assert.equal(store.getState().events.length, fixture.events.length);
  store.pauseFeed();
  const snapshot = store.getState().feedSnapshot;
  for (let i = 0; i < 110; i++) store.ingestEvent({...original,id:`verify-${i}`});
  assert.equal(store.getState().events.length, 100);
  assert.equal(store.getState().feedSnapshot, snapshot);
  assert.equal(store.getState().buffered, 110);
  store.pauseFeed();
  assert.equal(store.getState().buffered, 0);
  for (const kind of Object.keys(store.KINDS)) store.toggleFilter(kind);
  assert.equal(store.getState().filters.length, 0);
  store.toggleFilter('all');
  assert.equal(store.getState().filters.length, 8);
  const length = store.getState().events.length;
  store.ingestEvent({...original,id:'invalid',schema:'mc.event/2'});
  assert.equal(store.getState().events.length, length);
});

// Accelerate mock delays without changing browser implementation or waiting 7 s.
const nativeTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => nativeTimeout(fn, Math.max(1, ms / 25), ...args);
const adapter = createMock({ event: store.ingestEvent, connection: store.setConnection, sources: store.setSources, message: store.appendMessage, patchMessage: store.patchMessage }, fixture);
store.setChatTransport(adapter.sendChat);
await check('Offline/empty/over-limit chat is rejected without losing state', () => {
  adapter.setConnection('offline');
  const length = store.getState().messages.length;
  assert.equal(store.sendMessage('Keep my draft'), false);
  assert.equal(store.getState().messages.length, length);
  adapter.setConnection('live');
  assert.equal(store.sendMessage('  '), false);
  assert.equal(store.sendMessage('x'.repeat(4001)), false);
});

await check('Claude queues, respects session, then delivers a whole reply', async () => {
  store.setResponder('claude'); store.setSession('review');
  assert.equal(store.sendMessage('What needs attention?'), true);
  const id = store.getState().messages.at(-1).id;
  assert.equal(store.getState().messages.at(-1).status, 'sending');
  await until(() => store.getState().messages.find(message => message.id === id).status === 'queued');
  await until(() => store.getState().messages.find(message => message.id === id).status === 'answered');
  const reply = store.getState().messages.at(-1);
  assert.equal(reply.from, 'claude'); assert.equal(reply.status, 'answered');
  assert.match(reply.text, /^From the review session:/);
});

await check('Codex streams multiple text updates before completing', async () => {
  const lengths = new Set();
  const unsubscribe = store.subscribe(state => {
    const reply = state.messages.at(-1);
    if (reply.from === 'codex') lengths.add(reply.text.length);
  });
  store.setResponder('codex');
  store.sendMessage('Check the runner');
  const id = store.getState().messages.at(-1).id;
  await until(() => store.getState().messages.find(message => message.id === id).status === 'answered');
  unsubscribe();
  assert.ok(lengths.size > 10);
  assert.equal(store.getState().messages.at(-1).from, 'codex');
});

await check('Failure and retry preserve the original ID, responder, and session', async () => {
  adapter.setFailNext(true);
  store.setResponder('claude'); store.setSession('review');
  store.sendMessage('Review the release');
  const message = store.getState().messages.at(-1);
  await until(() => store.getState().messages.find(item => item.id === message.id).status === 'failed');
  store.setResponder('codex'); store.setSession('main');
  store.retryMessage(message.id);
  await until(() => store.getState().messages.find(item => item.id === message.id).status === 'answered');
  assert.equal(store.getState().messages.filter(item => item.id === message.id).length, 1);
  assert.equal(store.getState().messages.at(-1).from, 'claude');
  assert.match(store.getState().messages.at(-1).text, /^From the review session:/);
});

await check('Connection loss during a queued reply fails cleanly; reconnect can retry', async () => {
  store.setResponder('claude'); store.sendMessage('Check status');
  const id = store.getState().messages.at(-1).id;
  await until(() => store.getState().messages.find(message => message.id === id).status === 'queued');
  adapter.setConnection('offline');
  await until(() => store.getState().messages.find(message => message.id === id).status === 'failed');
  adapter.setConnection('live'); store.retryMessage(id);
  await until(() => store.getState().messages.find(message => message.id === id).status === 'answered');
});

await check('Live timer and burst produce unique events across all eight kinds', async () => {
  const ids = new Set(), kinds = new Set();
  const unsubscribe = store.subscribe((state, reason) => {
    if (reason === 'event') { ids.add(state.events[0].id); kinds.add(state.events[0].kind); }
  });
  adapter.start();
  await until(() => ids.size >= 2);
  adapter.burst(); adapter.burst(); adapter.stop(); unsubscribe();
  assert.ok(ids.size >= 18);
  assert.equal(kinds.size, 8);
});
globalThis.setTimeout = nativeTimeout;

await check('Reduced motion overrides the saved motion preference', () => {
  store.toggleMotion(); assert.equal(store.getState().motion, false);
  store.toggleMotion(); assert.equal(store.getState().motion, true);
  const change = new Event('change'); change.matches = true; media.dispatchEvent(change);
  assert.equal(store.getState().motion, false);
  const restore = new Event('change'); restore.matches = false; media.dispatchEvent(restore);
  assert.equal(store.getState().motion, true);
});

await check('Local-only assets, existing DOM hooks, safe data sinks, own-file budget', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(ids.length, new Set(ids).size, 'Duplicate HTML IDs');
  let bytes = Buffer.byteLength(html);
  for (const file of await readdir(new URL('./js/', import.meta.url))) {
    const code = await readFile(new URL(`./js/${file}`, import.meta.url), 'utf8');
    bytes += Buffer.byteLength(code);
    assert.doesNotMatch(code, /\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write/);
    for (const [,id] of code.matchAll(/getElementById\(['"]([^'"]+)['"]\)/g)) assert.ok(ids.includes(id), `Missing #${id}`);
    for (const [,path] of code.matchAll(/(?:from\s+|import\()['"]([^'"]+)['"]/g)) {
      assert.ok(path.startsWith('.'), `External import ${path}`);
      await stat(new URL(`./js/${path}`, import.meta.url));
    }
  }
  assert.doesNotMatch(html, /(?:src|href)="(?:https?:)?\/\//);
  for (const file of ['styles.css','DESIGN.md','verify.mjs']) bytes += (await stat(new URL(`./${file}`,import.meta.url))).size;
  assert.ok(bytes < 250000, `Own files are ${bytes} bytes`);
  console.log(`     Own files: ${bytes.toLocaleString()} bytes`);
});
console.log(`\n${passed} checks passed. Browser layout, real keyboard behavior, and GPU rendering still require visual review.`);
