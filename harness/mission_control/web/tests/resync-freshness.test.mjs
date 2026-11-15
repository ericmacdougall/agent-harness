// goodqa#16117, PR 257 review v1 F1: the stream updates held during a /api/state load are replayed only when they are
// newer than the installed snapshot and come from the same server process. Snapshots carry `stream: {generation,
// revision}`; each stream message carries `id: <generation>.<revision>` (MessageEvent.lastEventId), as the server sends.
import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.document.getElementById = () => null;
globalThis.setInterval = () => { throw new Error('no polling'); };

// A fake server process: a random generation and a revision counter shared by snapshots and stream messages.
const server = { generation: 'aa11', revision: 0 };
function restart(generation) { server.generation = generation; server.revision = 0; }

const sources = [];
class FakeES {
  static CLOSED = 2;
  constructor(url) { this.url = url; this.readyState = 1; this.l = {}; sources.push(this); }
  addEventListener(t, f) { this.l[t] = f; }
  close() { this.readyState = 2; }
  emit(t, data) { this.l[t]?.(data === undefined ? {} : { data: JSON.stringify(data) }); }
  // a stream message as the server frames it; `from` overrides the stamp (an old process, or none at all)
  send(t, data, from) {
    const id = from === undefined ? `${server.generation}.${++server.revision}` : from;
    this.l[t]?.({ data: JSON.stringify(data), lastEventId: id });
  }
}
globalThis.EventSource = FakeES;

const reads = (truth, at) => ({ goals: { truth, facts: [{ id: 'ledger:goals', truth, at: truth === 'current' ? at : '', error: '' }] } });
const ledger = (id, state) => ({ goals: { items: [{ id, title: id, state }] }, requirements: { items: [] }, status: {} });
const empty = () => ({ goals: { items: [] }, requirements: { items: [] }, status: {} });
const snapshot = (tag, stream, extra = {}) => ({ version: '1', host: 'h', csrf: 'c', initiatives: { items: [] }, owners: [],
  health: [], events: [], chat: { messages: [], replies: [], targets: [] }, asks: { items: [] },
  reads: reads('current', new Date().toISOString()), ledger: ledger(tag, 'LIVE_TESTED'), stream, ...extra });

// fetch is answered only when the test releases it. The server stamps the snapshot when the request reaches it, which
// a test chooses by calling `stamp()` (by default: when the request is made).
const pending = [];
globalThis.fetch = async () => {
  const at = { generation: server.generation, revision: server.revision };
  return new Promise(resolve => pending.push({ at, answer: body => resolve({ ok: true, status: 200, json: async () => body }) }));
};
const wait = ms => new Promise(r => setTimeout(r, ms));
async function nextFetch() {
  for (let i = 0; i < 100 && !pending.length; i++) await wait(10);
  assert.ok(pending.length, 'a state load started');
  return pending.shift();
}
const stamp = () => ({ generation: server.generation, revision: server.revision });

const store = await import('../js/store.js');
const live = await import('../js/live.js');
const goals = () => store.getState().ledger.goals.items.map(g => g.id);

test('start: the first load installs and the stream opens live', async () => {
  const started = live.start();
  const load = await nextFetch();
  load.answer(snapshot('boot', load.at));
  await started;
  sources[0].emit('open');
  assert.equal(store.getState().connection, 'live');
});

test('a snapshot newer than the held updates is not overwritten by them; newer held updates still replay', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const load = await nextFetch();
  es.send('ledger', ledger('older', 'BLOCKED'));      // received while the request is still on its way to the server
  const taken = stamp();                              // the server takes the snapshot after that message
  es.send('reads', reads('stale', ''));               // and this one after the snapshot
  load.answer(snapshot('snap', taken));
  await wait(20);
  assert.deepEqual(goals(), ['snap'], 'a held update older than the snapshot was replayed over it');
  assert.equal(store.getState().reads.goals.truth, 'stale', 'a held update newer than the snapshot replays');
  assert.equal(store.getState().connection, 'live');
});

test('a server restart: updates held from the old process are never replayed over the new process\'s snapshot', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const first = await nextFetch();                    // load A, on the old process
  es.send('ledger', ledger('old-process', 'LIVE_TESTED'));
  es.send('reads', reads('current', new Date().toISOString()));
  es.emit('error');                                   // the old process stops
  restart('bb22');
  es.emit('open');                                    // reopened on the new process: load B supersedes load A
  const second = await nextFetch();
  first.answer(snapshot('superseded', first.at));     // A answers late (or never): it must change nothing
  second.answer(snapshot('fresh', second.at, { reads: reads('unknown', ''), ledger: empty() }));
  await wait(20);
  assert.deepEqual(goals(), [], 'old-process rows replayed over the new process\'s empty snapshot');
  assert.equal(store.getState().reads.goals.truth, 'unknown', 'old-process "current" replayed over the new read');
  assert.equal(store.getState().connection, 'live');
});

test('a superseded load\'s held updates are dropped even when the next load fails', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const first = await nextFetch();
  es.send('ledger', ledger('held-by-superseded', 'LIVE_TESTED'));
  es.emit('error');
  restart('cc33');
  es.emit('open');
  const second = await nextFetch();
  pending.length = 0;
  second.answer(undefined);                           // B fails: nothing installed, B's own held updates replay
  await wait(20);
  assert.ok(!goals().includes('held-by-superseded'), 'the buffer of a superseded load outlived it');
  assert.notEqual(store.getState().connection, 'live');
  first.answer(snapshot('late', first.at));
  await wait(20);
  assert.ok(!goals().includes('late'));
});

test('a held update with no parsable stamp is dropped (fail closed)', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const load = await nextFetch();
  es.send('ledger', ledger('unstamped', 'BLOCKED'), '');
  es.send('owners', [], 'cc33.not-a-number');
  load.answer(snapshot('stamped', load.at));
  await wait(20);
  assert.deepEqual(goals(), ['stamped']);
  assert.equal(store.getState().connection, 'live');
});

test('a load begun before a later reopen is superseded at once: its answer installs nothing and is not live', async () => {
  const es = sources[0];
  assert.equal(store.getState().connection, 'live');
  es.emit('error');
  es.emit('open');
  const first = await nextFetch();                    // load A, on the old process
  es.emit('error');                                   // the old process stops while A is in flight
  restart('ee55');
  es.emit('open');                                    // reopened on the new process: a new resync is scheduled
  first.answer(snapshot('old-process-answer', first.at));  // A answers before the new resync's load has started
  await wait(20);
  assert.ok(!goals().includes('old-process-answer'), 'an answer from before the reopen was installed');
  assert.notEqual(store.getState().connection, 'live', 'live on an answer from before the reopen');
  const second = await nextFetch();
  second.answer(snapshot('after-reopen', second.at));
  await wait(20);
  assert.deepEqual(goals(), ['after-reopen']);
  assert.equal(store.getState().connection, 'live');
});

test('a live stream message from another server process marks the page not live and re-reads the state', async () => {
  const es = sources[0];
  assert.equal(store.getState().connection, 'live');
  restart('dd44');                                     // the server restarted between the state read and the stream
  es.send('ledger', ledger('new-process-row', 'BLOCKED'));
  assert.notEqual(store.getState().connection, 'live', 'live while showing a snapshot from another process');
  es.send('ledger', ledger('new-process-row-2', 'BLOCKED'));
  const load = await nextFetch();
  assert.equal(pending.length, 0, 'one re-read, not one per message');
  load.answer(snapshot('new-process', load.at));
  await wait(20);
  assert.deepEqual(goals(), ['new-process']);
  assert.equal(store.getState().connection, 'live');
  live.stop();
});
