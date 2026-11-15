// goodqa#16117 F2: a reconnect resync whose /api/state answer is older than stream messages that arrived meanwhile
// must not overwrite them, and a superseded answer must never mark the page live.
import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.document.getElementById = () => null;
globalThis.setInterval = () => { throw new Error('no polling'); };
const sources = [];
class FakeES {
  static CLOSED = 2;
  constructor(url) { this.url = url; this.readyState = 1; this.l = {}; sources.push(this); }
  addEventListener(t, f) { this.l[t] = f; }
  close() { this.readyState = 2; }
  emit(t, data) { this.l[t]?.(data === undefined ? {} : { data: JSON.stringify(data) }); }
}
globalThis.EventSource = FakeES;

const reads = (truth, at) => ({ state: 'ok', truth, generated: at, sources: {} });
const ledger = (id, state) => ({ goals: { items: [{ id, title: id, state }] }, requirements: { items: [] }, status: {} });
const snapshot = tag => ({ version: '1', host: 'h', csrf: 'c', initiatives: { items: [] }, owners: [], health: [], events: [],
  chat: { messages: [], replies: [], targets: [] }, asks: { items: [] }, reads: reads('current', tag), ledger: ledger(tag, 'LIVE_TESTED') });

// fetch answers only when the test releases it, so a response can arrive after newer stream messages
const pending = [];
globalThis.fetch = async () => new Promise(resolve => pending.push(body => resolve({ ok: true, status: 200, json: async () => body })));
const wait = ms => new Promise(r => setTimeout(r, ms));
async function nextFetch() { for (let i = 0; i < 100 && !pending.length; i++) await wait(10); assert.ok(pending.length, 'a state load started'); return pending.shift(); }

const store = await import('../js/store.js');
const live = await import('../js/live.js');

test('start: the first load installs and the stream opens live', async () => {
  const started = live.start();
  (await nextFetch())(snapshot('boot'));
  await started;
  sources[0].emit('open');
  assert.equal(store.getState().connection, 'live');
});

test('a delayed resync answer does not overwrite newer stream data or restore a false current', async () => {
  const es = sources[0];
  es.emit('error');                // drop: reconnecting
  es.emit('open');                 // reopen: resync after 300 ms
  const answer = await nextFetch();
  es.emit('reads', reads('stale', 'new'));        // newer than the answer still on its way
  es.emit('ledger', ledger('new', 'STALE'));
  answer(snapshot('old'));                        // the older answer lands last
  await wait(20);
  const state = store.getState();
  assert.equal(state.ledger.goals.items[0].id, 'new', 'the stream update arrived after the answer was taken');
  assert.equal(state.ledger.goals.items[0].state, 'STALE');
  assert.equal(state.reads.truth, 'stale', 'the reads block stays stale');
});

test('a superseded answer neither installs nor marks the page live', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const first = await nextFetch();
  es.emit('error');                // dropped again while the first load is in flight
  es.emit('open');                 // a second resync supersedes the first
  const second = await nextFetch();
  first(snapshot('superseded'));
  await wait(20);
  assert.notEqual(store.getState().ledger.goals.items[0].id, 'superseded');
  assert.notEqual(store.getState().connection, 'live', 'only the current load may mark the page live');
  es.emit('ledger', ledger('during-second', 'STALE'));
  second(snapshot('second'));
  await wait(20);
  assert.equal(store.getState().ledger.goals.items[0].id, 'during-second', 'held update replays after the current answer');
  assert.equal(store.getState().connection, 'live');
});

test('a failed resync replays the held stream updates and is not live', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  const answer = await nextFetch();
  es.emit('ledger', ledger('held', 'BLOCKED'));
  assert.notEqual(store.getState().ledger.goals.items[0].id, 'held', 'held while the load is in flight');
  pending.length = 0;
  answer(undefined);  // json() resolves to undefined: install throws, nothing installed
  await wait(20);
  assert.equal(store.getState().ledger.goals.items[0].id, 'held');
  assert.notEqual(store.getState().connection, 'live');
  live.stop();
});
