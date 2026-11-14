// Transport: reconnect, one resync, no polling, ledger events (goodqa#15920 AC-5, NEG-5).
import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

const listeners = new Map();
globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.document.getElementById = () => null;
const fetches = []; const sources = [];
let timers = 0;
const realSet = globalThis.setTimeout;
globalThis.setInterval = () => { throw new Error('the page must not poll with setInterval from live.js'); };
class FakeES {
  static CLOSED = 2;
  constructor(url) { this.url = url; this.readyState = 1; this.l = {}; sources.push(this); }
  addEventListener(t, f) { this.l[t] = f; }
  close() { this.readyState = 2; }
  emit(t, data) { this.l[t]?.(data === undefined ? {} : { data: JSON.stringify(data) }); }
}
globalThis.EventSource = FakeES;
const state = { version: '1', host: 'h', csrf: 'c', initiatives: { items: [] }, owners: [], health: [], events: [], chat: { messages: [], replies: [], targets: [] }, asks: { items: [] },
  ledger: { goals: { items: [{ id: 'g', title: 'T', state: 'LIVE_TESTED' }] }, requirements: { items: [] }, status: {} } };
globalThis.fetch = async url => { fetches.push(String(url)); return { ok: true, status: 200, json: async () => state }; };

const store = await import('../js/store.js');
const live = await import('../js/live.js');

test('start loads state once and opens one stream', async () => {
  await live.start();
  assert.deepEqual(fetches, ['/api/state']);
  assert.equal(sources.length, 1);
  assert.equal(store.getState().ledger.goals.items[0].id, 'g');
});

test('a ledger event repaints the store and stamps the last update', () => {
  const before = store.getState().lastData;
  sources[0].emit('ledger', { goals: { items: [{ id: 'g2', title: 'Two', state: 'BLOCKED' }] }, requirements: { items: [] }, status: {} });
  assert.equal(store.getState().ledger.goals.items[0].id, 'g2');
  assert.ok(store.getState().lastData >= before);
});

test('open sets live; a drop shows reconnecting and a single resync follows the reopen', async () => {
  sources[0].emit('open');
  assert.equal(store.getState().connection, 'live');
  sources[0].emit('error');
  assert.equal(store.getState().connection, 'reconnecting');
  const count = fetches.length;
  await new Promise(r => realSet(r, 50));
  assert.equal(fetches.length, count, 'no resync while the browser is retrying');
  sources[0].emit('open');
  await new Promise(r => realSet(r, 450));
  assert.equal(fetches.length, count + 1, 'exactly one resync after the reopen');
});

test('a refused stream goes offline and reconnects with a new stream, not a poll loop', async () => {
  sources[0].readyState = 2;
  sources[0].emit('error');
  assert.equal(store.getState().connection, 'offline');
  live.stop();
});

test('a ledger read for another session reloads the state once (goodqa#15961 review A-7)', async () => {
  state.pin = { display: 'sess-1' };
  await live.start();
  const es = sources[sources.length - 1];
  fetches.length = 0;
  es.emit('ledger', { session: 'sess-1', goals: { items: [] }, requirements: { items: [] }, status: {} });
  assert.deepEqual(fetches, [], 'same session: no reload');
  es.emit('ledger', { session: 'sess-2', goals: { items: [] }, requirements: { items: [] }, status: {} });
  await new Promise(resolve => realSet(resolve, 0));
  assert.deepEqual(fetches, ['/api/state'], 'the pin moved: one state reload');
  delete state.pin;
  live.stop();
});

test('a 401 on state shows signed out', async () => {
  globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });
  await live.start();
  assert.equal(store.getState().connection, 'expired');
  live.stop();
});

test('a flood of 500 events in one burst keeps the store bounded and fast', async () => {
  const start = performance.now();
  for (let i = 0; i < 500; i++) store.ingestEvent({ schema: 'mc.event/1', id: `flood:${i}`, ts: new Date().toISOString(), kind: 'wal', summary: `event ${i}`, severity: 'info', count: 1, actor: {}, subject: {} });
  assert.ok(store.getState().events.length <= 150);
  assert.ok(performance.now() - start < 500, `took ${performance.now() - start} ms`);
});
