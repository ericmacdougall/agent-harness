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

test('review PR 234 v6: the claim panels repaint when the link drops or returns, not on every connection word', () => {
  const reasons = [];
  const off = store.subscribe((_, reason) => reasons.push(reason));
  store.setConnection('live');
  reasons.length = 0;
  store.setConnection('reconnecting');
  store.setConnection('offline');      // still not live: no second repaint
  store.setConnection('live');
  off();
  assert.deepEqual(reasons, ['connection', 'truth', 'connection', 'connection', 'truth']);
});

test('review PR 234 v6: after a drop the page is live again only once it re-read the state (a restarted server)', async () => {
  const { claim } = await import('../js/adapt.js');
  const at = new Date().toISOString();
  const before = { ...state, ledger: { goals: { at, truth: 'current', items: [{ id: 'old', title: 'Old', state: 'LIVE_TESTED' }] }, requirements: { items: [] }, status: {} } };
  const restarted = { ...state, ledger: { goals: { at: '', truth: 'unknown', items: [] }, requirements: { items: [] }, status: {} } };
  let answer = before;
  globalThis.fetch = async url => {
    fetches.push(String(url));
    return answer ? { ok: true, status: 200, json: async () => answer } : { ok: false, status: 503, json: async () => ({}) };
  };
  await live.start();
  const stream = sources.at(-1);
  stream.emit('open');
  assert.equal(store.getState().connection, 'live');
  assert.equal(claim(store.getState(), 'goals').truth, 'current');
  stream.emit('error');                       // the server process stops; the browser retries
  answer = null;                              // the new process is not serving state yet
  stream.emit('open');                        // the stream reopens on the new process
  assert.notEqual(store.getState().connection, 'live', 'live on the stream opening alone, with the old process\'s rows');
  await new Promise(r => realSet(r, 450));    // the re-read failed
  assert.notEqual(store.getState().connection, 'live', 'live after a failed re-read');
  assert.notEqual(claim(store.getState(), 'goals').truth, 'current');
  assert.equal(store.getState().ledger.goals.items[0].id, 'old');
  answer = restarted;
  await new Promise(r => realSet(r, 1300));   // the re-read is tried again and succeeds
  assert.equal(store.getState().connection, 'live');
  assert.deepEqual(store.getState().ledger.goals.items, [], 'the new process\'s state replaced the old rows');
  assert.equal(claim(store.getState(), 'goals').truth, 'unknown');
  live.stop();
});
