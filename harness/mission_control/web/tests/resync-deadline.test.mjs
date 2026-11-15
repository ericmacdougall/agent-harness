// goodqa#16117, PR 257 review v3 F3: the state-load timeout is authoritative. A load whose fetch() or response.json()
// never settles (abort ignored, or no AbortController) still ends at the deadline: the page is not live, the caller's
// retry runs, and another request starts without the stalled one ever being answered. A body that arrives after the
// deadline installs nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.document.getElementById = () => null;
globalThis.setInterval = () => { throw new Error('no polling'); };

const GENERATION = '0123456789abcdef';
let revision = 0;
const sources = [];
class FakeES {
  static CLOSED = 2;
  constructor(url) { this.url = url; this.readyState = 1; this.l = {}; sources.push(this); }
  addEventListener(t, f) { this.l[t] = f; }
  close() { this.readyState = 2; }
  emit(t, data) { this.l[t]?.(data === undefined ? {} : { data: JSON.stringify(data), lastEventId: `${GENERATION}.${++revision}` }); }
}
globalThis.EventSource = FakeES;

const ledger = id => ({ goals: { items: [{ id, title: id, state: 'LIVE_TESTED' }] }, requirements: { items: [] }, status: {} });
const snapshot = (tag, stream) => ({ version: '1', host: 'h', csrf: 'c', initiatives: { items: [] }, owners: [], health: [],
  events: [], chat: { messages: [], replies: [], targets: [] }, asks: { items: [] }, reads: {}, ledger: ledger(tag), stream });

// Each request is recorded; the test decides whether and when its response, and separately its body, settle. The fake
// ignores the abort signal, as a fetch without AbortController support would.
const requests = [];
globalThis.fetch = () => {
  const stream = { generation: GENERATION, revision };
  const request = { stream };
  requests.push(request);
  return new Promise(resolve => {
    request.respond = body => resolve({ ok: true, status: 200, json: async () => body });
    request.respondStalledBody = () => {
      let release;
      const body = new Promise(r => { release = r; });
      request.releaseBody = value => release(value);
      resolve({ ok: true, status: 200, json: () => body });
    };
  });
};
const wait = ms => new Promise(r => setTimeout(r, ms));
async function until(check, ms, what) {
  for (let t = 0; t < ms && !check(); t += 10) await wait(10);
  assert.ok(check(), what);
}

const store = await import('../js/store.js');
const live = await import('../js/live.js');
const goals = () => store.getState().ledger.goals.items.map(g => g.id);

test('start: the first load installs and the stream opens live', async () => {
  const started = live.start();
  await until(() => requests.length === 1, 1000, 'the first load started');
  requests[0].respond(snapshot('boot', requests[0].stream));
  await started;
  sources[0].emit('open');
  assert.equal(store.getState().connection, 'live');
});

test('a resync whose fetch never settles ends at the deadline and another request starts', async () => {
  live.setStateTimeout(80);
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  await until(() => requests.length === 2, 1000, 'the resync load started');
  // requests[1] is never answered, not even after the test
  await wait(150);
  assert.notEqual(store.getState().connection, 'live', 'live after a timed-out load');
  await until(() => requests.length === 3, 2500, 'a retry started without the stalled request ever settling');
  requests[2].respond(snapshot('after-retry', requests[2].stream));
  await wait(20);
  assert.deepEqual(goals(), ['after-retry']);
  assert.equal(store.getState().connection, 'live');
});

test('a response whose body never settles ends at the deadline; a body that arrives late installs nothing', async () => {
  const es = sources[0];
  es.emit('error');
  es.emit('open');
  await until(() => requests.length === 4, 1000, 'the resync load started');
  const stalled = requests[3];
  stalled.respondStalledBody();
  await wait(150);
  assert.notEqual(store.getState().connection, 'live');
  await until(() => requests.length === 5, 2500, 'a retry started while the first body never settled');
  stalled.releaseBody(snapshot('late-body', stalled.stream));  // the old body arrives after its deadline
  await wait(20);
  assert.ok(!goals().includes('late-body'), 'a body after the deadline was installed');
  requests[4].respond(snapshot('fresh', requests[4].stream));
  await wait(20);
  assert.deepEqual(goals(), ['fresh']);
  assert.equal(store.getState().connection, 'live');
  live.stop();
});

test('a first load that never settles ends at the deadline and start() tries again', async () => {
  const before = requests.length;
  const started = live.start();
  await until(() => requests.length === before + 1, 1000, 'the first load started');
  await Promise.race([started, wait(500)]);
  assert.equal(store.getState().connection, 'offline', 'start() is offline after a timed-out first load');
  await until(() => requests.length === before + 2, 6500, 'start() retried without the stalled request settling');
  requests.at(-1).respond(snapshot('restarted', requests.at(-1).stream));
  await until(() => sources.length === 2, 1000, 'the stream opened after the retry');
  assert.deepEqual(goals(), ['restarted']);
  live.stop();
});
