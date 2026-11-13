// Chat end to end in node with a fake EventSource and fetch (goodqa#15920 AC-6, NEG-6): queued, read, replied with no
// reload; the retry reuses its key; nothing is sent without a user gesture; a draft and a pending message survive a reconnect.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import './dom-shim.mjs';

globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const sources = []; const posts = []; const gets = [];
class FakeES { static CLOSED = 2; constructor(u) { this.url = u; this.readyState = 1; this.l = {}; sources.push(this); } addEventListener(t, f) { this.l[t] = f; } close() { this.readyState = 2; } emit(t, d) { this.l[t]?.(d === undefined ? {} : { data: JSON.stringify(d) }); } }
globalThis.EventSource = FakeES;
let postPlan = [];   // per POST: 'ok' | 'drop' (lost response) | 409
const SESSION = 'baab765b-d85c-46b4-b7b9-588eb912c770';
const targets = [{ session: SESSION, waiting: true }];
const base = { version: '1', host: 'h', csrf: 'tok', initiatives: { items: [] }, owners: [], health: [], events: [], asks: { items: [] }, ledger: {},
  chat: { messages: [], replies: [], targets, main_session: SESSION, codex: { available: false, reason: 'off' } } };
globalThis.fetch = async (url, init = {}) => {
  if (init.method === 'POST') {
    posts.push({ url, body: JSON.parse(init.body), csrf: init.headers['X-MC-CSRF'] });
    const plan = postPlan.shift() || 'ok';
    if (plan === 'drop') throw new TypeError('network');
    if (plan === 409) return { ok: false, status: 409, json: async () => ({ error: 'no-target' }) };
    return { ok: true, status: 201, json: async () => ({ id: 'm1' }) };
  }
  gets.push(String(url));
  return { ok: true, status: 200, json: async () => base };
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const store = await import('../js/store.js');
const live = await import('../js/live.js');
const serverMessage = (key, patch = {}) => ({ id: 'm1', client_key: key, to: 'claude', session: SESSION, thread: null, text: 'hello', ts: new Date().toISOString(), status: 'queued', read_at: null, ...patch });
const chat = (messages, replies = []) => ({ messages, replies, targets, main_session: SESSION, codex: { available: false, reason: 'off' } });

test('a send is one POST with the CSRF header, then queued, read and replied arrive over SSE with no reload', async () => {
  await live.start();
  sources[0].emit('open');  // the stream is up: the composer is allowed
  assert.equal(gets.length, 1);
  assert.equal(store.sendMessage('hello'), true);
  await sleep(20);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].csrf, 'tok');
  const key = posts[0].body.client_key;
  assert.equal(store.getState().messages.at(-1).status, 'queued');
  sources[0].emit('chat', chat([serverMessage(key)]));
  assert.equal(store.getState().messages.find(m => m.id === 'm1').status, 'queued');
  sources[0].emit('chat', chat([serverMessage(key, { status: 'delivered', read_at: new Date().toISOString() })]));
  assert.equal(store.getState().messages.find(m => m.id === 'm1').status, 'delivered');
  assert.ok(store.getState().messages.find(m => m.id === 'm1').read_at);
  sources[0].emit('chat', chat([serverMessage(key, { status: 'answered' })], [{ id: 'r1', from: 'claude', reply_to: 'm1', text: 'hi there', ts: new Date().toISOString(), final: true }]));
  const msgs = store.getState().messages;
  assert.equal(msgs.find(m => m.id === 'm1').status, 'answered');
  assert.equal(msgs.find(m => m.id === 'r1').text, 'hi there');
  assert.equal(msgs.filter(m => m.client_key === key).length, 1, 'the local copy is replaced by the server record, not shown twice');
  assert.equal(gets.length, 1, 'no state reload happened');
});

test('a lost response is retried once with the same client key and the same text', async () => {
  posts.length = 0;
  postPlan = ['drop', 'ok'];
  store.sendMessage('again');
  await sleep(1700);
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body.client_key, posts[1].body.client_key);
  assert.equal(posts[0].body.text, posts[1].body.text);
});

test('a refused send fails visibly, keeps its text, and Retry resends the identical text with the same key', async () => {
  posts.length = 0;
  postPlan = [409];
  store.sendMessage('refused once');
  await sleep(30);
  const failed = store.getState().messages.at(-1);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.text, 'refused once');
  store.retryMessage(failed.id);
  await sleep(30);
  assert.equal(posts.length, 2);
  assert.equal(posts[1].body.text, 'refused once');
  assert.equal(posts[1].body.client_key, posts[0].body.client_key);
});

test('reconnects, resyncs and ledger updates never send anything', async () => {
  posts.length = 0;
  const before = gets.length;
  sources[0].emit('open'); sources[0].emit('error'); sources[0].emit('open');
  sources[0].emit('ledger', { goals: { items: [] }, requirements: { items: [] }, status: {} });
  sources[0].emit('asks', { items: [] });
  await sleep(450);
  assert.equal(posts.length, 0, 'no POST without a click or Enter');
  assert.equal(gets.length, before + 1, 'exactly one resync after the reconnect');
});

test('a failed message stays on screen through a reconnect and a fresh chat snapshot', async () => {
  postPlan = [409];
  store.sendMessage('stays failed');
  await sleep(30);
  assert.equal(store.getState().messages.at(-1).status, 'failed');
  sources[0].emit('error'); sources[0].emit('open');
  sources[0].emit('chat', chat([]));
  await sleep(400);
  assert.ok(store.getState().messages.some(m => m.text === 'stays failed' && m.status === 'failed'));
});

test('the draft is only ever cleared by an accepted send, so a reconnect cannot lose it', () => {
  const source = readFileSync(new URL('../js/chat.js', import.meta.url), 'utf8');
  assert.equal([...source.matchAll(/input\.value\s*=[^=]/g)].length, 1);
  assert.match(source, /if \(sendMessage\(input\.value\)\) \{ input\.value = ''/);
  assert.ok(!/setInterval|requestSubmit\(\)\s*;?\s*\}\s*\)\s*;\s*subscribe/.test(source));
});

test('with no main attached the composer refuses and says why', async () => {
  sources[0].emit('chat', { messages: [], replies: [], targets: [], main_session: '', codex: { available: false, reason: 'off' } });
  const access = store.chatAccess(store.getState());
  assert.equal(access.disabled, true);
  assert.match(access.notice, /No Claude main/);
  live.stop();
});
