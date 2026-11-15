// The browser's identity for an archive or restore request (goodqa#15920 F5): an exact retry after a lost response keeps
// its key; a request for a changed requirement (new digest) never reuses it.
import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const store = await import('../js/store.js');
const sent = [];
let plan = [];
store.setRequirementTransport(async item => {
  sent.push({ ...item });
  const next = plan.shift();
  if (next === 'fail') { const e = new Error('no answer'); e.retryable = true; throw e; }
});
const row = digest => ({ id: 'r1', digest });

test('an exact retry after a failed request reuses the key; success clears it', async () => {
  plan = ['fail'];
  const first = await store.requirementAction(row('d1'), 'archive', 'because');
  assert.equal(first.ok, false);
  const retry = await store.requirementAction(row('d1'), 'archive', 'because');
  assert.equal(retry.ok, true);
  assert.equal(sent[0].client_key, sent[1].client_key);
  assert.deepEqual([sent[0].digest, sent[1].digest], ['d1', 'd1']);
});

test('when the requirement changes between a failed request and its retry the retry is a new request with a new key', async () => {
  sent.length = 0;
  plan = ['fail'];
  await store.requirementAction(row('d1'), 'restore', 'because');
  const retry = await store.requirementAction(row('d2'), 'restore', 'because');  // the page now shows a changed requirement
  assert.equal(retry.ok, true);
  assert.equal(sent.length, 2);
  assert.notEqual(sent[0].client_key, sent[1].client_key);
  assert.equal(sent[1].digest, 'd2');
});

test('a different reason or action is a different request too, and a missing digest is never sent', async () => {
  sent.length = 0;
  plan = ['fail', 'fail'];
  await store.requirementAction(row('d1'), 'archive', 'one');
  await store.requirementAction(row('d1'), 'archive', 'two');
  assert.notEqual(sent[0].client_key, sent[1].client_key);
  const none = await store.requirementAction({ id: 'r1' }, 'archive', 'x');
  assert.equal(none.ok, false);
  assert.equal(sent.length, 2);
});
