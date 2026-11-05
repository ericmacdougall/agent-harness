import test from 'node:test';
import assert from 'node:assert/strict';
import { ledgerLabel, ledgerState, renderLedgerIcon, ledgerDirs, createLedgerTracker, MAX_DIRS } from './ledger-icon.js';

// A minimal DOM element, enough for renderLedgerIcon.
function el(tag, className, text) {
  const attrs = {};
  return { tag, className, textContent: text, dataset: {}, attrs, title: '', tabIndex: -1, setAttribute(k, v) { attrs[k] = v; } };
}

test('every state has a label, a distinct glyph class and an accessible name; none renders nothing', () => {
  const expected = {
    synced: 'Ledger: synced',
    tracked: 'Ledger: tracked by GoodQA',
    'local-only': 'Ledger: local only',
    diverged: 'Ledger: diverged from GoodQA',
    unknown: 'Ledger: status unknown',
  };
  for (const [state, label] of Object.entries(expected)) {
    const icon = renderLedgerIcon(el, { state });
    assert.equal(icon.attrs['aria-label'], label);
    assert.equal(icon.attrs.role, 'img');
    assert.equal(icon.dataset.ledgerState, state);
    assert.equal(icon.tabIndex, 0, 'keyboard reachable');
    assert.equal(icon.title, label);
  }
  assert.equal(renderLedgerIcon(el, { state: 'none' }), null);
  assert.equal(renderLedgerIcon(el, { state: 'pending', unsynced: 3 }).attrs['aria-label'], 'Ledger: 3 changes not synced');
  assert.equal(ledgerLabel({ state: 'pending', unsynced: 1 }), 'Ledger: 1 change not synced');
  // glyphs differ except the deliberately shared quiet check of synced and tracked
  const glyphs = ['synced', 'tracked', 'pending', 'local-only', 'diverged', 'unknown'].map(state => renderLedgerIcon(el, { state, unsynced: 2 }).textContent);
  assert.equal(glyphs[0], glyphs[1]);
  assert.equal(new Set(glyphs).size, 5);
});

test('hostile or malformed state data degrades to unknown, never to markup', () => {
  for (const bad of [null, undefined, {}, { state: 5 }, { state: '<img src=x onerror=1>' }, { state: 'admin' }]) {
    assert.equal(ledgerState(bad), 'unknown');
    assert.equal(renderLedgerIcon(el, bad).attrs['aria-label'], 'Ledger: status unknown');
  }
  assert.equal(ledgerLabel({ state: 'pending', unsynced: '9<script>' }), 'Ledger: changes not synced');
});

test('directories are unique, absolute and capped at 32', () => {
  const sessions = Array.from({ length: 50 }, (_, i) => ({ cwd: `/repo/${i}` })).concat([{ cwd: '/repo/1' }, { cwd: 'relative' }, {}, null]);
  const dirs = ledgerDirs(sessions, '/repo/root');
  assert.equal(dirs.length, MAX_DIRS);
  assert.equal(new Set(dirs).size, dirs.length);
  assert.ok(dirs.every(d => d.startsWith('/')));
  assert.deepEqual(ledgerDirs([{ cwd: '/a' }, { cwd: '/a' }], '/a'), ['/a']);
});

test('the tracker posts once per change, reports unknown for a failure, and notifies on change only', async () => {
  const calls = [];
  let changes = 0;
  let fail = false;
  const api = async (path, body) => {
    calls.push([path, body]);
    if (fail) throw new Error('boom');
    return { states: Object.fromEntries(body.cwds.map(d => [d, { state: 'pending', unsynced: 2 }])) };
  };
  const tracker = createLedgerTracker({ api, onChange: () => { changes++; }, setTimer: () => 1, clearTimer: () => {} });
  tracker.track(['/a', '/b']);
  await tracker.refresh();
  assert.equal(tracker.get('/a').state, 'pending');
  const posts = calls.length;
  tracker.track(['/a', '/b']); // unchanged directory list: no new request
  assert.equal(calls.length, posts);
  const before = changes;
  await tracker.refresh(); // same answer: no notification
  assert.equal(changes, before);
  fail = true;
  tracker.track(['/c']);
  await tracker.refresh();
  assert.equal(tracker.get('/c').state, 'unknown');
  assert.equal(calls[0][0], '/api/ledger/sync-state');
  assert.deepEqual(calls[0][1], { cwds: ['/a', '/b'] });
});
