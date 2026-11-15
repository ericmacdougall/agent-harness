// PR 242 on main: an owner row states "live" only while the owners read is current (or partial); a stale or unknown
// owners read, or a row from a stale source, never shows a live owner as live now.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import './dom-shim.mjs';

globalThis.window = globalThis.window || { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
const { shownState } = await import('../js/owners.js');
const here = new URL('..', import.meta.url).pathname;

const live = { state: 'live' };

test('current and partial reads show a live owner as live', () => {
  for (const truth of ['current', 'partial']) {
    const s = shownState(live, truth);
    assert.deepEqual([s.text, s.cls, s.live], ['• live', 'live', true], truth);
  }
});

test('a stale owners read shows the last known state, never live', () => {
  const s = shownState(live, 'stale');
  assert.deepEqual([s.text, s.cls, s.live], ['live (last known)', 'stale', false]);
});

test('an unknown owners read claims nothing about now', () => {
  const s = shownState(live, 'unknown');
  assert.deepEqual([s.text, s.cls, s.live], ['live (not known now)', 'unknown', false]);
});

test('a row from a stale source is last known even while the owners read is current', () => {
  const s = shownState({ state: 'live', source_stale: true }, 'current');
  assert.equal(s.live, false);
  assert.equal(s.cls, 'stale');
});

test('a non-live state keeps its own class while current', () => {
  assert.deepEqual(shownState({ state: 'SILENT-HIGH' }, 'current'), { text: 'SILENT-HIGH', cls: 'silent-high', live: false });
  assert.equal(shownState({}, 'current').text, 'unknown');
});

test('the row badge and its label are built from shownState and the owners gate, not the raw state', () => {
  const src = readFileSync(`${here}js/owners.js`, 'utf8');
  assert.match(src, /const shown = shownState\(owner, gate\(state, 'owners'\)\.truth\);/);
  assert.match(src, /parts\.status\.className = `owner-state \$\{owner\.held \? 'held' : shown\.cls\}`/);
  assert.doesNotMatch(src, /owner\.state === 'live' \? '• '/, 'no badge path draws live from the raw state');
});
