// Owner panel: live owners by default, parked/history folded per initiative, helpers nested and never counted
// (goodqa#15920 AC-2, AC-3, AC-4, AC-6; NEG-1, NEG-2, NEG-4, NEG-7, NEG-8).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { owners as adaptOwners, initiatives as adaptInitiatives, missionTiles, ledger } from '../js/adapt.js';
import { ownerGroups, ownerCounts, foldLabel, summaryLine, UNLINKED } from '../js/owner-groups.js';
import { inventory } from '../js/ledger-views.js';
import { text } from './dom-shim.mjs';

const here = new URL('..', import.meta.url).pathname;
const NOW = '2026-11-13T12:00:00Z';
const row = (agent_id, role, state, extra = {}) => ({ agent_id, role, state, runtime: 'claude', source: 'ah', ticket: '', last_item: { at: NOW }, ...extra });

// Six live owners across two initiatives, plus parked rows, helpers and Codex: the old panel counted all of them.
const RAW = [
  row('a1live000000000001', 'live', 'live', { ticket: 'goodqa#1' }),
  row('a1live000000000002', 'live', 'working', { ticket: 'goodqa#1' }),
  row('a1live000000000003', 'live', 'SILENT-HIGH', { ticket: 'goodqa#2' }),
  row('a1live000000000004', 'live', 'quiet', { ticket: 'goodqa#2' }),
  row('a1live000000000005', 'live', 'live'),
  row('deploy-wal', 'live', 'working', { runtime: 'unknown' }),
  row('a2park000000000001', 'parked', 'handoff', { ticket: 'goodqa#1' }),
  row('a2park000000000002', 'parked', 'DROPPED', { ticket: 'goodqa#1' }),
  row('a2park000000000003', 'parked', 'returned', { ticket: 'goodqa#2' }),
  row('a2park000000000004', 'parked', 'done'),
  row('a2park000000000005', 'parked', 'SILENT', { decision_required: true, ticket: 'goodqa#2' }),
  row('a3help000000000001', 'helper', 'live', { type: 'red-team', serves: 'a1live000000000001', ticket: 'goodqa#1' }),
  row('a3help000000000002', 'helper', 'done', { type: 'reviewer', serves: 'a1live000000000001' }),
  row('a3help000000000003', 'helper', 'handoff', { type: 'red-team', serves: 'a2park000000000003' }),
  row('a3help000000000004', 'helper', 'done', { type: 'click-tester', serves: null }),
  row('a3help000000000005', 'helper', 'DROPPED', { type: 'fixer', serves: 'gone-owner' }),
  row('codex:t1:main', 'live', 'observed', { runtime: 'codex', source: '' }),
  row('codex:t1:w1', 'helper', 'observed', { runtime: 'codex', source: '', serves: 'codex:t1:main' }),
  row('openai:sup', 'parked', 'idle', { runtime: 'codex', source: '' }),
  { agent_id: 'a9bogus0000000001', state: 'live', role: 'boss', source: 'ah', last_item: {} },
];
const INITS = adaptInitiatives({ items: [{ id: 'checkout', initiative: 'Checkout', ticket: 'goodqa#1' }, { id: 'reports', initiative: 'Reports', ticket: 'goodqa#2' }, { id: 'idle', initiative: 'Idle initiative', ticket: 'goodqa#99' }] }).items;
const OWNERS = adaptOwners(RAW, INITS);
const byGroup = groups => Object.fromEntries(groups.map(g => [g.id, g]));

test('headline counts live ah owners only, any runtime; Codex live is a separate figure', () => {
  const counts = ownerCounts(OWNERS);
  assert.equal(counts.live, 6, 'six slot holders, as the owner cap counts them');
  assert.equal(counts.codexLive, 1);
  assert.equal(counts.helpers, 6);
  assert.equal(counts.parked, 7, 'parked rows plus the unknown role (NEG-7) and the idle supervisor');
  assert.equal(counts.total, RAW.length);
  assert.ok(counts.total > counts.live * 3, 'the bug: the old panel showed every row as an owner');
  assert.match(summaryLine(counts, { session: 'baab765b-xyz' }), /^6 live owners per ah owners \(session baab765b\) · 1 live Codex/);
  assert.match(summaryLine(counts, { stale: true }), /STALE/);
});

test('an unknown role from the server is parked: shown, never counted (NEG-7)', () => {
  const bogus = OWNERS.find(o => o.agent_id === 'a9bogus0000000001');
  assert.equal(bogus.role, 'parked');
});

test('the Owners live tile and the inventory use the live count, not the row count (AC-2)', () => {
  const state = { owners: OWNERS, asks: [], messages: [], decisions: {}, asksFlagged: [], initiatives: INITS, ledger: null };
  const tile = missionTiles(state).find(t => t.id === 'owners');
  assert.equal(tile.value, '6');
  assert.match(tile.note, /1 live Codex/);
  assert.match(tile.note, /need attention/);
});

test('groups by initiative: live owners shown, every other row in exactly one fold (AC-3)', () => {
  const groups = ownerGroups(OWNERS, INITS);
  const g = byGroup(groups);
  assert.deepEqual(g.checkout.live.map(e => e.owner.agent_id), ['a1live000000000001', 'a1live000000000002']);
  assert.deepEqual(g.reports.live.map(e => e.owner.agent_id), ['a1live000000000003', 'a1live000000000004']);
  assert.ok(g[UNLINKED], 'owners without an initiative are grouped, not dropped');
  assert.equal(groups[groups.length - 1].id === UNLINKED || groups.every(x => x.liveCount > 0 || x.id !== UNLINKED), true);
  assert.equal(g.idle, undefined, 'an initiative with no rows renders no empty group');
  // every published row appears exactly once across live, helpers, done helpers, parked and loose
  const seen = [];
  for (const group of groups) {
    for (const e of [...group.live, ...group.decide]) seen.push(e.owner.agent_id, ...e.helpers.map(h => h.agent_id), ...e.doneHelpers.map(h => h.agent_id));
    for (const e of group.parked) seen.push(e.owner.agent_id, ...e.helpers.map(h => h.agent_id));
    seen.push(...group.loose.map(h => h.agent_id));
  }
  assert.deepEqual(seen.slice().sort(), OWNERS.map(o => o.agent_id).sort(), 'nothing hidden for good, nothing shown twice');
});

test('helpers nest under the owner they serve and never add to a count (AC-4, NEG-1, NEG-2)', () => {
  const g = byGroup(ownerGroups(OWNERS, INITS));
  const lead = g.checkout.live.find(e => e.owner.agent_id === 'a1live000000000001');
  assert.deepEqual(lead.helpers.map(h => h.agent_id), ['a3help000000000001'], 'a working helper shows under its live owner');
  assert.deepEqual(lead.doneHelpers.map(h => h.agent_id), ['a3help000000000002'], 'a finished helper of a live owner folds');
  const parked = g.reports.parked.find(e => e.owner.agent_id === 'a2park000000000003');
  assert.deepEqual(parked.helpers.map(h => h.agent_id), ['a3help000000000003'], 'a parked owner keeps its helper');
  const loose = g[UNLINKED].loose.map(h => h.agent_id).sort();
  assert.deepEqual(loose, ['a3help000000000004', 'a3help000000000005'], 'helpers with no listed owner stay visible');
  const codex = g[UNLINKED].live.find(e => e.owner.agent_id === 'codex:t1:main');
  assert.deepEqual(codex.helpers.map(h => h.agent_id), ['codex:t1:w1'], 'a Codex sub-agent nests under its thread main');
  assert.equal(g.checkout.liveCount, 2);
});

test('the fold names its size and how many rows need attention (NEG-8)', () => {
  const g = byGroup(ownerGroups(OWNERS, INITS));
  assert.equal(foldLabel(g.checkout), 'Parked / history (3) · 1 need attention', 'handoff, DROPPED, finished reviewer');
  assert.equal(foldLabel(g.reports), 'Parked / history (2)', 'the decision-required owner is not folded');
  assert.match(foldLabel(g[UNLINKED]), /need attention/, 'a DROPPED helper with no owner still raises attention');
});

test('a parked owner that needs a decision stays visible, uncounted (M5)', () => {
  const g = byGroup(ownerGroups(OWNERS, INITS));
  assert.deepEqual(g.reports.decide.map(e => e.owner.agent_id), ['a2park000000000005']);
  assert.equal(g.reports.liveCount, 2, 'not counted as live');
  assert.equal(g.reports.parked.some(e => e.owner.agent_id === 'a2park000000000005'), false);
});

test('zero live owners still shows the count 0 and an expandable fold (NEG-4)', () => {
  const only = adaptOwners([row('a2park000000000009', 'parked', 'done')], []);
  assert.equal(ownerCounts(only).live, 0);
  const [group] = ownerGroups(only, []);
  assert.equal(group.liveCount, 0);
  assert.equal(group.foldCount, 1);
});

test('the inventory row reports live owners, not rows', () => {
  const state = { ledger: ledger(null), now: Date.parse(NOW), chat: null, messages: [], decisions: {}, asksArchive: [], events: [],
    initiatives: INITS, initiativesStale: false, initiativesError: '', owners: OWNERS, asks: [], asksStale: [], asksFlagged: [], asksSweptAt: '', sessions: [], health: [], sources: [] };
  const out = inventory(state, () => {});
  assert.match(text(out), /6 live owners, 1 live Codex, 7 parked or history, 6 helpers/);
});

test('the default filter is the grouped live view and the panel has a summary line', () => {
  const html = readFileSync(`${here}index.html`, 'utf8');
  assert.match(html, /<option value="active" selected>Live owners by initiative<\/option>/);
  assert.match(html, /id="owner-summary"/);
});
