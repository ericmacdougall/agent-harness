// The zero or "none" claims outside the ledger panels (review PR 234 v3 F1 audit): Needs you, owners, initiatives,
// the at-risk strip, initiative activity lines and the activity feed. Their text is built by pure functions in adapt.js
// from the one status truth, so each is tested here without a DOM; the modules that render them may not hard-code it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ledger, sources, needsSummary, ownersEmpty, ownerCount, initiativesEmpty, initiativeCount, atRiskEmpty, noProgress, noAction,
  updatedText, feedEmpty, claim, worst, truthOf, CLAIM_SOURCES } from '../js/adapt.js';

const NOW = Date.parse('2027-01-15T09:00:00Z');
const at = '2027-01-15T08:00:00.000Z';
const row = (name, truth = 'current', status = 'ok') => ({ name, status, checked: NOW / 1000, ok_at: truth === 'unknown' ? null : Date.parse(at) / 1000, truth, detail: status === 'ok' ? '' : `${name} read failed` });
const NAMES = ['asks', 'owners', 'initiatives', 'wals', 'chat', 'codex-owners'];
function world(broken = '', truth = 'unknown') {
  const health = NAMES.map(name => (name === broken ? row(name, truth, truth === 'stale' ? 'error' : truth === 'partial' ? 'ok' : 'error') : row(name)));
  return { now: NOW, ledger: ledger({ status: { at, truth: 'current' } }), sources: sources(health), owners: [], asks: [], initiatives: [], events: [] };
}
const AUDIT = [
  ['Needs-you header count, label, title and "Nothing needs you right now."', ['asks'], s => { const n = needsSummary(s, 0, 0); return `${n.count}|${n.label}|${n.title}|${n.empty}`; },
    /^0\|Needs you: nothing waiting on you\|\|Nothing needs you right now\.$/],
  ['Needs-you "Nothing new needs you" with stale asks', ['asks'], s => needsSummary(s, 0, 2).empty, /^Nothing new needs you\. Older open asks are under Stale\.$/],
  ['Owners panel "No owners are running." and count "00"', ['owners', 'codex-owners'], s => `${ownersEmpty(s, false)}|${ownerCount(s, 0)}`, /^No owners are running\.\|00$/],
  ['Owners panel filter "No owners in this state."', ['owners', 'codex-owners'], s => ownersEmpty(s, true), /^No owners in this state\.$/],
  ['Initiatives panel "No initiatives in the file." and count "00"', ['initiatives'], s => `${initiativesEmpty(s)}|${initiativeCount(s, 0)}`, /^No initiatives in the file\.\|00$/],
  ['At-risk "Nothing open to rank."', ['initiatives'], s => atRiskEmpty(s), /^Nothing open to rank\.$/],
  ['At-risk "no progress recorded"', ['wals', 'owners', 'codex-owners'], s => noProgress(s), /^no progress recorded$/],
  ['At-risk "Main: no action recorded"', ['owners', 'codex-owners'], s => noAction(s), /^Main: no action recorded$/],
  ['Initiative card and inspector "No activity recorded"', ['wals', 'owners', 'codex-owners'], s => updatedText(s, { updated: null }, () => '5 min ago'), /^No activity recorded$/],
  ['Initiative "no activity for over 30 min"', ['wals', 'owners', 'codex-owners'], s => updatedText(s, { updated: at, stale: true }, () => '1 h ago', 'Updated '), /no activity for over 30 min/],
  ['Activity feed "Listening for signals…"', ['wals'], s => feedEmpty(s), /^Listening for signals…$/],
];
for (const [name, deps, render, zero] of AUDIT) {
  test(`audit: ${name} only when ${deps.join(', ')} ${deps.length > 1 ? 'are' : 'is'} current`, () => {
    assert.match(render(world()), zero, 'stated when every source is current');
    for (const dep of deps) for (const truth of ['unknown', 'stale', 'partial']) {
      assert.doesNotMatch(render(world(dep, truth)), zero, `not stated while ${dep} is ${truth}`);
    }
  });
}

test('audit: an unknown Needs-you count is "?" in the header, its label and the page title', () => {
  const n = needsSummary(world('asks'), 0, 0);
  assert.deepEqual([n.count, n.title], ['?', '(?) ']);
  assert.match(n.label, /unknown/);
  assert.match(n.empty, /Not known: Asks ledger could not be read/);
  assert.equal(needsSummary(world('asks'), 3, 0).count, '3');  // asks on hand are still shown and counted
});

test('audit: an initiatives file that is not configured is said so, and is not a reason to doubt other claims', () => {
  const s = world();
  s.sources = sources(NAMES.map(name => (name === 'initiatives' ? { name, status: 'off', truth: 'current', detail: 'no initiatives file configured' } : row(name))));
  assert.equal(initiativesEmpty(s), 'No initiatives file is configured.');
  assert.equal(claim(s, 'blockers').truth, 'current');
});

test('audit: the truth vocabulary is closed and worst() fails closed', () => {
  assert.deepEqual(['current', 'partial', 'stale', 'unknown', 'ok', '', null, undefined].map(truthOf), ['current', 'partial', 'stale', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
  assert.equal(worst('current', 'partial'), 'partial');
  assert.equal(worst('partial', 'stale', 'current'), 'stale');
  assert.equal(worst('current', 'bogus'), 'unknown');
  assert.equal(worst(), 'unknown');
  assert.equal(claim({}, 'blockers').truth, 'unknown');
  assert.equal(claim({}, 'no-such-claim').truth, 'unknown');
  for (const [id, deps] of Object.entries(CLAIM_SOURCES)) assert.ok(deps.length > 0, id);
});
// The source checks that the DOM modules no longer hard-code these sentences are in status-truth.test.mjs (old exports only).
