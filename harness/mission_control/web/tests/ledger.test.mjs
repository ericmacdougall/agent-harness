// Ledger adapters and the archive view model (GoodQA goodqa#15920 AC-4, AC-7, AC-8, AC-9). No DOM: pure functions.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ledger, archiveRows, dealRows, blockerRows, missionTiles, GOAL_STATE } from '../js/adapt.js';

const NOW = Date.parse('2026-11-13T12:00:00Z');
const iso = ageS => new Date(NOW - ageS * 1000).toISOString();

const snapshot = () => ({
  goals: { items: [{ id: 'g1', title: 'Ship it', state: 'LIVE_TESTED', ticket: 'goodqa#1', evidence: [{ id: 'e1', kind: 'live_test', verdict: 'PASS', at: iso(60), check: 'c', note: 'ok' }], evidence_total: 1, problems: { missing: 0, tampered: 0, unpinned: 0 }, owners: [] },
    { id: 'g2', title: '<img src=x onerror=alert(1)>', state: 'UNKNOWN', evidence: [] }], stale: false, error: '', at: iso(1) },
  requirements: { items: [
    { id: 'r1', text: 'keep chat live', at: iso(100), bucket: 'live', rule: 'live', reason: 'open: nothing', evidence_ref: '', expires_in_s: 86400 },
    { id: 'r2', text: 'old', at: iso(40 * 86400), bucket: 'archived', rule: 'R4', rule_title: 'expired', reason: 'older than 30 d', evidence_ref: 'age' },
    { id: 'r3', text: 'done', at: iso(5000), bucket: 'archived', rule: 'R1', reason: 'state is done', evidence_ref: '' }],
    total: 3, truncated: false, summary: { live: 1, archived: 2, rules: { R1: 1, R4: 1, live: 1 } }, stale: false, error: '', at: iso(1) },
  status: { counts: { blockers: 1 }, verified: [{ id: 'v1', agent: 'a1', at: iso(300), event: 'check', note: 'REALLY_TESTED t: ok', check: 't', verdict: 'PASS' }],
    live: [{ id: 'l1', agent: 'a1', at: iso(200), event: 'deploy', note: 'DEPLOYED x', check: '', verdict: '' }],
    failed: [{ id: 'f1', agent: 'a2', at: iso(100), event: 'check', note: 'FAIL', check: 'f', verdict: 'FAIL' }],
    pending: [{ id: 'p1', agent: 'a3', at: iso(50), event: 'check', note: 'PENDING_REAL_TEST q', check: 'q', verdict: '' }],
    blockers: [{ id: 'b1', agent: 'a3', at: iso(10), event: 'blocker', note: 'blocked on X' }], owners: { counts: {}, attention: [], live: [], undisposed: [] },
    stale: false, error: '', at: iso(1) },
});

test('ledger adapter keeps every string a string and bounds hostile input', () => {
  const huge = 'A'.repeat(100000);
  const out = ledger({ goals: { items: [{ id: 5, title: huge, state: {}, evidence: 'x' }, null, 7] }, requirements: { items: [{ id: 'r', text: huge, bucket: 'nonsense' }, { id: 'r2' }] }, status: { blockers: [{ id: 'b', note: huge }, 3] } });
  assert.equal(out.goals.items.length, 1);
  assert.ok(out.goals.items[0].title.length <= 300);
  assert.equal(out.goals.items[0].state, 'UNKNOWN');
  assert.ok(out.requirements.items.every(r => r.bucket === 'live' || r.bucket === 'archived'));
  assert.ok(out.requirements.items[0].text.length <= 700);
  assert.ok(out.status.blockers[0].note.length <= 500);
  assert.equal(out.status.blockers.length, 1);
});

test('ledger adapter tolerates absent or malformed snapshots', () => {
  for (const bad of [null, undefined, 5, 'x', [], {}, { goals: 5, requirements: [], status: null }]) {
    const out = ledger(bad);
    assert.deepEqual(out.goals.items, []);
    assert.deepEqual(out.requirements.items, []);
    assert.deepEqual(out.status.blockers, []);
    assert.equal(out.requirements.summary.live, 0);
  }
});

test('markup in goal and requirement text stays plain text in the model', () => {
  const out = ledger(snapshot());
  assert.equal(out.goals.items[1].title, '<img src=x onerror=alert(1)>');
});

test('archive rows combine archived asks and requirements, newest first, each with its reason and rule', () => {
  const asks = [{ id: 'wa1', text: 'ship?', at: iso(10), rule: 'R1', rule_title: 'terminal state', reason: 'resolved: answered by the user: yes', evidence_ref: 'wal:w1', decision: 'approved', owner: 'main', resolution: 'yes', ask_reason: 'why' }];
  const rows = archiveRows(asks, ledger(snapshot()).requirements.items);
  assert.deepEqual(rows.map(r => r.id), ['wa1', 'r3', 'r2']);
  assert.equal(rows[0].kind, 'ask');
  assert.equal(rows[1].kind, 'requirement');
  assert.ok(rows.every(r => r.reason && r.rule));
  assert.equal(archiveRows([], []).length, 0);
});

test('deploy and live-test rows carry a text verdict, not only a color, newest first', () => {
  const rows = dealRows(ledger(snapshot()).status, [], 20);
  assert.deepEqual(rows.map(r => r.id), ['p1', 'f1', 'l1', 'v1']);
  assert.deepEqual(rows.map(r => r.label), ['PENDING', 'FAILED', 'DEPLOYED', 'TESTED']);
  assert.ok(rows.every(r => r.symbol));
});

test('deploy rows also include deploy and release events from the feed', () => {
  const events = [{ id: 'e', kind: 'deploy', ts: iso(5), summary: 'shop 1.0 deployed', actor: { agent: '' }, subject: { repo: 'x' }, historic: false }, { id: 'w', kind: 'wal', ts: iso(1), summary: 'noise', actor: {}, subject: {} }];
  const rows = dealRows(ledger(snapshot()).status, events, 20);
  assert.equal(rows[0].id, 'event:e');
  assert.equal(rows.filter(r => r.id.startsWith('event:')).length, 1);
});

test('blocker rows gather ledger blockers, untraceable asks and dropped owners without a hold', () => {
  const rows = blockerRows(ledger(snapshot()).status, [{ id: 'wf', text: 'x', flagged: 'no source' }], [{ agent_id: 'o1', name: 'o1', state: 'DROPPED', severe: true, task: 't', held: false }, { agent_id: 'o2', state: 'DROPPED', severe: false, held: true }], []);
  assert.deepEqual(rows.map(r => r.source).sort(), ['ask', 'owner', 'status']);
});

test('mission tiles count goals, live owners, open asks, blockers and requirements', () => {
  const tiles = missionTiles({ ledger: ledger(snapshot()), owners: [{ state: 'live', severe: false }, { state: 'done', severe: false }], asks: [{ id: 'a' }], messages: [], decisions: {}, initiatives: [{ state: 'At risk' }, { state: 'Done' }] });
  const by = Object.fromEntries(tiles.map(t => [t.id, t]));
  assert.equal(by.goals.value, '1 / 2');
  assert.equal(by.owners.value, '1');
  assert.equal(by.blockers.value, '1');
  assert.equal(by.requirements.value, '1');
  assert.match(by.requirements.note, /2 archived/);
});

test('goal state labels are words', () => {
  assert.equal(GOAL_STATE.LIVE_TESTED, 'Live and tested');
  assert.ok(GOAL_STATE.UNKNOWN);
});

test('5000 requirements stay cheap to adapt', () => {
  const items = Array.from({ length: 5000 }, (_, i) => ({ id: `w${i}`, text: `req ${i}`, at: iso(i), bucket: i % 2 ? 'live' : 'archived', rule: i % 2 ? 'live' : 'R4', reason: 'x' }));
  const start = performance.now();
  const out = ledger({ requirements: { items, total: 5000 } });
  const rows = archiveRows([], out.requirements.items);
  assert.equal(out.requirements.items.length, 2000);  // the page bounds what it holds, whatever the server sends
  assert.equal(out.requirements.total, 5000);
  assert.equal(rows.length, 1000);
  assert.ok(performance.now() - start < 1500);
});
