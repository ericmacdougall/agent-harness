// Org graph model (goodqa#15950): validation, pyramid layout, the event-to-cue table and the list tree.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as org from '../js/org.js';

const agent = (id, kind, extra = {}) => ({ id, kind, label: id, model: 'claude-opus-5-5', effort: 'high', advisor_model: 'unknown', machine: 'host', state: 'live', severity: 'info', escalation: 0, ...extra });
const SNAP = {
  schema: 'mc.orggraph/1', generated: '2026-11-14T04:00:00Z', seq: 3, counts: { owner: 2, live_owners: 1 }, gaps: ['g'],
  nodes: [
    { id: 'user', kind: 'user', label: 'You', inbox: 2 },
    agent('coordinator', 'coordinator'),
    agent('own1', 'owner', { mission: 'Build', ticket: 'goodqa#1' }),
    agent('own2', 'owner', { state: 'done', mission: 'idle' }),
    agent('sub1', 'subagent', { owner: 'own1', parent: 'own1', ticket: 'goodqa#2', task: 'slice' }),
    agent('rev1', 'reviewer', { owner: 'own1', parent: 'own1', reviews: 'sub1', pairing_source: 'parent+ticket', severity: 'high', escalation: 2 }),
    agent('rev2', 'reviewer', { owner: '', reviews: 'unknown' }),
    { id: 'work:goodqa#2', kind: 'work', ref: 'goodqa#2', title: 'Slice', status: 'in_progress', layer: 0, via: 'held', holders: ['sub1'], owner: 'own1', read: true },
    { id: 'work:goodqa#3', kind: 'work', ref: 'goodqa#3', title: 'Next', status: 'todo', layer: 1, via: 'blocks', holders: [], owner: 'own1', read: true },
    { id: 'work:goodqa#4', kind: 'work', ref: 'goodqa#4', title: 'After', status: 'todo', layer: 2, via: 'blocks', holders: [], owner: 'own1', read: true },
    { id: '<img>', kind: 'owner' }, { id: 'x', kind: 'alien' },
  ],
  edges: [
    { from: 'user', to: 'coordinator', kind: 'inbox' }, { from: 'coordinator', to: 'own1', kind: 'spawn' }, { from: 'own1', to: 'sub1', kind: 'spawn' },
    { from: 'rev1', to: 'sub1', kind: 'review' }, { from: 'sub1', to: 'work:goodqa#2', kind: 'works_on' },
    { from: 'work:goodqa#2', to: 'work:goodqa#3', kind: 'next' }, { from: 'work:goodqa#3', to: 'work:goodqa#4', kind: 'next' }, { from: 'nope', to: 'sub1', kind: 'spawn' },
  ],
  changes: [{ type: 'spawned', node: 'sub1', kind: 'subagent', from: 'own1' }],
};

test('normalize keeps valid nodes and edges and drops malformed ones', () => {
  const g = org.normalize(SNAP);
  assert.equal(g.nodes.length, 10);
  assert.ok(!g.nodes.some(n => n.id === '<img>' || n.kind === 'alien'));
  assert.ok(!g.edges.some(e => e.from === 'nope'));
  assert.equal(org.normalize({ schema: 'other', nodes: [] }), null);
  assert.equal(org.normalize(null), null);
});

test('missing fields read "unknown", never blank or invented', () => {
  const g = org.normalize({ ...SNAP, nodes: [{ id: 'own9', kind: 'owner' }], edges: [] });
  const [n] = g.nodes;
  assert.deepEqual([n.model, n.effort, n.advisor_model, n.machine, n.state], ['unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
});

test('pyramid: user above coordinator above owners above agents above work; DAG steps go deeper', () => {
  const g = org.normalize(SNAP);
  const p = org.layout(g);
  const y = id => p.get(id)[1];
  assert.ok(y('user') > y('coordinator') && y('coordinator') > y('own1') && y('own1') > y('sub1') && y('sub1') > y('work:goodqa#2'));
  assert.ok(y('work:goodqa#2') > y('work:goodqa#3') && y('work:goodqa#3') > y('work:goodqa#4'));
  // a held item sits directly under the agent working on it
  assert.deepEqual([p.get('work:goodqa#2')[0], p.get('work:goodqa#2')[2]], [p.get('sub1')[0], p.get('sub1')[2]]);
  // next-in-line items cluster around the item they depend on
  const d = (a, b) => Math.hypot(p.get(a)[0] - p.get(b)[0], p.get(a)[2] - p.get(b)[2]);
  assert.ok(d('work:goodqa#3', 'work:goodqa#2') < 1);
  // a reviewer sits beside the sub-agent it reviews
  assert.ok(d('rev1', 'sub1') < 0.6);
});

test('every event type the user listed has a source and a cue', () => {
  const ids = org.EVENT_MAP.map(e => e.id);
  for (const id of ['dag', 'subagent-spawn', 'subagent-finish', 'subagent-assign', 'reviewer-spawn', 'reviewer-working', 'reviewer-verdict',
    'review-return', 'owner-message', 'coordinator', 'git', 'progress', 'inbox', 'decision']) assert.ok(ids.includes(id), id);
  for (const e of org.EVENT_MAP) { assert.ok(e.source && e.cue, e.id); assert.ok(!/^no source$/i.test(e.source), `${e.id} has no source`); }
});

test('org changes map to cues between real nodes', () => {
  const g = org.normalize(SNAP);
  const ids = new Set(org.EVENT_MAP.map(e => e.id));
  const cases = [
    [{ type: 'spawned', node: 'sub1', kind: 'subagent', from: 'own1' }, 'subagent-spawn', 'own1', 'sub1'],
    [{ type: 'spawned', node: 'own1', kind: 'owner', from: 'coordinator' }, 'coordinator', 'coordinator', 'own1'],
    [{ type: 'spawned', node: 'rev1', kind: 'reviewer', from: 'own1' }, 'reviewer-spawn', 'own1', 'rev1'],
    [{ type: 'finished', node: 'sub1', kind: 'subagent', to: 'own1' }, 'subagent-finish', 'sub1', 'own1'],
    [{ type: 'finished', node: 'rev1', kind: 'reviewer', to: 'sub1' }, 'review-return', 'rev1', 'sub1'],
    [{ type: 'message', from: 'own1', to: 'rev1' }, 'owner-message', 'own1', 'rev1'],
    [{ type: 'message', from: 'coordinator', to: 'own1' }, 'coordinator', 'coordinator', 'own1'],
    [{ type: 'assigned', node: 'sub1', kind: 'subagent', ticket: 'goodqa#2' }, 'subagent-assign', 'sub1', 'work:goodqa#2'],
    [{ type: 'dag', edge: { from: 'work:goodqa#2', to: 'work:goodqa#3', kind: 'next' } }, 'dag', 'work:goodqa#2', 'work:goodqa#3'],
  ];
  for (const [change, map, from, to] of cases) {
    const cue = org.cueForChange(change, g);
    assert.ok(cue, JSON.stringify(change));
    assert.equal(cue.map, map); assert.equal(cue.from, from); assert.equal(cue.to, to);
    assert.ok(ids.has(cue.map));
  }
  assert.equal(org.cueForChange({ type: 'progress', node: 'work:goodqa#3' }, g).ring, 'work:goodqa#3');
  assert.equal(org.cueForChange({ type: 'state', node: 'rev1', kind: 'reviewer' }, g).map, 'reviewer-working');
  assert.equal(org.cueForChange({ type: 'spawned', node: 'ghost', kind: 'subagent' }, g), null);
});

test('feed events map to inbox, decision, verdict, git and progress cues', () => {
  const g = org.normalize(SNAP);
  const ev = (kind, summary, extra = {}) => ({ kind, summary, actor: {}, subject: {}, ...extra });
  assert.deepEqual([org.cueForEvent(ev('wal', 'ask: approve?'), g).from, org.cueForEvent(ev('wal', 'ask: approve?'), g).to], ['coordinator', 'user']);
  assert.deepEqual([org.cueForEvent(ev('wal', 'ask_resolved: yes'), g).from, org.cueForEvent(ev('wal', 'ask_resolved: yes'), g).to], ['user', 'coordinator']);
  const verdict = org.cueForEvent(ev('wal', 'review_result: BLOCK goodqa#2', { actor: { agent: 'rev1' } }), g);
  assert.deepEqual([verdict.map, verdict.from, verdict.to, verdict.verdict], ['reviewer-verdict', 'rev1', 'sub1', 'rejected']);
  assert.equal(org.cueForEvent(ev('wal', 'review: ACCEPT', { actor: { agent: 'rev1' } }), g).verdict, 'approved');
  const merge = org.cueForEvent(ev('push', 'o/r: merged PR #7 feat/x into main', { subject: { repo: 'o/r' } }), g);
  assert.deepEqual([merge.map, merge.to, merge.merge], ['git', 'repo:o/r', true]);
  assert.equal(org.cueForEvent(ev('wal', 'check: tests pass', { actor: { agent: 'sub1' }, subject: { ticket: 'goodqa#2' } }), g).to, 'work:goodqa#2');
  assert.equal(org.cueForEvent({ ...ev('wal', 'ask: x'), historic: true }, g), null);
});

test('the list tree holds every graph node exactly once, in coordinator > owner > agent > work order', () => {
  const g = org.normalize(SNAP);
  const seen = [];
  const walk = (entries, depth) => entries.forEach(e => { if (e.node.kind !== 'group') seen.push([e.node.id, depth]); walk(e.children, depth + 1); });
  walk(org.tree(g), 0);
  assert.deepEqual(seen.map(s => s[0]).sort(), g.nodes.map(n => n.id).sort());
  const depth = Object.fromEntries(seen);
  assert.ok(depth.coordinator < depth.own1 && depth.own1 < depth.sub1 && depth.sub1 < depth['work:goodqa#2'] && depth['work:goodqa#2'] < depth['work:goodqa#3']);
});

test('describe shows the fields asked for per node type, with the reviewer pairing source', () => {
  const g = org.normalize(SNAP);
  const byId = new Map(g.nodes.map(n => [n.id, n]));
  const labels = id => org.describe(byId.get(id), byId).map(([k]) => k);
  for (const field of ['Model', 'Effort', 'Machine', 'Last activity']) assert.ok(labels('coordinator').includes(field));
  for (const field of ['Mission', 'Model', 'Effort', 'Machine', 'Last activity']) assert.ok(labels('own1').includes(field));
  for (const field of ['Task', 'Owner', 'Model', 'Effort', 'Machine']) assert.ok(labels('sub1').includes(field));
  for (const field of ['Task', 'Reviews', 'Model', 'Effort', 'Machine', 'Severity', 'Escalation']) assert.ok(labels('rev1').includes(field));
  assert.match(Object.fromEntries(org.describe(byId.get('rev2'), byId)).Reviews, /^unknown/);
});

test('type colors and the severity/escalation ramp are separate sets', () => {
  const types = new Set(Object.values(org.TYPE_COLORS).map(t => t.color.toLowerCase()));
  for (const c of [...Object.values(org.SEVERITY_COLORS), ...org.ESCALATION_COLORS.filter(Boolean)]) assert.ok(!types.has(c.toLowerCase()), c);
  const css = readFileSync(new URL('../mission.css', import.meta.url), 'utf8');
  for (const kind of Object.keys(org.TYPE_COLORS)) assert.match(css, new RegExp(`--org-${kind}:`));
});

test('the scene is a guarded module: no innerHTML, reduced motion respected, list mode and #gl=off fallback', () => {
  const src = readFileSync(new URL('../js/scene.js', import.meta.url), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML/.test(src));
  assert.match(src, /getState\(\)\.motion/);
  assert.match(src, /get\('gl'\) === 'off'/);
  assert.match(src, /role', 'treeitem'/);
  assert.ok(!/\.initiatives\b/.test(src), 'the topology no longer reads the hand-written initiatives file');
});

test('user node says loading before the asks source reports, never a false 0', () => {
  const loading = Object.fromEntries(org.describe({ id: 'user', kind: 'user', inbox: null }, new Map()));
  assert.equal(loading['Open asks (Needs you)'], 'loading…');
  assert.equal('Stale asks, still open' in loading, false);
  const ready = Object.fromEntries(org.describe({ id: 'user', kind: 'user', inbox: 0, inbox_stale: 2 }, new Map()));
  assert.equal(ready['Open asks (Needs you)'], '0');
});

test('initiatives snapshot carries live-derived and hidden file row counts', async () => {
  const adapt = await import('../js/adapt.js');
  const out = adapt.initiatives({ items: [{ id: 'live-goodqa_15950', initiative: 'Live org graph', ticket: 'goodqa#15950', source: 'live' }, { id: 'x', initiative: 'Old' }], mtime: 1, derived: 1, hidden_file_rows: 11 });
  assert.deepEqual([out.derived, out.hiddenFileRows], [1, 11]);
  assert.deepEqual(out.items.map(i => i.source), ['live', 'file']);
  assert.deepEqual([adapt.initiatives({ derived: -3 }).derived, adapt.initiatives({ hidden_file_rows: 'x' }).hiddenFileRows], [0, 0]);
});

test('normalize keeps the followed session for the meta line (goodqa#15961)', () => {
  assert.equal(org.normalize({ schema: 'mc.orggraph/1', nodes: [], session: 'baab765b-d85c' }).session, 'baab765b-d85c');
  assert.equal(org.normalize({ schema: 'mc.orggraph/1', nodes: [] }).session, '');
});
