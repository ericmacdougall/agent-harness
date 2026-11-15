// PR 262 review F2: the org inspector shows a node through the same Topology claim as the scene, refreshes when the
// graph or its truth changes, and closes when its node is gone. It never shows an earlier snapshot's details as current.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { inspectorView, inspectorRefreshes, describe, normalize, SCHEMA } from '../js/org.js';

const here = new URL('..', import.meta.url).pathname;
const graph = normalize({ schema: SCHEMA, nodes: [
  { id: 'coordinator', kind: 'coordinator', label: 'Main', state: 'live' },
  { id: 'o1', kind: 'owner', label: 'o1', state: 'live', live: true, mission: 'build' },
  { id: 'o2', kind: 'owner', label: 'o2', state: 'live', live: true, stale: true },
  { id: 'work:goodqa#1', kind: 'work', ref: 'goodqa#1', label: 'goodqa#1', title: 'T', status: 'in_progress', layer: 0 },
], edges: [] });
const fields = view => Object.fromEntries(describe(view.node, view.byId));

test('a current claim shows the node plainly', () => {
  const view = inspectorView(graph, 'current', 'o1');
  assert.equal(fields(view).State, 'live');
  assert.equal(fields(view).Read, undefined);
});

test('opening a node whose own source is stale shows it as last known, never live', () => {
  const view = inspectorView(graph, 'current', 'o2');
  assert.equal(view.node.live, false);
  assert.match(fields(view).State, /last known/);
  assert.match(fields(view).Read, /last known/);
});

test('losing freshness while open: the refreshed view is stale or unknown, for every node kind', () => {
  for (const truth of ['stale', 'unknown']) {
    for (const id of ['coordinator', 'o1', 'work:goodqa#1']) {
      const view = inspectorView(graph, truth, id);
      assert.equal(view.node.truth, truth, `${id} ${truth}`);
      assert.ok(fields(view).Read, `${id} ${truth} says it is not current`);
      if (view.node.kind !== 'work') assert.doesNotMatch(fields(view).State, /^live$/);
    }
  }
});

test('a node gone from the next snapshot closes the inspector (no view)', () => {
  const next = normalize({ schema: SCHEMA, nodes: graph.nodes.filter(n => n.id !== 'o1'), edges: [] });
  assert.equal(inspectorView(next, 'current', 'o1'), null);
  assert.equal(inspectorView(null, 'current', 'o1'), null);
});

test('the inspector refreshes on every reason that changes what it shows, only for an org selection', () => {
  for (const reason of ['orggraph', 'truth', 'health', 'reads', 'connection']) assert.equal(inspectorRefreshes(reason, { kind: 'org', id: 'o1' }), true, reason);
  assert.equal(inspectorRefreshes('tick', { kind: 'org', id: 'o1' }), false);
  assert.equal(inspectorRefreshes('orggraph', { kind: 'event', id: 'x' }), false);
  assert.equal(inspectorRefreshes('orggraph', null), false);
});

test('main.js reads org nodes only through inspectorView and refreshes an open inspector', () => {
  const src = readFileSync(here + 'js/main.js', 'utf8');
  assert.match(src, /inspectorView\(state\.orggraph, gate\(state, 'topology'\)\.truth, id\)/);
  assert.doesNotMatch(src, /state\.orggraph[^,]*\.nodes/, 'no raw snapshot node lookups');
  assert.match(src, /inspector\.open && inspectorRefreshes\(reason, state\.selection\)\) renderInspector\(state, true\)/);
});
