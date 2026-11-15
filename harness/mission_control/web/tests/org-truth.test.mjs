// PR 243 on main: every org-graph node, edge cue and animation is drawn through the Topology claim
// (gate(state, 'topology')). A stale or unknown claim, or a node whose own source is stale, is never drawn, counted or
// labelled as live, and nothing animates unless the claim is current or partial.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { nodeTruth, truthGraph, animates, stateText, isLive, normalize, describe, SCHEMA } from '../js/org.js';
import { gate } from '../js/adapt.js';
import { withReads, healthRows } from './reads.mjs';
import { sources } from '../js/adapt.js';

const here = new URL('..', import.meta.url).pathname;
const graph = normalize({ schema: SCHEMA, nodes: [
  { id: 'coordinator', kind: 'coordinator', label: 'Main', state: 'live' },
  { id: 'o1', kind: 'owner', label: 'o1', state: 'live', live: true },
  { id: 'o2', kind: 'owner', label: 'o2', state: 'live', live: true, stale: true },
  { id: 's1', kind: 'subagent', label: 's1', state: 'working' },
], edges: [] });

test('normalize keeps a node\'s own stale flag only as a real boolean', () => {
  const g = normalize({ schema: SCHEMA, nodes: [{ id: 'a', kind: 'owner', stale: 'yes' }, { id: 'b', kind: 'owner', stale: true }], edges: [] });
  assert.deepEqual(g.nodes.map(n => n.stale), [false, true]);
});

test('current: nodes keep their live state; a node with a stale source is last known', () => {
  const g = truthGraph(graph, 'current');
  const by = Object.fromEntries(g.nodes.map(n => [n.id, n]));
  assert.equal(isLive(by.o1), true);
  assert.equal(isLive(by.coordinator), true);
  assert.equal(by.o2.truth, 'stale');
  assert.equal(isLive(by.o2), false, 'a stale source never draws as live');
});

test('partial: the nodes that were read are whole and keep their state', () => {
  assert.equal(isLive(truthGraph(graph, 'partial').nodes.find(n => n.id === 'o1')), true);
  assert.equal(animates('partial'), true);
});

test('stale and unknown claims: no node is live, and each says why', () => {
  for (const truth of ['stale', 'unknown']) {
    const g = truthGraph(graph, truth);
    assert.ok(g.nodes.every(n => !isLive(n) && n.truth === truth), truth);
    assert.match(stateText(g.nodes[1]), truth === 'stale' ? /last known/ : /not known now/);
    assert.ok(describe(g.nodes[1]).some(([k, v]) => k === 'State' && /last known|not known now/.test(v)), truth);
  }
  assert.equal(nodeTruth({}, 'unknown'), 'unknown');
  assert.equal(nodeTruth({ stale: true }, 'unknown'), 'unknown', 'unknown wins: nothing is known now');
});

test('nothing animates unless the claim is current or partial', () => {
  assert.deepEqual(['current', 'partial', 'stale', 'unknown', undefined].map(animates), [true, true, false, false, false]);
});

test('the Topology claim is not current when the page is offline or the org-graph read failed', () => {
  const rows = healthRows(Date.now() / 1000);
  assert.equal(gate(withReads({ connection: 'live', sources: sources(rows) }), 'topology').truth, 'current');
  assert.notEqual(gate(withReads({ connection: 'offline', sources: sources(rows) }), 'topology').truth, 'current');
  const failed = rows.map(r => (r.name === 'org-graph' ? { ...r, status: 'error', truth: 'stale', detail: 'boom' } : r));
  assert.equal(gate(withReads({ connection: 'live', sources: sources(failed) }), 'topology').truth, 'stale');
});

test('the scene draws through the claim: rebuild, meshes, labels, cues and the spin all gate on it', () => {
  const src = readFileSync(`${here}js/scene.js`, 'utf8');
  assert.match(src, /claimTruth = gate\(state, 'topology'\)\.truth;\s*graph = truthGraph\(state\.orggraph, claimTruth\);/);
  assert.match(src, /function play\(cue\) \{\s*if \(!cue \|\| !animates\(claimTruth\)\) return;/);
  assert.match(src, /const enqueue = cue => \{ if \(!cue \|\| !animates\(claimTruth\)\) return;/);
  assert.match(src, /entry\.node\.kind === 'coordinator' && isLive\(entry\.node\) && animates\(claimTruth\)/);
  assert.match(src, /if \(node\.truth === 'stale' \|\| node\.truth === 'unknown'\) \{[^}]*emissiveIntensity = 0;/);
  assert.match(src, /\['truth', 'health', 'reads', 'connection'\]\.includes\(reason\)/, 'a truth change redraws the graph');
  assert.match(src, /queue = \[\]; pulses\.forEach\(disposePulse\); pulses = \[\];/, 'leaving current stops what is in flight');
  assert.match(src, /label\.classList\.toggle\('not-current'/);
  assert.match(src, /n\.truth\}:\$\{n\.live\}/, 'the scene signature includes truth, so a change rebuilds the meshes');
});
