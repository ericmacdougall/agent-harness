// PR 234 v7 audit T243-3: the Topology meta line states its counts through the topology claim, which rests on the
// org graph's read (collectors.FEEDS.orggraph: the org-graph source, the owner rows and their feeds, the pin).
import test from 'node:test';
import assert from 'node:assert/strict';
import { CLAIMS, topologyMeta, sources } from '../js/adapt.js';
import { withReads, healthRows, SOURCES } from './reads.mjs';

const at = Date.now() / 1000;
const COUNTS = { live_owners: 2, owner: 3, subagent: 1, reviewer: 1, work: 4 };
const state = (names, counts = COUNTS) => withReads({ connection: 'live', sources: sources(healthRows(at, names)),
  orggraph: { counts, session: 'baab765b-d85c', gaps: [] } });

test('T243-3: the topology claim is declared over the org graph read', () => {
  assert.deepEqual(CLAIMS.topology, ['orggraph']);
});

test('T243-3: every source current gives plain counts', () => {
  assert.match(topologyMeta(state(SOURCES), 'just now'), /^2 live of 3 owners · 1 sub-agents · 1 reviewers · 4 work items · graph last changed just now/);
});

test('T243-3: a partial org-graph read never states its counts plainly', () => {
  const rows = sources(healthRows(at, SOURCES)).map(row => (row.id === 'org-graph' ? { ...row, truth: 'partial' } : row));
  const line = topologyMeta(withReads({ connection: 'live', sources: rows, orggraph: { counts: COUNTS, session: 'x', gaps: [] } }), 'now');
  assert.match(line, /^2\+ live of 3\+ owners/, line);
});

test('T243-3: the owner read not current: the owner counts are not plain', () => {
  const line = topologyMeta(state(SOURCES.filter(name => name !== 'owners')), 'now');
  assert.doesNotMatch(line, /^2 live of 3 owners/, line);
});

test('T243-3: counts the server did not send read ?, never 0', () => {
  assert.match(topologyMeta(state(SOURCES, {}), 'now'), /^\? live of \? owners · \? sub-agents/);
});
