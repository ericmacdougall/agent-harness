// PR 234 v7 audit T243-1 and T243-7: the Initiatives panel is derived from live owners and the org graph's GoodQA
// ticket reads as well as the file, so its counts are stated through the initiatives claim (whose server read rests
// on all of them), and a count the server did not send is unknown, never 0.
import test from 'node:test';
import assert from 'node:assert/strict';
import { initiatives as adaptInitiatives, initiativesLine, initiativesLoss, sources } from '../js/adapt.js';
import { withReads, healthRows, SOURCES } from './reads.mjs';

const NOW = Date.now();
const at = NOW / 1000;
const state = (names, extra = {}) => withReads({ connection: 'live', now: NOW, sources: sources(healthRows(at, names)),
  initiativesDerived: 3, initiativesUntracked: 1, initiativesHidden: 0, initiativesMtime: NOW - 1000, ...extra });

test('T243-7: a missing or malformed derived count is unknown (null), not 0', () => {
  const view = adaptInitiatives({ items: [], derived: 'x' });
  assert.equal(view.derived, null);
  assert.equal(view.untracked, null);
  assert.equal(view.hiddenFileRows, null);
  assert.equal(adaptInitiatives({ items: [], derived: 2, untracked: 0, hidden_file_rows: 1 }).derived, 2);
});

test('T243-7: a count the server did not send makes the initiatives read partial', () => {
  assert.equal(initiativesLoss({ items: [], derived: 2, untracked: 0, hidden_file_rows: 0 }), 0);
  assert.ok(initiativesLoss({ items: [], derived: 2 }) > 0);
  assert.equal(initiativesLoss(null), 0);   // no snapshot yet: the read itself is unknown
});

test('T243-1: every source current gives the plain derived count', () => {
  assert.match(initiativesLine(state(SOURCES)), /^3 from live owners and GoodQA \(1 with no ticket\)/);
});

test('T243-1: the org graph ticket reads not current: the derived count is not stated plainly', () => {
  const line = initiativesLine(state(SOURCES.filter(name => name !== 'org-graph')));
  assert.doesNotMatch(line, /^3 from/, line);
  assert.match(line, /^3\+ from/, line);
});

test('T243-7: an unknown derived count reads ?, never 0', () => {
  const line = initiativesLine(state(SOURCES, { initiativesDerived: null, initiativesUntracked: null }));
  assert.match(line, /^\? from live owners/, line);
});
