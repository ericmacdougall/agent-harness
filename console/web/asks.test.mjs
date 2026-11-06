import test from 'node:test';
import assert from 'node:assert/strict';
import { fmtAge, ageMatches, stateMatches, sortRows } from './asks.js';

test('fmtAge handles missing and bad input', () => {
  assert.equal(fmtAge(undefined), '-');
  assert.equal(fmtAge(-5), '-');
  assert.equal(fmtAge(NaN), '-');
  assert.equal(fmtAge(30), '30s');
  assert.equal(fmtAge(3600), '60m');
  assert.equal(fmtAge(7200), '2h');
  assert.equal(fmtAge(86400 * 3), '3d');
});

test('age filter excludes rows with unknown age unless any', () => {
  assert.equal(ageMatches('any', undefined), true);
  assert.equal(ageMatches('gt1h', undefined), false);
  assert.equal(ageMatches('lt1h', 59), true);
  assert.equal(ageMatches('gt24h', 86399), false);
  assert.equal(ageMatches('gt24h', 86400), true);
});

test('owner attention filter hides quiet finished owners', () => {
  assert.equal(stateMatches('owners', 'attention', { state: 'done' }), false);
  assert.equal(stateMatches('owners', 'attention', { state: 'DROPPED' }), true);
  assert.equal(stateMatches('owners', 'attention', {}), true);
  assert.equal(stateMatches('asks', 'unresolved', { state: 'resolved' }), false);
  assert.equal(stateMatches('asks', 'unresolved', { state: 'stale' }), true);
});

test('sort puts attention states first and oldest first within a state', () => {
  const rows = [{ id: 'r', state: 'resolved', age_s: 1 }, { id: 'o1', state: 'open', age_s: 10 }, { id: 'o2', state: 'open', age_s: 99 }, { id: 'b', state: 'blocked', age_s: 5 }];
  assert.deepEqual(sortRows('asks', rows).map(r => r.id), ['b', 'o2', 'o1', 'r']);
});
