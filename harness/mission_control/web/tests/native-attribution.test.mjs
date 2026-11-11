import test from 'node:test';
import assert from 'node:assert/strict';
import { owners } from '../js/adapt.js';
test('unverified runtime is unknown rather than Claude', () => {
  const [row] = owners([{agent_id: 'unverified', runtime: 'unknown', state: 'unknown'}]);
  assert.equal(row.runtime, 'unknown');
  assert.equal(row.harness, 'unknown');
});
test('native app observation stays separate from unknown last activity', () => {
  const [row] = owners([{agent_id: 'project', runtime: 'codex', state: 'observed',
    observed_at: '2026-11-10T20:00:00Z', native_status: {type: 'active'}}]);
  assert.equal(row.observed_at, '2026-11-10T20:00:00Z');
  assert.equal(row.native_status, 'active');
  assert.equal(row.last_item.active, null);
  assert.equal(row.model, '');
});
