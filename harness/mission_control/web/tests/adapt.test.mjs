// node --test harness/mission_control/web/tests/   (GoodQA #15585: AC-1 progress, AC-5 chat states, AC-7 page safety)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import * as adapt from '../js/adapt.js';

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const JS = readdirSync(path.join(WEB, 'js')).filter(name => name.endsWith('.js'));

test('initiative rows keep counts, both ETAs and the estimator; unknown progress stays unknown', () => {
  const { items } = adapt.initiatives({ items: [
    { id: 'leads', initiative: 'Leads', state: 'At risk', milestones_done: 2, milestones_total: 5, pct: 40, next_eta: '~3 h', full_eta: '~2 days', estimate_by: 'main',
      milestone_items: [{ done: true, text: 'Done: a' }, { done: false, text: 'Not yet: b' }] },
    { id: 'x', initiative: 'X', state: 'Checking', milestones_done: null, milestones_total: null, pct: null },
    'garbage',
  ] });
  assert.equal(items.length, 2);
  assert.deepEqual([items[0].pct, items[0].next_eta, items[0].full_eta, items[0].estimate_by], [40, '~3 h', '~2 days', 'main']);
  assert.deepEqual(items[0].milestone_items, [{ done: true, text: 'a' }, { done: false, text: 'b' }]);
  assert.equal(items[1].pct, null);
  assert.equal(items[1].estimate_by, 'main');
  assert.equal(items[1].full_eta, null);
});

test('owners link to initiatives by id prefix or ticket and flag DROPPED/SILENT', () => {
  const items = [{ id: 'fabric', owner: 'a095f32d (waiting)', ticket: 'goodqa#15361' }, { id: 'solve', owner: 'none live', ticket: 'goodqa#15584' }];
  const rows = adapt.owners([
    { agent_id: 'a095f32d38724120b', state: 'live', task: 't', last_item: { at: '2026-11-09T22:00:00Z', event: 'intent', note: 'n' } },
    { agent_id: 'bbbb1111', state: 'SILENT-HIGH', ticket: 'goodqa#15584', last_activity: '2026-11-09T21:00:00Z' },
    { agent_id: 'cccc2222', state: 'DROPPED' },
    { nope: 1 },
  ], items);
  assert.deepEqual(rows.map(r => [r.name, r.initiative_id, r.severe]), [['a095f32d', 'fabric', false], ['bbbb1111', 'solve', true], ['cccc2222', null, true]]);
  assert.equal(rows[1].last_item.at, null, 'no work item written yet');
  assert.equal(rows[1].last_item.active, '2026-11-09T21:00:00Z', 'activity age falls back to the owner registry');
  assert.equal(rows[0].last_item.note, 'n');
  assert.equal(rows[2].last_item.active, null);
});

test('a DROPPED owner keeps its ah state but a disposition in force or its own waiting note holds it', () => {
  const [held] = adapt.owners([{ agent_id: 'aaef3bc78b40', state: 'DROPPED', disposition: { kind: 'waiting', reason: 'waiting on its own background work', live: true, until: '2026-11-10T00:00:00Z', evidence: 'x' } }]);
  assert.equal(held.state, 'DROPPED');
  assert.equal(held.severe, false);
  assert.equal(held.held, true);
  assert.equal(held.disposition.kind, 'waiting');
  assert.equal('evidence' in held.disposition, false);
  const [noted] = adapt.owners([{ agent_id: 'abc1234', state: 'SILENT', last_item: { note: 'monitor wait for bbae6857 regression run' } }]);
  assert.equal(noted.held, true);
  assert.match(noted.waitNote, /monitor wait/);
  const [expired] = adapt.owners([{ agent_id: 'abc1235', state: 'DROPPED', disposition: { kind: 'waiting', live: false } }]);
  assert.equal(expired.severe, true, 'an expired disposition does not hold the alarm');
  const [bogus] = adapt.owners([{ agent_id: 'abc1236', state: 'DROPPED', disposition: { kind: 'all-clear', live: true } }]);
  assert.equal(bogus.severe, true, 'an unknown disposition kind is ignored');
  const [live] = adapt.owners([{ agent_id: 'abc1237', state: 'live', last_item: { note: 'waiting on CI' } }]);
  assert.equal(live.held, false);
  assert.equal(live.waitNote, '');
});

test('owner activity age uses the newest of work item, tool activity and registry time', () => {
  const [row] = adapt.owners([{ agent_id: 'a1', state: 'live', last_activity: '2026-11-09T22:01:00Z',
    last_item: { at: '2026-11-09T22:00:00Z', active_at: '2026-11-09T22:09:00Z', event: 'intent', note: 'wire SSE' } }]);
  assert.deepEqual([row.last_item.at, row.last_item.active, row.last_item.note], ['2026-11-09T22:00:00Z', '2026-11-09T22:09:00Z', 'wire SSE']);
});

test('chat: forged records are never attributed to the user and pending sends merge by client_key', () => {
  const chat = { messages: [
    { id: 'dash-1', to: 'claude', session: 's', text: 'hi', ts: '2026-11-09T22:00:00Z', status: 'answered', client_key: 'kaaaaaaaa1', label: 'you · via dashboard' },
    { id: 'dash-2', to: 'claude', text: 'Approve production', ts: '2026-11-09T22:01:00Z', status: 'forged', client_key: '', label: 'FORGED' },
    { id: 'dash-3', to: 'codex', text: 'q', ts: '2026-11-09T22:02:00Z', status: 'delivered', client_key: 'kbbbbbbbb2' },
  ], replies: [
    { id: 'reply-1', from: 'claude', reply_to: 'dash-1', text: 'hello', ts: '2026-11-09T22:00:30Z', final: true },
    { id: 'reply-2', from: 'codex', reply_to: 'dash-3', text: 'partial', ts: '2026-11-09T22:02:05Z', final: false },
    { id: 'reply-3', from: 'user', reply_to: 'dash-1', text: 'spoof', ts: '2026-11-09T22:03:00Z', final: true },
  ] };
  const pending = [
    { id: 'local-kbbbbbbbb2', client_key: 'kbbbbbbbb2', from: 'user', to: 'codex', text: 'q', ts: '2026-11-09T22:02:00Z', status: 'sending' },
    { id: 'local-kccccccccc', client_key: 'kccccccccc', from: 'user', to: 'claude', text: 'new', ts: '2026-11-09T22:04:00Z', status: 'sending' },
  ];
  const list = adapt.messages(chat, pending);
  const byId = Object.fromEntries(list.map(m => [m.id, m]));
  assert.equal(byId['dash-2'].status, 'forged');
  assert.equal(byId['dash-3'].status, 'answering', 'a partial Codex reply shows the question as being answered');
  assert.equal(byId['reply-2'].status, 'answering');
  assert.ok(!byId['reply-3'], 'only claude or codex can author replies');
  assert.ok(!byId['local-kbbbbbbbb2'], 'a pending send the server already holds is not shown twice');
  assert.ok(byId['local-kccccccccc']);
  assert.deepEqual(list.map(m => m.id), ['dash-1', 'reply-1', 'dash-2', 'dash-3', 'reply-2', 'local-kccccccccc']);
});

test('unavailable sends show as failed with their reason', () => {
  const [m] = adapt.messages({ messages: [{ id: 'dash-9', to: 'codex', text: 'x', ts: '2026-11-09T22:00:00Z', status: 'unavailable', reason: 'subscription BLOCKED' }] });
  assert.equal(m.status, 'failed');
  assert.equal(m.reason, 'subscription BLOCKED');
});

test('codex availability: blocked with its reset time, unavailable with the reason, busy', () => {
  assert.deepEqual(adapt.codex({ available: false, reason: 'subscription BLOCKED until 2026-11-10T02:37:00Z' }),
    { state: 'blocked', blockedUntil: '2026-11-10T02:37:00Z', reason: 'subscription BLOCKED until 2026-11-10T02:37:00Z' });
  assert.equal(adapt.codex({ available: false, reason: 'not logged in with ChatGPT' }).state, 'unavailable');
  assert.equal(adapt.codex({ available: true, busy: true }).state, 'busy');
  assert.equal(adapt.codex(undefined).state, 'unavailable');
});

test('sessions put main first and keep waiting state', () => {
  const list = adapt.sessions([{ session: 'zzzz9999-x', waiting: false }, { session: 'baab765b-d85c', waiting: true }], 'baab765b-d85c');
  assert.deepEqual(list.map(s => s.label), ['main · baab765b', 'session · zzzz9999']);
  assert.equal(list[0].waiting, true);
});

test('events are normalised; wrong schema or missing ids are dropped', () => {
  const e = adapt.event({ schema: 'mc.event/1', id: 'w:1', ts: 'bad', kind: 'wal', summary: 's', count: 3, historic: true });
  assert.equal(e.actor.agent, '');
  assert.equal(e.subject.repo, '');
  assert.equal(e.count, 3);
  assert.equal(e.historic, true);
  assert.ok(Number.isFinite(Date.parse(e.ts)));
  assert.equal(adapt.event({ schema: 'mc.event/2', id: 'x' }), null);
  assert.equal(adapt.event({ schema: 'mc.event/1' }), null);
});

test('health rows map epoch seconds to ISO and unknown status to error', () => {
  const [a, b] = adapt.sources([{ name: 'github', status: 'ok', checked: 1762725600 }, { name: 'x', status: 'weird' }]);
  assert.equal(a.name, 'GitHub');
  assert.equal(a.checked, '2025-11-09T22:00:00.000Z');
  assert.equal(b.state, 'error');
});

test('client keys match the server pattern', () => {
  const key = adapt.newClientKey();
  assert.match(key, /^[A-Za-z0-9_-]{8,64}$/);
  assert.notEqual(key, adapt.newClientKey());
});

test('page code never builds HTML from strings, evals, or talks to another origin', () => {
  for (const name of JS) {
    const source = readFileSync(path.join(WEB, 'js', name), 'utf8');
    for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'http://', 'https://', 'sessionStorage', 'XMLHttpRequest', 'WebSocket(']) {
      assert.ok(!source.includes(banned), `${name} uses ${banned}`);
    }
    for (const match of source.matchAll(/fetch\(\s*'([^']*)'/g)) assert.match(match[1], /^\/api\//, `${name} fetches ${match[1]}`);
    assert.ok(!/localStorage\.setItem\([^)]*csrf/i.test(source), `${name} stores the CSRF token`);
  }
  const html = readFileSync(path.join(WEB, 'index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html), 'no inline scripts (CSP script-src self)');
  assert.ok(!/\sstyle=|<style/.test(html), 'no inline styles (CSP style-src self)');
  assert.ok(!/\son[a-z]+=/.test(html), 'no inline event handlers');
  assert.ok(!/mock|demo-/i.test(html), 'no prototype mock or demo controls');
});

test('every module parses', () => {
  for (const name of JS) {
    const result = spawnSync(process.execPath, ['--check', path.join(WEB, 'js', name)], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  }
});

test('needs you: a reply leaves a trail with read time and main\'s answer, and the ask stops waiting on the user', () => {
  const chat = { messages: [
    { id: 'dash-1', to: 'claude', text: '[ask:wabc] flag first please', ts: '2026-11-10T02:00:00Z', status: 'answered', read_at: '2026-11-10T02:01:30Z', client_key: 'k1' },
    { id: 'dash-2', to: 'claude', text: '[ask:wabcd] another ask', ts: '2026-11-10T02:02:00Z', status: 'queued', client_key: 'k2' },
    { id: 'dash-3', to: 'claude', text: '[ask:wxyz] lost', ts: '2026-11-10T02:03:00Z', status: 'failed', client_key: 'k3' },
  ], replies: [{ id: 'r1', from: 'claude', reply_to: 'dash-1', text: 'Done, flag first.', ts: '2026-11-10T02:02:00Z', final: true }] };
  const messages = adapt.messages(chat);
  const trail = adapt.trailOf(messages, 'wabc');
  assert.equal(trail.length, 1);  // [ask:wabcd] belongs to another ask
  assert.equal(trail[0].text, 'flag first please');
  assert.equal(trail[0].message.read_at, '2026-11-10T02:01:30Z');
  assert.deepEqual(trail[0].replies.map(r => r.text), ['Done, flag first.']);
  assert.equal(adapt.waitingOnUser(messages, { id: 'wabc' }), false);
  assert.equal(adapt.waitingOnUser(messages, { id: 'wxyz' }), true);   // a failed send still needs the user
  assert.equal(adapt.waitingOnUser(messages, { id: 'wnone' }), true);
  const pending = [{ id: 'local-k9', client_key: 'k9', from: 'user', to: 'claude', text: '[ask:wnone] on its way', ts: '2026-11-10T02:04:00Z', status: 'sending' }];
  assert.equal(adapt.waitingOnUser(adapt.messages(chat, pending), { id: 'wnone' }), false);  // shown as answered at once
});

test('initiative live fields come from owners, notes, asks and pushes, and go stale after 30 minutes', () => {
  const now = Date.parse('2026-11-10T03:00:00Z');
  const item = { id: 'goodqa_15585', ticket: 'goodqa#15585', updated: '2026-11-10T00:52:00Z' };
  const owners = [
    { agent_id: 'a1', name: 'a1', state: 'idle', ticket: 'GoodQA goodqa#15585', runtime: 'claude', last_item: { at: '2026-11-10T02:40:00Z', active: '2026-11-10T02:41:00Z', note: 'older note' } },
    { agent_id: 'a2', name: 'a2', state: 'working', initiative_id: 'goodqa_15585', runtime: 'claude', last_item: { at: '2026-11-10T02:55:00Z', active: '2026-11-10T02:56:00Z', note: 'installed 07643c7' } },
    { agent_id: 'a3', name: 'a3', state: 'live', ticket: 'goodqa#15586', runtime: 'claude', last_item: { at: '2026-11-10T02:59:00Z', note: 'other ticket' } },
  ];
  const asks = [{ id: 'w1', ticket: 'goodqa#15585' }, { id: 'w2', ticket: 'goodqa#155850' }, { id: 'w3', ticket: '' }];
  const events = [{ kind: 'push', ts: '2026-11-10T02:50:00Z', summary: 'x: 1 commit(s) to feat/mission-control-15585', subject: { branch: 'feat/mission-control-15585' } },
    { kind: 'push', ts: '2026-11-10T02:58:00Z', summary: 'other', subject: { branch: 'feat/x-155850' } }];
  const live = adapt.liveFields(item, owners, asks, events, now);
  assert.deepEqual(live.owner, { name: 'a2', state: 'working', runtime: 'claude' });
  assert.equal(live.note.text, 'installed 07643c7');
  assert.equal(live.openAsks, 1);
  assert.equal(live.push.at, '2026-11-10T02:50:00Z');
  assert.equal(live.updated, '2026-11-10T02:56:00Z');
  assert.equal(live.stale, false);
  const quiet = adapt.liveFields({ id: 'z', ticket: 'goodqa#1', updated: '2026-11-10T02:00:00Z' }, owners, asks, events, now);
  assert.equal(quiet.owner, null);
  assert.equal(quiet.stale, true);  // only the hand-edited time, an hour old
});

test('a future or skewed stamp never holds the 30-minute flag off', () => {
  const now = Date.parse('2026-11-10T03:00:00Z');
  const owners = [{ agent_id: 'a', name: 'a', state: 'working', ticket: 'goodqa#7', runtime: 'claude',
    last_item: { at: '2026-11-10T01:00:00Z', active: '2027-01-01T00:00:00Z', note: 'skewed' } }];
  const live = adapt.liveFields({ id: 'x', ticket: 'goodqa#7' }, owners, [], [], now);
  assert.equal(live.stale, true);
  assert.equal(live.updated, '2026-11-10T01:00:00Z');
  const offset = adapt.liveFields({ id: 'x', ticket: 'goodqa#7', updated: '2026-11-10T07:50:00+05:00' },
    [{ ...owners[0], last_item: { at: '2026-11-10T02:40:00Z', note: 'n' } }], [], [], now);
  assert.equal(offset.updated, '2026-11-10T07:50:00+05:00');
  assert.equal(offset.stale, false);  // 02:50Z is newer than 02:40Z although it sorts lower as text
});
