// The page-side gate (goodqa#15920, PR 234 v7). Every count and every "none" the page states goes through
// adapt.claim()/gate(), which composes the server's read of each dataset the claim declares (adapt.CLAIMS).
//
// 1. Observed against declared: each panel is rendered over a recording Proxy of the state. The datasets it reads must
//    be datasets its claims declare (or a stated exemption), and every state key it reads must be mapped.
// 2. The modules that only run in a browser are scanned: the datasets they read must be covered by the claims they use.
// 3. A scan for counts and "none" sentences written outside the gate.
// 4. Seeded violations in the shapes found on the stacked PRs (T242-3, T243-1, T243-3) prove 1 to 3 fail on them.
// 5. Rows that fail before this change by assertion: a source that feeds a dataset but was not in the page's list.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { text } from './dom-shim.mjs';
import * as adapt from '../js/adapt.js';
import * as v from '../js/ledger-views.js';
import { FEEDS, SOURCES, withReads, healthRows } from './reads.mjs';

const here = new URL('..', import.meta.url).pathname;
const NOW = Date.parse('2027-01-15T09:00:00Z');
const at = '2027-01-15T08:00:00.000Z';
const ui = { goalsLimit: 6, dealsLimit: 8, blockersLimit: 8, reqFilter: 'all', reqQuery: '', reqLimit: v.PAGE, archiveKind: 'all', archiveLimit: v.PAGE, set() {}, more() {} };
const part = extra => ({ at, truth: 'current', error: '', ...extra });

// A state with rows in every dataset (full) or in none (empty): both, because a panel reads different data on each path.
function world(full, broken = '') {
  const health = healthRows(Date.parse(at) / 1000).map(row => (row.name === broken ? { ...row, status: 'error', truth: 'unknown', ok_at: null, detail: `${row.name} read failed` } : row));
  const req = { id: 'r1', text: 'R', bucket: 'live', rule: 'live', reason: 'x', at };
  const snapshot = {
    goals: part({ items: full ? [{ id: 'g1', title: 'G', state: 'LIVE_TESTED', evidence: [] }] : [], total: full ? 1 : 0 }),
    requirements: part({ items: full ? [req, { ...req, id: 'r2', bucket: 'archived', rule: 'R1' }] : [], total: full ? 2 : 0 }),
    status: part({ blockers: full ? [{ id: 'b1', note: 'blocked', at }] : [], verified: full ? [{ id: 'v1', note: 'ok', at, verdict: 'PASS' }] : [], counts: {} }),
  };
  const owner = { agent_id: 'a0123456789abcdef', name: 'a0123456', runtime: 'claude', state: 'DROPPED', severe: true, task: 'T', ticket: 'goodqa#1', last_item: { note: 'No work item recorded yet' } };
  const ask = { id: 'wask1', text: 'Q?', at, ticket: 'goodqa#1' };
  return withReads({
    now: NOW, connection: 'live', lastData: NOW, ledger: adapt.ledger(snapshot), sources: adapt.sources(health),
    owners: full ? [owner] : [], ownerRows: [], initiatives: full ? [{ id: 'i1', initiative: 'Ship', state: 'Blocked', ticket: 'goodqa#1', owner: '' }] : [], initiativesStale: false, initiativesError: '',
    asks: full ? [ask] : [], asksStale: [], asksFlagged: full ? [{ ...ask, id: 'wask2', flagged: 'no source' }] : [], asksCleared: [], asksResolved: [],
    asksArchive: full ? [{ ...ask, id: 'wask3', kind: 'ask', rule: 'R1', bucket: 'archived' }] : [], asksArchiveTotal: full ? 1 : 0, asksSweptAt: '', asksSession: 's',
    events: full ? [{ id: 'e1', kind: 'deploy', ts: at, summary: 'deployed', actor: {}, subject: { branch: 'x-1' }, historic: false }] : [], messages: [], sessions: [], decisions: {}, loss: {},
  });
}

// ---- 1. observed against declared
function recording(state) {
  const seen = { keys: new Set(), data: new Set(), consulted: new Set(), claims: new Set(), unmapped: new Set() };
  const note = key => {
    seen.keys.add(key);
    if (!(key in adapt.STATE_DATASETS)) seen.unmapped.add(key);
    else if (adapt.STATE_DATASETS[key]) seen.data.add(adapt.STATE_DATASETS[key]);
  };
  const proxy = new Proxy(state, {
    get(target, key) {
      if (typeof key !== 'string') return target[key];
      if (key === 'ledger') return new Proxy(target.ledger, { get: (led, name) => { if (typeof name === 'string') note(`ledger.${name}`); return led[name]; } });
      if (key === 'reads') return new Proxy(target.reads || {}, { get: (map, name) => { if (typeof name === 'string') seen.consulted.add(name); return map[name]; } });
      note(key);
      return target[key];
    },
    ownKeys: target => Reflect.ownKeys(target),  // a spread of the state reads nothing by itself
  });
  return { proxy, seen };
}
function observe(render) {
  const seen = { data: new Set(), claims: new Set(), unmapped: new Set(), consulted: new Set() };
  for (const full of [true, false]) {
    const r = recording(world(full));
    adapt.observe.claim = id => r.seen.claims.add(id);
    try { render(r.proxy); } finally { adapt.observe.claim = null; }
    for (const k of Object.keys(seen)) r.seen[k].forEach(x => seen[k].add(x));
  }
  return seen;
}
// What a set of claims lets a panel read: the datasets they declare, and the exemptions stated beside them.
const allowed = claims => new Set([...claims].flatMap(id => [...(adapt.CLAIMS[id] || []), ...Object.keys(adapt.SAFE_READS[id] || {})]));
function gaps(seen) {
  const ok = allowed(seen.claims);
  return { ungated: [...seen.data].filter(d => !ok.has(d)).sort(), unmapped: [...seen.unmapped].sort() };
}
const PANELS = {
  tiles: s => v.tiles(s, () => {}), goals: s => v.goals(s, ui), deals: s => v.deals(s, ui), blockers: s => v.blockers(s, ui),
  requirements: s => v.requirements(s, ui), archive: s => v.archive(s, ui), inventory: s => v.inventory(s, () => {}),
};
// every builder ledger-views exports is listed: a new one cannot be left out
test('every panel builder is under the derivation', () => {
  const builders = Object.keys(v).filter(name => typeof v[name] === 'function' && v[name].length >= 1 && /^\(?state|^function \w+\(state/.test(String(v[name]).replace(/^export /, '')));
  assert.deepEqual(builders.filter(name => !(name in PANELS)).sort(), []);
});
for (const [name, render] of Object.entries(PANELS)) {
  test(`derived: the ${name} panel reads only datasets its claims declare`, () => {
    const seen = observe(render);
    assert.ok(seen.claims.size > 0, 'the panel states its counts through the gate');
    assert.deepEqual(gaps(seen), { ungated: [], unmapped: [] });
    // and consults the server's read of every one of them (a declared dataset that is never consulted would be dead)
    for (const id of seen.claims) for (const dataset of adapt.CLAIMS[id]) assert.ok(seen.consulted.has(dataset), `${id} consults ${dataset}`);
  });
}
test('derived: no claim declares a dataset that no panel reads under it', () => {
  const read = Object.fromEntries(Object.keys(adapt.CLAIMS).map(id => [id, new Set()]));
  for (const render of Object.values(PANELS)) {
    const seen = observe(render);
    for (const id of seen.claims) seen.data.forEach(d => read[id].add(d));
  }
  for (const [id, datasets] of Object.entries(adapt.CLAIMS)) {
    if (!read[id].size) continue;  // used only by the browser-only modules (scanned below)
    assert.deepEqual(datasets.filter(d => !read[id].has(d)), [], `claim ${id}`);
  }
});

// ---- 2. the modules that need a browser: a scan of what they read against the claims they use
const HELPER_CLAIMS = {};
for (const [name, fn] of Object.entries(adapt.observe ? adapt : {})) {
  if (typeof fn !== 'function' || !/\b(claim|gate|countText|noneText)\(/.test(String(fn))) continue;
  const used = new Set();
  adapt.observe.claim = id => used.add(id);
  try { fn(world(true), 'No work item yet', 0); } catch { /* a helper with another signature: what it claimed before it threw still counts */ } finally { adapt.observe.claim = null; }
  HELPER_CLAIMS[name] = used;
}
function scan(source) {
  const keys = new Set([...source.matchAll(/\b(?:state|getState\(\))\.(\w+)\b(?!\()/g)].map(m => m[1]));
  const ledgerParts = [...source.matchAll(/\b(?:state|led)\.?(?:ledger)?\.(goals|requirements|status)\b/g)].map(m => `ledger.${m[1]}`);
  keys.delete('ledger');
  ledgerParts.forEach(k => keys.add(k));
  const claims = new Set([...source.matchAll(/\b(?:claim|gate)\(\s*\w+,\s*'(\w+)'/g)].map(m => m[1]));
  for (const [name, used] of Object.entries(HELPER_CLAIMS)) if (new RegExp(`\\b${name}\\(`).test(source)) used.forEach(id => claims.add(id));
  const data = new Set([...keys].filter(k => adapt.STATE_DATASETS[k]).map(k => adapt.STATE_DATASETS[k]));
  const ok = allowed(claims);
  return { ungated: [...data].filter(d => !ok.has(d)).sort(), unmapped: [...keys].filter(k => !(k in adapt.STATE_DATASETS)).sort() };
}
// Modules that show rows and make no count or "none" claim from a dataset, each with the reason.
const ROWS_ONLY = {
  'adapt.js': 'the gate itself and pure mapping', 'store.js': 'the store: holds the state, states nothing', 'live.js': 'transport', 'ui.js': 'element helpers', 'theme.js': 'theme',
  'health.js': 'the Source health strip shows each source\'s own row',
  'chat.js': 'shows the messages on hand; its empty text is instructions, not a claim that there are none',
};
const MODULE_EXEMPT = {
  'main.js': { asks: 'the inspector shows the selected row', chat: 'the session picker lists the sessions on hand', initiatives: 'the inspector shows the selected row' },
  'needs.js': { chat: 'a reply on hand takes an ask off the waiting count; a missing chat read leaves every ask waiting (adapt.SAFE_READS.needs)' },
  'scene.js': { asks: 'draws a node per row on hand', chat: 'draws the chat node', initiatives: 'draws a node per row on hand', owners: 'draws a node per row on hand; its status line is written by main.js under the progress claim', events: 'animates the events on hand' },
  'initiatives.js': { asks: 'a card adds "N open asks" only when it holds some (adapt.SAFE_READS.initiatives)' },
  'views.js': { events: 'reads the last event only to decide which section repaints' },
};
for (const file of readdirSync(`${here}js`).filter(f => f.endsWith('.js')).sort()) {
  test(`scan: ${file} reads only datasets covered by the claims it uses`, () => {
    if (ROWS_ONLY[file]) return;  // exempt, with its reason above
    const found = scan(readFileSync(`${here}js/${file}`, 'utf8'));
    const exempt = MODULE_EXEMPT[file] || {};
    assert.deepEqual({ ungated: found.ungated.filter(d => !exempt[d]), unmapped: found.unmapped }, { ungated: [], unmapped: [] });
  });
}

// ---- 3. counts and "none" sentences written outside the gate
const GATED = /\b(countText|feedCount|ownerCount|initiativeCount|ownerCountTitle|noneText|needsSummary|\w*Empty)\(|\.count\(|\.none\(/;
const RAW = [/\$\{[^}]*(\.length|\?\? 0|\|\| 0)[^}]*\}/, /String\([^)]*\.length\)/, /textContent = [^;`]*\.length/, /el\([^)]*'(No |Nothing |None |Zero )[^']*'/];
export function ungatedLines(source) {
  const lines = source.split('\n');
  return lines.map((line, i) => ({ line, i })).filter(({ line, i }) => RAW.some(re => re.test(line)) && !GATED.test(line)
    && !/held:/.test(line) && !/held:/.test(lines[i - 1] || '')).map(({ line, i }) => `${i + 1}: ${line.trim().slice(0, 100)}`);
}
for (const file of readdirSync(`${here}js`).filter(f => f.endsWith('.js') && f !== 'adapt.js').sort()) {
  test(`scan: ${file} writes no count or "none" outside the gate`, () => {
    assert.deepEqual(ungatedLines(readFileSync(`${here}js/${file}`, 'utf8')), [], 'state it through gate()/countText()/noneText(), or mark a count of rows on hand with "// held: <why>"');
  });
}

// ---- 4. seeded violations, in the shapes the stacked PRs carry
test('seeded T242-3: a summary line of plain counts is caught by the scan', () => {
  const line = "summary.textContent = `${live.length} live owners per ah owners · ${state.owners.filter(o => o.parked).length} parked or history`;";
  assert.equal(ungatedLines(line).length, 1);
});
test('seeded T243-3: raw "?? 0" counts from an undeclared state key are caught twice', () => {
  const line = "meta.textContent = `${state.org.counts.live_owners ?? 0} live of ${state.org.counts.owner ?? 0} owners`;";
  assert.equal(ungatedLines(line).length, 1);
  assert.deepEqual(scan(line).unmapped, ['org'], 'state.org is not in STATE_DATASETS');
  const seen = observe(s => String(s.org));
  assert.deepEqual(gaps(seen).unmapped, ['org']);
});
test('seeded T243-1: a panel that reads owners under a claim that declares only initiatives is caught', () => {
  const seen = observe(s => adapt.gate(s, 'initiatives').count(s.initiatives.length + s.owners.filter(o => o.state === 'live').length));
  assert.deepEqual(gaps(seen).ungated, ['owners']);
  assert.deepEqual(scan("el('p', '', gate(state, 'initiatives').count(state.initiatives.length + state.owners.length))").ungated, ['owners']);
});
test('seeded: a claim id that is not declared is unknown, and so is a dataset the server sent no read for', () => {
  assert.equal(adapt.claim(world(false), 'topology').truth, 'unknown');
  const s = world(false);
  delete s.reads.owners;
  assert.equal(adapt.claim(s, 'owners').truth, 'unknown');
  assert.equal(adapt.gate(s, 'owners').count(0), '?');
  assert.equal(adapt.claim({ ...world(false), reads: undefined }, 'goals').truth, 'unknown');
  // a server that says "current" over a fact that is not is not believed
  s.reads.owners = { truth: 'current', facts: [{ id: 'owners', truth: 'stale', at }] };
  assert.equal(adapt.claim(s, 'owners').truth, 'stale');
});

// ---- 5. every source that feeds a claim's datasets holds the claim back (fails before this change by assertion)
const zeroOwners = s => `${adapt.ownersEmpty(s, false)}|${adapt.ownerCount(s, 0)}`;
const ZERO = [
  ['blockers', s => text(v.blockers(s, ui)), /^No blockers recorded\.$/m],
  ['owners', zeroOwners, /^No owners are running\.\|00$/],
  ['deploys', s => text(v.deals(s, ui)), /No deploys or live tests recorded in the last 12 hours\./],
  ['needs', s => adapt.needsSummary(s, 0, 0).empty, /^Nothing needs you right now\.$/],
  ['requirements', s => text(v.requirements(s, { ...ui, reqFilter: 'live' })), /No requirements recorded\./],
  ['activity', s => adapt.feedEmpty(s), /^Listening for signals…$/],
];
for (const [id, render, zero] of ZERO) {
  const feeds = FEEDS && adapt.CLAIMS ? [...new Set(adapt.CLAIMS[id].flatMap(d => FEEDS[d]))].filter(src => !src.startsWith('ledger:')) : [];
  test(`chain: the ${id} zero is stated only while every source that feeds it is current (${feeds.length} sources)`, () => {
    assert.match(render(world(false)), zero, 'stated when every source is current');
    for (const source of feeds) assert.doesNotMatch(render(world(false, source)), zero, `not stated while ${source} has not read`);
  });
}
test('v6 F2: blockers and owners rest on the supervised-owner and work-log sources that feed the owner rows', () => {
  for (const source of ['codex-owners', 'wals']) {
    const s = world(false, source);
    assert.doesNotMatch(text(v.blockers(s, ui)), /No blockers recorded/, source);
    assert.equal(adapt.missionTiles(s).find(t => t.id === 'blockers').value, '?', source);
    assert.doesNotMatch(zeroOwners(s), /No owners are running/, source);
  }
});
test('rows the page could not show make the claim partial', () => {
  const s = world(true);
  assert.equal(adapt.gate({ ...s, loss: { owners: 2 } }, 'owners').count(3), '3+');
  const led = adapt.ledger({ goals: part({ items: [{ id: 'g1', title: 'G', state: 'UNKNOWN' }, 'not a row', { title: 'no id' }], total: 3 }) });
  assert.equal(led.goals.lost, 2);
  assert.equal(adapt.claim(withReads({ ...s, ledger: led }), 'goals').truth, 'partial');
});
test('a feed at the cap of events held is a floor, not the whole count', () => {
  const s = world(false);
  s.events = Array.from({ length: adapt.EVENTS_HELD }, (_, i) => ({ id: `e${i}`, kind: 'wal' }));
  assert.equal(adapt.feedCount(s, 12), '12+');
  assert.equal(adapt.feedCount(world(false), 0), '0');
});
test('every claim section repaints on a truth change (v6 F3)', () => {
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  const sections = [...views.matchAll(/\{ id: '([\w-]+)',[^\n]*on: \[([^\]]*)\]/g)];
  assert.ok(sections.length >= 7);
  for (const [, id, on] of sections) assert.match(on, /'truth'/, id);
  for (const file of ['owners.js', 'needs.js', 'initiatives.js', 'activity.js']) assert.match(readFileSync(`${here}js/${file}`, 'utf8'), /'truth'/, file);
});
