// Status truth (review PR 234 v3 F1, v2 F2): Mission Control never shows an unavailable, stale or partial source as a
// healthy zero. The first half renders what the real server publishes (truth_scenarios.py drives collectors.Ledger and
// collectors.Health) after a timeout, a nonzero exit or invalid JSON, a failure after a good empty read, a partial read
// and each recovery. The second half is the audit of every ledger-panel zero or "none" claim, one test per claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { text, walk } from './dom-shim.mjs';
import { ledger, sources, missionTiles, atRisk, ownersEmpty } from '../js/adapt.js';
import * as v from '../js/ledger-views.js';
import { withReads, SOURCES } from './reads.mjs';

const SCRIPT = fileURLToPath(new URL('./truth_scenarios.py', import.meta.url));
const run = spawnSync(process.env.PYTHON || 'python3', ['-I', SCRIPT], { encoding: 'utf8', timeout: 60000 });
if (run.status !== 0) throw new Error(`truth_scenarios.py failed: ${run.stderr || run.error}`);
const SCENARIOS = JSON.parse(run.stdout);
const NOW = Date.parse('2027-01-15T09:00:00Z');
const LAST_GOOD = '2027-01-15 08:00 UTC';  // T0 in truth_scenarios.py: the empty read before the failure
const ui = { goalsLimit: 6, dealsLimit: 8, blockersLimit: 8, reqFilter: 'all', reqQuery: '', reqLimit: v.PAGE, archiveKind: 'all', archiveLimit: v.PAGE, set() {}, more() {} };
const base = { now: NOW, connection: 'live', events: [], owners: [], initiatives: [], asks: [], messages: [], decisions: {}, asksFlagged: [], asksArchive: [], asksArchiveTotal: 0, asksStale: [], asksSweptAt: '', sessions: [] };
const stateOf = sc => ({ ...base, ledger: ledger(sc.ledger), sources: sources(sc.health), reads: sc.reads });  // the real server's reads
const tile = (s, id) => missionTiles(s).find(t => t.id === id);
const ledgerHealth = s => s.sources.find(r => r.id === 'ledger');
// one inventory row as 'health | holds' (cells joined, so a word boundary is real)
const inventoryRow = (s, name) => {
  const tr = walk(v.inventory(s, () => {})).find(n => n.tagName === 'TR' && n.children[0]?.textContent === name);
  return { textContent: `${tr.children[2].textContent} | ${tr.children[3].textContent}` };
};
const ANY_TIME = /Last good read \d{4}-\d\d-\d\d \d\d:\d\d UTC/;  // Health stamps its own wall-clock time

for (const mode of ['timeout', 'nonzero', 'invalid_json']) {
  test(`initial ${mode}: Blockers, Deploys, the Blockers tile and Source health say unknown, never zero`, () => {
    const s = stateOf(SCENARIOS[`initial_${mode}`]);
    const blockers = text(v.blockers(s, ui));
    assert.doesNotMatch(blockers, /No blockers recorded/);
    assert.match(blockers, /Not known: Status \(ah status\) could not be read, so Mission Control cannot say there are no blockers/);
    assert.match(blockers, /Status \(ah status\): not read successfully yet \(ah status (timed out|exited 1|returned unreadable output)\)/);
    const deals = text(v.deals(s, ui));
    assert.doesNotMatch(deals, /No deploys or live tests recorded/);
    assert.match(deals, /Not known/);
    const t = tile(s, 'blockers');
    assert.equal(t.value, '?');
    assert.match(t.note, /unknown/);
    assert.equal(t.alert, true);
    assert.equal(ledgerHealth(s).label, 'error · unknown');
    assert.equal(ledgerHealth(s).state, 'error');
    assert.match(text([inventoryRow(s, 'Blockers')]), /unknown/);
    assert.doesNotMatch(text([inventoryRow(s, 'Blockers')]), /\| 0 recorded/);
  });

  test(`failure after a good empty read (${mode}): stale, with the last good time beside the claim`, () => {
    const s = stateOf(SCENARIOS[`stale_after_empty_${mode}`]);
    const blockers = text(v.blockers(s, ui));
    assert.doesNotMatch(blockers, /No blockers recorded/);
    assert.match(blockers, new RegExp(`No blockers as of the last good read \\(${LAST_GOOD}\\)\\. Later reads failed, so this is not current\\.`));
    assert.match(blockers, new RegExp(`Status \\(ah status\\): showing the last good read from ${LAST_GOOD}`));
    assert.match(text(v.deals(s, ui)), /as of the last good read/);
    const t = tile(s, 'blockers');
    assert.equal(t.value, '0');
    assert.equal(t.note, `not current: last good read ${LAST_GOOD}`);
    assert.equal(ledgerHealth(s).label, 'error · stale');
    assert.match(ledgerHealth(s).note, ANY_TIME);
    assert.match(text([inventoryRow(s, 'Blockers')]), /stale/);
  });

  for (const from of ['initial', 'stale']) {
    test(`recovery after a ${from} ${mode}: the zero claims come back, current`, () => {
      const s = stateOf(SCENARIOS[`recovered_${from}_${mode}`]);
      const blockers = text(v.blockers(s, ui));
      assert.match(blockers, /^No blockers recorded\.$/m);
      assert.doesNotMatch(blockers, /Not known|last good read|could not be read/);
      assert.match(text(v.deals(s, ui)), /No deploys or live tests recorded in the last 12 hours\./);
      assert.deepEqual([tile(s, 'blockers').value, tile(s, 'blockers').note, tile(s, 'blockers').alert], ['0', 'across status, asks, owners', false]);
      assert.equal(ledgerHealth(s).label, 'ok');
      assert.match(text([inventoryRow(s, 'Blockers')]), /^ok \| 0 recorded in status$/);
    });
  }
}

test('a good empty read is current: the plain zero is stated (the claims above are not vacuous)', () => {
  const s = stateOf(SCENARIOS.current_empty);
  assert.equal(s.ledger.status.truth, 'current');
  assert.match(text(v.blockers(s, ui)), /^No blockers recorded\.$/m);
  assert.equal(tile(s, 'blockers').value, '0');
  assert.equal(tile(s, 'goals').value, '0 / 0');
});

test('a partial read says partial beside Blockers, Deploys, the tile and Source health', () => {
  const s = stateOf(SCENARIOS.partial);
  assert.equal(s.ledger.status.truth, 'partial');
  const blockers = text(v.blockers(s, ui));
  assert.doesNotMatch(blockers, /No blockers recorded/);
  assert.match(blockers, /No blockers in what could be read\. The read was partial/);
  assert.match(blockers, /agent-x\.jsonl/);
  assert.equal(tile(s, 'blockers').value, '0+');
  assert.equal(ledgerHealth(s).label, 'partial');
  assert.equal(ledgerHealth(s).state, 'stale');
});

test('a failure after a partial read is stale, not partial or current', () => {
  const s = stateOf(SCENARIOS.stale_after_partial);
  assert.equal(s.ledger.status.truth, 'stale');
  assert.match(text(v.blockers(s, ui)), /as of the last good read/);
});

test('Blockers rest on four sources: an asks source that never read keeps the zero unknown although status is fine', () => {
  const s = stateOf(SCENARIOS.asks_never_read);
  assert.equal(s.ledger.status.truth, 'current');
  const blockers = text(v.blockers(s, ui));
  assert.doesNotMatch(blockers, /No blockers recorded/);
  assert.match(blockers, /Not known: Asks ledger could not be read/);
  assert.equal(tile(s, 'blockers').value, '?');
  assert.equal(tile(s, 'asks').value, '?');
});

// ---- review PR 234 v6 (v5 F1 and its class): main's session moves. Whatever the page gets after the move (pushed after a
// tick, served by /api/state before the next tick, pushed by the session watch, or after a failed read for the new
// session) states no zero from the previous session's requirements or status. Reading the new session states them again.
for (const [name, health] of [['session_dropped', 'unknown'], ['session_moved_served', null], ['session_moved_watched', 'unknown'], ['session_moved_failed', 'error · unknown']]) {
  test(`v6 ${name}: no zero or "none" from the previous session's requirements or status`, () => {
    const s = stateOf(SCENARIOS[name]);
    const blockers = text(v.blockers(s, ui));
    assert.doesNotMatch(blockers, /No blockers recorded/);
    assert.match(blockers, /Not known: Status \(ah status\) (has not been read yet|could not be read)/);
    assert.doesNotMatch(text(v.deals(s, ui)), /No deploys or live tests recorded/);
    assert.equal(tile(s, 'blockers').value, '?');
    assert.match(tile(s, 'blockers').note, /unknown/);
    assert.match(text([inventoryRow(s, 'Blockers')]), /unknown/);
    if (name !== 'session_moved_failed') {  // there the new session's requirements read succeeded
      assert.doesNotMatch(text(v.requirements(s, { ...ui, reqFilter: 'live' })), /No requirements recorded/);
      assert.equal(tile(s, 'requirements').value, '?');
    }
    if (health) assert.equal(ledgerHealth(s).label, health);
  });
}

test('v6: moving to a session and reading it states the zeros again (the checks above are not vacuous)', () => {
  const s = stateOf(SCENARIOS.session_moved_read);
  assert.match(text(v.blockers(s, ui)), /^No blockers recorded\.$/m);
  assert.equal(tile(s, 'blockers').value, '0');
  assert.equal(tile(s, 'requirements').value, '0');
  assert.equal(ledgerHealth(s).label, 'ok');
});

// ---- the audit: every zero or "none" claim of the ledger panels, with the sources it now depends on (CLAIM_SOURCES).
// Each test breaks one source at a time and checks the plain zero disappears, and that it is stated when all are current.
const at = '2027-01-15T08:00:00.000Z';
const row = (name, truth = 'current', status = 'ok') => ({ name, status, checked: NOW / 1000, ok_at: truth === 'unknown' ? null : Date.parse(at) / 1000, truth, detail: status === 'ok' ? '' : `${name} read failed` });
const NAMES = SOURCES;
const LEDGER = ['goals', 'requirements', 'status'];
// world(): every source current. world(dep, 'failed'): dep's reads all failed. world(dep, 'never'): dep has not been
// read at all and reports no error (before the first read, or no main session yet).
function world(broken = '', how = 'failed') {
  const part = name => (`ledger:${name}` !== broken ? { at, truth: 'current', error: '' }
    : how === 'failed' ? { at: '', truth: 'unknown', error: `${name} read failed` } : { at: '', truth: 'unknown', error: '' });
  const snapshot = Object.fromEntries(LEDGER.map(name => [name, part(name)]));
  const health = NAMES.filter(name => !(name === broken && how === 'never')).map(name => (name === broken ? row(name, 'unknown', 'error') : row(name)));
  return withReads({ ...base, ledger: ledger(snapshot), sources: sources(health) });
}
const AUDIT = [
  ['Goals tile "0 / 0"', ['ledger:goals'], s => `${tile(s, 'goals').value} · ${tile(s, 'goals').note}`, /^0 \/ 0 · 0 live, not done · 0 open$/],
  ['Goals panel "No goals in the ledger yet."', ['ledger:goals'], s => text(v.goals(s, ui)), /No goals in the ledger yet\./],
  ['Owners tile "0 · none need attention"', ['owners'], s => `${tile(s, 'owners').value} · ${tile(s, 'owners').note}`, /^0 · none need attention$/],
  ['Needs-you tile "0 · nothing waiting"', ['asks'], s => `${tile(s, 'asks').value} · ${tile(s, 'asks').note}`, /^0 · nothing waiting$/],
  ['Blockers tile "0"', ['ledger:status', 'asks', 'owners', 'initiatives'], s => `${tile(s, 'blockers').value} · ${tile(s, 'blockers').note}`, /^0 · across status, asks, owners$/],
  ['Blockers panel "No blockers recorded."', ['ledger:status', 'asks', 'owners', 'initiatives'], s => text(v.blockers(s, ui)), /^No blockers recorded\.$/m],
  ['Requirements tile "0 · 0 archived"', ['ledger:requirements'], s => `${tile(s, 'requirements').value} · ${tile(s, 'requirements').note}`, /^0 · 0 archived$/],
  ['Requirements panel "No requirements recorded." and "Live 0"', ['ledger:requirements'], s => text(v.requirements({ ...s, ...{} }, { ...ui, reqFilter: 'live' })), /Live 0[\s\S]*No requirements recorded\./],
  ['Deploys panel "No deploys or live tests recorded"', ['ledger:status'], s => text(v.deals(s, ui)), /No deploys or live tests recorded in the last 12 hours\./],
  ['Archive panel "Nothing is archived." and "All 0"', ['ledger:requirements', 'asks'], s => text(v.archive(s, ui)), /All 0[\s\S]*Nothing is archived\./],
  ['Inventory Blockers row "0 recorded" and ok', ['ledger:status', 'asks', 'owners', 'initiatives'], s => text([inventoryRow(s, 'Blockers')]), /^ok \| 0 recorded in status$/],
  ['Inventory Owners row "0 owners" and ok', ['owners'], s => text([inventoryRow(s, 'Owners')]), /^ok \| 0 owners$/],
  ['Inventory Open asks row "0 open" and ok', ['asks'], s => text([inventoryRow(s, 'Open asks')]), /^ok \| 0 open, 0 stale, 0 untraceable$/],
  ['Inventory Initiatives row "0 initiatives" and ok', ['initiatives'], s => text([inventoryRow(s, 'Initiatives')]), /^ok \| 0 initiatives$/],
  ['Inventory Deploys row "0 deploys" and ok', ['ledger:status'], s => text([inventoryRow(s, 'Deploys and live tests')]), /^ok \| 0 deploys, 0 tested, 0 failed, 0 pending$/],
  ['Inventory Activity row "0 events" and ok', ['wals'], s => text([inventoryRow(s, 'Activity feed')]), /^ok \| 0 events held$/],
  ['Inventory Chat row "0 messages" and ok', ['chat'], s => text([inventoryRow(s, 'Chat')]), /^ok \| 0 messages, 0 sessions$/],
  ['Inventory Decisions row "0 decisions" and ok', ['ledger:status'], s => text([inventoryRow(s, 'Decisions and commits')]), /^ok \| 0 decisions, 0 commits, 0 claimed, 0 assumptions$/],
];
for (const [name, deps, render, zero] of AUDIT) {
  test(`audit: ${name} only when ${deps.join(', ')} ${deps.length > 1 ? 'are' : 'is'} current`, () => {
    assert.match(render(world()), zero, 'stated when every source is current');
    for (const dep of deps) for (const how of ['failed', 'never']) assert.doesNotMatch(render(world(dep, how)), zero, `not stated while ${dep} is unknown (${how})`);
  });
}

// review PR 234 v6: every claim also rests on the link. With every source current, a page that is not live (connecting,
// reconnecting, offline, signed out, or with no connection state at all) states none of the audited zeros; the live
// world() above states each of them, so this is not vacuous.
for (const connection of ['connecting', 'reconnecting', 'offline', 'expired', undefined]) {
  test(`v6: a page that is ${connection || 'without a connection state'} states no zero from what it last received`, () => {
    const s = { ...world(), connection, lastData: Date.parse(at) };
    for (const [name, , render, zero] of AUDIT) assert.doesNotMatch(render(s), zero, `${name} while ${connection}`);
    const blockers = text(v.blockers(s, ui));
    assert.match(blockers, new RegExp(`No blockers as of the last good read \\(${LAST_GOOD}\\)`));
    assert.match(blockers, /Connection to Mission Control: not connected/);
    assert.equal(tile({ ...s, lastData: 0 }, 'blockers').value, '?');  // nothing received yet: unknown, not stale
  });
}

test('v6: an owner claim with no OpenAI supervised owners row is unknown (a source that has not reported is never skipped)', () => {
  const s = world();
  assert.match(`${tile(s, 'owners').value} · ${tile(s, 'owners').note}`, /^0 · none need attention$/);
  const missing = withReads({ ...s, sources: s.sources.filter(r => r.id !== 'codex-owners') });
  assert.doesNotMatch(`${tile(missing, 'owners').value} · ${tile(missing, 'owners').note}`, /none need attention/);
  assert.doesNotMatch(ownersEmpty(missing, false), /^No owners are running\.$/);
  // an instance without OpenAI supervisors reports the row as off with nothing to report: the zero stands
  const off = withReads({ ...s, sources: sources([...NAMES.filter(n => n !== 'codex-owners').map(n => row(n)), { name: 'codex-owners', status: 'off', truth: 'current', detail: 'not configured' }]) });
  assert.equal(ownersEmpty(off, false), 'No owners are running.');
});

test('v6 (v5 F2): at-risk with no source truth passed gives no UNCOVERED or STALLED verdict', () => {
  const item = [{ id: 'i1', initiative: 'Ship', state: 'Active', ticket: 'goodqa#1' }];
  const working = [{ name: 'o', state: 'live', ticket: 'goodqa#1', progress: { at: '2027-01-15T06:00:00Z', event: 'commit' } }];
  for (const known of [undefined, {}, { progress: 'current' }, { owners: 'bogus' }]) {
    const row = atRisk(item, [], [], NOW, null, 6, known)[0];
    assert.equal(row.status, 'unknown', JSON.stringify(known));
    assert.doesNotMatch(row.reason, /no owner/);
  }
  for (const known of [undefined, {}, { owners: 'current' }, { owners: 'current', progress: 'later' }]) {
    const row = atRisk(item, working, [], NOW, null, 6, known)[0];
    assert.equal(row.status, 'unknown', JSON.stringify(known));
    assert.doesNotMatch(row.reason, /no real progress/);
  }
});

test('audit: Source health rows show the truth, not plain ok, for partial, stale and never-read sources', () => {
  const [ok, part, stale, never, off, odd] = sources([row('owners'), row('ledger', 'partial'), row('asks', 'stale', 'error'), row('wals', 'unknown', 'error'),
    { name: 'initiatives', status: 'off', truth: 'current', detail: 'no initiatives file configured' }, { name: 'github', status: 'ok', truth: 'fine' }]);
  assert.deepEqual([ok.label, part.label, stale.label, never.label, off.label, odd.label], ['ok', 'partial', 'error · stale', 'error · unknown', 'off', 'unknown']);
  assert.deepEqual([ok.state, part.state, stale.state, never.state, odd.state], ['ok', 'stale', 'error', 'error', 'stale']);
  assert.match(stale.note, new RegExp(`Last good read ${LAST_GOOD}`));
  assert.match(never.note, /No good read yet/);
});

test('audit: a snapshot with no truth field, or before any snapshot, claims nothing', () => {
  const s = withReads({ ...base, ledger: ledger({ status: { blockers: [], at } }), sources: sources(NAMES.map(name => row(name))) });
  assert.equal(s.ledger.status.truth, 'unknown');
  assert.doesNotMatch(text(v.blockers(s, ui)), /No blockers recorded/);
  const empty = { ...base, ledger: ledger(null), sources: [] };
  assert.equal(tile(empty, 'blockers').value, '?');
  assert.equal(tile(empty, 'goals').value, '? / ?');
});

test('audit: more goals than the server keeps make the goals tile partial, and the panel says how many', () => {
  const s = world();
  s.ledger = ledger({ goals: { items: [{ id: 'g', title: 'one', state: 'DONE_LIVE', evidence: [] }], total: 80, at, truth: 'partial' } });
  assert.equal(tile(s, 'goals').value, '1+ / 80+');
  assert.match(text(v.goals(s, ui)), /Showing 1 of 80 goals/);
});

test('audit: ledger blockers beyond the 30 the server holds are counted, not dropped', () => {
  const s = world();
  s.ledger = ledger({ status: { at, truth: 'current', counts: { blockers: 45 }, blockers: Array.from({ length: 30 }, (_, i) => ({ id: `b${i}`, note: 'x', at })) } });
  assert.equal(tile(s, 'blockers').value, '45');
  assert.match(text(v.blockers(s, ui)), /15 more ledger blockers/);
});

test('v6: every count the page states from a status list is the ledger\'s whole count, not the 30 rows held', () => {
  const s = world();
  const held = key => Array.from({ length: 30 }, (_, i) => ({ id: `${key}${i}`, note: 'x', at }));
  const lists = ['live', 'verified', 'failed', 'pending', 'decisions', 'commits', 'claimed', 'assumptions', 'blockers'];
  s.ledger = ledger({ status: { at, truth: 'current', counts: Object.fromEntries(lists.map((key, i) => [key, 40 + i])), ...Object.fromEntries(lists.map(key => [key, held(key)])) } });
  assert.equal(text([inventoryRow(s, 'Deploys and live tests')]), 'ok | 40 deploys, 41 tested, 42 failed, 43 pending');
  assert.equal(text([inventoryRow(s, 'Decisions and commits')]), 'ok | 44 decisions, 45 commits, 46 claimed, 47 assumptions');
  assert.equal(text([inventoryRow(s, 'Blockers')]), 'ok | 48 recorded in status');
  const deals = text(v.deals(s, ui));
  assert.match(deals, /46 more deploy and test records are in the ledger than Mission Control holds/);
  assert.match(deals, /Showing 8 of 166 records/);
  // only rows the server did not send: a whole list adds nothing, and the empty sentence stays when nothing is hidden
  const whole = world();
  whole.ledger = ledger({ status: { at, truth: 'current', counts: { live: 1 }, live: [{ id: 'l', note: 'x', at }] } });
  assert.doesNotMatch(text(v.deals(whole, ui)), /more deploy and test records/);
  const hiddenOnly = world();
  hiddenOnly.ledger = ledger({ status: { at, truth: 'current', counts: { verified: 3 } } });
  assert.doesNotMatch(text(v.deals(hiddenOnly, ui)), /No deploys or live tests recorded/);
});

// The modules that render these claims build no zero sentence of their own: the text comes from the helpers above.
const SRC = name => readFileSync(new URL(`../js/${name}`, import.meta.url), 'utf8');
const LITERALS = {
  'needs.js': ['Nothing needs you right now', 'nothing waiting on you'],
  'owners.js': ['Waiting for the owner list', 'No owners in this state', ".padStart(2, '0')", '${state.owners.length} owners in all', ": 'No work item yet';", 'Last work item: ${owner.last_item.note}'],
  'initiatives.js': ['Nothing open to rank', 'no progress recorded', 'no action recorded', 'No activity recorded', 'Waiting for the initiatives file', ".padStart(2, '0')", 'no live owner', "'no owner'"],
  'main.js': ['No activity recorded', 'no activity for over 30 min', 'String(state.owners.length)', 'String(state.initiatives.length)', 'no live owner', 'textContent = SCENE_TEXT['],
  'activity.js': ['Listening for signals', '`${events.length} work items'],
  'ledger-views.js': ["'No blockers recorded.')", "'Nothing is archived.')", 'status.error', 'part.error ?', 'led.status.stale'],
};
for (const [file, literals] of Object.entries(LITERALS)) {
  test(`audit: ${file} states no zero or "none" of its own (it uses the status-truth helpers)`, () => {
    const code = SRC(file);
    for (const literal of literals) assert.ok(!code.includes(literal), `${file} still contains ${literal}`);
  });
}

test('audit: at-risk gives no UNCOVERED or STALLED verdict ("no owner", "no progress") from sources that are not current', () => {
  const item = [{ id: 'i1', initiative: 'Ship', state: 'Active', ticket: 'goodqa#1' }];
  const old = Date.parse('2027-01-15T06:00:00Z');
  const working = [{ name: 'o', state: 'live', ticket: 'goodqa#1', progress: { at: new Date(old).toISOString(), event: 'commit' } }];
  const sure = { owners: 'current', progress: 'current' };
  assert.equal(atRisk(item, [], [], NOW, null, 6, sure)[0].status, 'uncovered');  // current sources: the verdict stands
  assert.equal(atRisk(item, working, [], NOW, null, 6, sure)[0].status, 'stalled');
  for (const truth of ['unknown', 'stale', 'partial']) {
    const uncovered = atRisk(item, [], [], NOW, null, 6, { owners: truth, progress: 'current' })[0];
    assert.notEqual(uncovered.status, 'uncovered', truth);
    assert.doesNotMatch(uncovered.reason, /no owner|no working owner/, truth);
    const stalled = atRisk(item, working, [], NOW, null, 6, { owners: 'current', progress: truth })[0];
    assert.notEqual(stalled.status, 'stalled', truth);
    assert.doesNotMatch(stalled.reason, /no real progress|no result, commit or deploy/, truth);
  }
});

test('audit: the Needs-you counts in the page shell start unknown ("?"), not 0, before the first read', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /id="needs-count" class="needs-count">\?</);
  assert.match(html, /id="needs-panel-count" class="count-badge">\?</);
});

test('audit: the panels whose zero claims rest on Source health repaint when a source truth changes', () => {
  const views = readFileSync(new URL('../js/views.js', import.meta.url), 'utf8');
  for (const id of ['mission-tiles', 'blockers-list', 'archive-body']) assert.match(views, new RegExp(`id: '${id}'[^\\n]*'truth'`), id);
  assert.match(readFileSync(new URL('../js/store.js', import.meta.url), 'utf8'), /update\(\{\}, 'truth'\)/);
  for (const file of ['needs.js', 'owners.js', 'initiatives.js', 'activity.js']) assert.match(SRC(file), /'truth'\]\.includes\(reason\)/, file);
});

