// Views: layout order, hostile text, bounded rows, coverage, no innerHTML (goodqa#15920 AC-3, AC-4, AC-7, AC-8, AC-9).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { created, text, walk } from './dom-shim.mjs';
import { ledger } from '../js/adapt.js';
import * as v from '../js/ledger-views.js';

const here = new URL('..', import.meta.url).pathname;
const html = readFileSync(`${here}index.html`, 'utf8');
const NOW = Date.parse('2026-11-13T12:00:00Z');
const iso = s => new Date(NOW - s * 1000).toISOString();
const PAYLOADS = ['<img src=x onerror=alert(1)>', '</script><script>alert(2)</script>', 'javascript:alert(3)', '‮evil', 'A'.repeat(100000)];
const ui = { goalsLimit: 6, dealsLimit: 8, blockersLimit: 8, reqFilter: 'all', reqQuery: '', reqLimit: v.PAGE, archiveKind: 'all', archiveLimit: v.PAGE, set() {}, more() {} };

function hostile(payload) {
  const ev = { id: 'e1', kind: 'deploy', at: iso(5), verdict: 'PASS', check: payload, note: payload, by: payload };
  return {
    now: NOW, events: [{ id: 'x', kind: 'deploy', ts: iso(2), summary: payload, actor: { agent: payload }, subject: { repo: payload }, historic: false }],
    ledger: ledger({
      goals: { items: [{ id: 'g', title: payload, target: payload, state: 'LIVE_TESTED', evidence: [ev], owners: [payload], deferral: payload }] },
      requirements: { items: [{ id: 'r', text: payload, bucket: 'live', rule: 'live', reason: payload, source: payload, owner: payload, at: iso(5) }, { id: 'r2', text: payload, bucket: 'archived', rule: 'R1', reason: payload, evidence_ref: payload, at: iso(9) }] },
      status: { verified: [{ id: 'v', note: payload, check: payload, agent: payload, at: iso(5), verdict: 'PASS' }], blockers: [{ id: 'b', note: payload, agent: payload, at: iso(4) }] },
    }),
    asksArchive: [{ id: 'wa', text: payload, at: iso(7), rule: 'R1', reason: payload, owner: payload, resolution: payload, ask_reason: payload, decision: payload }],
    asksFlagged: [{ id: 'wf', text: payload, flagged: payload }], owners: [{ agent_id: 'o', name: payload, state: 'DROPPED', severe: true, task: payload, last_item: {} }], initiatives: [], asks: [], messages: [], decisions: {},
    asksStale: [], asksSweptAt: '', initiativesStale: false, initiativesError: '', sessions: [],
  };
}

test('hostile text never becomes an element: every renderer uses text only', () => {
  const allowed = new Set(['DIV', 'P', 'SPAN', 'UL', 'LI', 'ARTICLE', 'H3', 'DETAILS', 'SUMMARY', 'BUTTON', 'TIME', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', '#TEXT']);
  for (const payload of PAYLOADS) {
    created.length = 0;
    const s = hostile(payload);
    const out = [v.tiles(s, () => {}), ...v.goals(s, ui), ...v.deals(s, ui), ...v.blockers(s, ui), ...v.requirements(s, ui), ...v.archive(s, ui), ...v.inventory(s, () => {})];
    assert.ok(text(out).length > 0);
    assert.deepEqual([...new Set(created)].filter(t => !allowed.has(t)), [], payload.slice(0, 20));
    for (const node of walk(out)) for (const k of Object.keys(node.attrs)) assert.ok(!/^(href|src|srcdoc|on)/i.test(k), `attribute ${k}`);
  }
});

test('long text is clamped with a disclosure, never silently cut', () => {
  const node = v.longText('B'.repeat(5000), 'x', 240);
  const t = text(node);
  assert.ok(node.all().some(n => n.tagName === 'DETAILS'));
  assert.ok(t.includes('Show all 5000 characters'));
  assert.ok(t.includes('B'.repeat(5000)));
});

test('5000 requirements render at most one page, with a count of the rest', () => {
  const items = Array.from({ length: 5000 }, (_, i) => ({ id: `w${i}`, text: `req ${i}`, at: iso(i), bucket: i % 2 ? 'live' : 'archived', rule: i % 2 ? 'live' : 'R4', reason: 'x' }));
  const s = { now: NOW, ledger: ledger({ requirements: { items, total: 5000 } }), asksArchive: [] };
  const start = performance.now();
  const out = v.requirements(s, { ...ui, reqFilter: 'live' });
  const rows = walk(out).filter(n => n.tagName === 'LI' && n.className.includes('req '));
  assert.equal(rows.length, v.PAGE);
  assert.match(text(out), /Show \d+ more of \d+/);
  const arch = v.archive(s, ui);
  assert.equal(walk(arch).filter(n => n.tagName === 'LI' && n.className.includes('req ')).length, v.PAGE);
  assert.ok(performance.now() - start < 1000);
});

test('archive and requirement rows say why they are where they are', () => {
  const s = hostile('plain');
  const t = text([...v.requirements(s, ui), ...v.archive(s, ui)]);
  assert.match(t, /Archived because: plain/);
  assert.match(t, /Live because: plain/);
  assert.match(t, /Archived · R1/);
});

test('the page orders its sections: mission, owners, needs you, deploys, blockers', () => {
  const at = id => html.indexOf(`id="${id}"`);
  const order = ['mission-panel', 'owners-panel', 'needs-panel', 'deploys-panel', 'blockers-panel'].map(at);
  assert.ok(order.every(i => i > 0), String(order));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  for (const id of ['view-requirements', 'view-archive', 'view-activity', 'view-topology', 'view-sources']) assert.ok(at(id) > at('blockers-panel'), id);
  assert.ok(!html.includes('<dialog id="needs-dialog"'), 'Needs you is part of the page, not a dialog');
});

test('tabs, panels and landmarks are labelled', () => {
  assert.match(html, /role="tablist" aria-label="Views"/);
  const tabs = [...html.matchAll(/<button id="tab-([a-z]+)" [^>]*role="tab"[^>]*aria-controls="([^"]+)"/g)];
  assert.ok(tabs.length >= 6);
  for (const [, name, controls] of tabs) assert.ok(html.includes(`id="${controls}"`), `${name} controls ${controls}`);
  for (const m of html.matchAll(/<section id="view-[a-z]+"[^>]*>/g)) assert.match(m[0], /role="tabpanel"[^>]*aria-labelledby="tab-/);
  assert.match(html, /class="skip-link"/);
  assert.match(html, /<html lang="en">/);
  for (const m of html.matchAll(/<(input|select|textarea)\b[^>]*>/g)) {
    const id = /id="([^"]+)"/.exec(m[0])?.[1];
    assert.ok(/aria-label=/.test(m[0]) || (id && new RegExp(`for="${id}"`).test(html)) || /<label[^>]*>[^<]*<span[^>]*>[^<]*<\/span><input/.test(html), `unlabelled control ${m[0].slice(0, 60)}`);
  }
  assert.match(html, /id="connection" class="connection connecting" role="status"/);
});

test('every element id the scripts look up exists in the page', () => {
  const dir = `${here}js/`;
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
  const missing = [];
  for (const f of readdirSync(dir)) for (const m of readFileSync(dir + f, 'utf8').matchAll(/getElementById\('([^']+)'\)/g)) if (!ids.has(m[1]) && !/^(needs-text|needs-input)/.test(m[1])) missing.push(`${f}:${m[1]}`);
  assert.deepEqual(missing, []);
});

test('no script builds markup from strings', () => {
  for (const f of readdirSync(`${here}js`)) {
    const src = readFileSync(`${here}js/${f}`, 'utf8');
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function']) assert.ok(!src.includes(sink), `${f} uses ${sink}`);
  }
});

test('coverage map names a UI section for every state key, SSE event and ledger field', () => {
  const map = JSON.parse(readFileSync(`${here}coverage.json`, 'utf8'));
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
  for (const group of Object.values(map)) for (const [key, where] of Object.entries(group)) assert.ok(where === 'internal' || ids.has(where), `${key} -> ${where}`);
  const live = readFileSync(`${here}js/live.js`, 'utf8');
  const sse = [...live.matchAll(/addEventListener\('([a-z]+)', message/g)].map(m => m[1]);
  assert.deepEqual(sse.sort(), Object.keys(map.sse).sort());
});

// ---- spec v2 additions
const SENT = n => `SENTINEL_${n}`;
test('every ledger field the server sends is rendered: a unique sentinel per field is found in its section', () => {
  const ev = { id: SENT('evid'), kind: 'live_test', verdict: 'PASS', at: iso(60), check: SENT('evcheck'), note: SENT('evnote'), by: SENT('evby') };
  const s = {
    now: NOW, events: [], asks: [], messages: [], decisions: {}, initiatives: [], owners: [], asksFlagged: [], asksArchive: [], asksArchiveTotal: 0, asksStale: [], sessions: [],
    ledger: ledger({
      goals: { items: [{ id: 'g', title: SENT('gtitle'), target: SENT('gtarget'), ticket: 'goodqa#1', state: 'IN_PROGRESS', priority: 2, owners: [SENT('gowner')], deferral: SENT('gdefer'), evidence: [ev], problems: { missing: 2 } }] },
      requirements: { items: [{ id: 'r', text: SENT('rtext'), source: SENT('rsource'), owner: SENT('rowner'), ticket: 'goodqa#2', at: iso(5), bucket: 'archived', rule: 'R1', reason: SENT('rreason'), evidence_ref: SENT('rref') }] },
      status: { verified: [{ id: 'v', note: SENT('vnote'), check: SENT('vcheck'), agent: SENT('vagent'), at: iso(5), verdict: 'PASS' }], live: [{ id: 'l', note: SENT('lnote'), at: iso(6) }],
        failed: [{ id: 'f', note: SENT('fnote'), at: iso(7), verdict: 'FAIL' }], pending: [{ id: 'p', note: SENT('pnote'), at: iso(8) }], blockers: [{ id: 'b', note: SENT('bnote'), agent: SENT('bagent'), at: iso(4) }] },
    }),
  };
  const sections = { goals: v.goals(s, ui), deals: v.deals(s, { ...ui, dealsLimit: 50 }), blockers: v.blockers(s, ui), requirements: v.requirements(s, ui), archive: v.archive(s, ui) };
  const want = {
    goals: ['gtitle', 'gtarget', 'gowner', 'gdefer', 'evcheck', 'evnote'], deals: ['vnote', 'vcheck', 'lnote', 'fnote', 'pnote'], blockers: ['bnote', 'bagent'],
    requirements: ['rtext', 'rsource', 'rowner', 'rreason', 'rref'], archive: ['rtext', 'rsource', 'rreason', 'rref'],
  };
  for (const [name, keys] of Object.entries(want)) for (const k of keys) assert.ok(text(sections[name]).includes(SENT(k)), `${name} lacks ${k}`);
  assert.match(text(sections.goals), /Ledger problems: 2 missing/);
});

test('missing who, when or source shows "unknown", never a blank', () => {
  const s = { now: NOW, ledger: ledger({ requirements: { items: [{ id: 'r', text: 'x', bucket: 'live', reason: 'open' }, { id: 'r2', text: 'y', bucket: 'archived', rule: 'R1', reason: 'done' }] } }), asksArchive: [{ id: 'wa', text: 'z', rule: 'R1', reason: 'done' }], asksArchiveTotal: 1 };
  const t = text([...v.requirements(s, { ...ui, reqFilter: 'all' }), ...v.archive(s, ui)]);
  assert.match(t, /Source: unknown/);
  assert.match(t, /time unknown/);
  assert.match(t, /no owner recorded/);
  assert.match(t, /registered by unknown/);
});

test('calm defaults: five goals, five deploys, five blockers and one page of requirements, with the rest behind a button', () => {
  const many = n => Array.from({ length: n }, (_, i) => ({ id: `i${i}`, note: `n${i}`, at: iso(i), verdict: 'PASS', check: `c${i}` }));
  const s = { now: NOW, events: [], owners: [], initiatives: [], asksFlagged: [], asksArchive: [], asksArchiveTotal: 0,
    ledger: ledger({ goals: { items: many(40).map(r => ({ id: r.id, title: r.note, state: 'UNKNOWN', evidence: [] })) },
      requirements: { items: many(200).map(r => ({ id: r.id, text: r.note, at: r.at, bucket: 'live', reason: 'x' })) }, status: { verified: many(40), blockers: many(40) } }) };
  const count = (nodes, cls) => walk(nodes).filter(n => n.className.split(' ').includes(cls)).length;
  assert.equal(count(v.goals(s, { ...ui, goalsLimit: 5 }), 'goal'), 5);
  assert.equal(count(v.deals(s, { ...ui, dealsLimit: 5 }), 'deal'), 5);
  assert.equal(count(v.blockers(s, { ...ui, blockersLimit: 5 }), 'blocker'), 5);
  assert.equal(count(v.requirements(s, { ...ui, reqFilter: 'live' }), 'req'), 25);
  assert.match(text(v.goals(s, { ...ui, goalsLimit: 5 })), /Show 35 more goals/);
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  assert.match(views, /goalsLimit: 5, dealsLimit: 5, blockersLimit: 5/);
  assert.equal(v.PAGE, 25);
  assert.match(readFileSync(`${here}js/owners.js`, 'utf8'), /OWNERS_SHOWN = 8/);
  assert.match(readFileSync(`${here}js/needs.js`, 'utf8'), /ASKS_SHOWN = 5/);
});

test('details are collapsed by default and nothing is open on first render', () => {
  const s = hostile('plain');
  const nodes = [...v.goals(s, ui), ...v.requirements(s, ui), ...v.archive(s, ui)];
  const open = walk(nodes).filter(n => n.tagName === 'DETAILS' && n.open === true);
  assert.equal(open.length, 0);
  assert.ok(!/<details[^>]* open/.test(html.replace(/<details id="needs-[a-z]+"[^>]*hidden>/g, '')), 'no details starts open in the page');
});

test('Archive and Restore are explicit: a button, then a reason, then a confirm that stays disabled until there is a reason', () => {
  const calls = [];
  const row = ledger({ requirements: { items: [{ id: 'r1', text: 'x', bucket: 'live', reason: 'open', digest: 'abc' }] } }).requirements.items[0];
  const idle = v.requirementItem(row, NOW, { arm: (r, a) => calls.push(['arm', r.id, a]) });
  const open = walk(idle).find(n => n.tagName === 'BUTTON' && n.attrs['aria-label'] === 'Archive requirement r1');
  assert.ok(open && !walk(idle).some(n => n.tagName === 'TEXTAREA'));
  open.click();
  assert.deepEqual(calls, [['arm', 'r1', 'archive']]);
  const armed = v.requirementItem(row, NOW, { armed: { id: 'r1', action: 'archive' }, draft: '', submit: r => calls.push(['submit', r.id]) });
  const confirm = walk(armed).find(n => n.tagName === 'BUTTON' && /^Confirm archive/.test(n.attrs['aria-label']));
  assert.equal(confirm.disabled, true);
  assert.ok(walk(armed).some(n => n.tagName === 'TEXTAREA' && n.maxLength === 300));
  const withReason = v.requirementItem(row, NOW, { armed: { id: 'r1', action: 'archive' }, draft: 'because' });
  assert.equal(walk(withReason).find(n => /^Confirm archive/.test(n.attrs['aria-label'] || '')).disabled, false);
  const archived = ledger({ requirements: { items: [{ id: 'r2', text: 'x', bucket: 'archived', rule: 'M', reason: 'by you', digest: 'abc' }] } }).requirements.items[0];
  assert.ok(walk(v.requirementItem(archived, NOW, {})).some(n => n.attrs['aria-label'] === 'Restore requirement r2'));
});

test('every sink that could turn data into markup, script or a link is absent from the scripts', () => {
  const sinks = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'DOMParser', 'srcdoc', 'cssText', 'window.open', 'location.href', 'location.assign', 'createContextualFragment'];
  for (const f of readdirSync(`${here}js`)) {
    const src = readFileSync(`${here}js/${f}`, 'utf8');
    for (const sink of sinks) assert.ok(!src.includes(sink), `${f} uses ${sink}`);
    assert.ok(!/setAttribute\(\s*['"`](on[a-z]+|href|src|srcdoc|style)['"`]/i.test(src), `${f} sets a dangerous attribute`);
  }
});

test('requirement text is isolated for bidirectional scripts (dir=auto)', () => {
  const node = v.longText('‮evil', 'x', 240);
  assert.ok(walk(node).some(n => n.attrs.dir === 'auto'));
});

test('live regions: activity is announced only as a batch every 4.5 s, and only the named regions exist', () => {
  const regions = [...html.matchAll(/id="([a-z-]+)"[^>]*aria-live="polite"/g)].map(m => m[1]).sort();
  assert.deepEqual(regions, ['activity-announcer', 'chat-announcer', 'connection-announcer', 'needs-announcer', 'requirement-announcer']);
  assert.match(readFileSync(`${here}js/activity.js`, 'utf8'), /\}, 4500\)/);
  for (const f of ['ledger-views.js', 'adapt.js']) assert.ok(!/announcer/.test(readFileSync(`${here}js/${f}`, 'utf8')), `${f} must not announce`);
  assert.match(readFileSync(`${here}js/views.js`, 'utf8'), /requirement-announcer/);
});

test('the scene loads only through a guarded dynamic import, so a missing WebGL or bundle cannot blank the page', () => {
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  const main = readFileSync(`${here}js/main.js`, 'utf8');
  assert.ok(!/from '\.\/scene\.js'/.test(main) && !/from '\.\/scene\.js'/.test(views));
  assert.match(views, /import\('\.\/scene\.js'\)[\s\S]*\.catch\(/);
  assert.match(html, /id="scene-load-note"/);
});

test('a repaint never pulls a focused control away or loses an open details element', () => {
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  assert.match(views, /box\.contains\(document\.activeElement\)[^\n]*return/);
  assert.match(views, /details\[open\]/);
});

test('the scripts POST only to the three known write routes', () => {
  const routes = new Set();
  for (const f of readdirSync(`${here}js`)) for (const m of readFileSync(`${here}js/${f}`, 'utf8').matchAll(/fetch\('([^']+)',\s*\{\s*method: 'POST'/g)) routes.add(m[1]);
  assert.deepEqual([...routes].sort(), ['/api/approve', '/api/chat', '/api/requirements/archive']);
  const map = JSON.parse(readFileSync(`${here}coverage.json`, 'utf8'));
  assert.ok(map.routes['POST /api/requirements/archive'] && map.routes['POST /api/chat'] && map.routes['POST /api/approve']);
  assert.ok(!/fetch\(/.test(readFileSync(`${here}js/ledger-views.js`, 'utf8')), 'the archive view calls no endpoint');
});

test('coverage names a control for every route and control the page has', () => {
  const map = JSON.parse(readFileSync(`${here}coverage.json`, 'utf8'));
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
  for (const [name, where] of [...Object.entries(map.routes), ...Object.entries(map.controls)]) assert.ok(ids.has(where), `${name} -> ${where}`);
  for (const control of ['session pick', 'Claude or Codex switch', 'owner filter', 'event filters', 'pause feed', 'tool activity', 'theme', 'motion', 'requirement search', 'show more owners', 'show more asks']) assert.ok(map.controls[control], control);
});

test('the summary tiles show the live owner count and the dashboard-archived count when there is one', () => {
  const s = { now: NOW, owners: [{ state: 'live', severe: false }, { state: 'live', severe: false }, { state: 'done', severe: false }], asks: [], messages: [], decisions: {}, initiatives: [],
    ledger: ledger({ requirements: { items: [{ id: 'r', text: 'mine', bucket: 'archived', rule: 'M', user_sourced: true, reason: 'x', at: iso(5) }] } }) };
  const t = text(v.tiles(s, () => {}));
  assert.match(t, /Owners live[\s\S]*|2[\s\S]*Owners live/);
  const owners = walk(v.tiles(s, () => {})).find(n => n.attrs['aria-label']?.startsWith('Owners live: 2'));
  assert.ok(owners, 'the owners tile says 2');
  assert.ok(walk(v.tiles(s, () => {})).some(n => /Your requirements archived from the dashboard: 1/.test(n.attrs['aria-label'] || '')));
});

test('a user-sourced requirement archived from the dashboard keeps a distinct badge and says whose click it was', () => {
  const row = ledger({ requirements: { items: [{ id: 'r', text: 'mine', bucket: 'archived', rule: 'M', user_sourced: true, reason: 'archived from dashboard session abcdef12 at t: x', at: iso(5),
    manual: { action: 'archive', by: 'dashboard session abcdef12', at: iso(4) } }] } }).requirements.items[0];
  const nodes = [v.requirementItem(row, NOW, {}), v.archiveItem(row, NOW, {})];
  const t = text(nodes);
  assert.match(t, /Archived from the dashboard · your own words/);
  assert.match(t, /Click recorded from dashboard session abcdef12/);
  assert.match(t, /not proof that you made it/);
  assert.ok(walk(nodes).some(n => n.className.includes('manual-user')));
  const s = { now: NOW, asksArchive: [], asksArchiveTotal: 0, ledger: ledger({ requirements: { items: [{ id: 'r', text: 'mine', bucket: 'archived', rule: 'M', user_sourced: true, reason: 'x', at: iso(5) }, { id: 'q', text: 'other', bucket: 'archived', rule: 'R1', reason: 'x', at: iso(6) }] } }) };
  const only = v.archive(s, { ...ui, archiveKind: 'manual-user' });
  assert.equal(walk(only).filter(n => n.tagName === 'LI' && n.className.includes('req ')).length, 1);
  assert.match(text(v.archive(s, ui)), /Dashboard-archived, your words 1/);
});

test('textual evidence from the producer is shown on the requirement row', () => {
  const row = ledger({ requirements: { items: [{ id: 'r', text: 'x', bucket: 'live', reason: 'open', evidence_text: 'REALLY_TESTED a: PASS on the live host', has_evidence: true }] } }).requirements.items[0];
  assert.match(text(v.requirementItem(row, NOW, {})), /Evidence recorded: REALLY_TESTED a: PASS on the live host/);
});
