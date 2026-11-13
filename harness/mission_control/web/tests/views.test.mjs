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
