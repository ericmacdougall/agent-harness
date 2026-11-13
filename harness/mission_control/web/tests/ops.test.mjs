// Ops alerts and owner capacity (goodqa#15934 AC-5 to AC-7, NEG-2, NEG-6): unknown is never shown as zero, hostile text
// stays text, lists are bounded, and the page wires the two snapshots.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { created, text, walk } from './dom-shim.mjs';
import * as o from '../js/ops-views.js';

const here = new URL('..', import.meta.url).pathname;
const NOW = Date.parse('2026-11-13T12:00:00Z');
const iso = s => new Date(NOW - s * 1000).toISOString();
const row = (key, severity = 'high', extra = {}) => ({ key, cls: key.split(':')[0], severity, host: 'mac', message: `message of ${key}`, at: iso(120), seq: 1, agent: '', stop_block: false, ticket: '', ...extra });
const snap = (items, extra = {}) => ({ items, total: items.length, truncated: false, counts: { critical: 0, high: items.length, warning: 0, info: 0 }, classes: {}, stale: false, error: '', at: iso(30), watcher_at: '', watcher_late: false, ...extra });
const ui = (over = {}) => ({ alertsLimit: 8, alertSeverity: 'all', set(k, v) { this[k] = v; }, more(k) { this[k] += 8; }, ...over });
const state = (alerts, capacity = null) => ({ now: NOW, alerts: o.adaptAlerts(alerts), capacity: o.adaptCapacity(capacity) });

test('a read that never succeeded says unknown, never "no alerts"', () => {
  const never = text(o.alertsPanel(state(null), ui()));
  assert.match(never, /not been read yet/i);
  assert.doesNotMatch(never, /No active alerts/);
  const failed = text(o.alertsPanel(state(snap([], { at: '', error: 'ops-watch active exited 1' })), ui()));
  assert.match(failed, /could not be read/i);
  assert.match(failed, /exited 1/);
  assert.doesNotMatch(failed, /No active alerts/);
  assert.match(text(o.alertsPanel(state(snap([])), ui())), /No active alerts/);
});

test('a stale read keeps its rows and says so with the reason', () => {
  const out = text(o.alertsPanel(state(snap([row('mem:swap')], { stale: true, error: 'ops-watch active exited 3' })), ui()));
  assert.match(out, /last good read/i);
  assert.match(out, /exited 3/);
  assert.match(out, /mem:swap/);
});

test('each alert shows severity as text, its key, message, host, age, ticket and the stop flag', () => {
  const out = text(o.alertsPanel(state(snap([row('liveness:s/agent-a1', 'critical', { stop_block: true, ticket: 'goodqa#15585', agent: 'a1', host: 't2-dev' })],
    { counts: { critical: 1, high: 0, warning: 0, info: 0 }, classes: { liveness: 1 } })), ui()));
  for (const needle of ['critical', 'liveness:s/agent-a1', 'message of liveness:s/agent-a1', 't2-dev', '2 m ago', 'goodqa#15585', 'blocks main from stopping', '1 active', 'liveness 1']) assert.ok(out.includes(needle), needle);
});

test('the list is bounded with show more, and the severity filter narrows it', () => {
  const items = [...Array.from({ length: 20 }, (_, i) => row(`heavy:copy:${i}`, 'warning')), row('mem:jetsam', 'critical')];
  const s = state(snap(items, { total: 400, truncated: true, counts: { critical: 1, high: 0, warning: 399, info: 0 } }));
  const u = ui();
  const nodes = o.alertsPanel(s, u);
  assert.equal(walk(nodes).filter(n => n.tagName === 'LI' && n.className.includes('alert-row')).length, 8);
  const out = text(nodes);
  assert.match(out, /Show 13 more/);
  assert.match(out, /first 21 of 400/);
  walk(nodes).find(n => n.tagName === 'BUTTON' && n.textContent.startsWith('Show 13 more')).click();
  assert.equal(u.alertsLimit, 16);
  const chip = walk(nodes).find(n => n.tagName === 'BUTTON' && n.dataset.severity === 'critical');
  assert.equal(chip.attrs['aria-pressed'], 'false');
  chip.click();
  assert.equal(u.alertSeverity, 'critical');
  const narrowed = o.alertsPanel(s, u);
  assert.equal(walk(narrowed).filter(n => n.tagName === 'LI' && n.className.includes('alert-row')).length, 1);
  assert.equal(walk(narrowed).find(n => n.tagName === 'BUTTON' && n.dataset.severity === 'critical').attrs['aria-pressed'], 'true');
});

test('hostile text never becomes an element or an attribute that loads anything', () => {
  const allowed = new Set(['DIV', 'P', 'SPAN', 'UL', 'LI', 'DETAILS', 'SUMMARY', 'BUTTON', '#TEXT']);
  for (const payload of ['<img src=x onerror=alert(1)>', '</script><script>alert(2)</script>', 'javascript:alert(3)', 'A'.repeat(100000)]) {
    created.length = 0;
    const hostile = { key: payload, cls: payload, severity: payload, host: payload, message: payload, at: payload, seq: payload, agent: payload, stop_block: payload, ticket: payload };
    const s = state({ items: [hostile, null, 7, 'x'], total: payload, truncated: payload, counts: { critical: payload }, classes: { [payload]: payload }, stale: payload, error: payload, at: iso(5) },
      { known: true, cap: payload, held: payload, live: payload, silent: payload, decisions: payload, full: payload, floor: payload, stale: payload, error: payload, source: payload });
    const out = [...o.alertsPanel(s, ui()), ...o.capacityLine(s)];
    assert.ok(text(out).length > 0);
    assert.deepEqual([...new Set(created)].filter(t => !allowed.has(t)), [], payload.slice(0, 20));
    for (const node of walk(out)) for (const k of Object.keys(node.attrs)) assert.ok(!/^(href|src|srcdoc|on)/i.test(k), `attribute ${k}`);
  }
});

test('an unknown severity is shown as info, never promoted', () => {
  const a = o.adaptAlerts(snap([row('x:1', 'CRITICAL'), row('y:1', null)]));
  assert.deepEqual(a.items.map(i => i.severity), ['info', 'info']);
});

test('the capacity line shows held slots against the cap by the gate rule, and never a guess', () => {
  const line = cap => text(o.capacityLine(state(null, cap)));
  const base = { known: true, cap: 8, held: 4, live: 3, silent: 1, decisions: 2, full: false, floor: false, stale: false, error: '', source: 'ah owners' };
  const full = line(base);
  for (const needle of ['4 of 8 held', '1 silent', '2 need a decision', 'ah owners', "spawn gate's slot rule"]) assert.ok(full.includes(needle), needle);
  assert.doesNotMatch(full, /cap reached|at least|last good/);
  assert.match(line({ ...base, held: 8, full: true }), /8 of 8 held · cap reached/);
  assert.match(line({ ...base, floor: true }), /at least 4 of 8 held/);
  assert.match(line({ ...base, floor: true }), /this is a floor/);
  assert.match(line({ ...base, stale: true }), /last good count/);
  const noCap = line({ ...base, cap: null, full: true });
  assert.match(noCap, /Owner slots held: 4 · cap not known/);
  assert.doesNotMatch(noCap, /cap reached/);
  assert.match(line(null), /not been read yet/i);
  assert.match(line({ known: false, error: '' }), /not been read yet/i);
  const unknown = line({ known: false, held: 0, error: "the spawn gate's slot rule could not be loaded" });
  assert.match(unknown, /not known \(the spawn gate's slot rule could not be loaded\)/);
  assert.doesNotMatch(unknown, /\b0\b/);   // unknown is never shown as zero owners
});

test('a watcher that stopped running is said so; an unknown run time is said so', () => {
  const late = text(o.alertsPanel(state(snap([row('mem:swap')], { watcher_at: iso(7200), watcher_late: true })), ui()));
  assert.match(late, /ops-watch last ran 2 h ago\. Its alerts may be out of date/);
  const unknown = text(o.alertsPanel(state(snap([row('mem:swap')])), ui()));
  assert.match(unknown, /last ops-watch run is not known/);
  const fine = text(o.alertsPanel(state(snap([row('mem:swap')], { watcher_at: iso(60), watcher_late: false })), ui()));
  assert.doesNotMatch(fine, /ops-watch last ran|not known/);
});

test('after a repaint the focus goes back to the same chip, or to show more, or to the last row', () => {
  const chip = { dataset: { severity: 'high' }, classList: { contains: () => false } };
  assert.deepEqual(o.refocusSelectors(chip), ['[data-severity="high"]']);
  assert.deepEqual(o.refocusSelectors({ dataset: { severity: 'all' }, classList: { contains: () => false } }), ['[data-severity="all"]']);
  assert.deepEqual(o.refocusSelectors({ dataset: {}, classList: { contains: c => c === 'more-button' } }), ['.more-button', '.alert-row:last-child']);
  for (const other of [null, { dataset: { severity: '"] , body, [x="' }, classList: { contains: () => false } }, { dataset: {}, classList: { contains: () => false } }]) assert.deepEqual(o.refocusSelectors(other), []);
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  assert.ok(views.includes('o.refocusSelectors(document.activeElement)'));
  const rows = walk(o.alertsPanel(state(snap([row('a:1')], { watcher_at: iso(60) })), ui())).filter(n => n.tagName === 'LI');
  assert.equal(rows[0].attrs.tabindex, '-1');   // a row can take the focus when "show more" is gone
});

test('the page wires both snapshots: seed, SSE listeners, sections, markup and coverage', () => {
  const live = readFileSync(`${here}js/live.js`, 'utf8');
  for (const needle of ['setAlerts(state.alerts)', 'setCapacity(state.capacity)', "addEventListener('alerts', message", "addEventListener('capacity', message"]) assert.ok(live.includes(needle), needle);
  const views = readFileSync(`${here}js/views.js`, 'utf8');
  for (const needle of ["id: 'alerts-list'", "id: 'owner-cap'", "on: ['alerts']", "on: ['capacity']"]) assert.ok(views.includes(needle), needle);
  const html = readFileSync(`${here}index.html`, 'utf8');
  for (const id of ['alerts-panel', 'alerts-heading', 'alerts-list', 'owner-cap']) assert.equal(html.split(`id="${id}"`).length, 2, id);
  const map = JSON.parse(readFileSync(`${here}coverage.json`, 'utf8'));
  assert.equal(map.state.alerts, 'alerts-panel');
  assert.equal(map.state.capacity, 'owner-cap');
  assert.equal(map.sse.alerts, 'alerts-panel');
  assert.equal(map.sse.capacity, 'owner-cap');
  const src = readFileSync(`${here}js/ops-views.js`, 'utf8');
  assert.ok(!/fetch\(/.test(src), 'the alerts view calls no endpoint: it is read-only');
});
