// PR 243 review F2: the Topology list and the node labels must follow every org-graph update, including one that
// changes only displayed details (task, mission, ticket, work title/status, advisor model, last activity, restricted)
// and leaves the geometry signature alone. Mounts the real scene.js on a small DOM (the #gl=off static view).
import test from 'node:test';
import assert from 'node:assert/strict';

// ---- a DOM just big enough for scene.js: ids, attributes, a few selectors, focus and layout stubs
const byIdRegistry = new Map();
class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.dataset = {}; this.className = '';
    this._text = ''; this.listeners = {}; this.hidden = false; this.parentElement = null; this.tabIndex = -1; this.title = '';
    this.style = { setProperty() {} }; this.offsetWidth = 80; this.offsetHeight = 20;
  }
  set textContent(v) { this._text = String(v); this.children.forEach(c => { c.parentElement = null; }); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  append(...nodes) {
    for (const n of nodes) {
      const child = typeof n === 'string' ? Object.assign(new El('#text'), { _text: n }) : n;
      child.parentElement = this; this.children.push(child);
    }
  }
  replaceChildren(...nodes) { this.children.forEach(c => { c.parentElement = null; }); this.children = []; this.append(...nodes); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') byIdRegistry.set(String(v), this); }
  getAttribute(k) { return this.attrs[k] ?? null; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  click() { (this.listeners.click || []).forEach(f => f({ detail: 1, target: this, stopPropagation() {} })); }
  focus() { document.activeElement = this; }
  setPointerCapture() {}
  getBoundingClientRect() { return { left: 0, top: 0, width: 600, height: 420, right: 600, bottom: 420 }; }
  get classList() {
    const s = this; const list = () => s.className.split(' ').filter(Boolean);
    return { add: c => { if (!list().includes(c)) s.className = [...list(), c].join(' '); }, remove: c => { s.className = list().filter(x => x !== c).join(' '); },
      toggle: (c, on) => { const has = list().includes(c); const want = on === undefined ? !has : on; if (want && !has) s.classList.add(c); if (!want && has) s.classList.remove(c); return want; },
      contains: c => list().includes(c) };
  }
  descendants() { return this.children.flatMap(c => [c, ...c.descendants()]); }
  matchesCompound(part) {
    const tag = part.match(/^[a-z]+/i)?.[0];
    if (tag && this.tagName !== tag.toUpperCase()) return false;
    const id = part.match(/#([\w-]+)/)?.[1];
    if (id && this.attrs.id !== id && byIdRegistry.get(id) !== this) return false;
    for (const [, k, v] of part.matchAll(/\[([\w-]+)="([^"]*)"\]/g)) {
      const value = k.startsWith('data-') ? this.dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] : this.attrs[k];
      if (value !== v) return false;
    }
    return true;
  }
  matches(selector) {
    const parts = selector.trim().split(/\s+/);
    if (!this.matchesCompound(parts.at(-1))) return false;
    let node = this.parentElement;
    for (let i = parts.length - 2; i >= 0; i--) {
      while (node && !node.matchesCompound(parts[i])) node = node.parentElement;
      if (!node) return false;
      node = node.parentElement;
    }
    return true;
  }
  closest(selector) { for (let n = this; n; n = n.parentElement) if (n.tagName !== '#TEXT' && n.matches(selector)) return n; return null; }
  querySelectorAll(selector) { return this.descendants().filter(n => n.tagName !== '#TEXT' && n.matches(selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
const element = id => { if (!byIdRegistry.has(id)) { const e = new El('div'); e.setAttribute('id', id); } return byIdRegistry.get(id); };
globalThis.document = {
  createElement: tag => new El(tag), createTextNode: text => Object.assign(new El('#text'), { _text: String(text) }),
  getElementById: element, activeElement: null, hidden: false, body: new El('body'), documentElement: new El('html'),
  addEventListener() {},
};
globalThis.window = { innerWidth: 500, innerHeight: 800, addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.getComputedStyle = () => ({ getPropertyValue: () => '' });
globalThis.location = { hash: '#gl=off' };
globalThis.requestAnimationFrame = () => 0;
globalThis.cancelAnimationFrame = () => {};
globalThis.IntersectionObserver = class { observe() {} };
globalThis.ResizeObserver = class { observe() {} };
globalThis.CSS = { escape: s => String(s) };
const realInterval = globalThis.setInterval;
globalThis.setInterval = (fn, ms) => { const handle = realInterval(fn, ms); handle.unref?.(); return handle; };

const store = await import('../js/store.js');
const { mountScene } = await import('../js/scene.js');

// ---- two snapshots: the same nodes, states, models, severities and edges; only the displayed details differ
const agent = (id, kind, extra = {}) => ({ id, kind, label: id, model: 'claude-opus-5-5', effort: 'high', advisor_model: 'claude-fable-5-2',
  machine: 'host', state: 'live', severity: 'info', escalation: 0, last_activity: '2026-11-14T04:00:00Z', ...extra });
const snapshot = (seq, v) => ({
  schema: 'mc.orggraph/1', generated: '2026-11-14T04:00:00Z', seq, counts: { owner: 1, live_owners: 1 }, gaps: [], changes: [],
  nodes: [
    { id: 'user', kind: 'user', label: 'You', inbox: 1 },
    agent('coordinator', 'coordinator'),
    agent('own1', 'owner', { mission: v.mission, ticket: v.ownTicket, advisor_model: v.advisor, last_activity: v.activity }),
    agent('sub1', 'subagent', { owner: 'own1', parent: 'own1', task: v.task, ticket: 'goodqa#2' }),
    agent('sub2', 'subagent', { owner: 'own1', parent: 'own1', task: v.restricted ? 'restricted' : 'Task-Gamma visible', ticket: '', restricted: v.restricted }),
    { id: 'work:goodqa#2', kind: 'work', ref: 'goodqa#2', title: v.title, status: v.status, done: false, layer: 0, via: 'held',
      holders: ['sub1'], owner: 'own1', read: true },
  ],
  edges: [{ from: 'user', to: 'coordinator', kind: 'inbox' }, { from: 'coordinator', to: 'own1', kind: 'spawn' },
    { from: 'own1', to: 'sub1', kind: 'spawn' }, { from: 'own1', to: 'sub2', kind: 'spawn' }, { from: 'sub1', to: 'work:goodqa#2', kind: 'works_on' }],
});
const BEFORE = { mission: 'Mission-Alpha', ownTicket: 'goodqa#1', advisor: 'claude-fable-5-2', activity: '2026-11-14T04:00:00Z',
  task: 'Task-Alpha slice', restricted: false, title: 'Title-Alpha', status: 'todo' };
const AFTER = { mission: 'Mission-Beta', ownTicket: 'goodqa#9', advisor: 'claude-opus-5-5-advisor', activity: '2026-11-14T05:30:00Z',
  task: 'Task-Beta slice', restricted: true, title: 'Title-Beta', status: 'in_progress' };

const labelsBox = () => document.getElementById('scene-labels');
const label = id => labelsBox().children.find(l => l.dataset.nodeId === id);
const listText = () => document.getElementById('org-list').textContent;
const accessible = () => labelsBox().children.map(l => `${l.getAttribute('aria-label')} ${l.title} ${l.textContent}`).join('\n');

store.setOrgGraph(snapshot(1, BEFORE));
await mountScene();

test('a details-only update refreshes the labels\' visible and accessible text, keeping focus (3D/static view)', () => {
  store.setOrgGraph(snapshot(2, BEFORE));
  assert.match(label('own1').getAttribute('aria-label'), /Mission-Alpha/);   // not vacuous: the first snapshot shows
  label('own1').focus();
  store.setOrgGraph(snapshot(3, AFTER));
  const text = accessible();
  for (const fresh of ['Mission-Beta', 'goodqa#9', 'claude-opus-5-5-advisor', '2026-11-14T05:30:00Z', 'Task-Beta slice', 'Title-Beta', 'in_progress'])
    assert.ok(text.includes(fresh), `label text misses ${fresh}`);
  for (const old of ['Mission-Alpha', 'goodqa#1.', 'Task-Alpha', 'Title-Alpha', 'Task-Gamma']) assert.ok(!text.includes(old), `label text still shows ${old}`);
  assert.equal(document.activeElement?.dataset.nodeId, 'own1', 'the focused node label keeps focus');
  assert.ok(labelsBox().children.includes(document.activeElement), 'focus is on a label that is still on the page');
});

test('a details-only update refreshes the list view\'s visible text (task, mission, ticket, work title/status, advisor, activity, restricted)', () => {
  store.setOrgGraph(snapshot(4, BEFORE));
  document.getElementById('org-view-toggle').click();   // Show as list
  assert.equal(document.getElementById('org-list-wrap').hidden, false);
  assert.ok(listText().includes('Mission-Alpha') && listText().includes('Title-Alpha') && listText().includes('todo'));
  store.setOrgGraph(snapshot(5, AFTER));
  const text = listText();
  for (const fresh of ['Mission-Beta', 'goodqa#9', 'claude-opus-5-5-advisor', '2026-11-14T05:30:00Z', 'Task-Beta slice', 'Title-Beta', 'in_progress'])
    assert.ok(text.includes(fresh), `list misses ${fresh}`);
  for (const old of ['Mission-Alpha', 'Task-Alpha', 'Title-Alpha', 'Status: todo', 'Task-Gamma']) assert.ok(!text.includes(old), `list still shows ${old}`);
  const items = document.getElementById('org-list').querySelectorAll('[role="treeitem"]');
  assert.ok(items.some(i => i.dataset.nodeId === 'sub1'), 'the list is a tree of treeitems');
  document.getElementById('org-view-toggle').click();
});

test('a details-only update keeps the list\'s collapsed subtrees and focused row (no re-expand, no refocus)', () => {
  store.setOrgGraph(snapshot(6, BEFORE));
  document.getElementById('org-view-toggle').click();   // Show as list
  const tree = document.getElementById('org-list');
  const item = id => tree.querySelectorAll('[role="treeitem"]').find(i => i.dataset.nodeId === id);
  const owner = item('own1');
  assert.equal(owner.getAttribute('aria-expanded'), 'true');
  owner.setAttribute('aria-expanded', 'false');           // the reader collapsed the owner's subtree
  const focused = item('coordinator');
  focused.focus();
  let refocused = 0;
  const realFocus = El.prototype.focus;
  El.prototype.focus = function () { refocused++; realFocus.call(this); };
  try {
    store.setOrgGraph(snapshot(7, AFTER));                // a last-activity / details tick
  } finally { El.prototype.focus = realFocus; }
  assert.equal(item('own1').getAttribute('aria-expanded'), 'false', 'a collapsed subtree stays collapsed');
  assert.equal(document.activeElement, focused, 'the focused row is the same element');
  assert.equal(refocused, 0, 'no focus() call, so a screen reader does not re-announce the row');
  assert.ok(tree.textContent.includes('Mission-Beta') && tree.textContent.includes('Title-Beta'), 'the text still updates');
  assert.ok(!tree.textContent.includes('Mission-Alpha'));
  document.getElementById('org-view-toggle').click();
});
