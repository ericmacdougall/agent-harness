// View tabs, section routing and the ledger-backed panels' mounting (goodqa#15920). One live page, no polling: every
// repaint is driven by the store (an SSE snapshot or event) and coalesced into one animation frame.
import { getState, subscribe, setTab, TABS } from './store.js';
import * as v from './ledger-views.js';

const SECTIONS = [
  // id, builder, store reasons that repaint it, view that must be showing (null: always)
  { id: 'mission-tiles', build: (s, ui, go) => [v.tiles(s, go)], on: ['ledger', 'owners', 'asks', 'chat', 'initiatives', 'decisions'], view: 'overview' },
  { id: 'goals-list', build: (s, ui) => v.goals(s, ui), on: ['ledger'], view: 'overview', slow: true },
  { id: 'deploys-list', build: (s, ui) => v.deals(s, ui), on: ['ledger', 'event'], view: 'overview', slow: true },
  { id: 'blockers-list', build: (s, ui) => v.blockers(s, ui), on: ['ledger', 'asks', 'owners', 'initiatives'], view: 'overview' },
  { id: 'requirements-body', build: (s, ui) => v.requirements(s, ui), on: ['ledger'], view: 'requirements', slow: true },
  { id: 'archive-body', build: (s, ui) => v.archive(s, ui), on: ['ledger', 'asks'], view: 'archive', slow: true },
  { id: 'inventory-body', build: (s, ui, go) => v.inventory(s, go), on: ['ledger', 'asks', 'owners', 'initiatives', 'chat', 'health', 'seed'], view: 'sources', slow: true },
];

export function mountViews() {
  const tablist = document.getElementById('tabs');
  const tabs = [...tablist.querySelectorAll('[role="tab"]')];
  const views = Object.fromEntries([...document.querySelectorAll('[data-view]')].map(node => [node.dataset.view, node]));
  const dirty = new Set();
  let frame = 0;
  let ticks = 0;

  const ui = {
    goalsLimit: 6, dealsLimit: 8, blockersLimit: 8, reqFilter: 'live', reqQuery: '', reqLimit: v.PAGE, archiveKind: 'all', archiveLimit: v.PAGE,
    set(key, value) {
      this[key] = value;
      if (key === 'reqFilter' || key === 'reqQuery') this.reqLimit = v.PAGE;
      if (key === 'archiveKind') this.archiveLimit = v.PAGE;
      repaint(['requirements-body', 'archive-body'], true);
    },
    more(key) {
      this[key] += key === 'goalsLimit' ? 6 : v.PAGE;
      repaint(['goals-list', 'deploys-list', 'blockers-list', 'requirements-body', 'archive-body'], true);
    },
  };

  function go(target) {
    if (TABS.includes(target)) { setTab(target); document.getElementById(`tab-${target}`)?.focus(); return; }
    setTab('overview');
    const node = document.getElementById(target);
    if (!node) return;
    node.scrollIntoView({ block: 'start' });
    if (!node.hasAttribute('tabindex')) node.setAttribute('tabindex', '-1');
    node.focus({ preventScroll: true });
  }
  window.mcGo = go;

  // A repaint keeps what the reader opened: details elements and the scroll position of the section survive it.
  function paint(section, state, force) {
    const box = document.getElementById(section.id);
    if (!box) return;
    if (!force && box.contains(document.activeElement) && document.activeElement !== document.body) return;  // never pull a focused control away
    const open = new Set([...box.querySelectorAll('details[open]')].map(d => `${d.closest('[data-id]')?.dataset.id || ''}:${d.className}`));
    const nodes = section.build(state, ui, go);
    box.replaceChildren(...nodes);
    box.querySelectorAll('details').forEach(d => { if (open.has(`${d.closest('[data-id]')?.dataset.id || ''}:${d.className}`)) d.open = true; });
  }
  const forced = new Set();
  function flush() {
    frame = 0;
    const state = getState();
    for (const id of dirty) {
      const section = SECTIONS.find(s => s.id === id);
      if (section && (section.view === 'overview' || section.view === state.tab)) paint(section, state, forced.has(id));
    }
    dirty.clear();
    forced.clear();
  }
  function repaint(ids, force = false) {
    ids.forEach(id => { dirty.add(id); if (force) forced.add(id); });
    if (!frame) frame = requestAnimationFrame(flush);
  }

  function select(name, focus) {
    for (const tab of tabs) {
      const on = tab.dataset.tab === name;
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    }
    for (const [key, node] of Object.entries(views)) node.hidden = !(key === name || (name === 'chat' && innerWidth >= 1100 && key === 'overview'));
    document.body.dataset.tab = name;
  }
  tablist.addEventListener('click', event => {
    const tab = event.target.closest('[role="tab"]');
    if (tab) setTab(tab.dataset.tab);
  });
  tablist.addEventListener('keydown', event => {
    const visible = tabs.filter(tab => tab.offsetParent !== null);
    const at = visible.indexOf(document.activeElement);
    if (at < 0) return;
    const next = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: visible.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    const target = visible[(next + visible.length) % visible.length];
    setTab(target.dataset.tab);
    target.focus();
  });
  document.getElementById('req-search')?.addEventListener('input', event => ui.set('reqQuery', event.target.value));

  let sceneState = 'idle';
  function ensureScene() {
    if (sceneState !== 'idle') return;
    sceneState = 'loading';
    const note = document.getElementById('scene-load-note');
    import('./scene.js').then(m => { m.mountScene(); sceneState = 'ready'; if (note) note.hidden = true; })
      .catch(error => { sceneState = 'failed'; if (note) { note.hidden = false; note.textContent = `The topology view could not load (${String(error?.message || error).slice(0, 120)}). The rest of the page is unaffected.`; } });
  }

  subscribe((state, reason) => {
    if (reason === 'tab') {
      select(state.tab, false);
      repaint(SECTIONS.filter(s => s.view === state.tab).map(s => s.id), true);
      if (state.tab === 'topology') ensureScene();  // scene.js shows its own static view for #gl=off or no WebGL
      if (innerWidth < 1100) window.scrollTo({ top: 0, behavior: 'instant' });
      return;
    }
    if (reason === 'tick') {
      ticks += 1;
      if (ticks % 30 === 0) repaint(SECTIONS.filter(s => s.slow).map(s => s.id));  // relative ages only; nothing is fetched
      return;
    }
    const hit = SECTIONS.filter(s => s.on.includes(reason) && (reason !== 'event' || ['deploy', 'release'].includes(state.lastEvent?.kind)));
    if (hit.length) repaint(hit.map(s => s.id));
  });
  select(getState().tab, false);
  repaint(SECTIONS.map(s => s.id), true);
  return { go, ui };
}
