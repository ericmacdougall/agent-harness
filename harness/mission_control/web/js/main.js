import { getState, subscribe, tick, select, setTab, setResponder, toggleFilter, toggleMotion, cycleTheme, KINDS, TABS } from './store.js';
import { el, button, progress, checklist, field, eta, age, stateClass } from './ui.js';
import { mountInitiatives } from './initiatives.js';
import { liveFields } from './adapt.js';
import { mountActivity } from './activity.js';
import { mountOwners } from './owners.js';
import { mountChat } from './chat.js';
import { mountNeeds } from './needs.js';
import { mountHealth } from './health.js';
import { mountViews } from './views.js';
import * as live from './live.js';
import { describe as describeOrg, TYPE_COLORS as ORG_TYPES } from './org.js';

mountInitiatives(); mountActivity(); mountOwners(); mountChat(); mountHealth(); mountNeeds();
const { go } = mountViews();  // the 3D topology loads only when its tab is first opened
document.getElementById('needs-button').addEventListener('click', () => go('needs-panel'));
// Wrapped navigation and zoom change the sticky header's height. Share its actual size
// with anchor offsets and the chat dock rather than assuming a fixed desktop height.
const pageHeader = document.querySelector('.page-header');
const measureHeader = () => document.documentElement.style.setProperty('--header-height', `${pageHeader.getBoundingClientRect().height}px`);
if (typeof ResizeObserver !== 'undefined') new ResizeObserver(measureHeader).observe(pageHeader);
window.addEventListener('resize', measureHeader);
measureHeader();

const filters = document.getElementById('event-filters');
const all = button('filter-chip all', 'All', () => toggleFilter('all'));
all.dataset.kind = 'all'; filters.append(all);
Object.entries(KINDS).forEach(([key, kind]) => {
  const chip = button('filter-chip', '', () => toggleFilter(key));
  chip.dataset.kind = key; chip.style.setProperty('--kind-color', kind.color);
  const icon = el('span', 'kind-icon', kind.icon); icon.setAttribute('aria-hidden', 'true');
  chip.append(icon, el('span', '', kind.label)); filters.append(chip);
});
document.getElementById('motion-toggle').addEventListener('click', toggleMotion);
document.getElementById('theme-toggle').addEventListener('click', cycleTheme);
const scheme = window.matchMedia('(prefers-color-scheme: light)');
const THEME_TEXT = { auto: 'Theme: auto', light: 'Theme: light', dark: 'Theme: dark' };
function applyTheme(state) {
  const resolved = state.theme === 'auto' ? (scheme.matches ? 'light' : 'dark') : state.theme;
  document.documentElement.dataset.theme = resolved;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', resolved === 'light' ? '#f4f5f3' : '#0e1113');
  const toggle = document.getElementById('theme-toggle');
  toggle.dataset.mode = state.theme;
  document.getElementById('theme-label').textContent = THEME_TEXT[state.theme];
  toggle.setAttribute('aria-label', `${THEME_TEXT[state.theme]}${state.theme === 'auto' ? ` (${resolved}, follows your system)` : ''}. Change theme`);
}
scheme.addEventListener('change', () => applyTheme(getState()));
applyTheme(getState());
subscribe((state, reason) => { if (reason === 'theme') applyTheme(state); });

const CONNECTION_TEXT = { live: 'Live', connecting: 'Connecting', reconnecting: 'Reconnecting', offline: 'Offline', expired: 'Signed out' };
const CONNECTION_NOTE = {
  live: 'Connected. Updates arrive as they happen.', connecting: 'Connecting to Mission Control.',
  reconnecting: 'Connection dropped. Reconnecting; the last data stays on screen.', offline: 'Offline. Showing the last data received; retrying with a growing delay.',
  expired: 'Session ended. Run `mc` in a terminal for a fresh link.',
};
const SCENE_TEXT = {
  live: 'Owners linked. Signals flowing.', connecting: 'Connecting to Mission Control…',
  reconnecting: 'Reconnecting. Last known fleet retained.', offline: 'Offline. Showing the last known fleet.',
  expired: 'Session ended. Run `server.py open` in a terminal for a fresh link.',
};
let announcedConnection = '';
function shell(state, reason) {
  const lastUpdate = document.getElementById('last-update');
  lastUpdate.textContent = state.lastData ? `Updated ${age(new Date(state.lastData).toISOString(), state.now)}` : 'waiting for data';
  lastUpdate.title = state.lastData ? `Last data from the server: ${new Date(state.lastData).toLocaleTimeString()}` : '';
  lastUpdate.classList.toggle('old', !!state.lastData && state.connection === 'live' && state.now - state.lastData > 180000);
  const chatConnection = document.getElementById('chat-connection-status');
  chatConnection.textContent = `${CONNECTION_TEXT[state.connection] || state.connection} · ${lastUpdate.textContent}`;
  chatConnection.classList.toggle('old', state.connection !== 'live' || lastUpdate.classList.contains('old'));
  if (reason === 'tick' || reason === 'highlight') return;
  const connection = document.getElementById('connection');
  connection.className = `connection ${state.connection}`;
  connection.querySelector('span').textContent = CONNECTION_TEXT[state.connection] || state.connection;
  connection.title = CONNECTION_NOTE[state.connection] || '';
  if (announcedConnection !== state.connection) {
    if (announcedConnection) document.getElementById('connection-announcer').textContent = CONNECTION_NOTE[state.connection] || state.connection;
    announcedConnection = state.connection;
  }
  filters.querySelectorAll('button').forEach(chip => chip.setAttribute('aria-pressed', String(chip.dataset.kind === 'all' ? state.filters.length === Object.keys(KINDS).length : state.filters.includes(chip.dataset.kind))));
  document.body.classList.toggle('motion-off', !state.motion);
  const motion = document.getElementById('motion-toggle');
  motion.setAttribute('aria-pressed', String(state.motion));
  motion.setAttribute('aria-label', state.reducedMotion ? 'Motion is off: system reduced motion preference' : state.motion ? 'Turn motion off' : 'Turn motion on');
  motion.disabled = state.reducedMotion;
  motion.title = state.reducedMotion ? 'Your system reduced motion setting takes precedence' : 'Toggle ambient motion';
  document.getElementById('motion-label').textContent = state.reducedMotion ? 'Reduced motion' : state.motion ? 'Motion on' : 'Motion off';
  document.getElementById('scene-status').textContent = SCENE_TEXT[state.connection] || '';
}
shell(getState(), 'initial');
subscribe(shell);

const inspector = document.getElementById('inspector'), content = document.getElementById('inspector-content');
function renderInspector(state) {
  const selection = state.selection;
  if (!selection) { if (inspector.open) inspector.close(); return; }
  const { kind, id } = selection;
  content.replaceChildren();
  document.getElementById('inspector-type').textContent = kind === 'initiative' ? 'INITIATIVE BRIEF' : `${kind.toUpperCase()} DETAIL`;
  const title = el('h2'); title.id = 'detail-title'; inspector.setAttribute('aria-labelledby', title.id);
  const fields = el('dl', 'detail-fields');
  if (kind === 'initiative') {
    const item = state.initiatives.find(entry => entry.id === id); if (!item) return select(null);
    title.textContent = item.initiative;
    content.append(title, el('span', `state-badge ${stateClass(item.state)}`, item.state));
    if (item.note) content.append(el('p', 'detail-intro', item.note));
    if (item.error) content.append(el('p', 'detail-error', `Data error: ${item.error}`));
    content.append(progress(item), checklist(item, true));
    const live = liveFields(item, state.owners, state.asks, state.events, state.now);  // same as the card (click-test a954 F2)
    fields.append(field('Ticket', item.ticket || '—'),
      field('Owner', live.owner ? `${live.owner.name} · ${live.owner.state}` : (item.owner ? `${item.owner} · no live owner` : '—')),
      field('Next step', item.next_step || '—'),
      field('Next step estimate', eta(item.next_eta, item.estimate_by, '')), field('Full completion estimate', eta(item.full_eta, item.estimate_by, '')),
      field('Updated', live.updated ? `${age(live.updated, state.now)}${live.stale ? ' · no activity for over 30 min' : ''}` : 'No activity recorded'));
    if (live.note) fields.append(field('Last note', `“${live.note.text}” · ${live.note.by} · ${age(live.note.at, state.now)}`));
    content.append(fields);
    const owner = state.owners.find(entry => entry.initiative_id === item.id);
    if (owner) content.append(button('detail-action', `Inspect owner ${owner.name} ↗`, () => select('owner', owner.agent_id)));
  } else if (kind === 'owner') {
    const owner = state.owners.find(entry => entry.agent_id === id); if (!owner) return select(null);
    title.textContent = owner.name;
    content.append(title, el('span', `state-badge ${stateClass(owner.state)}`, owner.state), el('p', 'detail-intro', owner.task));
    fields.append(field('Agent id', owner.agent_id), field('Harness', owner.harness === 'openai' ? 'OpenAI / Codex' : owner.harness === 'claude' ? 'Claude' : 'Unknown · source not verified'),
      field('Model', owner.model || 'Not recorded by the owner source'), field('Stream', owner.stream || owner.task),
      field('Source', owner.source_stale ? 'Stale · showing last known status' : 'Current snapshot'),
      field('Role', owner.type || '—'), field('Ticket', owner.ticket || '—'),
      field('Last reply', owner.last_reply || 'No reply available from the owner source'),
      field('Last work item', owner.last_item.note), field('Work item kind', owner.last_item.event || '—'),
      field('Work item written', owner.last_item.at ? `${age(owner.last_item.at, state.now)} · ${new Date(owner.last_item.at).toLocaleString()}` : '—'),
      field('Last active', owner.last_item.active ? `${age(owner.last_item.active, state.now)} · ${new Date(owner.last_item.active).toLocaleString()}` : '—'));
    if (owner.disposition) fields.append(field('Recorded disposition', [owner.disposition.kind, owner.disposition.reason || owner.disposition.ref,
      owner.disposition.until ? `until ${new Date(owner.disposition.until).toLocaleString()}` : '', owner.disposition.live ? 'in force' : 'expired'].filter(Boolean).join(' · ')));
    if (owner.waitNote) fields.append(field('Agent says', owner.waitNote));
    content.append(fields);
    if (owner.initiative_id) content.append(button('detail-action', 'Open linked initiative ↗', () => select('initiative', owner.initiative_id)));
    // Owners take direction through main: this page has no verified route to an owner, so it offers the one that
    // works (a message to main that names the owner) and no controls that cannot act.
    content.append(button('detail-action secondary', 'Message main about this owner', () => {
      select(null);
      setResponder('claude');
      setTab('chat');
      const input = document.getElementById('chat-input');
      if (!input.value.trim()) { input.value = `About owner ${owner.name} (${owner.agent_id}): `; input.dispatchEvent(new Event('input', { bubbles: true })); }
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    }));
    content.append(el('p', 'detail-note', 'Owners take direction through main. Pausing, reassigning or messaging an owner directly is done by main; ask it here.'));
  } else if (kind === 'event') {
    const event = [...state.events, ...state.feedSnapshot].find(entry => entry.id === id); if (!event) return select(null);
    title.textContent = `${KINDS[event.kind].icon} ${KINDS[event.kind].label}`;
    content.append(title, el('p', 'detail-intro', event.summary));
    fields.append(field('Time', new Date(event.ts).toLocaleString()), field('Severity', event.severity), field('Source', event.source),
      field('Actor', [event.actor.agent, event.actor.runtime].filter(Boolean).join(' · ') || '—'), field('Session', event.actor.session || '—'),
      field('Repository', event.subject.repo || '—'), field('Branch', event.subject.branch || '—'), field('Ticket', event.subject.ticket || '—'),
      field('Count', String(event.count)), field('Schema', event.schema), field('Event ID', event.id));
    content.append(fields);
    if (event.subject.initiative && state.initiatives.some(item => item.id === event.subject.initiative)) content.append(button('detail-action', 'Open linked initiative ↗', () => select('initiative', event.subject.initiative)));
  } else if (kind === 'source') {
    const source = state.sources.find(entry => entry.id === id); if (!source) return select(null);
    title.textContent = source.name;
    content.append(title, el('span', `state-badge ${source.state}`, source.state), el('p', 'detail-intro', source.note || 'No detail.'));
    fields.append(field('Last checked', `${age(source.checked, state.now)} · ${new Date(source.checked).toLocaleString()}`), field('Connection', state.connection));
    content.append(fields);
  } else if (kind === 'repo') {
    title.textContent = id;
    content.append(title, el('p', 'detail-intro', 'Recent pushes, releases and deploys for this repository.'));
    state.events.filter(event => event.subject.repo === id).slice(0, 8).forEach(event => content.append(button('lab-button', `${KINDS[event.kind].icon} ${event.summary}`, () => select('event', event.id))));
  } else if (kind === 'org') {
    // A node of the live org graph (goodqa#15950): the fields the snapshot carries, "unknown" where none exists.
    const graph = state.orggraph;
    const node = graph?.nodes.find(entry => entry.id === id); if (!node) return select(null);
    const byId = new Map(graph.nodes.map(entry => [entry.id, entry]));
    document.getElementById('inspector-type').textContent = `${(ORG_TYPES[node.kind]?.label || node.kind).toUpperCase()} DETAIL`;
    title.textContent = node.kind === 'work' ? `${node.ref} · ${node.title}` : node.kind === 'coordinator' ? 'Main coordinator' : node.kind === 'user' ? 'You' : `${node.label} · ${node.type}`;
    content.append(title);
    for (const [label, value] of describeOrg(node, byId)) fields.append(field(label, value));
    if (!['user', 'coordinator', 'work'].includes(node.kind)) fields.append(field('Agent id', node.id));
    content.append(fields);
    if (node.kind === 'work' && node.ref) content.append(el('p', 'detail-note', `GoodQA ${node.ref}`));
  } else if (kind === 'hub') {
    title.textContent = 'Main coordinator';
    content.append(title, el('p', 'detail-intro', 'Every initiative and owner reports into the coordinating session.'));
    fields.append(field('Session', state.mainSession || '—'), field('Host', state.host || '—'), field('Owners', String(state.owners.length)), field('Initiatives', String(state.initiatives.length)));
    content.append(fields);
  }
  if (!inspector.open) inspector.showModal();
  else document.getElementById('inspector-close').focus();
}
subscribe((state, reason) => { if (reason === 'selection') renderInspector(state); });
document.getElementById('inspector-close').addEventListener('click', () => select(null));
inspector.addEventListener('close', () => { if (getState().selection) select(null); });
inspector.addEventListener('click', event => {
  if (event.target !== inspector) return;
  const rect = inspector.getBoundingClientRect();
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) select(null);
});

const approval = document.getElementById('approval-dialog');
document.getElementById('approval-help').addEventListener('click', () => approval.showModal());
document.getElementById('approval-close').addEventListener('click', () => approval.close());
// Escape closes the open dialog explicitly, not only through the browser's native cancel (which assistive and
// automation tools that send synthetic keys do not trigger). Closing an already-closed dialog is a no-op.
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  const open = [...document.querySelectorAll('dialog[open]')].pop();
  if (!open) return;
  event.preventDefault();
  if (open === inspector) select(null); else open.close();
});

// iOS VisualViewport accounts for keyboard resizing and focus-driven panning.
const visual = window.visualViewport;
function viewport() {
  const height = visual?.height || window.innerHeight;
  document.documentElement.style.setProperty('--viewport-height', `${height}px`);
  document.documentElement.style.setProperty('--viewport-top', `${visual?.offsetTop || 0}px`);
  const editing = document.activeElement === document.getElementById('chat-input');
  document.body.classList.toggle('keyboard-open', window.innerWidth < 768 && editing && window.innerHeight - height > 110);
}
visual?.addEventListener('resize', viewport); visual?.addEventListener('scroll', viewport);
window.addEventListener('resize', viewport); document.addEventListener('focusin', viewport); document.addEventListener('focusout', () => setTimeout(viewport, 0)); viewport();
let timer = setInterval(() => { if (!document.hidden) tick(); }, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
window.addEventListener('pagehide', () => { clearInterval(timer); live.stop(); });
window.addEventListener('pageshow', event => { if (event.persisted) { tick(); timer = setInterval(() => { if (!document.hidden) tick(); }, 1000); live.start(); } });
// Deep links such as #tab=chat&to=codex (a phone bookmark straight to the chat) set view preferences only.
const hash = new URLSearchParams(location.hash.slice(1));
if (TABS.includes(hash.get('tab'))) setTab(hash.get('tab'));
if (['claude', 'codex'].includes(hash.get('to'))) setResponder(hash.get('to'));
live.start();
