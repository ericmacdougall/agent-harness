// All panels depend on this module only for data. Transport lives in main/mock.
export const KINDS = Object.freeze({
  wal: { label: 'Work log', icon: '≋', color: '#eaff9e' },
  push: { label: 'Push', icon: '↑', color: '#9ebfff' },
  release: { label: 'Release', icon: '✦', color: '#d4b5ff' },
  deploy: { label: 'Deploy', icon: '◎', color: '#7edbca' },
  ticket: { label: 'Ticket', icon: '▤', color: '#f1c782' },
  chat: { label: 'Chat', icon: '↗', color: '#f4b5d4' },
  owner: { label: 'Owner', icon: '◇', color: '#b5cad6' },
  system: { label: 'System', icon: '⊞', color: '#c7c9ce' },
});
const media = window.matchMedia('(prefers-reduced-motion: reduce)');
let savedMotion = true;
try { savedMotion = localStorage.getItem('mc-motion') !== 'off'; } catch { /* Storage is optional. */ }
let state = {
  initiatives: [], owners: [], events: [], messages: [], sources: [], sessions: [],
  connection: 'live', now: Date.now(), filters: Object.keys(KINDS),
  selection: null, highlight: null, tab: 'overview', responder: 'claude', session: 'main',
  motion: savedMotion && !media.matches, motionPreference: savedMotion, reducedMotion: media.matches,
  feedPaused: false, feedSnapshot: [], buffered: 0, ownerFilter: 'all', fallback: false,
};
const listeners = new Set();
const seen = new Set();
const routes = new Map();
let transport;
export const getState = () => state;
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export function update(patch, reason = 'update') {
  state = { ...state, ...patch };
  listeners.forEach(fn => fn(state, reason));
}
export function seed(data) { data.events.forEach(event => seen.add(event.id)); update(data, 'seed'); }
export function tick() { update({ now: Date.now() }, 'tick'); }
export function select(kind, id) { update({ selection: kind ? { kind, id } : null }, 'selection'); }
export function highlight(id) { if (state.highlight !== id) update({ highlight: id }, 'highlight'); }
export function setTab(tab) { update({ tab }, 'tab'); }
export function toggleFilter(kind) {
  const filters = kind === 'all' ? Object.keys(KINDS) : state.filters.includes(kind) ? state.filters.filter(k => k !== kind) : [...state.filters, kind];
  update({ filters }, 'filters');
}
export function pauseFeed() {
  update(state.feedPaused ? { feedPaused: false, feedSnapshot: [], buffered: 0 } : { feedPaused: true, feedSnapshot: [...state.events], buffered: 0 }, 'feed');
}
export function toggleMotion() {
  const preference = !state.motionPreference;
  try { localStorage.setItem('mc-motion', preference ? 'on' : 'off'); } catch { /* Optional. */ }
  update({ motionPreference: preference, motion: preference && !state.reducedMotion }, 'motion');
}
media.addEventListener('change', event => update({ reducedMotion: event.matches, motion: state.motionPreference && !event.matches }, 'motion'));
export function ingestEvent(event) {
  if (event.schema !== 'mc.event/1' || !KINDS[event.kind] || seen.has(event.id)) return;
  seen.add(event.id);
  if (seen.size > 1000) seen.delete(seen.values().next().value);
  const owners = state.owners.map(owner => owner.agent_id === event.actor.agent ? { ...owner, last_item: { at: event.ts, event: event.kind, note: event.summary } } : owner);
  update({ events: [event, ...state.events].slice(0, 100), owners, buffered: state.feedPaused ? state.buffered + 1 : 0 }, 'event');
}
export function setConnection(connection) { update({ connection }, 'connection'); }
export function setSources(sources) { update({ sources }, 'health'); }
export function patchOwner(id, patch) { update({ owners: state.owners.map(owner => owner.agent_id === id ? { ...owner, ...patch } : owner) }, 'owners'); }
export function patchInitiative(id, patch) { update({ initiatives: state.initiatives.map(item => item.id === id ? { ...item, ...patch } : item) }, 'initiatives'); }
export function appendMessage(message) { update({ messages: [...state.messages, message].slice(-60) }, 'chat'); }
export function patchMessage(id, patch) { update({ messages: state.messages.map(message => message.id === id ? { ...message, ...patch } : message) }, 'chat'); }
export function setChatTransport(send) { transport = send; }
export function setResponder(responder) { update({ responder }, 'routing'); }
export function setSession(session) { update({ session }, 'routing'); }
export function sendMessage(text) {
  const clean = text.trim();
  if (!clean || clean.length > 4000 || state.connection !== 'live' || !transport) return false;
  const message = { id: crypto.randomUUID(), from: 'user', text: clean, ts: new Date().toISOString(), status: 'sending', to: state.responder };
  routes.set(message.id, state.session);
  appendMessage(message);
  Promise.resolve().then(() => transport(message, { session: routes.get(message.id) })).catch(() => patchMessage(message.id, { status: 'failed' }));
  return true;
}
export function retryMessage(id) {
  const message = state.messages.find(item => item.id === id);
  if (!message || message.status !== 'failed' || state.connection !== 'live') return;
  patchMessage(id, { status: 'sending', ts: new Date().toISOString() });
  Promise.resolve().then(() => transport({ ...message, status: 'sending', ts: new Date().toISOString() }, { session: routes.get(id) || 'main' })).catch(() => patchMessage(id, { status: 'failed' }));
}
export const messageSession = id => routes.get(id) || 'main';
