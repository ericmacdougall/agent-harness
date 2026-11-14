// The page's single state store. Panels read state and subscribe; transport (live.js) writes through these setters.
import * as adapt from './adapt.js';

export const KINDS = Object.freeze({
  wal: { label: 'Work log', icon: '≋', color: '#eaff9e' },
  push: { label: 'Push', icon: '↑', color: '#9ebfff' },
  release: { label: 'Release', icon: '✦', color: '#d4b5ff' },
  deploy: { label: 'Deploy', icon: '◎', color: '#7edbca' },
  ticket: { label: 'Ticket', icon: '▤', color: '#f1c782' },
  chat: { label: 'Chat', icon: '↗', color: '#f4b5d4' },
  owner: { label: 'Owner', icon: '◇', color: '#b5cad6' },
  initiative: { label: 'Initiative', icon: '◈', color: '#eaff9e' },
  system: { label: 'System', icon: '⊞', color: '#c7c9ce' },
});
const media = window.matchMedia('(prefers-reduced-motion: reduce)');
let savedMotion = true, savedTheme = 'auto';
try { savedMotion = localStorage.getItem('mc-motion') !== 'off'; } catch { /* storage is optional */ }
try { const theme = localStorage.getItem('mc-theme'); if (['light', 'dark'].includes(theme)) savedTheme = theme; } catch { /* optional */ }
let state = {
  initiatives: [], initiativesStale: false, initiativesError: '', owners: [], ownerRows: [], events: [], messages: [], sources: [],
  host: '', chat: null, pending: [], sessions: [], mainSession: '', asks: [], asksResolved: [], asksSession: '',
  asksStale: [], asksFlagged: [], asksCleared: [], asksSweptAt: '', asksArchive: [], asksArchiveTotal: 0,
  ledger: adapt.ledger(null), lastData: 0,
  decisions: {},  // ask id -> this page's own Approve/Deny click while it is in flight or after it was refused
  connection: 'connecting', now: Date.now(), filters: Object.keys(KINDS),
  selection: null, highlight: null, tab: 'overview', responder: 'claude', session: '',
  motion: savedMotion && !media.matches, motionPreference: savedMotion, reducedMotion: media.matches,
  feedPaused: false, feedSnapshot: [], buffered: 0, ownerFilter: 'active', ownerFolds: {}, fallback: false, showQuiet: false,
  theme: savedTheme,
  chatAvailability: { claude: {}, codex: { state: 'unavailable', blockedUntil: null, reason: 'Checking Codex…' } },
};
const listeners = new Set();
const seen = new Set();
let transport;
export const getState = () => state;
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
// A server message (a snapshot or an event) is what "last update" counts; ticks and local clicks are not.
const DATA_REASONS = new Set(['initiatives', 'owners', 'health', 'seed', 'event', 'chat', 'asks', 'ledger', 'availability']);
export function update(patch, reason = 'update') {
  state = DATA_REASONS.has(reason) ? { ...state, ...patch, lastData: Date.now() } : { ...state, ...patch };
  listeners.forEach(fn => { try { fn(state, reason); } catch (error) { reportError(error, reason); } });
}
// A broken panel must not hide silently: show a short notice and keep the rest of the page running.
export function reportError(error, where = '') {
  console.error(error);
  const box = document.getElementById('page-error');
  if (!box) return;
  box.hidden = false;
  box.textContent = `Display error${where ? ` (${where})` : ''}: ${String(error?.message || error).slice(0, 160)} at ${String(error?.stack || '').split('\n')[1]?.trim().slice(0, 120) || ''}`;
}
window.addEventListener('error', event => reportError(event.error || event.message, 'page'));
window.addEventListener('unhandledrejection', event => reportError(event.reason, 'async'));
export function tick() { update({ now: Date.now() }, 'tick'); }
export function select(kind, id) { update({ selection: kind ? { kind, id } : null }, 'selection'); }
export function highlight(id) { if (state.highlight !== id) update({ highlight: id }, 'highlight'); }
export const TABS = Object.freeze(['overview', 'requirements', 'archive', 'activity', 'topology', 'sources', 'chat']);
export function setTab(tab) { if (TABS.includes(tab) && tab !== state.tab) update({ tab }, 'tab'); }
export function toggleFilter(kind) {
  const all = Object.keys(KINDS);
  const filters = kind === 'all' ? all : state.filters.length === all.length ? [kind] : state.filters.includes(kind) ? state.filters.filter(k => k !== kind) : [...state.filters, kind];
  update({ filters: filters.length ? filters : all }, 'filters');
}
export function pauseFeed() {
  update(state.feedPaused ? { feedPaused: false, feedSnapshot: [], buffered: 0 } : { feedPaused: true, feedSnapshot: [...state.events], buffered: 0 }, 'feed');
}
export function toggleQuiet() { update({ showQuiet: !state.showQuiet }, 'filters'); }
export function toggleMotion() {
  const preference = !state.motionPreference;
  try { localStorage.setItem('mc-motion', preference ? 'on' : 'off'); } catch { /* optional */ }
  update({ motionPreference: preference, motion: preference && !state.reducedMotion }, 'motion');
}
// Theme: auto follows the system; light and dark are the user's own choice and are remembered on this device.
export function cycleTheme() {
  const theme = { auto: 'light', light: 'dark', dark: 'auto' }[state.theme] || 'auto';
  try { if (theme === 'auto') localStorage.removeItem('mc-theme'); else localStorage.setItem('mc-theme', theme); } catch { /* optional */ }
  update({ theme }, 'theme');
}
media.addEventListener('change', event => update({ reducedMotion: event.matches, motion: state.motionPreference && !event.matches }, 'motion'));

// ---- server snapshots
export function setInitiatives(snapshot) {
  const { items, stale, error } = adapt.initiatives(snapshot);
  update({ initiatives: items, initiativesStale: stale, initiativesError: error, owners: adapt.owners(state.ownerRows, items) }, 'initiatives');
  update({}, 'owners');
}
export function setOwners(rows) { update({ ownerRows: Array.isArray(rows) ? rows : [], owners: adapt.owners(rows, state.initiatives) }, 'owners'); }
export function setSources(rows) { update({ sources: adapt.sources(rows) }, 'health'); }
export function setHost(host) { update({ host: String(host || '') }, 'host'); }
export function seedEvents(list) {
  const events = (Array.isArray(list) ? list : []).map(adapt.event).filter(e => e && KINDS[e.kind]);
  events.forEach(e => seen.add(e.id));
  events.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  update({ events: events.slice(0, 150) }, 'seed');
}
export function ingestEvent(raw) {
  const event = adapt.event(raw);
  if (!event || !KINDS[event.kind] || seen.has(event.id)) return;
  seen.add(event.id);
  if (seen.size > 2000) seen.delete(seen.values().next().value);
  const events = [event, ...state.events].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 150);
  let owners = state.owners;
  // A quiet event (tool call, prompt, subagent start/stop) refreshes the owner's activity age, never its work item.
  if (!event.historic && event.actor.agent) owners = owners.map(o => o.agent_id !== event.actor.agent ? o : event.quiet
    ? { ...o, last_item: { ...o.last_item, active: event.ts } }
    : { ...o, last_item: { at: event.ts, active: event.ts, event: event.kind, note: event.summary } });
  const counted = state.feedPaused && !event.historic && (!event.quiet || state.showQuiet);
  update({ events, owners, lastEvent: event, buffered: counted ? state.buffered + 1 : state.buffered }, 'event');
}
export function setLedger(snapshot) { update({ ledger: adapt.ledger(snapshot) }, 'ledger'); }
export function setConnection(connection) { if (state.connection !== connection) update({ connection }, 'connection'); }
export function setChat(chat) {
  if (!chat || typeof chat !== 'object') return;
  const sessions = adapt.sessions(chat.targets, chat.main_session);
  const claude = Object.fromEntries(sessions.map(s => [s.id, { attached: true, waiting: s.waiting }]));
  const codex = chat.codex ? adapt.codex(chat.codex) : state.chatAvailability.codex;
  const known = new Set((chat.messages || []).map(m => m.client_key).filter(Boolean));
  const pending = state.pending.filter(p => !known.has(p.client_key));
  // a click the server has recorded is shown from the server's record from here on
  const decisions = Object.fromEntries(Object.entries(state.decisions).filter(([, d]) => !known.has(d.client_key)));
  const session = sessions.some(s => s.id === state.session) ? state.session : sessions[0]?.id || state.session || '';
  update({ chat, pending, decisions, sessions, mainSession: String(chat.main_session || ''), session, chatAvailability: { claude, codex },
    messages: adapt.messages(chat, pending) }, 'chat');
  update({}, 'availability');
}
export function setCodex(raw) {
  update({ chatAvailability: { ...state.chatAvailability, codex: adapt.codex(raw) } }, 'availability');
  update({}, 'chat');
}

// ---- chat
export function setChatTransport(send) { transport = send; }
export function setResponder(responder) { update({ responder }, 'routing'); update({}, 'chat'); }
export function setSession(session) { update({ session }, 'routing'); update({}, 'chat'); }
export function chatAccess(current = state, responder = current.responder, session = current.session) {
  if (current.connection === 'expired') return { disabled: true, presence: 'SIGNED OUT', notice: 'This dashboard session ended. Run `mc` in a terminal (or `python3 ~/.agent-harness/mission-control/app/server.py open`) for a fresh link.' };
  if (current.connection !== 'live') return { disabled: true, presence: current.connection.toUpperCase(), notice: current.connection === 'offline' ? 'Mission Control is offline. Your draft stays here; sending resumes when it is back.' : 'Reconnecting to the stream. Sending is paused; your draft is kept.' };
  if (responder === 'claude') {
    const main = current.chatAvailability.claude[session];
    if (!main?.attached) return { disabled: true, presence: 'NO MAIN', notice: 'No Claude main is attached. In main, run `python3 ~/.claude/hooks/mc_inbox.py wait --session <id>` in the background.' };
    if (!main.waiting) return { disabled: false, presence: 'BUSY', notice: 'Main is busy. It will see your message at its next stop.' };
  } else {
    const codex = current.chatAvailability.codex;
    if (codex.state === 'blocked') {
      const time = codex.blockedUntil && new Date(codex.blockedUntil);
      const until = time && Number.isFinite(time.getTime()) ? time.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }) : 'the subscription resets';
      return { disabled: true, presence: 'UNAVAILABLE', notice: `Codex subscription is blocked until ${until}. There is no API-key fallback; choose Claude or wait.` };
    }
    if (codex.state === 'unavailable') return { disabled: true, presence: 'UNAVAILABLE', notice: `Codex unavailable: ${codex.reason || 'not signed in with ChatGPT'}.` };
    if (codex.state === 'busy') return { disabled: false, presence: 'BUSY', notice: 'Codex is answering another message; yours will queue.' };
  }
  return { disabled: false, presence: 'READY', notice: '' };
}
function patchPending(key, patch) {
  const pending = state.pending.map(p => p.client_key === key ? { ...p, ...patch } : p);
  update({ pending, messages: adapt.messages(state.chat, pending) }, 'chat');
}
async function deliver(item) {
  try {
    await transport(item);
    patchPending(item.client_key, { status: item.to === 'claude' ? 'queued' : 'delivered', reason: '' });
  } catch (error) {
    patchPending(item.client_key, { status: 'failed', reason: String(error?.message || 'not delivered').slice(0, 200) });
  }
}
export function sendMessage(text, { thread = null } = {}) {
  const clean = String(text).trim();
  if (!clean || clean.length > 4000 || chatAccess().disabled || !transport) return false;
  const key = adapt.newClientKey();
  const item = { id: `local-${key}`, client_key: key, from: 'user', to: state.responder, session: state.responder === 'claude' ? state.session : '',
    thread, text: clean, ts: new Date().toISOString(), status: 'sending', reason: '' };
  const pending = [...state.pending, item].slice(-20);
  update({ pending, messages: adapt.messages(state.chat, pending) }, 'chat');
  deliver(item);
  return true;
}
// A local message the server never confirmed keeps its key (idempotent); a server-side failure is a new send.
export function retryMessage(id) {
  const message = state.messages.find(m => m.id === id);
  if (!message || message.from !== 'user' || message.status !== 'failed' || message.approval || !transport) return;  // a decision is never resent as chat text
  if (chatAccess(state, message.to, message.session || state.session).disabled) return;
  const local = state.pending.find(p => p.id === id);
  if (local) { patchPending(local.client_key, { status: 'sending', reason: '' }); deliver({ ...local }); return; }
  const key = adapt.newClientKey();
  const item = { id: `local-${key}`, client_key: key, from: 'user', to: message.to, session: message.session || state.session, thread: null,
    text: message.text, ts: new Date().toISOString(), status: 'sending', reason: '' };
  const pending = [...state.pending, item].slice(-20);
  update({ pending, messages: adapt.messages(state.chat, pending) }, 'chat');
  deliver(item);
}
// ---- needs you: open asks from main's session. A reply is an ordinary chat message to main, tagged with the ask id,
// so it carries no authority beyond the chat channel's own; main resolves the ask from it.
export function setAsks(snapshot) {
  const items = Array.isArray(snapshot?.items) ? snapshot.items.filter(a => a && /^[A-Za-z0-9_-]{1,40}$/.test(String(a.id))) : [];
  const resolved = Array.isArray(snapshot?.resolved) ? snapshot.resolved.filter(a => a && /^[A-Za-z0-9_-]{1,40}$/.test(String(a.id))) : [];
  const list = key => (Array.isArray(snapshot?.[key]) ? snapshot[key].filter(a => a && /^[A-Za-z0-9_-]{1,40}$/.test(String(a.id))) : []);
  // the sweeper's sections: stale asks are still open and answerable; flagged ones are not valid asks; cleared rows
  // are settled asks it hid, each with its reason
  // an expired ask is archived by the archive rule, so it leaves the stale section: it is shown once, with its reason
  const archive = adapt.archiveRows(Array.isArray(snapshot?.archive) ? snapshot.archive.filter(a => a && /^[A-Za-z0-9_-]{1,40}$/.test(String(a.id))) : [], []);
  const archived = new Set(archive.map(a => a.id));
  update({ asks: items, asksResolved: resolved, asksStale: list('stale').filter(a => !archived.has(a.id)), asksFlagged: list('flagged'), asksCleared: list('cleared'), asksArchive: archive, asksArchiveTotal: Number.isInteger(snapshot?.archive_total) ? snapshot.archive_total : archive.length,
    asksSweptAt: typeof snapshot?.swept_at === 'string' ? snapshot.swept_at : '', asksSession: String(snapshot?.session || '') }, 'asks');
}
export function askReplyAccess(ask, current = state) { return chatAccess(current, 'claude', ask?.session || current.asksSession); }
export function sendAskReply(ask, text) {
  const clean = String(text).trim();
  const session = ask?.session || state.asksSession;
  const body = `[ask:${ask?.id}] ${clean}`;
  if (!clean || !ask?.id || body.length > 4000 || askReplyAccess(ask).disabled || !transport) return false;
  const key = adapt.newClientKey();
  const item = { id: `local-${key}`, client_key: key, from: 'user', to: 'claude', session, thread: null,
    text: body, ts: new Date().toISOString(), status: 'sending', reason: '' };
  const pending = [...state.pending, item].slice(-20);
  update({ pending, messages: adapt.messages(state.chat, pending) }, 'chat');
  deliver(item);
  return key;
}
// ---- decisions: Approve or Deny on an open ask. The request carries only the ask id, the digest of the text this
// page showed and the decision; the server re-reads the ask and signs the record. Nothing here is optimistic: the
// card says "sending" until the server has stored the record, then follows the record's own state.
let approveTransport;
export const DECISION_NOTE_MAX = 500;
export function setApproveTransport(send) { approveTransport = send; }
export function decisionAccess(ask, current = state) {
  if (!ask?.approvable) return { disabled: true, notice: ask?.blocked || 'This ask cannot be decided here. Answer with a reply.' };
  const access = askReplyAccess(ask, current);
  if (access.disabled) return { disabled: true, notice: access.presence === 'NO MAIN' ? 'Main is not attached, so a decision cannot be delivered. In main, run `python3 ~/.claude/hooks/mc_inbox.py wait --session <id>` in the background.' : access.notice };
  return { disabled: false, notice: '' };
}
function setDecision(askId, value) {
  const decisions = { ...state.decisions };
  if (value) decisions[askId] = value; else delete decisions[askId];
  update({ decisions }, 'chat');
}
export function decideAsk(ask, decision, note = '') {
  const clean = String(note || '').trim();
  if (!ask?.id || !['approve', 'deny'].includes(decision) || clean.length > DECISION_NOTE_MAX || !approveTransport) return false;
  if (decisionAccess(ask).disabled || state.decisions[ask.id]?.status === 'sending') return false;
  // a retry after "no response" reuses the key, so the server returns the same record and never a second one
  const previous = state.decisions[ask.id];
  const client_key = previous?.retryable && previous.decision === decision && previous.note === clean ? previous.client_key : adapt.newClientKey();
  const item = { ask_id: ask.id, digest: ask.digest, decision, note: clean, client_key, ts: new Date().toISOString(), status: 'sending', reason: '' };
  setDecision(ask.id, item);
  approveTransport(item).then(
    () => { if (state.decisions[ask.id]?.client_key === client_key) setDecision(ask.id, { ...item, status: 'sent' }); },
    error => { if (state.decisions[ask.id]?.client_key === client_key) setDecision(ask.id, { ...item, status: 'failed', retryable: !!error?.retryable, reason: String(error?.message || 'no answer from Mission Control').slice(0, 200) }); });
  return true;
}
// ---- requirements: Archive and Restore are the only writes the cleanup has. One click, one explicit confirm, one
// reason; the same exact request reuses its client key, so a lost response and a retry record once.
let requirementTransport;
export function setRequirementTransport(send) { requirementTransport = send; }
const requirementKeys = new Map();
export async function requirementAction(row, action, reason) {
  const clean = String(reason || '').trim();
  if (!row?.id || !row.digest || !['archive', 'restore'].includes(action) || !clean || clean.length > 300 || !requirementTransport) return { ok: false, message: 'a reason of 1 to 300 characters is required' };
  const sig = `${row.id}|${action}|${clean}|${row.digest}`;  // the digest is part of the request: a changed requirement is a new request
  if (!requirementKeys.has(sig)) requirementKeys.set(sig, adapt.newClientKey());
  try {
    await requirementTransport({ req_id: row.id, action, reason: clean, digest: row.digest, client_key: requirementKeys.get(sig) });
    requirementKeys.delete(sig);
    return { ok: true };
  } catch (error) {
    return { ok: false, retryable: !!error?.retryable, message: String(error?.message || 'not recorded').slice(0, 200) };
  }
}
export const messageSession = id => state.messages.find(m => m.id === id)?.session || state.session;
