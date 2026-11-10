// Transport to the local Mission Control server: GET /api/state, SSE /api/events, POST /api/chat.
// Same-origin only; the session cookie is HttpOnly and the CSRF token lives in memory, never in storage.
import { setInitiatives, setOwners, setSources, setHost, seedEvents, ingestEvent, setConnection, setChat, setCodex, setChatTransport, setAsks } from './store.js';

let csrf = '';
let source = null;
let resyncTimer = 0;
let failures = 0;

class SendError extends Error {
  constructor(message, retryable) { super(message); this.retryable = retryable; }
}

async function loadState() {
  const response = await fetch('/api/state', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
  if (response.status === 401 || response.status === 403) { setConnection('expired'); return false; }
  if (!response.ok) throw new Error(`state ${response.status}`);
  const state = await response.json();
  csrf = typeof state.csrf === 'string' ? state.csrf : '';
  setHost(state.host);
  setInitiatives(state.initiatives);
  setOwners(state.owners);
  setSources(state.health);
  seedEvents(state.events);
  setChat(state.chat);
  setAsks(state.asks);
  return true;
}

function parse(message) {
  try { return JSON.parse(message.data); } catch { return null; }
}

function connect() {
  source?.close();
  source = new EventSource('/api/events');
  source.addEventListener('open', () => {
    if (failures > 0) resync();
    failures = 0;
    setConnection('live');
  });
  source.addEventListener('error', () => {
    failures += 1;
    if (source.readyState === EventSource.CLOSED) {
      setConnection('offline');
      // The browser stops retrying after a refused response; check whether the session ended, then reconnect.
      clearTimeout(resyncTimer);
      resyncTimer = setTimeout(async () => {
        try { if (await loadState()) connect(); } catch { setConnection('offline'); resyncTimer = setTimeout(connect, 10000); }
      }, Math.min(30000, 2000 * failures));
    } else {
      setConnection('reconnecting');
    }
  });
  source.addEventListener('event', message => { const data = parse(message); if (data) ingestEvent(data); });
  source.addEventListener('initiatives', message => { const data = parse(message); if (data) setInitiatives(data); });
  source.addEventListener('owners', message => { const data = parse(message); if (data) setOwners(data); });
  source.addEventListener('health', message => { const data = parse(message); if (data) setSources(data); });
  source.addEventListener('chat', message => { const data = parse(message); if (data) setChat(data); });
  source.addEventListener('codex', message => { const data = parse(message); if (data) setCodex(data); });
  source.addEventListener('asks', message => { const data = parse(message); if (data) setAsks(data); });
}

function resync() {
  clearTimeout(resyncTimer);
  resyncTimer = setTimeout(() => { loadState().catch(() => {}); }, 300);
}

async function post(item) {
  const body = JSON.stringify({ to: item.to, text: item.text, client_key: item.client_key, session: item.to === 'claude' ? item.session : null, thread: item.thread || null });
  let response;
  try {
    response = await fetch('/api/chat', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-MC-CSRF': csrf }, body });
  } catch {
    throw new SendError('no response from Mission Control', true);
  }
  if (response.status === 401) { setConnection('expired'); throw new SendError('dashboard session ended', false); }
  if (response.ok) return response.json().catch(() => ({}));
  let detail = {};
  try { detail = await response.json(); } catch { /* keep the status code */ }
  const why = { 'no-target': 'no Claude main is attached to that session', unavailable: detail.message || 'Codex is unavailable',
    csrf: 'page out of date, reload', 'too-long': 'message is over 4000 characters', 'bad-text': 'message has characters that cannot be sent' }[detail.error];
  throw new SendError(why || detail.message || `refused (${response.status})`, response.status >= 500);
}

// A lost response is retried once with the same client_key; the server returns the same message, never a duplicate.
export async function sendChat(item) {
  try {
    return await post(item);
  } catch (error) {
    if (!error.retryable) throw error;
    await new Promise(resolve => setTimeout(resolve, 1500));
    return post(item);
  }
}

export async function start() {
  setChatTransport(sendChat);
  try {
    if (await loadState()) connect();
  } catch {
    setConnection('offline');
    resyncTimer = setTimeout(start, 5000);
  }
}

export function stop() { source?.close(); source = null; clearTimeout(resyncTimer); }
