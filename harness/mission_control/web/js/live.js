// Transport to the local Mission Control server: GET /api/state, SSE /api/events, POST /api/chat, POST /api/approve.
// Same-origin only; the session cookie is HttpOnly and the CSRF token lives in memory, never in storage.
import { setInitiatives, setOwners, setSources, setHost, seedEvents, ingestEvent, setConnection, setChat, setCodex, setChatTransport, setApproveTransport, setAsks, setLedger, setRequirementTransport, setOrgGraph } from './store.js';

let shownSession = null;

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
  setLedger(state.ledger);
  setOrgGraph(state.orggraph);
  // goodqa#15961: the session this page shows; every session-scoped write names it, and the server refuses a
  // write when the pin has moved since (409 session_changed) instead of recording it against another session.
  shownSession = typeof state.pin?.display === 'string' ? state.pin.display : null;
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
  source.addEventListener('ledger', message => {
    const data = parse(message);
    if (!data) return;
    setLedger(data);
    // goodqa#15961 review A-7: the ledger was read for another session than the one this page shows (the pin
    // moved). Reload the whole state once, so the header, the lists and the session every write names agree.
    if (shownSession && typeof data.session === 'string' && data.session && data.session !== shownSession) {
      shownSession = null;   // writes are refused (409) until the reload names the new session
      loadState().catch(() => setConnection('offline'));
    }
  });
  source.addEventListener('orggraph', message => { const data = parse(message); if (data) setOrgGraph(data); });
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

// POST /api/approve. Every refusal is turned into words the card can show; nothing is assumed sent.
const APPROVE_WHY = {
  'no-target': 'main is not attached, so it could not be delivered', 'no-main': 'Mission Control does not know main yet',
  'not-open': 'this ask is no longer open', 'stale-digest': 'the ask changed since you read it; read it again and decide',
  'key-conflict': 'this page reused a request id; decide again', 'asks-unavailable': 'the asks ledger could not be read',
  csrf: 'this page is out of date; reload it', 'bad-note': 'the note has characters that cannot be sent or is too long',
  session_changed: 'Mission Control now follows another session; the page is reloading, try again', unpinned: 'Mission Control is not pinned to a main session yet',
  pin_mismatch: 'the configured session differs from the mission ledger; writes are off until they agree',
};
async function postApproval(item) {
  const body = JSON.stringify({ ask_id: item.ask_id, digest: item.digest, decision: item.decision, client_key: item.client_key, note: item.note || null, session: shownSession });
  let response;
  try {
    response = await fetch('/api/approve', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-MC-CSRF': csrf }, body });
  } catch {
    throw new SendError('no answer from Mission Control; it may or may not have been recorded. Choosing the same decision again is safe', true);
  }
  if (response.status === 401) { setConnection('expired'); throw new SendError('this dashboard session ended', false); }
  if (response.ok) return response.json().catch(() => ({}));
  let detail = {};
  try { detail = await response.json(); } catch { /* keep the status code */ }
  if (detail.error === 'already-decided') {
    const made = detail.decision === 'approve' ? 'approved' : detail.decision === 'deny' ? 'denied' : 'decided';
    throw new SendError(`this ask was already ${made}, here or in another tab. A sent decision cannot be changed from this page; tell main in a reply`, false);
  }
  throw new SendError(APPROVE_WHY[detail.error] || detail.message || `refused (${response.status})`, response.status >= 500);
}
export async function sendApproval(item) {
  try {
    return await postApproval(item);
  } catch (error) {
    if (!error.retryable) throw error;
    await new Promise(resolve => setTimeout(resolve, 1500));
    return postApproval(item);  // same client_key: the server returns the same record, never a second decision
  }
}

const REQ_WHY = {
  'unknown-requirement': 'this requirement is no longer in the ledger read', 'stale-digest': 'the requirement changed since you read it; read it again',
  'already-archived': 'it is already archived', 'not-archived': 'it is not archived', 'bad-reason': 'a reason of 1 to 300 characters is required',
  'no-main': 'Mission Control does not know main yet', csrf: 'this page is out of date; reload it', 'key-conflict': 'this page reused a request id; try again',
  session_changed: 'Mission Control now follows another session; the page is reloading, try again', unpinned: 'Mission Control is not pinned to a main session yet',
  pin_mismatch: 'the configured session differs from the mission ledger; writes are off until they agree',
};
export async function sendRequirement(item) {
  const body = JSON.stringify({ req_id: item.req_id, action: item.action, reason: item.reason, digest: item.digest, client_key: item.client_key, session: shownSession });
  let response;
  try {
    response = await fetch('/api/requirements/archive', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-MC-CSRF': csrf }, body });
  } catch {
    throw new SendError('no answer from Mission Control; it may or may not have been recorded. Sending it again is safe', true);
  }
  if (response.status === 401) { setConnection('expired'); throw new SendError('this dashboard session ended', false); }
  if (response.ok) return response.json().catch(() => ({}));
  let detail = {};
  try { detail = await response.json(); } catch { /* keep the status code */ }
  throw new SendError(REQ_WHY[detail.error] || detail.message || `refused (${response.status})`, response.status >= 500);
}

export async function start() {
  setChatTransport(sendChat);
  setRequirementTransport(sendRequirement);
  setApproveTransport(sendApproval);
  try {
    if (await loadState()) connect();
  } catch {
    setConnection('offline');
    resyncTimer = setTimeout(start, 5000);
  }
}

export function stop() { source?.close(); source = null; clearTimeout(resyncTimer); }
