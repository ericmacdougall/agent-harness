// Transport to the local Mission Control server: GET /api/state, SSE /api/events, POST /api/chat, POST /api/approve.
// Same-origin only; the session cookie is HttpOnly and the CSRF token lives in memory, never in storage.
import { setInitiatives, setOwners, setSources, setHost, seedEvents, ingestEvent, setConnection, setChat, setCodex, setChatTransport, setApproveTransport, setAsks, setLedger, setRequirementTransport, setReads } from './store.js';

let csrf = '';
let source = null;
let resyncTimer = 0;
let failures = 0;
// goodqa#16117 F2: a state response is a snapshot taken when the server answered, and stream messages can be newer
// than it. While a load is in flight, stream updates are held in `held` and applied after the response is installed,
// so a slow response never overwrites newer stream data. Each load has a generation; a response from a load that a
// later one superseded is dropped (it neither installs nor marks the page live).
let loadGen = 0;
let held = null;
// goodqa#16117, PR 257 review v1 F1: what a load held is replayed only when it is newer than the snapshot just installed.
// The server stamps /api/state with `stream: {generation, revision}` taken before it reads anything, and every stream
// message with `id: <generation>.<revision>` from the same counter. A held message is replayed when it has the
// snapshot's generation and a higher revision; one from another server process, at or below the snapshot, or with no
// readable stamp is dropped. A new load starts with an empty buffer: anything an earlier load held arrived before this
// request was sent, so this snapshot already supersedes it.
let installed = null;   // the stamp of the installed snapshot
let otherProcess = false;  // a re-read is pending because a live message came from another server process
// A load that never answers would hold the stream for ever: it is aborted, which replays what it held, and the
// caller's retry and backoff take over. Tests shorten it.
let stateTimeoutMs = 15000;
export function setStateTimeout(ms) { stateTimeoutMs = ms; }

class SendError extends Error {
  constructor(message, retryable) { super(message); this.retryable = retryable; }
}

const STAMP = /^([0-9a-f]{1,64})\.([0-9]{1,15})$/;
function messageStamp(message) {
  const found = STAMP.exec(typeof message?.lastEventId === 'string' ? message.lastEventId : '');
  return found ? { generation: found[1], revision: Number(found[2]) } : null;
}
function snapshotStamp(stream) {
  const generation = stream?.generation, revision = stream?.revision;
  return typeof generation === 'string' && generation && Number.isSafeInteger(revision) && revision >= 0 ? { generation, revision } : null;
}
// Newer than the installed snapshot: same server process, later revision. Without both stamps nothing is newer.
function supersedes(stamp, snapshot) {
  return !!stamp && !!snapshot && stamp.generation === snapshot.generation && stamp.revision > snapshot.revision;
}

// `snapshot` is the stamp of the snapshot just installed: only what supersedes it replays. Without one (the load
// failed, timed out or was refused, so nothing was installed) everything held is still the newest data and replays.
function replayHeld(gen, snapshot) {
  if (gen !== loadGen) return;  // a newer load holds the stream now; it replays what it holds
  const queue = held || [];
  held = null;
  for (const [apply, data, stamp] of queue) {
    if (snapshot === undefined || supersedes(stamp, snapshot)) apply(data);
  }
}

async function loadState() {
  const gen = ++loadGen;
  held = [];  // a superseded load's buffer is dropped: this snapshot is taken after all of it arrived
  let state;
  const abort = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = setTimeout(() => {
    abort?.abort();
    if (gen === loadGen) replayHeld(gen);  // even when the fetch ignores the abort, the stream is released
  }, stateTimeoutMs);
  try {
    const response = await fetch('/api/state', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }, signal: abort?.signal });
    if (gen !== loadGen) return false;  // superseded while in flight
    if (response.status === 401 || response.status === 403) { replayHeld(gen); setConnection('expired'); return false; }
    if (!response.ok) throw new Error(`state ${response.status}`);
    state = await response.json();
    if (gen !== loadGen) return false;
    if (!held) throw new Error('state load timed out');  // released by the timeout: this answer is older than what was shown
    installState(state);
  } catch (error) {
    replayHeld(gen);  // the held stream updates are still the newest data; the stream is never left held
    throw error;
  } finally {
    clearTimeout(timer);
  }
  replayHeld(gen, installed);  // then what the stream sent after the snapshot was taken, in order
  return true;
}

function installState(state) {
  installed = snapshotStamp(state.stream);  // null (unstamped) replays nothing held
  otherProcess = false;
  csrf = typeof state.csrf === 'string' ? state.csrf : '';
  setHost(state.host);
  setReads(state.reads);  // first: the rows below are never shown ahead of the server's read of them
  setInitiatives(state.initiatives);
  setOwners(state.owners);
  setSources(state.health);
  seedEvents(state.events);
  setChat(state.chat);
  setAsks(state.asks);
  setLedger(state.ledger);
}

// A stream message: applied now, or held while a state load is in flight (see `held`).
function deliver(apply) {
  return message => {
    const data = parse(message);
    if (!data) return;
    const stamp = messageStamp(message);
    if (held) { held.push([apply, data, stamp]); return; }
    apply(data);
    // The server restarted between the state read and this stream (or the stream reopened on a new process without a
    // drop the page saw): the rest of the page is the old process's. Not live until this process's state is read.
    if (stamp && installed && stamp.generation !== installed.generation && !otherProcess) {
      otherProcess = true;
      setConnection('reconnecting');
      resync();
    }
  };
}

function parse(message) {
  try { return JSON.parse(message.data); } catch { return null; }
}

function connect() {
  source?.close();
  source = new EventSource('/api/events');
  source.addEventListener('open', () => {
    // review PR 234 v6: after a drop the server may be a new process, and what the page holds came from the old one.
    // The page is live again only once it holds this server's state, never on the stream opening alone.
    const reopened = failures > 0;
    failures = 0;
    if (reopened) resync();
    else setConnection('live');
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
  source.addEventListener('event', deliver(ingestEvent));
  source.addEventListener('initiatives', deliver(setInitiatives));
  source.addEventListener('owners', deliver(setOwners));
  source.addEventListener('health', deliver(setSources));
  source.addEventListener('chat', deliver(setChat));
  source.addEventListener('codex', deliver(setCodex));
  source.addEventListener('asks', deliver(setAsks));
  source.addEventListener('ledger', deliver(setLedger));
  source.addEventListener('reads', deliver(setReads));
}

// Re-read the state after a reopened stream, then show live, unless the stream dropped again meanwhile. A failed
// read leaves the page not live (every claim at best stale) and tries again, backing off, while the stream stays open.
function resync(delay = 300) {
  clearTimeout(resyncTimer);
  // A load begun before this (re)open may be answered by a process that has since stopped. It is superseded now, not
  // when the next load starts: its answer installs nothing and never marks the page live. What it held stays held
  // until the next load starts, whose snapshot is taken after all of it arrived (goodqa#16117 sweep).
  loadGen += 1;
  resyncTimer = setTimeout(async () => {
    try {
      if (await loadState() && failures === 0) setConnection('live');
    } catch {
      if (failures === 0 && source) resync(Math.min(30000, delay * 4));
    }
  }, delay);
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
};
async function postApproval(item) {
  const body = JSON.stringify({ ask_id: item.ask_id, digest: item.digest, decision: item.decision, client_key: item.client_key, note: item.note || null });
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
  'session_changed': 'main moved to another session and its list has not loaded yet; nothing was recorded. Try again in a minute',
  'no-main': 'Mission Control does not know main yet', csrf: 'this page is out of date; reload it', 'key-conflict': 'this page reused a request id; try again',
};
export async function sendRequirement(item) {
  const body = JSON.stringify({ req_id: item.req_id, action: item.action, reason: item.reason, digest: item.digest, client_key: item.client_key });
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

export function stop() { source?.close(); source = null; clearTimeout(resyncTimer); loadGen += 1; held = null; installed = null; otherProcess = false; }
