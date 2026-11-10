// Pure mapping from the Mission Control server's JSON (GoodQA #15585) to the view model the panels render.
// No DOM, no network: tested with `node --test harness/mission_control/web/tests/`.
// Every string stays a string; panels render with textContent only.

const str = (value, max = 4000) => (typeof value === 'string' ? value : value == null ? '' : String(value)).slice(0, max);
const isoFromEpoch = seconds => (typeof seconds === 'number' && Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString() : null);
const validIso = value => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null);

export const SEVERE = state => /^(DROPPED|SILENT)/.test(str(state));
export const shortId = id => str(id).slice(0, 8);

export function initiative(row) {
  const item = {
    id: str(row.id, 64) || 'row', initiative: str(row.initiative, 200) || 'Untitled', state: str(row.state, 60) || 'Unknown',
    milestones_done: Number.isFinite(row.milestones_done) ? row.milestones_done : null,
    milestones_total: Number.isFinite(row.milestones_total) ? row.milestones_total : null,
    pct: Number.isFinite(row.pct) ? Math.max(0, Math.min(100, row.pct)) : null,
    owner: str(row.owner, 80), ticket: str(row.ticket, 60), milestones: str(row.milestones, 4000),
    milestone_items: Array.isArray(row.milestone_items) ? row.milestone_items.map(m => ({ done: !!m.done, text: str(m.text, 200).replace(/^(Done:|Not yet:)\s*/i, '') })) : [],
    next_step: str(row.next_step, 600), next_eta: str(row.next_eta, 80) || null, full_eta: str(row.full_eta, 80) || null,
    estimate_by: str(row.estimate_by, 80) || 'main', note: str(row.note, 600), updated: str(row.updated, 60), error: str(row.error, 300),
  };
  if (item.pct === null) item.milestones_done = item.milestones_total = null;
  return item;
}

export function initiatives(snapshot) {
  const items = Array.isArray(snapshot?.items) ? snapshot.items.filter(x => x && typeof x === 'object').map(initiative) : [];
  return { items, stale: !!snapshot?.stale, error: str(snapshot?.error, 300) };
}

// An initiative's free-text owner ("a095f32d (waiting)", "none live", "main") links to an owner row by id prefix.
export function ownerKey(text) {
  const match = /^([0-9a-f]{7,17})\b/i.exec(str(text).trim());
  return match ? match[1].toLowerCase() : null;
}

const DISPOSITION_KINDS = ['waiting', 'resumed', 'reassigned', 'closed', 'legacy', 'superseded', 'wontdo'];
const WAIT_NOTE = /\b(?:waiting (?:on|for)|monitor wait|own background (?:work|job|task|run)s?|background (?:job|task|run|work) (?:running|in flight|pending))\b/i;
// ah owners decides the state; the page never rewrites it. A DROPPED/SILENT owner with a recorded disposition that is still
// in force, or whose own last note says it is waiting, is shown as held: the label stays, the red alarm does not.
export function ownerHold(r, last) {
  const d = r && r.disposition && typeof r.disposition === 'object' && DISPOSITION_KINDS.includes(r.disposition.kind) ? r.disposition : null;
  const disposition = d ? { kind: d.kind, ref: str(d.ref, 60), reason: str(d.reason, 200), until: validIso(d.until) || null, live: d.live === true } : null;
  const note = str(last?.note, 200);
  const waitNote = SEVERE(r?.state) && WAIT_NOTE.test(note) ? note : '';
  const held = SEVERE(r?.state) && (Boolean(disposition?.live) || Boolean(waitNote));
  return { severe: SEVERE(r?.state) && !held, held, disposition, waitNote };
}

export function owners(rows, items = []) {
  if (!Array.isArray(rows)) return [];
  return rows.filter(r => r && typeof r === 'object' && r.agent_id).map(r => {
    const id = str(r.agent_id, 40);
    const linked = items.find(i => (ownerKey(i.owner) && id.toLowerCase().startsWith(ownerKey(i.owner))) || (r.ticket && i.ticket === r.ticket));
    const last = r.last_item && typeof r.last_item === 'object' ? r.last_item : null;
    const at = validIso(last?.at) || null;
    const active = [validIso(last?.active_at), at, validIso(r.last_activity)].filter(Boolean).sort().pop() || null;
    return {
      agent_id: id, name: r.runtime === 'codex' ? `codex ${shortId(id)}` : shortId(id), runtime: r.runtime === 'codex' ? 'codex' : 'claude',
      type: str(r.type, 40), task: str(r.task, 200) || (r.runtime === 'codex' ? 'Codex session' : 'Owner'), ticket: str(r.ticket, 60),
      state: str(r.state, 24) || 'unknown', ...ownerHold(r, last),
      last_item: { at, active, event: str(last?.event, 40), note: str(last?.note, 200) || 'No work item recorded yet' },
      initiative_id: linked ? linked.id : null,
    };
  });
}

const SOURCE_NAMES = { wals: 'Claude + Codex WALs', initiatives: 'Initiatives file', owners: 'Owners', github: 'GitHub', goodqa: 'GoodQA tickets',
  't2-dev': 't2-dev', 'file-drop': 'Event drops', codex: 'Codex chat', chat: 'Chat store' };
export function sources(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.filter(r => r && r.name).map(r => ({
    id: str(r.name, 40), name: SOURCE_NAMES[r.name] || str(r.name, 40), state: ['ok', 'error', 'off', 'stale'].includes(r.status) ? r.status : 'error',
    checked: isoFromEpoch(r.checked) || new Date(0).toISOString(), note: str(r.detail, 200) || (r.status === 'ok' ? 'Reading normally.' : ''),
  }));
}

export function event(raw) {
  if (!raw || raw.schema !== 'mc.event/1' || typeof raw.id !== 'string') return null;
  const actor = raw.actor && typeof raw.actor === 'object' ? raw.actor : {};
  const subject = raw.subject && typeof raw.subject === 'object' ? raw.subject : {};
  return {
    schema: 'mc.event/1', id: str(raw.id, 200), ts: validIso(raw.ts) || new Date().toISOString(), kind: str(raw.kind, 20),
    source: str(raw.source, 40), severity: ['info', 'warn', 'high'].includes(raw.severity) ? raw.severity : 'info',
    summary: str(raw.summary, 280), count: Number.isInteger(raw.count) && raw.count > 0 ? raw.count : 1, historic: raw.historic === true, quiet: raw.quiet === true,
    actor: { runtime: str(actor.runtime, 40), session: str(actor.session, 160), agent: str(actor.agent, 160) },
    subject: { repo: str(subject.repo, 160), branch: str(subject.branch, 160), ticket: str(subject.ticket, 160), initiative: str(subject.initiative, 160) },
  };
}

// Codex availability reasons come from the server: "subscription BLOCKED until 2026-11-10T02:37:00Z", "not logged in with ChatGPT".
export function codex(raw) {
  const reason = str(raw?.reason, 300);
  if (raw?.available) return { state: raw.busy ? 'busy' : 'ready', blockedUntil: null, reason };
  const until = /until (\d{4}-\d\d-\d\dT[\d:.]+Z)/.exec(reason);
  if (/blocked/i.test(reason)) return { state: 'blocked', blockedUntil: until ? until[1] : null, reason };
  return { state: 'unavailable', blockedUntil: null, reason: reason || 'Codex is not available' };
}

export function sessions(targets, mainSession) {
  const list = Array.isArray(targets) ? targets.filter(t => t && typeof t.session === 'string') : [];
  return list.map(t => ({ id: t.session, label: `${t.session === mainSession ? 'main' : 'session'} · ${shortId(t.session)}`, waiting: !!t.waiting }))
    .sort((a, b) => Number(b.id === mainSession) - Number(a.id === mainSession));
}

const USER_STATUS = { queued: 'queued', delivered: 'delivered', answered: 'answered', failed: 'failed', forged: 'forged', unavailable: 'failed', answering: 'answering' };

// Server records plus this page's pending sends (keyed by client_key) -> one ordered message list.
export function messages(chat, pending = []) {
  const out = [];
  const keys = new Set();
  const replies = Array.isArray(chat?.replies) ? chat.replies : [];
  const replying = new Map();
  for (const reply of replies) if (reply && reply.reply_to) replying.set(reply.reply_to, reply);
  for (const m of Array.isArray(chat?.messages) ? chat.messages : []) {
    if (!m || typeof m.id !== 'string') continue;
    if (m.client_key) keys.add(m.client_key);
    let status = USER_STATUS[m.status] || 'queued';
    const partial = replying.get(m.id);
    if (partial && !partial.final && status !== 'answered' && status !== 'failed') status = 'answering';
    out.push({ id: m.id, from: 'user', to: m.to === 'codex' ? 'codex' : 'claude', session: str(m.session, 128), text: str(m.text), ts: validIso(m.ts) || new Date().toISOString(),
      status: m.status === 'forged' || m.label === 'FORGED' ? 'forged' : status, reason: str(m.reason, 300), client_key: str(m.client_key, 64),
      read_at: validIso(m.read_at) || '' });
  }
  for (const r of replies) {
    if (!r || typeof r.id !== 'string' || !['claude', 'codex'].includes(r.from)) continue;
    out.push({ id: r.id, from: r.from, to: r.from, reply_to: str(r.reply_to, 40), text: str(r.text, 65536), ts: validIso(r.ts) || new Date().toISOString(),
      status: r.final ? 'answered' : 'answering' });
  }
  for (const p of pending) if (!keys.has(p.client_key)) out.push(p);
  return out.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts) || (a.from === 'user' ? -1 : 1)).slice(-80);
}

export function newClientKey(random = () => Math.random()) {
  const bytes = globalThis.crypto?.getRandomValues ? globalThis.crypto.getRandomValues(new Uint8Array(16)) : Uint8Array.from({ length: 16 }, () => Math.floor(random() * 256));
  return 'k' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// Up to three repositories with recent pushes or releases become scene nodes.
export function repos(events, limit = 3) {
  const counts = new Map();
  for (const e of events) if (e.subject.repo && ['push', 'release', 'deploy'].includes(e.kind)) counts.set(e.subject.repo, (counts.get(e.subject.repo) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([repo]) => repo);
}

// ---- needs you
// The user's replies to one ask (oldest first), each with main's replies to it. A reply is a chat message whose text
// starts with `[ask:<id>]` exactly; `[ask:<id>x]` is another ask.
export function trailOf(messages, id) {
  const tag = `[ask:${id}]`;
  return (Array.isArray(messages) ? messages : [])
    .filter(m => m && m.from === 'user' && typeof m.text === 'string' && m.text.startsWith(tag))
    .map(m => ({ message: m, text: m.text.slice(tag.length).trim(),
      replies: messages.filter(r => r && r.from !== 'user' && r.reply_to === m.id) }));
}
// An ask still needs the user until a reply of theirs is on its way (a failed or rejected send does not count).
export const waitingOnUser = (messages, ask) => !trailOf(messages, ask.id).some(t => !['failed', 'forged'].includes(t.message.status));

// ---- initiative live fields: derived from the owners, WAL notes, asks and pushes the page already has, so a row is
// current even when initiatives.json (names, links, estimates) was last edited hours ago.
export const STALE_AFTER_MS = 30 * 60 * 1000;
export const ticketKey = value => String(value || '').trim().toLowerCase().replace(/^goodqa\s+/, '');
export function liveFields(item, owners = [], asks = [], events = [], now = Date.now()) {
  const key = ticketKey(item.ticket);
  const number = (key.match(/#(\d+)$/) || [])[1] || '';
  const linked = owners.filter(o => o.initiative_id === item.id || (key && ticketKey(o.ticket) === key));
  const rank = o => (['live', 'working'].includes(o.state) ? 0 : 1);
  const owner = [...linked].sort((a, b) => rank(a) - rank(b) || String(b.last_item?.active || '').localeCompare(String(a.last_item?.active || '')))[0] || null;
  const notes = linked.filter(o => o.last_item?.at).sort((a, b) => b.last_item.at.localeCompare(a.last_item.at));
  const note = notes[0] ? { text: notes[0].last_item.note, at: notes[0].last_item.at, by: notes[0].name } : null;
  const openAsks = key ? asks.filter(a => ticketKey(a.ticket) === key).length : 0;
  const branchHas = number ? new RegExp(`(^|\\D)${number}(\\D|$)`) : null;
  const push = branchHas ? events.filter(e => e.kind === 'push' && branchHas.test(e.subject?.branch || ''))
    .sort((a, b) => b.ts.localeCompare(a.ts))[0] || null : null;
  const stamps = [owner?.last_item?.active, note?.at, push?.ts, validIso(item.updated)].filter(Boolean);
  const updated = stamps.sort().pop() || null;
  const stale = !updated || now - Date.parse(updated) > STALE_AFTER_MS;
  return { owner: owner ? { name: owner.name, state: owner.state, runtime: owner.runtime } : null, note, openAsks,
    push: push ? { summary: push.summary, at: push.ts } : null, updated, stale };
}
