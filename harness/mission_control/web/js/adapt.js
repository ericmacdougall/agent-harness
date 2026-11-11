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
    const id = str(r.agent_id, 80);
    const linked = items.find(i => (ownerKey(i.owner) && id.toLowerCase().startsWith(ownerKey(i.owner))) || (r.ticket && i.ticket === r.ticket));
    const last = r.last_item && typeof r.last_item === 'object' ? r.last_item : null;
    const at = validIso(last?.at) || null;
    const active = [validIso(last?.active_at), at, validIso(r.last_activity)].filter(Boolean).sort().pop() || null;
    return {
      agent_id: id, name: str(r.name, 64) || (r.runtime === 'codex' ? `codex ${shortId(id)}` : shortId(id)), runtime: ['codex', 'claude'].includes(r.runtime) ? r.runtime : 'unknown',
      harness: r.runtime === 'codex' ? 'openai' : r.runtime === 'claude' ? 'claude' : 'unknown', model: str(r.model, 80), stream: str(r.stream, 160),
      last_reply: str(r.last_reply, 2000), source_stale: r.source_stale === true,
      observed_at: validIso(str(r.observed_at).replace(' UTC', 'Z').replace(' ', 'T')),
      native_status: str(r.native_status?.type, 40),
      type: str(r.type, 40), task: str(r.task, 200) || (r.runtime === 'codex' ? 'Codex session' : 'Owner'), ticket: str(r.ticket, 60),
      state: str(r.state, 24) || 'unknown', ...ownerHold(r, last),
      last_item: { at, active, event: str(last?.event, 40), note: str(last?.note, 200) || 'No work item recorded yet' },
      progress: validIso(last?.progress_at) ? { at: last.progress_at, event: str(last.progress_event, 40), note: str(last.progress_note, 160) } : null,
      initiative_id: linked ? linked.id : null,
    };
  });
}

const SOURCE_NAMES = { wals: 'Claude + Codex WALs', initiatives: 'Initiatives file', owners: 'Owners', github: 'GitHub', goodqa: 'GoodQA tickets',
  't2-dev': 't2-dev', 'file-drop': 'Event drops', codex: 'Codex chat', chat: 'Chat store', 'codex-owners': 'OpenAI supervised owners' };
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

const USER_STATUS = { queued: 'queued', delivered: 'delivered', answered: 'answered', failed: 'failed', forged: 'forged', unavailable: 'failed', answering: 'answering', expired: 'expired' };

// The signed decision a dashboard record carries, as the server reports it: ask id, decision and expiry, nothing else.
export function approvalOf(raw) {
  if (!raw || typeof raw !== 'object' || !/^[A-Za-z0-9_-]{1,40}$/.test(str(raw.ask_id)) || !['approve', 'deny'].includes(raw.decision)) return null;
  return { ask_id: raw.ask_id, decision: raw.decision, expires: isoFromEpoch(raw.expires) || '' };
}

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
      read_at: validIso(m.read_at) || '', approval: m.status === 'forged' || m.label === 'FORGED' ? null : approvalOf(m.approval) });
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
export const waitingOnUser = (messages, ask) => !trailOf(messages, ask.id).some(t => !['failed', 'forged'].includes(t.message.status))
  && !decisionOf(messages, ask)?.live;

// ---- decisions: Approve or Deny on an ask is a signed server record (a chat message that carries `approval`).
// The newest record for the ask decides what the card shows; `local` is this page's own click still in flight or
// refused. `live` means a decision is standing or on its way, so the buttons stay away; an expired or refused one
// leaves the ask open and the buttons back.
export function decisionOf(messages, ask, local = null) {
  const records = (Array.isArray(messages) ? messages : [])
    .filter(m => m && m.from === 'user' && m.approval && m.approval.ask_id === ask?.id && (!ask?.session || !m.session || m.session === ask.session));
  const record = records[records.length - 1] || null;
  const recordLive = record && ['queued', 'delivered', 'answering', 'answered'].includes(record.status);
  // 'sent': the server stored the record; its snapshot follows within a second, so the card still says sending.
  // A standing record always wins over this page's refused click (another tab decided first).
  const pending = local && ['sending', 'sent'].includes(local.status);
  if (local && (pending || (!recordLive && (!record || Date.parse(local.ts) > Date.parse(record.ts))))) {
    const status = pending ? 'sending' : 'failed';
    return { decision: local.decision, status, reason: str(local.reason, 300), live: pending, message: null, replies: [] };
  }
  if (!record) return null;
  const status = ['queued', 'delivered', 'answering', 'answered', 'expired'].includes(record.status) ? record.status : 'failed';
  return { decision: record.approval.decision, status, reason: str(record.reason, 300), live: !['expired', 'failed'].includes(status),
    message: record, expires: record.approval.expires, replies: messages.filter(r => r && r.from !== 'user' && r.reply_to === record.id) };
}
const minutesLeft = (expires, now) => Math.max(1, Math.ceil((Date.parse(expires) - now) / 60000));
// One honest line for a decision: what was decided and exactly how far it has got.
export function decisionStatus(decision, { now = Date.now(), waiting = true, time = String, gap = () => '' } = {}) {
  if (!decision) return '';
  const noun = decision.decision === 'approve' ? 'approval' : 'denial';
  const done = decision.decision === 'approve' ? 'Approved' : 'Denied';
  if (decision.status === 'sending') return `Sending your ${noun}…`;
  if (decision.status === 'failed') return `Your ${noun} was not recorded${decision.reason ? `: ${decision.reason}` : ''}. Nothing was sent.`;
  if (decision.status === 'expired') return `Your ${noun} expired before main read it, so it does not count. Decide again when main is listening.`;
  if (decision.status === 'queued') {
    const left = Number.isFinite(Date.parse(decision.expires)) ? ` · expires in ${minutesLeft(decision.expires, now)} min if unread` : '';
    return `${done} · sent, ${waiting ? 'waiting for main to read it' : 'main is busy and reads it at its next stop'}${left}`;
  }
  const message = decision.message || {};
  const read = message.read_at ? `read by main at ${time(message.read_at)}${gap(message.ts, message.read_at) ? ` (${gap(message.ts, message.read_at)})` : ''}` : 'read by main';
  return `${done} · ${read}${decision.status === 'answering' ? ' · main is answering' : decision.status === 'answered' ? ' · main replied' : ''}`;
}

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
  // compare instants, not strings (mixed offsets), and ignore times in the future (clock skew or a bad writer), so a
  // skewed stamp can never hold the 30-minute flag off (delta red-team L-c)
  const stamps = [owner?.last_item?.active, note?.at, push?.ts, validIso(item.updated)]
    .filter(Boolean).map(ts => ({ ts, ms: Date.parse(ts) })).filter(s => Number.isFinite(s.ms) && s.ms <= now + 120000);
  const newest = stamps.sort((a, b) => a.ms - b.ms).pop() || null;
  const updated = newest ? newest.ts : null;
  const stale = !newest || now - newest.ms > STALE_AFTER_MS;
  return { owner: owner ? { name: owner.name, state: owner.state, runtime: owner.runtime } : null, note, openAsks,
    push: push ? { summary: push.summary, at: push.ts } : null, updated, stale };
}

// The header of an ask the user has replied to follows main's progress (click-test a954 F1: it stayed "waiting").
export function askProgress(trail, decision = null) {
  if (decision?.live) {
    const done = decision.decision === 'approve' ? 'Approved by you' : 'Denied by you';
    return decision.status === 'sending' ? 'Sending your decision' : `${done} · ${decision.replies.length ? 'main replied' : decision.status === 'queued' ? 'waiting for main' : 'read by main'}`;
  }
  const live = trail.filter(t => !['failed', 'forged'].includes(t.message.status));
  if (!live.length) return '';
  if (live.some(t => t.replies.length)) return 'Answered by you · main replied';
  if (live.some(t => t.message.read_at || ['delivered', 'answering', 'answered'].includes(t.message.status))) return 'Answered by you · read by main';
  return 'Answered by you · waiting for main';
}
// One status line per reply: the read time is stated as "Read by main at T", then where main has got to.
export function replyStatus(message, time, gap) {
  const base = { sending: 'Sending…', queued: 'Sent · waiting for main to read it', failed: 'Not sent · retry from the chat panel',
    forged: 'Rejected: not signed by this dashboard' };
  if (base[message.status]) return base[message.status];
  const read = message.read_at ? `Read by main at ${time(message.read_at)} (${gap(message.ts, message.read_at)})` : 'Read by main';
  return read + ({ answering: ' · answering', answered: ' · answered' }[message.status] || '');
}

// ---- slowest / at risk: mission goals ranked by time since REAL progress (an owner's result, check, commit, deploy,
// merge, release or handoff, or a push to the ticket's branch), not by any note. UNCOVERED (no working owner and no
// recorded disposition) comes first. Derived from ah owners plus initiatives.json until the harness mission-coverage
// check publishes its own verdicts; `coverage` (id -> {status, reason, action}) overrides when present.
export const STALLED_AFTER_MS = 90 * 60 * 1000;
const FINISHED = /\b(done|live|complete|completed|shipped|cancel+ed|parked|on hold)\b/i;
export function atRisk(initiatives = [], owners = [], events = [], now = Date.now(), coverage = null, limit = 6) {
  const rows = [];
  for (const item of initiatives) {
    if (!item || FINISHED.test(item.state || '')) continue;
    const key = ticketKey(item.ticket);
    const number = (key.match(/#(\d+)$/) || [])[1] || '';
    const linked = owners.filter(o => o.initiative_id === item.id || (key && ticketKey(o.ticket) === key));
    const working = linked.filter(o => ['live', 'working', 'quiet'].includes(o.state));
    // a live decision that keeps the goal covered (waiting on a named thing, resumed, reassigned); closed/superseded/
    // wontdo end that owner's work, not the goal, so they do not cover it
    const decided = linked.map(o => o.disposition).find(d => d && ['waiting', 'resumed', 'reassigned'].includes(d.kind));
    const branchHas = number ? new RegExp(`(^|\\D)${number}(\\D|$)`) : null;
    const pushes = branchHas ? events.filter(e => ['push', 'deploy', 'release'].includes(e.kind) && branchHas.test(e.subject?.branch || '')) : [];
    const stamps = [...linked.map(o => o.progress && { at: o.progress.at, what: `${o.progress.event} by ${o.name}` }),
      ...pushes.map(e => ({ at: e.ts, what: e.kind }))]
      .filter(s => s && Number.isFinite(Date.parse(s.at)) && Date.parse(s.at) <= now + 120000);
    const last = stamps.sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0] || null;
    const since = last ? now - Date.parse(last.at) : Infinity;
    let status, reason;
    if (!working.length && !decided) {
      status = 'uncovered';
      reason = linked.length ? `no working owner (${linked.map(o => `${o.name} ${o.state}`).join(', ')}) and no recorded decision` : 'no owner and no recorded decision';
    } else if (since > STALLED_AFTER_MS) {
      status = 'stalled';
      reason = last ? `no real progress since ${last.what}` : 'no result, commit or deploy recorded yet';
    } else {
      status = 'moving';
      reason = `last progress: ${last.what}`;
    }
    const action = decided ? `${decided.kind}${decided.reason ? `: ${decided.reason}` : ''}` : '';
    const external = coverage && typeof coverage === 'object' ? coverage[item.id] || coverage[key] : null;
    if (external && ['uncovered', 'stalled', 'moving'].includes(external.status)) {
      status = external.status; reason = str(external.reason, 200) || reason;
    }
    rows.push({ id: item.id, initiative: item.initiative, ticket: item.ticket, status, reason,
      action: (external && str(external.action, 200)) || action, last: last ? last.at : null, since });
  }
  const order = { uncovered: 0, stalled: 1, moving: 2 };
  return rows.sort((a, b) => order[a.status] - order[b.status] || b.since - a.since).slice(0, limit);
}
