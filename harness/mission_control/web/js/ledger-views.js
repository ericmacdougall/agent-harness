// The ledger-backed panels (goodqa#15920): mission overview, deploys and live tests, blockers, requirements, archive and
// the data inventory. Builders are pure: state in, nodes out, textContent only (no HTML is ever parsed from data).
// Each long text is clamped with a disclosure, and each list is bounded with "show more", so volume never takes over.
import { el, button, age, stateClass } from './ui.js';
import { GOAL_STATE, missionTiles, dealRows, blockerRows, archiveRows, unreadLine, claim, truthLines, noneText, countText, hiddenBlockers, hiddenDeals, statusCount } from './adapt.js';

export const PAGE = 25;  // default rows per list; "show more" adds one page
const clip = (text, max) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);
const when = (iso, now) => (iso ? age(iso, now) : 'time unknown');
const daysLeft = seconds => (seconds >= 86400 ? `${Math.ceil(seconds / 86400)} d` : `${Math.max(1, Math.ceil(seconds / 3600))} h`);
export const TARGETS = Object.freeze({ requirements: 'tab', archive: 'tab' });

// A long text shows its first lines, and the whole of it one click away. Never hidden outright.
export function longText(text, className = 'text', max = 240) {
  const wrap = el('div', className);
  if (text.length <= max) { const p = el('p', 'clamp', text || '(no text recorded)'); p.setAttribute('dir', 'auto'); wrap.append(p); return wrap; }
  const details = el('details', 'more');
  const full = el('p', 'full', text);
  full.setAttribute('dir', 'auto');
  details.append(el('summary', '', `${clip(text, max)} Show all ${text.length} characters`), full);
  wrap.append(details);
  return wrap;
}

export function badge(text, tone = '') {
  return el('span', `badge ${tone}`.trim(), text);
}

export function tiles(state, go) {
  const list = el('ul', 'tiles');
  for (const tile of missionTiles(state)) {
    const item = el('li');
    const control = button(`tile tile-${tile.id}`, '', () => go(tile.target));
    control.append(el('span', 'tile-value', tile.value), el('span', 'tile-label', tile.label), el('span', 'tile-note', tile.note));
    control.setAttribute('aria-label', `${tile.label}: ${tile.value}. ${tile.note}. Go to the section.`);
    item.append(control);
    list.append(item);
  }
  return list;
}

function evidenceItem(row, now) {
  const item = el('li', `evidence verdict-${stateClass(row.verdict) || 'none'}`);
  const mark = row.verdict === 'PASS' ? '✓ PASS' : row.verdict === 'FAIL' ? '✕ FAIL' : row.verdict || 'no verdict';
  item.append(el('span', 'evidence-mark', mark), el('span', 'evidence-kind', row.kind.replace('_', ' ') || 'record'),
    el('span', 'evidence-check', row.check || row.id), el('span', 'evidence-age', when(row.at, now)));
  if (row.note) item.append(el('p', 'evidence-note', clip(row.note, 300)));
  return item;
}

export function goalCard(goal, now) {
  const card = el('article', `goal state-${stateClass(goal.state)}`);
  card.dataset.id = goal.id;
  const head = el('div', 'goal-head');
  const title = el('h3', 'goal-title', goal.title || goal.id);
  head.append(title, badge(GOAL_STATE[goal.state] || goal.state.replace(/_/g, ' ').toLowerCase(), `goal-state ${stateClass(goal.state)}`));
  card.append(head);
  const meta = [goal.ticket, goal.owners.length ? `owner ${goal.owners.join(', ')}` : '', goal.priority != null ? `priority ${goal.priority}` : '',
    `${goal.evidence_total} evidence record${goal.evidence_total === 1 ? '' : 's'}`].filter(Boolean).join(' · ');
  card.append(el('p', 'goal-meta', meta));
  if (goal.target && goal.target.toLowerCase() !== goal.title.toLowerCase()) card.append(el('p', 'goal-target', `Target: ${goal.target}`));
  const problems = Object.entries(goal.problems).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`);
  if (problems.length) card.append(el('p', 'goal-problem', `Ledger problems: ${problems.join(', ')}`));
  if (goal.deferral) card.append(el('p', 'goal-meta', `Deferred: ${goal.deferral}`));
  if (goal.evidence.length) {
    const details = el('details', 'goal-evidence');
    const newest = goal.evidence[0];
    details.append(el('summary', '', `Evidence · latest ${newest.verdict || newest.kind} ${when(newest.at, now)}`));
    const list = el('ul', 'evidence-list');
    goal.evidence.forEach(row => list.append(evidenceItem(row, now)));
    if (goal.evidence_total > goal.evidence.length) list.append(el('li', 'evidence-more', `${goal.evidence_total - goal.evidence.length} older records are in the ledger (ah goals).`));
    details.append(list);
    card.append(details);
  }
  return card;
}

// review PR 234 v3 F1: beside every claim, what its sources could not tell (one line per source that is not current).
export function truthNotice(c) {
  const lines = truthLines(c);
  if (!lines.length) return null;
  const box = el('div', `notice warn truth-${c.truth}`);
  box.setAttribute('role', 'status');
  lines.forEach(line => box.append(el('p', '', line)));
  return box;
}
const notices = (c, ...more) => [truthNotice(c), ...more].filter(Boolean);

export function goals(state, ui) {
  const part = state.ledger.goals;
  const c = claim(state, 'goals');
  const out = notices(c);
  if (part.total > part.items.length) out.push(el('p', 'notice', `Showing ${part.items.length} of ${part.total} goals.`));
  if (!part.items.length) out.push(el('p', 'empty', noneText(c, 'No goals in the ledger yet.', 'goals')));
  part.items.slice(0, ui.goalsLimit).forEach(goal => out.push(goalCard(goal, state.now)));
  if (part.items.length > ui.goalsLimit) out.push(button('more-button', `Show ${part.items.length - ui.goalsLimit} more goals`, () => ui.more('goalsLimit')));
  return out;
}

export function deals(state, ui) {
  const status = state.ledger.status;
  const all = dealRows(status, state.events, 500);
  const c = claim(state, 'deploys');
  const out = notices(c, unreadNotice(status));
  const hidden = hiddenDeals(status);
  if (hidden) out.push(el('p', 'notice', `${hidden} more deploy and test records are in the ledger than Mission Control holds (ah status lists them all).`));
  if (!all.length && !hidden) out.push(el('p', 'empty', noneText(c, 'No deploys or live tests recorded in the last 12 hours.', 'deploys or live tests')));
  if (all.length) out.push(el('p', 'count-line', `Showing ${Math.min(all.length, ui.dealsLimit)} of ${all.length + hidden} records from the last ${Math.round(status.since_s / 3600) || 12} hours.`));
  const list = el('ul', 'deals');
  all.slice(0, ui.dealsLimit).forEach(row => {
    const item = el('li', `deal tone-${row.tone}`);
    item.append(el('span', 'deal-label', `${row.symbol} ${row.label}`), longText(row.text, 'deal-text', 200));
    item.append(el('span', 'deal-meta', [row.check, row.agent ? `by ${row.agent.slice(0, 12)}` : '', row.source === 'feed' ? 'from the live feed' : '', when(row.at, state.now)].filter(Boolean).join(' · ')));
    list.append(item);
  });
  out.push(list);
  if (all.length > ui.dealsLimit) out.push(button('more-button', `Show ${all.length - ui.dealsLimit} more`, () => ui.more('dealsLimit')));
  return out;
}

// review PR 234 v2 F2: what a partial status read missed, beside every panel that depends on it.
function unreadNotice(status) {
  if (!status.incomplete) return null;
  const box = el('div', 'notice warn');
  box.setAttribute('role', 'status');
  box.append(el('p', '', unreadLine(status)));
  if (status.unread.items.length) {
    const list = el('ul', 'unread');
    status.unread.items.forEach(r => list.append(el('li', '', [r.wal, r.reason].filter(Boolean).join(': '))));
    box.append(list);
  }
  return box;
}

export function blockers(state, ui) {
  const all = blockerRows(state.ledger.status, state.asksFlagged, state.owners, state.initiatives);
  const c = claim(state, 'blockers');
  const out = notices(c, unreadNotice(state.ledger.status));
  const hidden = hiddenBlockers(state.ledger.status);
  if (hidden) out.push(el('p', 'notice', `${hidden} more ledger blockers are recorded than Mission Control holds (ah status lists them all).`));
  if (!all.length && !hidden) out.push(el('p', 'empty', noneText(c, 'No blockers recorded.', 'blockers')));
  const list = el('ul', 'blockers');
  all.slice(0, ui.blockersLimit).forEach(row => {
    const item = el('li', `blocker src-${row.source}`);
    item.append(el('span', 'blocker-title', row.title), longText(row.text, 'blocker-text', 200),
      el('span', 'blocker-meta', [row.agent ? row.agent.slice(0, 16) : '', when(row.at, state.now)].filter(Boolean).join(' · ')));
    list.append(item);
  });
  out.push(list);
  if (all.length > ui.blockersLimit) out.push(button('more-button', `Show ${all.length - ui.blockersLimit} more`, () => ui.more('blockersLimit')));
  return out;
}

function ruleLine(row) {
  if (row.bucket === 'archived' && row.rule === 'M' && row.user_sourced) return 'Archived from the dashboard · your own words';
  return row.bucket === 'archived' ? `Archived · ${row.rule} ${row.rule_title || ''}`.trim() : 'Live';
}
const manualUser = row => row.bucket === 'archived' && row.rule === 'M' && row.user_sourced === true;

function actionArea(row, ui) {
  const area = el('div', 'req-actions');
  const action = row.bucket === 'archived' ? 'restore' : 'archive';
  const armed = ui.armed && ui.armed.id === row.id ? ui.armed : null;
  if (action === 'archive' && row.clipped) {
    // review PR 234 v2 F3: never offer a confirmation on words the user could not read in full
    area.append(el('p', 'req-notice', 'This requirement cannot be archived here: Mission Control can show only part of it. Ask main to archive or supersede it.'));
    return area;
  }
  if (!armed) {
    const open = button('req-action', action === 'archive' ? 'Archive…' : 'Restore…', () => ui.arm?.(row, action));
    open.setAttribute('aria-label', `${action === 'archive' ? 'Archive' : 'Restore'} requirement ${row.id}`);
    area.append(open);
    if (ui.notice?.[row.id]) area.append(el('span', 'req-notice', ui.notice[row.id]));
    return area;
  }
  const form = el('form', 'req-form');
  const input = el('textarea');
  input.id = `req-reason-${row.id}`;
  input.rows = 2;
  input.maxLength = 300;
  input.value = ui.draft || '';
  const label = el('label', 'needs-label', armed.action === 'archive' ? 'Why are you archiving this? (required, recorded with your click)' : 'Why are you restoring this? (required, recorded with your click)');
  label.htmlFor = input.id;
  const confirm = el('button', `req-action confirm ${armed.action}`, armed.action === 'archive' ? 'Confirm archive' : 'Confirm restore');
  confirm.type = 'submit';
  confirm.disabled = !input.value.trim() || !!ui.busy;
  confirm.setAttribute('aria-label', `Confirm ${armed.action} of requirement ${row.id}`);
  input.addEventListener('input', () => { ui.draft = input.value; confirm.disabled = !input.value.trim() || !!ui.busy; });
  const cancel = button('req-action cancel', 'Cancel', () => ui.cancel?.());
  const buttons = el('div', 'needs-actions');
  buttons.append(confirm, cancel);
  form.append(label, input, buttons);
  form.addEventListener('submit', event => { event.preventDefault(); if (!confirm.disabled) ui.submit?.(row); });
  area.append(form);
  const status = el('p', 'req-status', ui.busy ? 'Recording…' : ui.error || 'Nothing is deleted. The row moves between Requirements and Archive, and the click is logged.');
  status.setAttribute('role', 'status');
  area.append(status);
  return area;
}

export function requirementItem(row, now, ui = {}) {
  const item = el('li', `req ${row.bucket}`);
  item.dataset.id = row.id;
  const top = el('div', 'req-top');
  top.append(badge(ruleLine(row), manualUser(row) ? 'manual-user' : row.bucket === 'archived' ? 'archived' : 'live'), el('span', 'req-id', row.id), el('time', 'req-age', when(row.at, now)));
  item.append(top, longText(row.text, 'req-text', 300));
  if (row.clipped) item.append(el('p', 'notice warn', `Showing the first ${row.text.length} of ${row.text_len || 'more'} characters. The rest is in the session WAL; Mission Control does not read it.`));
  const meta = [`Source: ${row.source || 'unknown'}`, row.owner ? `owner ${row.owner}` : 'no owner recorded', row.ticket || 'no ticket'].join(' · ');
  item.append(el('p', 'req-meta', meta));
  item.append(el('p', 'req-why', `${row.bucket === 'archived' ? 'Archived because' : 'Live because'}: ${row.reason}${row.evidence_ref ? ` (evidence ${row.evidence_ref})` : ''}`));
  if (row.evidence_text) item.append(el('p', 'req-meta', `Evidence recorded: ${row.evidence_text}`));
  if (row.bucket === 'live' && row.expires_in_s != null) {
    item.append(el('p', 'req-expiry', `ASSUMPTION: moves to the archive in ${daysLeft(row.expires_in_s)} (30 days with no owner, ticket or evidence, and not sourced to you) unless one is recorded.`));
  }
  if (row.unowned_note) item.append(el('p', 'req-expiry', row.unowned_note));
  item.append(actionArea(row, ui));
  return item;
}

function filterBar(id, label, options, value, onChange) {
  const group = el('div', 'segmented');
  group.id = id;
  group.setAttribute('role', 'group');
  group.setAttribute('aria-label', label);
  options.forEach(([key, text]) => {
    const control = button('segment', text, () => onChange(key));
    control.setAttribute('aria-pressed', String(value === key));
    group.append(control);
  });
  return group;
}

export function requirements(state, ui) {
  const part = state.ledger.requirements;
  const summary = part.summary;
  const c = claim(state, 'requirements');
  const out = [];
  out.push(filterBar('req-filter', 'Show requirements', [['live', `Live ${countText(summary.live, c)}`], ['archived', `Archived ${countText(summary.archived, c)}`], ['all', `All ${countText(part.items.length, c)}`]], ui.reqFilter, key => ui.set('reqFilter', key)));
  out.push(...notices(c));
  if (part.truncated) out.push(el('p', 'notice', `Showing the newest ${part.items.length} of ${part.total} recorded requirements.`));
  const query = ui.reqQuery.trim().toLowerCase();
  const matches = part.items.filter(r => (ui.reqFilter === 'all' || r.bucket === ui.reqFilter) && (!query || r.text.toLowerCase().includes(query) || r.id.toLowerCase().includes(query)));
  if (!matches.length) out.push(el('p', 'empty', part.items.length ? noneText(c, 'No requirements match.', 'matching requirements') : noneText(c, 'No requirements recorded.', 'requirements')));
  const list = el('ul', 'req-list');
  matches.slice(0, ui.reqLimit).forEach(row => list.append(requirementItem(row, state.now, ui)));
  out.push(list);
  if (matches.length > ui.reqLimit) out.push(button('more-button', `Show ${Math.min(PAGE, matches.length - ui.reqLimit)} more of ${matches.length - ui.reqLimit}`, () => ui.more('reqLimit')));
  return out;
}

export function archiveItem(row, now, ui = {}) {
  const item = el('li', `req archived kind-${row.kind}`);
  item.dataset.id = row.id;
  const top = el('div', 'req-top');
  top.append(badge(row.kind === 'ask' ? 'Ask' : 'Requirement', 'kind'), badge(manualUser(row) ? 'Archived from the dashboard · your own words' : `${row.rule} ${row.rule_title || ''}`.trim(), manualUser(row) ? 'manual-user' : 'archived'), el('span', 'req-id', row.id), el('time', 'req-age', when(row.at, now)));
  item.append(top, longText(row.text, 'req-text', 300));
  if (row.clipped) item.append(el('p', 'notice warn', `Showing the first ${row.text.length} of ${row.text_len || 'more'} characters. The rest is in the session WAL; Mission Control does not read it.`));
  item.append(el('p', 'req-why', `Archived because: ${row.reason}${row.evidence_ref ? ` (evidence ${row.evidence_ref})` : ''}`));
  const prov = row.kind === 'ask'
    ? [`registered by ${row.owner || 'unknown'}`, row.ticket, row.decision ? `decision ${row.decision}` : '', row.resolution ? `resolution: ${row.resolution}` : '', row.ask_reason ? `asked because: ${row.ask_reason}` : '']
    : [`Source: ${row.source || 'unknown'}`, row.owner ? `owner ${row.owner}` : 'no owner recorded', row.ticket];
  const line = prov.filter(Boolean).join(' · ');
  if (line) item.append(el('p', 'req-meta', line));
  if (row.manual) item.append(el('p', 'req-meta', `Click recorded from ${row.manual.by || 'a dashboard session'} at ${row.manual.at || 'unknown time'}. A dashboard click is not proof that you made it.`));
  if (row.kind === 'requirement') item.append(actionArea(row, ui));
  return item;
}

export function archive(state, ui) {
  const rows = archiveRows(state.asksArchive, state.ledger.requirements.items);
  const kinds = { all: rows.length, ask: rows.filter(r => r.kind === 'ask').length, requirement: rows.filter(r => r.kind === 'requirement').length, 'manual-user': rows.filter(manualUser).length };
  const c = claim(state, 'archive');
  const askTruth = claim(state, 'needs'), reqTruth = claim(state, 'requirements');
  const out = [];
  if (state.asksArchiveTotal > state.asksArchive.length) out.push(el('p', 'notice', `Showing the newest ${state.asksArchive.length} of ${state.asksArchiveTotal} archived asks. The rest are in the asks ledger (provenance.py asks).`));
  out.push(filterBar('archive-kind', 'Show archived items', [['all', `All ${countText(kinds.all, c)}`], ['ask', `Asks ${countText(kinds.ask, askTruth)}`], ['requirement', `Requirements ${countText(kinds.requirement, reqTruth)}`], ['manual-user', `Dashboard-archived, your words ${countText(kinds['manual-user'], reqTruth)}`]], ui.archiveKind, key => ui.set('archiveKind', key)));
  out.push(...notices(c));
  const matches = rows.filter(r => ui.archiveKind === 'all' || (ui.archiveKind === 'manual-user' ? manualUser(r) : r.kind === ui.archiveKind));
  const kindClaim = { ask: askTruth, requirement: reqTruth, 'manual-user': reqTruth }[ui.archiveKind] || c;
  if (!matches.length) out.push(el('p', 'empty', noneText(kindClaim, 'Nothing is archived.', 'archived items')));
  const list = el('ul', 'req-list');
  matches.slice(0, ui.archiveLimit).forEach(row => list.append(archiveItem(row, state.now, ui)));
  out.push(list);
  if (matches.length > ui.archiveLimit) out.push(button('more-button', `Show ${Math.min(PAGE, matches.length - ui.archiveLimit)} more of ${matches.length - ui.archiveLimit}`, () => ui.more('archiveLimit')));
  return out;
}

// Every dataset the server holds, where it is shown, and how fresh it is. The honest list of what has no UI is at the end.
export const GAPS = Object.freeze([
  'Requirements of earlier sessions: only main\'s current session is read.',
  'Who registered a requirement: ah requirements has an owner field, always empty today, shown as no owner recorded.',
  'Peer-review receipts: Mission Control has no read path for them.',
  'Full ticket comment threads: only checkpoint comments arrive, as feed events.',
  'Release-kit deploy records outside the WALs: no read path.',
]);
const unreadCount = status => (status.unread.count > 0 ? `${status.unread.count} logs unread` : 'some logs unread');
const TRUTH_WORD = { current: 'ok', partial: 'partial', stale: 'stale', unknown: 'unknown' };
export function inventory(state, go) {
  const led = state.ledger;
  const st = led.status;
  const n = (count, c) => countText(count, c);
  const sc = key => statusCount(st, key);  // the ledger's whole count, not the 30 rows held
  const unread = st.incomplete ? `incomplete: ${unreadCount(st)}; ` : '';
  // [name, claim, holds, shown in, tab]: each row's Health is its claim's truth, its counts follow the same rule
  const spec = [
    ['Goals', 'goals', c => `${n(led.goals.items.length, c)} goals`, 'Overview', 'overview'],
    ['Initiatives', 'initiatives', c => `${n(state.initiatives.length, c)} initiatives`, 'Overview', 'overview'],
    ['Owners', 'owners', c => `${n(state.owners.length, c)} owners`, 'Overview', 'overview'],
    ['Open asks', 'needs', c => `${n(state.asks.length, c)} open, ${n(state.asksStale.length, c)} stale, ${n(state.asksFlagged.length, c)} untraceable`, 'Overview', 'overview'],
    ['Deploys and live tests', 'deploys', c => `${unread}${n(sc('live'), c)} deploys, ${n(sc('verified'), c)} tested, ${n(sc('failed'), c)} failed, ${n(sc('pending'), c)} pending`, 'Overview', 'overview'],
    ['Blockers', 'blockers', c => `${unread}${n(sc('blockers'), c)} recorded in status`, 'Overview', 'overview'],
    ['Requirements', 'requirements', c => `${n(led.requirements.summary.live, c)} live, ${n(led.requirements.summary.archived, c)} archived of ${n(led.requirements.total, c)}`, 'Requirements', 'requirements'],
    ['Archived asks', 'needs', c => `${n(state.asksArchive.length, c)} archived`, 'Archive', 'archive'],
    ['Activity feed', 'activity', c => `${n(state.events.length, c)} events held`, 'Activity', 'activity'],
    ['Chat', 'chat', c => `${n(state.messages.length, c)} messages, ${n(state.sessions.length, c)} sessions`, 'Chat panel', 'chat'],
    ['Decisions and commits', 'decisions', c => `${unread}${n(sc('decisions'), c)} decisions, ${n(sc('commits'), c)} commits, ${n(sc('claimed'), c)} claimed, ${n(sc('assumptions'), c)} assumptions`, 'Sources', 'sources'],
  ];
  const rowsOut = spec.map(([name, id, holds, where, tab]) => {
    const c = claim(state, id);
    const at = c.facts.map(f => f.at).filter(Boolean).sort()[0] || '';
    const errors = c.bad.map(f => f.error).filter(Boolean);
    return [name, at, c.truth, errors.join('; '), holds(c), where, tab];
  });
  const table = el('table', 'inventory');
  const head = el('tr');
  ['Data', 'Last read', 'Health', 'Holds', 'Shown in'].forEach(text => head.append(el('th', '', text)));
  const thead = el('thead');
  thead.append(head);
  const body = el('tbody');
  for (const [name, at, truth, error, holds, where, tab] of rowsOut) {
    const row = el('tr');
    const tone = truth === 'current' ? 'ok' : truth === 'unknown' ? 'bad' : 'warn';
    row.append(el('th', '', name), el('td', '', at ? age(at, state.now) : 'never'), el('td', tone, `${TRUTH_WORD[truth]}${error ? `: ${error}` : ''}`), el('td', '', holds));
    const cell = el('td');
    cell.append(button('link-button', where, () => go(tab)));
    row.append(cell);
    body.append(row);
  }
  table.append(thead, body);
  const gaps = el('ul', 'gaps');
  GAPS.forEach(text => gaps.append(el('li', '', text)));
  return [table, el('h3', 'gaps-title', 'Not shown by this page (no read path today)'), gaps];
}
