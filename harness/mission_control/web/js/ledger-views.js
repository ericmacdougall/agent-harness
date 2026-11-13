// The ledger-backed panels (goodqa#15920): mission overview, deploys and live tests, blockers, requirements, archive and
// the data inventory. Builders are pure: state in, nodes out, textContent only (no HTML is ever parsed from data).
// Each long text is clamped with a disclosure, and each list is bounded with "show more", so volume never takes over.
import { el, button, age, stateClass } from './ui.js';
import { GOAL_STATE, missionTiles, dealRows, blockerRows, archiveRows } from './adapt.js';

export const PAGE = 50;
const clip = (text, max) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);
const when = (iso, now) => (iso ? age(iso, now) : 'no time recorded');
const daysLeft = seconds => (seconds >= 86400 ? `${Math.ceil(seconds / 86400)} d` : `${Math.max(1, Math.ceil(seconds / 3600))} h`);
export const TARGETS = Object.freeze({ requirements: 'tab', archive: 'tab' });

// A long text shows its first lines, and the whole of it one click away. Never hidden outright.
export function longText(text, className = 'text', max = 240) {
  const wrap = el('div', className);
  if (text.length <= max) { wrap.append(el('p', 'clamp', text || '(no text recorded)')); return wrap; }
  const details = el('details', 'more');
  details.append(el('summary', '', `${clip(text, max)} Show all ${text.length} characters`), el('p', 'full', text));
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

export function goals(state, ui) {
  const part = state.ledger.goals;
  const out = [];
  if (part.error) out.push(el('p', 'notice warn', `${part.stale ? 'Showing the last good read. ' : ''}Goal ledger: ${part.error}`));
  if (!part.items.length) out.push(el('p', 'empty', part.error ? 'The goal ledger could not be read.' : 'No goals in the ledger yet.'));
  part.items.slice(0, ui.goalsLimit).forEach(goal => out.push(goalCard(goal, state.now)));
  if (part.items.length > ui.goalsLimit) out.push(button('more-button', `Show ${part.items.length - ui.goalsLimit} more goals`, () => ui.more('goalsLimit')));
  return out;
}

export function deals(state, ui) {
  const status = state.ledger.status;
  const all = dealRows(status, state.events, 500);
  const out = [];
  if (status.error) out.push(el('p', 'notice warn', `${status.stale ? 'Showing the last good read. ' : ''}Status: ${status.error}`));
  if (!all.length) out.push(el('p', 'empty', 'No deploys or live tests recorded in the last 12 hours.'));
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

export function blockers(state, ui) {
  const all = blockerRows(state.ledger.status, state.asksFlagged, state.owners, state.initiatives);
  const out = [];
  if (!all.length) out.push(el('p', 'empty', 'No blockers recorded.'));
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
  return row.bucket === 'archived' ? `Archived · ${row.rule} ${row.rule_title || ''}`.trim() : 'Live';
}

export function requirementItem(row, now) {
  const item = el('li', `req ${row.bucket}`);
  item.dataset.id = row.id;
  const top = el('div', 'req-top');
  top.append(badge(ruleLine(row), row.bucket === 'archived' ? 'archived' : 'live'), el('span', 'req-id', row.id), el('time', 'req-age', when(row.at, now)));
  item.append(top, longText(row.text, 'req-text', 300));
  const meta = [row.source ? `Source: ${row.source}` : '', row.owner ? `owner ${row.owner}` : '', row.ticket].filter(Boolean).join(' · ');
  if (meta) item.append(el('p', 'req-meta', meta));
  item.append(el('p', 'req-why', `${row.bucket === 'archived' ? 'Archived because' : 'Live because'}: ${row.reason}${row.evidence_ref ? ` (evidence ${row.evidence_ref})` : ''}`));
  if (row.bucket === 'live' && row.expires_in_s != null) {
    item.append(el('p', 'req-expiry', `Moves to the archive in ${daysLeft(row.expires_in_s)} unless an owner, ticket or evidence is recorded.`));
  }
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
  const out = [];
  out.push(filterBar('req-filter', 'Show requirements', [['live', `Live ${summary.live}`], ['archived', `Archived ${summary.archived}`], ['all', `All ${part.items.length}`]], ui.reqFilter, key => ui.set('reqFilter', key)));
  if (part.error) out.push(el('p', 'notice warn', `${part.stale ? 'Showing the last good read. ' : ''}Requirements: ${part.error}`));
  if (part.truncated) out.push(el('p', 'notice', `Showing the newest ${part.items.length} of ${part.total} recorded requirements.`));
  const query = ui.reqQuery.trim().toLowerCase();
  const matches = part.items.filter(r => (ui.reqFilter === 'all' || r.bucket === ui.reqFilter) && (!query || r.text.toLowerCase().includes(query) || r.id.toLowerCase().includes(query)));
  if (!matches.length) out.push(el('p', 'empty', part.items.length ? 'No requirements match.' : part.error ? 'The requirements could not be read.' : 'No requirements recorded.'));
  const list = el('ul', 'req-list');
  matches.slice(0, ui.reqLimit).forEach(row => list.append(requirementItem(row, state.now)));
  out.push(list);
  if (matches.length > ui.reqLimit) out.push(button('more-button', `Show ${Math.min(PAGE, matches.length - ui.reqLimit)} more of ${matches.length - ui.reqLimit}`, () => ui.more('reqLimit')));
  return out;
}

export function archiveItem(row, now) {
  const item = el('li', `req archived kind-${row.kind}`);
  item.dataset.id = row.id;
  const top = el('div', 'req-top');
  top.append(badge(row.kind === 'ask' ? 'Ask' : 'Requirement', 'kind'), badge(`${row.rule} ${row.rule_title || ''}`.trim(), 'archived'), el('span', 'req-id', row.id), el('time', 'req-age', when(row.at, now)));
  item.append(top, longText(row.text, 'req-text', 300));
  item.append(el('p', 'req-why', `Archived because: ${row.reason}${row.evidence_ref ? ` (evidence ${row.evidence_ref})` : ''}`));
  const prov = row.kind === 'ask'
    ? [row.owner ? `registered by ${row.owner}` : '', row.ticket, row.decision ? `decision ${row.decision}` : '', row.resolution ? `resolution: ${row.resolution}` : '', row.ask_reason ? `asked because: ${row.ask_reason}` : '']
    : [row.source ? `Source: ${row.source}` : '', row.owner ? `owner ${row.owner}` : '', row.ticket];
  const line = prov.filter(Boolean).join(' · ');
  if (line) item.append(el('p', 'req-meta', line));
  return item;
}

export function archive(state, ui) {
  const rows = archiveRows(state.asksArchive, state.ledger.requirements.items);
  const kinds = { all: rows.length, ask: rows.filter(r => r.kind === 'ask').length, requirement: rows.filter(r => r.kind === 'requirement').length };
  const out = [filterBar('archive-kind', 'Show archived items', [['all', `All ${kinds.all}`], ['ask', `Asks ${kinds.ask}`], ['requirement', `Requirements ${kinds.requirement}`]], ui.archiveKind, key => ui.set('archiveKind', key))];
  const matches = rows.filter(r => ui.archiveKind === 'all' || r.kind === ui.archiveKind);
  if (!matches.length) out.push(el('p', 'empty', 'Nothing is archived.'));
  const list = el('ul', 'req-list');
  matches.slice(0, ui.archiveLimit).forEach(row => list.append(archiveItem(row, state.now)));
  out.push(list);
  if (matches.length > ui.archiveLimit) out.push(button('more-button', `Show ${Math.min(PAGE, matches.length - ui.archiveLimit)} more of ${matches.length - ui.archiveLimit}`, () => ui.more('archiveLimit')));
  return out;
}

// Every dataset the server holds, where it is shown, and how fresh it is. The honest list of what has no UI is at the end.
export const GAPS = Object.freeze([
  'Peer-review receipts: Mission Control has no read path for them.',
  'Full ticket comment threads: only checkpoint comments arrive, as feed events.',
  'Release-kit deploy records outside the WALs: no read path.',
]);
export function inventory(state, go) {
  const led = state.ledger;
  const rowsOut = [
    ['Goals', led.goals.at, led.goals.stale, led.goals.error, `${led.goals.items.length} goals`, 'Overview', 'overview'],
    ['Initiatives', '', state.initiativesStale, state.initiativesError, `${state.initiatives.length} initiatives`, 'Overview', 'overview'],
    ['Owners', '', false, '', `${state.owners.length} owners`, 'Overview', 'overview'],
    ['Open asks', state.asksSweptAt, false, '', `${state.asks.length} open, ${state.asksStale.length} stale, ${state.asksFlagged.length} untraceable`, 'Overview', 'overview'],
    ['Deploys and live tests', led.status.at, led.status.stale, led.status.error, `${led.status.live.length} deploys, ${led.status.verified.length} tested, ${led.status.failed.length} failed, ${led.status.pending.length} pending`, 'Overview', 'overview'],
    ['Blockers', led.status.at, led.status.stale, led.status.error, `${led.status.blockers.length} recorded`, 'Overview', 'overview'],
    ['Requirements', led.requirements.at, led.requirements.stale, led.requirements.error, `${led.requirements.summary.live} live, ${led.requirements.summary.archived} archived of ${led.requirements.total}`, 'Requirements', 'requirements'],
    ['Archived asks', state.asksSweptAt, false, '', `${state.asksArchive.length} archived`, 'Archive', 'archive'],
    ['Activity feed', '', false, '', `${state.events.length} events held`, 'Activity', 'activity'],
    ['Chat', '', false, '', `${state.messages.length} messages, ${state.sessions.length} sessions`, 'Chat panel', 'chat'],
    ['Decisions and commits', led.status.at, led.status.stale, led.status.error, `${led.status.decisions.length} decisions, ${led.status.commits.length} commits, ${led.status.claimed.length} claimed, ${led.status.assumptions.length} assumptions`, 'Sources', 'sources'],
  ];
  const table = el('table', 'inventory');
  const head = el('tr');
  ['Data', 'Last read', 'Health', 'Holds', 'Shown in'].forEach(text => head.append(el('th', '', text)));
  const thead = el('thead');
  thead.append(head);
  const body = el('tbody');
  for (const [name, at, stale, error, holds, where, tab] of rowsOut) {
    const row = el('tr');
    row.append(el('th', '', name), el('td', '', at ? age(at, state.now) : 'live'), el('td', error ? 'bad' : stale ? 'warn' : 'ok', error ? `error: ${error}` : stale ? 'stale' : 'ok'), el('td', '', holds));
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
