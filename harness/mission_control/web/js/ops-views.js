// Ops alerts and owner capacity (goodqa#15934). The ops-watch ring already knows what is wrong (silent owners, due
// asks, merged but not deployed, open PENDING ids, disk, drifted hooks); this panel is its read path. Read-only: an
// alert clears when its cause does, never from here. Builders are pure: state in, nodes out, textContent only.
import { el, button, age } from './ui.js';
import { longText, badge } from './ledger-views.js';

export const SEVERITIES = Object.freeze(['critical', 'high', 'warning', 'info']);
const str = (value, max) => (typeof value === 'string' ? value.slice(0, max) : '');
const count = value => (Number.isInteger(value) && value >= 0 ? value : 0);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// The server already bounds and redacts; the adapters only fix the shape, so a malformed snapshot cannot break a panel.
export function adaptAlerts(snapshot) {
  const raw = snapshot && typeof snapshot === 'object' ? snapshot : null;
  const items = (Array.isArray(raw?.items) ? raw.items : []).filter(row => row && typeof row === 'object' && typeof row.key === 'string' && row.key).slice(0, 200).map(row => ({
    key: str(row.key, 200), cls: str(row.cls, 24) || 'other', severity: SEVERITIES.includes(row.severity) ? row.severity : 'info',
    host: str(row.host, 64), message: str(row.message, 600), at: str(row.at, 40), agent: str(row.agent, 40),
    stopBlock: row.stop_block === true, ticket: str(row.ticket, 60),
  }));
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, count(raw?.counts?.[s])]));
  const classes = Object.entries(raw?.classes && typeof raw.classes === 'object' ? raw.classes : {}).slice(0, 24)
    .map(([name, n]) => [str(name, 24), count(n)]).filter(([name, n]) => name && n > 0).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return { read: !!raw, at: str(raw?.at, 40), stale: raw?.stale === true, error: str(raw?.error, 200), items,
    total: Math.max(count(raw?.total), items.length), truncated: raw?.truncated === true, counts, classes };
}

export function adaptCapacity(snapshot) {
  const raw = snapshot && typeof snapshot === 'object' ? snapshot : null;
  const cap = Number.isInteger(raw?.cap) && raw.cap > 0 ? raw.cap : null;
  return { read: !!raw, cap, live: count(raw?.live), silent: count(raw?.silent), decisions: count(raw?.decisions),
    over: raw?.over === true && cap !== null, source: str(raw?.source, 40) || 'owner source' };
}

export function capacityLine(state) {
  const c = state.capacity;
  if (!c.read) return [el('p', 'empty', 'Owner capacity has not been read yet.')];
  const line = el('p', `capacity${c.over ? ' over' : ''}`);
  const parts = [c.cap === null ? `${plural(c.live, 'live owner', 'live owners')} · cap not known` : `Owner slots: ${c.live} of ${c.cap} live`];
  if (c.over) parts.push('over the cap: finish or hand off an owner before starting another');
  if (c.silent) parts.push(`${c.silent} silent`);
  if (c.decisions) parts.push(c.decisions === 1 ? '1 needs a decision' : `${c.decisions} need a decision`);
  parts.push(`from ${c.source}; the spawn gate keeps its own count`);
  line.textContent = parts.join(' · ');
  return [line];
}

export function alertsPanel(state, ui) {
  const a = state.alerts;
  if (!a.read) return [el('p', 'empty', 'Ops alerts have not been read yet.')];
  if (!a.at) return [el('p', 'empty', a.error ? `Ops alerts could not be read (${a.error}). The alert state is not known.` : 'Ops alerts have not been read yet.')];
  const out = [];
  if (a.stale) out.push(el('p', 'stale-note', `Showing the last good read, from ${age(a.at, state.now)}. The newest read failed: ${a.error || 'no reason given'}.`));
  if (!a.total) { out.push(el('p', 'empty', 'No active alerts.')); return out; }
  const bySeverity = SEVERITIES.filter(s => a.counts[s]).map(s => `${a.counts[s]} ${s}`).join(' · ');
  out.push(el('p', 'alerts-summary', `${a.total} active${bySeverity ? `: ${bySeverity}` : ''}`));
  if (a.classes.length) out.push(el('p', 'alerts-classes', `By kind: ${a.classes.map(([name, n]) => `${name} ${n}`).join(' · ')}`));

  const chips = el('div', 'alert-filters');
  chips.setAttribute('role', 'group');
  chips.setAttribute('aria-label', 'Filter alerts by severity');
  ['all', ...SEVERITIES].forEach(severity => {
    const chip = button('filter-chip', severity === 'all' ? 'All' : severity, () => ui.set('alertSeverity', severity));
    chip.dataset.severity = severity;
    chip.setAttribute('aria-pressed', String(ui.alertSeverity === severity));
    chips.append(chip);
  });
  out.push(chips);

  const shown = a.items.filter(row => ui.alertSeverity === 'all' || row.severity === ui.alertSeverity);
  if (!shown.length) out.push(el('p', 'empty', `No ${ui.alertSeverity} alerts in the rows read.`));
  const list = el('ul', 'blockers alerts');
  shown.slice(0, ui.alertsLimit).forEach(row => {
    const item = el('li', `blocker alert-row sev-${row.severity}`);
    item.dataset.id = row.key;
    const title = el('span', 'blocker-title');
    title.append(badge(row.severity, `kind sev-${row.severity}`), ` ${row.key}`);
    const meta = [row.host, row.at ? age(row.at, state.now) : 'time unknown', row.stopBlock ? 'blocks main from stopping' : '', row.ticket, row.agent ? `owner ${row.agent.slice(0, 16)}` : ''];
    item.append(title, longText(row.message, 'blocker-text', 200), el('span', 'blocker-meta', meta.filter(Boolean).join(' · ')));
    list.append(item);
  });
  out.push(list);
  if (shown.length > ui.alertsLimit) out.push(button('more-button', `Show ${shown.length - ui.alertsLimit} more`, () => ui.more('alertsLimit')));
  if (a.truncated || a.total > a.items.length) out.push(el('p', 'alerts-note', `Rows are the first ${a.items.length} of ${a.total}, most severe first. The counts cover all of them.`));
  return out;
}
