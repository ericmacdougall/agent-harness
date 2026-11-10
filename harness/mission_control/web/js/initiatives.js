import { getState, subscribe, select, highlight } from './store.js';
import { el, button, progress, checklist, eta, stateClass, age } from './ui.js';
import { liveFields, atRisk } from './adapt.js';

const LABEL = { uncovered: 'UNCOVERED', stalled: 'STALLED', moving: 'moving' };
function sinceText(row, now) {
  if (!row.last) return 'no progress recorded';
  return `progress ${age(row.last, now)}`;
}
// The strip that answers "what is moving slowest" without being asked: UNCOVERED first, then STALLED, oldest progress
// first, each with why and what main is doing about it. "No action recorded" is shown as a problem, not hidden.
function renderAtRisk(state) {
  const box = document.getElementById('at-risk-list');
  if (!box) return;
  const rows = atRisk(state.initiatives, state.owners, state.events, state.now, state.coverage || null);
  const fragment = document.createDocumentFragment();
  for (const row of rows) {
    const item = el('li', `at-risk-item ${row.status}`);
    const top = el('div', 'at-risk-top');
    top.append(el('span', `at-risk-badge ${row.status}`, LABEL[row.status]), el('span', 'ticket-id', row.ticket || 'no ticket'),
      el('span', 'at-risk-since', sinceText(row, state.now)));
    const title = button('at-risk-title', row.initiative || row.id, () => select('initiative', row.id));
    title.setAttribute('aria-label', `${LABEL[row.status]}: ${row.initiative}. Open details`);
    const action = el('p', `at-risk-action${row.action ? '' : ' none'}`, row.action ? `Main: ${row.action}` : 'Main: no action recorded');
    item.append(top, title, el('p', 'at-risk-reason', row.reason), action);
    fragment.append(item);
  }
  if (!rows.length) fragment.append(el('li', 'empty-state', 'Nothing open to rank.'));
  box.replaceChildren(fragment);
  const flagged = rows.filter(r => r.status !== 'moving').length;
  document.getElementById('at-risk').classList.toggle('has-risk', flagged > 0);
}

export function mountInitiatives() {
  const list = document.getElementById('initiatives-list');
  function render(state) {
    if (!document.getElementById('at-risk')?.contains(document.activeElement)) renderAtRisk(state);
    const expanded = new Set([...list.querySelectorAll('details[open]')].map(item => item.closest('article').dataset.id));
    const fragment = document.createDocumentFragment();
    state.initiatives.forEach(item => {
      const card = el('article', 'initiative-card');
      card.dataset.id = item.id;
      const top = el('div', 'initiative-topline');
      top.append(el('span', 'ticket-id', item.ticket || 'no ticket'), el('span', `state-badge ${stateClass(item.state)}`, item.state));
      const title = button('initiative-title', '', () => select('initiative', item.id));
      title.setAttribute('aria-label', `Open ${item.initiative} details`);
      title.append(el('span', '', item.initiative), el('span', '', '↗'));
      title.addEventListener('focus', () => highlight(item.id));
      title.addEventListener('blur', () => highlight(null));
      card.addEventListener('pointerenter', () => highlight(item.id));
      card.addEventListener('pointerleave', () => highlight(null));
      const live = liveFields(item, state.owners, state.asks, state.events, state.now);
      const owner = live.owner;
      const ownerLine = el('div', 'initiative-owner');
      ownerLine.append(el('span', '', owner?.runtime === 'codex' ? '◇' : '✳'), el('span', '', owner ? `${owner.name} · ${owner.runtime} · ${owner.state}` : (item.owner ? `${item.owner} · no live owner` : 'no owner')));
      const liveBox = el('div', 'initiative-live');
      if (live.note) liveBox.append(el('p', 'initiative-live-note', `“${live.note.text}” · ${live.note.by} · ${age(live.note.at, state.now)}`));
      const facts = [];
      if (live.openAsks) facts.push(`${live.openAsks} open ask${live.openAsks === 1 ? '' : 's'}`);
      if (live.push) facts.push(`last push ${age(live.push.at, state.now)}`);
      if (facts.length) liveBox.append(el('p', 'initiative-live-facts', facts.join(' · ')));
      const updated = el('p', `initiative-updated${live.stale ? ' stale' : ''}`, live.updated ? `Updated ${age(live.updated, state.now)}${live.stale ? ' · no activity for over 30 min' : ''}` : 'No activity recorded');
      liveBox.append(updated);
      const line = el('div', 'progress-line');
      line.append(progress(item), el('span', `progress-pct${item.pct === null ? ' unknown' : ''}`, item.pct === null ? '—' : `${item.pct}%`));
      const next = el('p', 'initiative-next');
      next.append(el('strong', '', 'Next  '), document.createTextNode(item.next_step || 'not set'));
      const estimates = el('div', 'initiative-estimates');
      estimates.append(el('p', 'eta', eta(item.next_eta, item.estimate_by, 'Next')), el('p', 'eta', eta(item.full_eta, item.estimate_by, 'Done')));
      card.classList.toggle('stale-row', live.stale);
      card.append(top, title, ownerLine, liveBox, line, checklist(item, expanded.has(item.id)), next, estimates);
      if (item.error) card.append(el('p', 'initiative-note error', `↳ Data error: ${item.error}`));
      else if (/at risk|blocked/i.test(item.state) && item.note) card.append(el('p', 'initiative-note', `↳ ${item.note.slice(0, 160)}`));
      fragment.append(card);
    });
    if (!state.initiatives.length) fragment.append(el('p', 'empty-state', state.initiativesError ? `Initiatives file: ${state.initiativesError}` : 'Waiting for the initiatives file…'));
    list.replaceChildren(fragment);
    document.getElementById('initiatives-panel').classList.toggle('stale', state.initiativesStale);
    document.getElementById('initiative-count').textContent = String(state.initiatives.length).padStart(2, '0');
  }
  render(getState());
  // ages and the 30-min flag; skipped while the keyboard is inside the list so focus is never lost (L-d)
  setInterval(() => { if (!document.hidden && !list.contains(document.activeElement)) render(getState()); }, 30000);
  subscribe((state, reason) => {
    if (['initiatives', 'owners', 'asks', 'seed'].includes(reason)) render(state);
    if (reason === 'highlight') list.querySelectorAll('article').forEach(card => card.classList.toggle('is-highlighted', card.dataset.id === state.highlight));
  });
}
