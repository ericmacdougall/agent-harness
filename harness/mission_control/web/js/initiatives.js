import { getState, subscribe, select, highlight } from './store.js';
import { el, button, progress, checklist, eta, stateClass } from './ui.js';

export function mountInitiatives() {
  const list = document.getElementById('initiatives-list');
  function render(state) {
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
      const owner = state.owners.find(owner => owner.initiative_id === item.id && owner.state === 'live') || state.owners.find(owner => owner.initiative_id === item.id);
      const ownerLine = el('div', 'initiative-owner');
      ownerLine.append(el('span', '', owner?.runtime === 'codex' ? '◇' : '✳'), el('span', '', owner ? `${owner.name} · ${owner.runtime} · ${owner.state}` : (item.owner || 'no owner')));
      const line = el('div', 'progress-line');
      line.append(progress(item), el('span', `progress-pct${item.pct === null ? ' unknown' : ''}`, item.pct === null ? '—' : `${item.pct}%`));
      const next = el('p', 'initiative-next');
      next.append(el('strong', '', 'Next  '), document.createTextNode(item.next_step || 'not set'));
      const estimates = el('div', 'initiative-estimates');
      estimates.append(el('p', 'eta', eta(item.next_eta, item.estimate_by, 'Next')), el('p', 'eta', eta(item.full_eta, item.estimate_by, 'Done')));
      card.append(top, title, ownerLine, line, checklist(item, expanded.has(item.id)), next, estimates);
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
  subscribe((state, reason) => {
    if (reason === 'initiatives' || reason === 'owners') render(state);
    if (reason === 'highlight') list.querySelectorAll('article').forEach(card => card.classList.toggle('is-highlighted', card.dataset.id === state.highlight));
  });
}
