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
      top.append(el('span', 'ticket-id', item.ticket), el('span', `state-badge ${stateClass(item.state)}`, item.state));
      const title = button('initiative-title', '', () => select('initiative', item.id));
      title.setAttribute('aria-label', `Open ${item.initiative} details`);
      title.append(el('span', '', item.initiative), el('span', '', '↗'));
      title.addEventListener('focus', () => highlight(item.id));
      title.addEventListener('blur', () => highlight(null));
      card.addEventListener('pointerenter', () => highlight(item.id));
      card.addEventListener('pointerleave', () => highlight(null));
      const owner = state.owners.find(owner => owner.agent_id === item.owner);
      const ownerLine = el('div', 'initiative-owner');
      ownerLine.append(el('span', '', owner?.runtime === 'claude' ? '✳' : '◇'), el('span', '', `${item.owner} · ${owner?.runtime || 'coordinator'}`));
      const line = el('div', 'progress-line');
      line.append(progress(item), el('span', `progress-pct${item.pct === null ? ' unknown' : ''}`, item.pct === null ? 'checking' : `${item.pct}%`));
      const next = el('p', 'initiative-next');
      next.append(el('strong', '', 'Next  '), document.createTextNode(item.next_step));
      const estimates = el('div', 'initiative-estimates');
      estimates.append(el('p', 'eta', eta(item.next_eta, item.estimate_by, 'Next')), el('p', 'eta', eta(item.full_eta, item.estimate_by, 'Done')));
      card.append(top, title, ownerLine, line, checklist(item, expanded.has(item.id)), next, estimates);
      if (['At risk', 'Blocked'].includes(item.state)) card.append(el('p', 'initiative-note', item.state === 'Blocked' ? '↳ Runner needs reassignment' : '↳ Coordinator decision needed'));
      fragment.append(card);
    });
    list.replaceChildren(fragment);
    document.getElementById('initiative-count').textContent = String(state.initiatives.length).padStart(2, '0');
  }
  render(getState());
  subscribe((state, reason) => {
    if (reason === 'initiatives' || reason === 'seed') render(state);
    if (reason === 'highlight') list.querySelectorAll('article').forEach(card => card.classList.toggle('is-highlighted', card.dataset.id === state.highlight));
  });
}
