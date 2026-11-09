import { getState, subscribe, select, update, highlight } from './store.js';
import { el, button, age, freshness, stateClass } from './ui.js';

export function mountOwners() {
  const list = document.getElementById('owners-list');
  const rows = new Map();
  document.getElementById('owner-filter').addEventListener('change', event => update({ ownerFilter: event.target.value }, 'owner-filter'));
  function render(state) {
    const owners = state.owners.filter(owner => state.ownerFilter === 'all' || owner.state === state.ownerFilter);
    const wanted = new Set(owners.map(owner => owner.agent_id));
    for (const [id, parts] of rows) if (!wanted.has(id)) { parts.row.remove(); rows.delete(id); }
    list.querySelector('.empty-state')?.remove();
    owners.forEach((owner, index) => {
      let parts = rows.get(owner.agent_id);
      if (!parts) {
        const row = button('owner-row', '', () => select('owner', owner.agent_id));
        row.dataset.id = owner.agent_id;
        row.addEventListener('focus', () => highlight(owner.agent_id));
        row.addEventListener('blur', () => highlight(null));
        row.addEventListener('pointerenter', () => highlight(owner.agent_id));
        row.addEventListener('pointerleave', () => highlight(null));
        const avatar = el('span', `runtime-avatar ${owner.runtime}`, owner.runtime === 'claude' ? '✳' : '◇');
        avatar.setAttribute('aria-hidden', 'true');
        const info = el('div', 'owner-info'), nameRow = el('div', 'owner-name-row');
        const name = el('span', 'owner-name', owner.agent_id), status = el('span', 'owner-state');
        nameRow.append(name, status);
        const task = el('div', 'owner-task', owner.task), last = el('div', 'owner-last');
        const note = el('span', 'owner-last-note'), time = el('time', 'owner-age');
        last.append(note, time); info.append(nameRow, task, last); row.append(avatar, info);
        parts = { row, status, task, note, time };
        rows.set(owner.agent_id, parts);
        list.insertBefore(row, list.children[index] || null);
      }
      parts.status.textContent = owner.state === 'DROPPED' ? '× dropped' : `${owner.state === 'live' ? '• ' : ''}${owner.state}`;
      parts.status.className = `owner-state ${stateClass(owner.state)}`;
      parts.task.textContent = owner.task;
      parts.note.textContent = owner.last_item.note;
      parts.time.dateTime = owner.last_item.at;
      parts.time.textContent = age(owner.last_item.at, state.now);
      parts.time.className = `owner-age ${freshness(owner.last_item.at, state.now)}`;
      parts.row.setAttribute('aria-label', `${owner.agent_id}, ${owner.runtime}, ${owner.state}. ${owner.task}. Last work: ${owner.last_item.note}, ${age(owner.last_item.at, state.now)}. Open details.`);
    });
    if (!owners.length) list.append(el('p', 'empty-state', 'No owners in this state.'));
    document.getElementById('owner-count').textContent = String(state.owners.length).padStart(2, '0');
  }
  render(getState());
  subscribe((state, reason) => {
    if (['event','owners','owner-filter','seed'].includes(reason)) render(state);
    if (reason === 'tick') rows.forEach(({ time }) => { time.textContent = age(time.dateTime, state.now); time.className = `owner-age ${freshness(time.dateTime, state.now)}`; });
    if (reason === 'highlight') rows.forEach(({ row }, id) => row.classList.toggle('is-highlighted', id === state.highlight));
  });
}
