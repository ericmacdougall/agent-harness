import { getState, subscribe, select, update, highlight } from './store.js';
import { el, button, age, freshness, stateClass } from './ui.js';

export const OWNERS_SHOWN = 8;
const ACTIVE = /^(live|working|finishing|waiting|blocked|error|offline|observed|stale|unknown)/;

// What the owner itself or a recorded disposition says, beside the ah owners state (never instead of it).
export function holdLine(owner) {
  if (!owner.held) return '';
  if (owner.disposition?.live) {
    const why = owner.disposition.reason || owner.disposition.ref;
    return `Recorded ${owner.disposition.kind}${why ? `: ${why}` : ''}`;
  }
  return owner.waitNote ? `Agent says: ${owner.waitNote}` : '';
}

export function mountOwners() {
  const list = document.getElementById('owners-list');
  const rows = new Map();
  document.getElementById('owners-more').addEventListener('click', () => update({ ownersAll: !getState().ownersAll }, 'owner-filter'));
  document.getElementById('owner-filter').addEventListener('change', event => update({ ownerFilter: event.target.value }, 'owner-filter'));
  function render(state) {
    const severe = owner => owner.severe;
    const rank = owner => owner.severe ? 0 : owner.type === 'project' || owner.state === 'live' ? 1 : owner.runtime === 'codex' ? 3 : 2;
    const active = owner => owner.severe || owner.held || ACTIVE.test(owner.state);
    const matches = owner => state.ownerFilter === 'all' || (state.ownerFilter === 'active' ? active(owner)
      : owner.state.startsWith(state.ownerFilter) || (state.ownerFilter === 'codex' && owner.runtime === 'codex'));
    const owners = state.owners.filter(matches)
      .sort((a, b) => rank(a) - rank(b) || Date.parse(b.last_item.active || 0) - Date.parse(a.last_item.active || 0)).slice(0, state.ownersAll ? 80 : OWNERS_SHOWN);
    const total = state.owners.filter(matches).length;
    const more = document.getElementById('owners-more');
    more.hidden = total <= OWNERS_SHOWN;
    more.textContent = state.ownersAll ? 'Show fewer owners' : `Show all ${total} owners`;
    more.setAttribute('aria-expanded', String(!!state.ownersAll));
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
        const name = el('span', 'owner-name', owner.name), status = el('span', 'owner-state');
        const runtime = el('span', 'owner-runtime');
        nameRow.append(name, runtime, status);
        const task = el('div', 'owner-task', owner.task), last = el('div', 'owner-last');
        const note = el('span', 'owner-last-note'), time = el('time', 'owner-age');
        const hold = el('div', 'owner-hold');
        last.append(note, time); info.append(nameRow, task, hold, last); row.append(avatar, info);
        parts = { row, status, task, note, time, runtime, avatar, hold };
        rows.set(owner.agent_id, parts);
        list.insertBefore(row, list.children[index] || null);
      }
      if (list.children[index] !== parts.row) list.insertBefore(parts.row, list.children[index] || null);
      parts.row.classList.toggle('owner-severe', severe(owner));
      parts.row.classList.toggle('owner-held', owner.held);
      const holdText = holdLine(owner);
      parts.hold.textContent = holdText;
      parts.hold.hidden = !holdText;
      parts.runtime.textContent = `${owner.runtime === 'claude' ? 'Claude' : owner.runtime === 'codex' ? 'OpenAI' : 'Harness unknown'} · ${owner.model || 'model unknown'}`;
      parts.avatar.className = `runtime-avatar ${owner.runtime}`;
      parts.avatar.textContent = owner.runtime === 'claude' ? '✳' : '◇';
      parts.status.textContent = severe(owner) ? `! ${owner.state}` : owner.held ? `${owner.state} · ${owner.disposition?.live ? owner.disposition.kind : 'waiting'}` : `${owner.state === 'live' ? '• ' : ''}${owner.state}`;
      parts.status.className = `owner-state ${owner.held ? 'held' : stateClass(owner.state)}`;
      const observationAge = owner.observed_at ? (state.now - Date.parse(owner.observed_at)) / 1000 : null;
      const native = observationAge === null ? '' : observationAge >= 0 && observationAge <= 120 && !owner.source_stale
        ? `Native ${owner.native_status || 'unknown'} observed ${new Date(owner.observed_at).toLocaleTimeString()}`
        : `Native observation stale/unknown (${new Date(owner.observed_at).toLocaleTimeString()})`;
      parts.task.textContent = [owner.stream || owner.task, owner.ticket, native, owner.source_stale ? 'STALE SOURCE' : ''].filter(Boolean).join(' · ');
      parts.note.textContent = owner.last_item.note;
      parts.time.dateTime = owner.last_item.active || '';
      parts.time.title = owner.last_item.at ? `Work item written ${new Date(owner.last_item.at).toLocaleString()}` : 'No work item yet';
      parts.time.textContent = age(owner.last_item.active, state.now);
      parts.time.className = `owner-age ${freshness(owner.last_item.active, state.now)}`;
      parts.row.setAttribute('aria-label', `${owner.name}, ${owner.runtime}, ${owner.state}. ${owner.task}. ${holdText ? `${holdText}. ` : ''}Last work item: ${owner.last_item.note}. Last active ${age(owner.last_item.active, state.now)}. Open details.`);
    });
    if (!owners.length) list.append(el('p', 'empty-state', state.owners.length ? 'No owners in this state.' : 'Waiting for the owner list…'));
    const count = document.getElementById('owner-count');
    count.textContent = String(owners.length).padStart(2, '0');
    count.title = `${owners.length} shown of ${total} matching, ${state.owners.length} owners in all`;
  }
  render(getState());
  subscribe((state, reason) => {
    if (['event','owners','owner-filter'].includes(reason)) render(state);
    if (reason === 'tick') rows.forEach(({ time }) => { time.textContent = age(time.dateTime, state.now); time.className = `owner-age ${freshness(time.dateTime, state.now)}`; });
    if (reason === 'highlight') rows.forEach(({ row }, id) => row.classList.toggle('is-highlighted', id === state.highlight));
  });
}
