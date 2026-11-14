import { getState, subscribe, select, update, highlight } from './store.js';
import { el, button, age, freshness, stateClass } from './ui.js';
import { ownerGroups, ownerCounts, foldLabel, summaryLine, isHelper } from './owner-groups.js';

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

// Make a container's element children exactly `nodes`, moving only what is out of place: a moved node loses focus.
export function syncChildren(container, nodes) {
  nodes.forEach((node, index) => { if (container.children[index] !== node) container.insertBefore(node, container.children[index] || null); });
  while (container.children.length > nodes.length) container.children[container.children.length - 1].remove();
}

// How a helper row names the owner it serves (helpers never count; they sit under their owner).
export function helperLine(helper, owner) {
  const kind = helper.type || 'helper';
  return owner ? `Helper (${kind}) for ${owner.name}` : `Helper (${kind}), no owner found`;
}

export function mountOwners() {
  const list = document.getElementById('owners-list');
  const summary = document.getElementById('owner-summary');
  const rows = new Map();     // agent_id -> row parts, reused across renders so focus and hover survive
  const groups = new Map();   // initiative id -> group parts (the fold button is never rebuilt)
  let seq = 0, mode = '';
  const emptyState = el('p', 'empty-state');
  document.getElementById('owners-more').addEventListener('click', () => update({ ownersAll: !getState().ownersAll }, 'owner-filter'));
  document.getElementById('owner-filter').addEventListener('change', event => update({ ownerFilter: event.target.value }, 'owner-filter'));

  function rowFor(owner, state, servedBy) {
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
      parts = { row, status, task, note, time, runtime, avatar, hold, name };
      rows.set(owner.agent_id, parts);
    }
    const helper = isHelper(owner);
    parts.row.className = helper ? 'helper-row' : 'owner-row';
    parts.row.classList.toggle('owner-severe', !!owner.severe);
    parts.row.classList.toggle('owner-held', !!owner.held);
    parts.name.textContent = owner.name;
    const holdText = holdLine(owner);
    parts.hold.textContent = holdText;
    parts.hold.hidden = !holdText;
    parts.runtime.textContent = `${owner.runtime === 'claude' ? 'Claude' : owner.runtime === 'codex' ? 'OpenAI' : 'Harness unknown'} · ${owner.model || 'model unknown'}`;
    parts.avatar.className = `runtime-avatar ${owner.runtime}`;
    parts.avatar.textContent = owner.runtime === 'claude' ? '✳' : '◇';
    parts.status.textContent = owner.severe ? `! ${owner.state}` : owner.held ? `${owner.state} · ${owner.disposition?.live ? owner.disposition.kind : 'waiting'}` : `${owner.state === 'live' ? '• ' : ''}${owner.state}`;
    parts.status.className = `owner-state ${owner.held ? 'held' : stateClass(owner.state)}`;
    const observationAge = owner.observed_at ? (state.now - Date.parse(owner.observed_at)) / 1000 : null;
    const native = observationAge === null ? '' : observationAge >= 0 && observationAge <= 120 && !owner.source_stale
      ? `Native ${owner.native_status || 'unknown'} observed ${new Date(owner.observed_at).toLocaleTimeString()}`
      : `Native observation stale/unknown (${new Date(owner.observed_at).toLocaleTimeString()})`;
    const role = helper ? helperLine(owner, servedBy) : owner.role === 'live' ? '' : owner.decision_required ? 'Parked, decision required' : '';
    parts.task.textContent = [role, owner.stream || owner.task, owner.ticket, native, owner.source_stale ? 'STALE SOURCE' : ''].filter(Boolean).join(' · ');
    parts.note.textContent = owner.last_item.note;
    parts.time.dateTime = owner.last_item.active || '';
    parts.time.title = owner.last_item.at ? `Work item written ${new Date(owner.last_item.at).toLocaleString()}` : 'No work item yet';
    parts.time.textContent = age(owner.last_item.active, state.now);
    parts.time.className = `owner-age ${freshness(owner.last_item.active, state.now)}`;
    parts.row.setAttribute('aria-label', `${role ? `${role}. ` : ''}${owner.name}, ${owner.runtime}, ${owner.state}. ${owner.task}. ${holdText ? `${holdText}. ` : ''}Last work item: ${owner.last_item.note}. Last active ${age(owner.last_item.active, state.now)}. Open details.`);
    return parts.row;
  }

  // Every filter but the default is the flat list it always was (all owners, by state, Codex).
  function renderFlat(state, used) {
    const severe = owner => owner.severe;
    const rank = owner => severe(owner) ? 0 : owner.type === 'project' || owner.state === 'live' ? 1 : owner.runtime === 'codex' ? 3 : 2;
    const active = owner => owner.severe || owner.held || ACTIVE.test(owner.state);
    const matches = owner => state.ownerFilter === 'all' || (state.ownerFilter === 'active' ? active(owner)
      : owner.state.startsWith(state.ownerFilter) || (state.ownerFilter === 'codex' && owner.runtime === 'codex'));
    const all = state.owners.filter(matches);
    const owners = all.slice().sort((a, b) => rank(a) - rank(b) || Date.parse(b.last_item.active || 0) - Date.parse(a.last_item.active || 0))
      .slice(0, state.ownersAll ? all.length : OWNERS_SHOWN);
    const more = document.getElementById('owners-more');
    more.hidden = all.length <= OWNERS_SHOWN;
    more.textContent = state.ownersAll ? 'Show fewer owners' : `Show all ${all.length} rows`;
    more.setAttribute('aria-expanded', String(!!state.ownersAll));
    const nodes = owners.map(owner => { used.add(owner.agent_id); return rowFor(owner, state, null); });
    emptyState.textContent = state.owners.length ? 'No owners in this state.' : 'Waiting for the owner list…';
    syncChildren(list, nodes.length ? nodes : [emptyState]);
  }

  // Default: live owners grouped by initiative; each group folds its parked/history rows behind one button.
  function renderGrouped(state, used, placed) {
    document.getElementById('owners-more').hidden = true;
    const folds = state.ownerFolds || {};
    const layout = ownerGroups(state.owners, state.initiatives);
    const place = (owner, group, servedBy) => { used.add(owner.agent_id); placed.set(owner.agent_id, group.id); return rowFor(owner, state, servedBy); };
    const sections = layout.map(group => {
      let parts = groups.get(group.id);
      if (!parts) {
        const n = ++seq, id = group.id;
        const section = el('section', 'owner-group'), heading = el('h3', 'owner-group-title');
        heading.id = `owner-group-${n}`;
        section.setAttribute('aria-labelledby', heading.id);
        section.dataset.group = id;
        const liveBox = el('div', 'owner-group-live'), empty = el('p', 'owner-group-empty', 'No live owner in this initiative.');
        const fold = button('owner-fold', '', () => {
          const current = getState().ownerFolds || {};
          update({ ownerFolds: { ...current, [id]: !current[id] } }, 'owner-filter');
        });
        const body = el('div', 'owner-fold-body');
        body.id = `owner-fold-${n}`;
        body.hidden = true;
        fold.setAttribute('aria-controls', body.id);
        section.append(heading, liveBox, fold, body);
        parts = { section, heading, liveBox, empty, fold, body };
        groups.set(id, parts);
      }
      parts.heading.textContent = `${group.label} · ${group.liveCount} live${group.decide.length ? ` · ${group.decide.length} need a decision` : ''}`;
      const liveNodes = [...group.live, ...group.decide].flatMap(entry => [place(entry.owner, group, null), ...entry.helpers.map(h => place(h, group, entry.owner))]);
      syncChildren(parts.liveBox, liveNodes.length ? liveNodes : [parts.empty]);
      const open = Boolean(folds[group.id]) && group.foldCount > 0;
      parts.fold.hidden = group.foldCount === 0;
      parts.fold.textContent = foldLabel(group);
      parts.fold.setAttribute('aria-expanded', String(open));
      parts.fold.classList.toggle('needs-attention', group.attention > 0);
      parts.body.hidden = !open;
      const foldNodes = !open ? [] : [
        ...group.parked.flatMap(entry => [place(entry.owner, group, null), ...entry.helpers.map(h => place(h, group, entry.owner))]),
        ...[...group.live, ...group.decide].flatMap(entry => entry.doneHelpers.map(h => place(h, group, entry.owner))),
        ...group.loose.map(h => place(h, group, null)),
      ];
      syncChildren(parts.body, foldNodes);
      return parts.section;
    });
    for (const id of [...groups.keys()]) if (!layout.some(group => group.id === id)) groups.delete(id);
    emptyState.textContent = 'Waiting for the owner list…';
    syncChildren(list, sections.length ? sections : [emptyState]);
  }

  let lastPlaced = new Map();
  function render(state) {
    const grouped = state.ownerFilter === 'active';
    if (mode !== (grouped ? 'grouped' : 'flat')) { list.replaceChildren(); groups.clear(); mode = grouped ? 'grouped' : 'flat'; }
    const focused = document.activeElement;
    const focusedId = focused && list.contains(focused) ? focused.dataset?.id : null;
    const used = new Set(), placed = new Map();
    if (grouped) renderGrouped(state, used, placed); else renderFlat(state, used);
    for (const id of [...rows.keys()]) if (!used.has(id)) rows.delete(id);
    // a focused row that folded away or vanished hands focus to its group's fold button, never to the page body
    if (focusedId && !focused.isConnected) groups.get(lastPlaced.get(focusedId))?.fold.focus();
    lastPlaced = placed.size ? placed : lastPlaced;
    const counts = ownerCounts(state.owners);
    const stale = state.owners.some(owner => owner.source === 'ah' && owner.source_stale);
    const session = state.owners.find(owner => owner.source === 'ah' && owner.session)?.session || '';
    const count = document.getElementById('owner-count');
    count.textContent = String(counts.live).padStart(2, '0');
    count.title = summaryLine(counts, { session, stale });
    if (summary) summary.textContent = summaryLine(counts, { session, stale });
  }
  render(getState());
  subscribe((state, reason) => {
    if (['event', 'owners', 'owner-filter', 'initiatives'].includes(reason)) render(state);
    if (reason === 'tick') rows.forEach(({ time }) => { time.textContent = age(time.dateTime, state.now); time.className = `owner-age ${freshness(time.dateTime, state.now)}`; });
    if (reason === 'highlight') rows.forEach(({ row }, id) => row.classList.toggle('is-highlighted', id === state.highlight));
  });
}
