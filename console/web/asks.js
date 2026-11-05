// Asks / Owners / Requirements view. Read-only: it only GETs /api/asks-view and renders text with textContent.
const TABS = [['asks', 'Asks'], ['owners', 'Owners'], ['requirements', 'Requirements']];
const REFRESH_MS = 30000;
const PAGE = 150;
const AGE = [['any', 'Any age'], ['lt1h', 'Under 1 hour'], ['gt1h', 'Over 1 hour'], ['gt24h', 'Over 24 hours']];
const ASK_ORDER = ['blocked', 'waiting-on-user', 'open', 'stale', 'assumption', 'resolved'];
const OWNER_QUIET = new Set(['done', 'returned', 'idle-helper', 'handoff']);
const OWNER_ORDER = ['DROPPED', 'SILENT', 'quiet', 'live', 'finishing'];

export function fmtAge(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '-';
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
  if (seconds < 129600) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

export function ageMatches(filter, seconds) {
  if (filter === 'any') return true;
  if (!Number.isFinite(seconds)) return false;
  if (filter === 'lt1h') return seconds < 3600;
  if (filter === 'gt1h') return seconds >= 3600;
  return seconds >= 86400;
}

export function rowState(tab, row) {
  return String(row.state || 'unknown');
}

export function stateMatches(tab, filter, row) {
  const state = rowState(tab, row);
  if (filter === 'all') return true;
  if (filter === 'attention' && tab === 'owners') return !OWNER_QUIET.has(state);
  if (filter === 'unresolved' && tab === 'asks') return state !== 'resolved';
  return state === filter;
}

export function sortRows(tab, rows) {
  const order = tab === 'asks' ? ASK_ORDER : tab === 'owners' ? OWNER_ORDER : [];
  const rank = row => { const i = order.indexOf(rowState(tab, row)); return i < 0 ? order.length : i; };
  return [...rows].sort((a, b) => rank(a) - rank(b) || (b.age_s ?? b.idle_s ?? -1) - (a.age_s ?? a.idle_s ?? -1));
}

export function openAsksView({ api, el }) {
  const dialog = document.querySelector('#asks-dialog');
  const body = dialog.querySelector('#asks-content');
  const view = { tab: 'asks', data: null, session: 'all', state: { asks: 'all', owners: 'attention', requirements: 'all' }, age: 'any', text: '', shown: PAGE, generation: 0, timer: 0 };

  function shell() {
    body.replaceChildren();
    const tablist = el('div', 'asks-tabs');
    tablist.setAttribute('role', 'tablist');
    tablist.setAttribute('aria-label', 'Asks views');
    for (const [id, label] of TABS) {
      const tab = el('button', 'asks-tab');
      tab.type = 'button';
      tab.id = `asks-tab-${id}`;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', 'asks-panel');
      tab.dataset.tab = id;
      tab.append(el('span', '', label), el('span', 'asks-count'));
      tab.addEventListener('click', () => select(id, false));
      tab.addEventListener('keydown', event => {
        const i = TABS.findIndex(([t]) => t === view.tab);
        const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[event.key];
        if (next === undefined) return;
        event.preventDefault();
        select(TABS[(next + TABS.length) % TABS.length][0], true);
      });
      tablist.append(tab);
    }
    const filters = el('div', 'asks-filters');
    filters.setAttribute('role', 'group');
    filters.setAttribute('aria-label', 'Filters');
    filters.append(
      field('Session', 'asks-session', [['all', 'All sessions']], value => { view.session = value; refresh(true); }),
      field('State', 'asks-state', [], value => { view.state[view.tab] = value; view.shown = PAGE; renderList(); }),
      field('Age', 'asks-age', AGE, value => { view.age = value; view.shown = PAGE; renderList(); }),
    );
    const search = el('div', 'asks-field');
    const label = el('label', '', 'Search');
    label.htmlFor = 'asks-search';
    const input = el('input');
    input.id = 'asks-search';
    input.type = 'search';
    input.autocomplete = 'off';
    input.addEventListener('input', () => { view.text = input.value.trim().toLowerCase(); view.shown = PAGE; renderList(); });
    search.append(label, input);
    filters.append(search);
    const refreshButton = el('button', 'quiet-button', 'Refresh now');
    refreshButton.type = 'button';
    refreshButton.id = 'asks-refresh';
    refreshButton.addEventListener('click', () => refresh(true));
    const status = el('p', 'asks-status', 'Loading…');
    status.id = 'asks-status';
    status.setAttribute('role', 'status');
    const panel = el('div', 'asks-panel');
    panel.id = 'asks-panel';
    panel.setAttribute('role', 'tabpanel');
    panel.tabIndex = 0;
    panel.setAttribute("aria-label", "Results");
    body.append(tablist, filters, el('div', 'asks-statusbar'), panel);
    body.querySelector('.asks-statusbar').append(status, refreshButton);
    syncTabs();
  }

  function field(label, id, options, onChange) {
    const wrap = el('div', 'asks-field');
    const l = el('label', '', label);
    l.htmlFor = id;
    const select = el('select');
    select.id = id;
    fillSelect(select, options);
    select.addEventListener('change', () => onChange(select.value));
    wrap.append(l, select);
    return wrap;
  }

  function fillSelect(select, options) {
    const keep = select.value;
    select.replaceChildren(...options.map(([value, text]) => { const o = el('option', '', text); o.value = value; return o; }));
    if (options.some(([v]) => v === keep)) select.value = keep;
  }

  function stateOptions() {
    const rows = section().rows;
    const seen = [...new Set(rows.map(r => rowState(view.tab, r)))];
    const order = view.tab === 'asks' ? ASK_ORDER : view.tab === 'owners' ? OWNER_ORDER : [];
    seen.sort((a, b) => { const x = order.indexOf(a), y = order.indexOf(b); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y) || a.localeCompare(b); });
    const lead = [['all', 'All states']];
    if (view.tab === 'owners') lead.unshift(['attention', 'Needs attention (not done/returned)']);
    if (view.tab === 'asks') lead.unshift(['unresolved', 'Unresolved']);
    return [...lead, ...seen.map(s => [s, s])];
  }

  function section() {
    const s = view.data && view.data[view.tab];
    return s && Array.isArray(s.rows) ? s : { rows: [], error: view.data ? 'unavailable: no data' : '' };
  }

  function syncTabs() {
    for (const tab of body.querySelectorAll('[role=tab]')) {
      const active = tab.dataset.tab === view.tab;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
      const sec = view.data && view.data[tab.dataset.tab];
      tab.querySelector('.asks-count').textContent = sec && Array.isArray(sec.rows) && !sec.error ? ` ${sec.rows.length}` : '';
    }
    const panel = body.querySelector('#asks-panel');
    if (panel) panel.setAttribute('aria-labelledby', `asks-tab-${view.tab}`);
  }

  function select(tab, focus) {
    view.tab = tab;
    view.shown = PAGE;
    syncTabs();
    syncFilters();
    renderList();
    if (focus) body.querySelector(`#asks-tab-${tab}`).focus();
  }

  function syncFilters() {
    const stateSelect = body.querySelector('#asks-state');
    fillSelect(stateSelect, stateOptions());
    if (![...stateSelect.options].some(o => o.value === view.state[view.tab])) view.state[view.tab] = 'all';
    stateSelect.value = view.state[view.tab];
    const sessions = new Set();
    for (const [id] of TABS) for (const r of (view.data?.[id]?.rows || [])) if (r.session) sessions.add(r.session);
    const sessionSelect = body.querySelector('#asks-session');
    fillSelect(sessionSelect, [['all', 'All sessions'], ...[...sessions].sort().map(s => [s, `${s.slice(0, 8)}…`])]);
    if (view.session !== 'all' && ![...sessionSelect.options].some(o => o.value === view.session)) {
      const o = el('option', '', `${view.session.slice(0, 8)}…`);
      o.value = view.session;
      sessionSelect.append(o);
    }
    sessionSelect.value = view.session;
  }

  function matches(row) {
    if (!stateMatches(view.tab, view.state[view.tab], row)) return false;
    if (!ageMatches(view.age, row.age_s ?? row.idle_s)) return false;
    if (!view.text) return true;
    return [row.id, row.text, row.task, row.agent_id, row.owner, row.ticket, row.source].some(v => typeof v === 'string' && v.toLowerCase().includes(view.text));
  }

  function badge(state) {
    const b = el('span', `asks-badge asks-state-${state.replace(/[^A-Za-z0-9-]/g, '')}`, state);
    return b;
  }

  function dl(pairs) {
    const list = el('dl', 'asks-meta');
    for (const [k, v] of pairs) {
      if (v === undefined || v === null || v === '') continue;
      const wrap = el('div');
      wrap.append(el('dt', '', k), el('dd', '', v));
      list.append(wrap);
    }
    return list;
  }

  function card(row) {
    const li = el('li', 'asks-row');
    const head = el('div', 'asks-row-head');
    const state = rowState(view.tab, row);
    head.append(badge(state), el('code', 'asks-id', row.id));
    const age = view.tab === 'owners' ? row.idle_s : row.age_s;
    head.append(el('span', 'asks-age', `${view.tab === 'owners' ? 'idle ' : ''}${fmtAge(age)}`));
    li.append(head);
    if (view.tab === 'asks') {
      li.append(el('p', 'asks-text', row.text || '(no text)'));
      li.append(dl([['Why', row.why], ['Owner', row.owner], ['Source', row.source_label ? `${row.source_label}: ${row.source}` : row.source],
        ['Session', row.session && row.session.slice(0, 8)], ['Surfaced', row.surfaced_count === null || row.surfaced_count === undefined ? 'not tracked' : `${row.surfaced_count}x`],
        ['Resolved', row.resolved_at]]));
    } else if (view.tab === 'owners') {
      li.append(el('p', 'asks-text', row.task || row.type || '(no task recorded)'));
      const d = row.disposition;
      li.append(dl([['Agent', row.agent_id], ['Type', row.type], ['Severity', row.severity], ['Ticket', row.ticket],
        ['Disposition', d ? [d.kind, d.ref && `ref ${d.ref}`, d.until && `until ${d.until}`, d.reason].filter(Boolean).join(' - ') : 'none'],
        ['Needs decision', row.decision_required ? 'yes' : ''], ['Session', row.session && row.session.slice(0, 8)]]));
    } else {
      li.append(el('p', 'asks-text', row.text || '(no text)'));
      li.append(dl([['Source', row.source], ['Ticket', row.ticket], ['Owner', row.owner], ['Evidence', row.evidence], ['Session', row.session && row.session.slice(0, 8)], ['Recorded', row.at]]));
    }
    return li;
  }

  function renderList() {
    const panel = body.querySelector('#asks-panel');
    if (!panel) return;
    const sec = section();
    panel.replaceChildren();
    if (sec.error) {
      const p = el('p', 'asks-error', sec.error);
      p.setAttribute('role', 'alert');
      panel.append(p);
      return;
    }
    const rows = sortRows(view.tab, sec.rows.filter(row => (view.session === 'all' || row.session === view.session)).filter(matches));
    const note = el('p', 'asks-summary', `${rows.length} of ${sec.rows.length} shown${sec.truncated ? '. The ledger is larger than this view: results are partial.' : ''}`);
    panel.append(note);
    if (!rows.length) { panel.append(el('p', 'asks-empty', sec.rows.length ? 'Nothing matches these filters.' : 'Nothing recorded.')); return; }
    const list = el('ul', 'asks-list');
    list.setAttribute('aria-label', TABS.find(([t]) => t === view.tab)[1]);
    for (const row of rows.slice(0, view.shown)) list.append(card(row));
    panel.append(list);
    if (rows.length > view.shown) {
      const more = el('button', 'quiet-button', `Show ${Math.min(PAGE, rows.length - view.shown)} more`);
      more.type = 'button';
      more.addEventListener('click', () => { view.shown += PAGE; renderList(); more.remove(); list.lastElementChild?.querySelector('code')?.focus?.(); });
      panel.append(more);
    }
  }

  async function refresh(manual) {
    const mine = ++view.generation;
      const status = body.querySelector('#asks-status');
    if (status && manual) status.textContent = 'Refreshing…';
    try {
      const query = view.session === 'all' ? '' : `?session=${encodeURIComponent(view.session)}`;
      const data = await api(`/api/asks-view${query}`);
      if (mine !== view.generation || !dialog.open) return;
      view.data = data;
      syncTabs();
      syncFilters();
      renderList();
      if (status) status.textContent = `Updated ${new Date().toLocaleTimeString()}. Refreshes every 30 seconds.`;
    } catch (error) {
      if (mine !== view.generation) return;
      if (status) status.textContent = `Could not refresh: ${error.message || 'request failed'}. Showing the last data.`;
    }
  }

  function tick() {
    view.timer = window.setTimeout(async () => {
      if (!dialog.open) return;
      if (!document.hidden) await refresh(false);
      tick();
    }, REFRESH_MS);
  }

  shell();
  dialog.onclose = () => { view.generation++; window.clearTimeout(view.timer); };
  if (!dialog.open) dialog.showModal();
  refresh(true);
  tick();
}
