// Pull request list and review map dialog. Selecting a PR and pressing the button generates (or reopens)
// the map through the console API; the page itself is shown in a sandboxed frame served from an
// unguessable URL, so its script cannot reach this window or the console token.
export function initReviewMap({ api, notify, el, session, $ }) {
  const model = { prs: [], selected: null, state: 'open', loading: false, generating: false, attaching: false, map: null };
  const list = $('#pr-list');
  const open = $('#pr-open-map');
  const stateSelect = $('#pr-state');
  const status = $('#pr-status');
  const dialog = $('#review-map-dialog');

  function describe(row) {
    const parts = [row.draft ? 'draft' : String(row.state || '').toLowerCase()];
    if (row.map) parts.push('map ready');
    return parts.filter(Boolean).join(' · ');
  }

  function render() {
    list.replaceChildren();
    if (!model.prs.length) {
      list.append(el('p', 'sidebar-empty', model.loading ? 'Loading pull requests…' : 'No pull requests loaded.'));
    }
    for (const row of model.prs) {
      const item = el('button', `pr-row${model.selected === row.number ? ' selected' : ''}`);
      item.type = 'button';
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', String(model.selected === row.number));
      item.dataset.testid = `pr-row-${row.number}`;
      item.append(el('span', 'pr-number', `#${row.number}`), el('span', 'pr-title', row.title || '(no title)'),
        el('span', 'pr-meta', describe(row)));
      item.title = row.branch || '';
      item.addEventListener('click', () => { model.selected = row.number; render(); });
      list.append(item);
    }
    open.disabled = model.selected === null || model.generating || model.loading;
    open.textContent = model.generating ? 'Building review map…' : 'Open review map';
    open.setAttribute('aria-busy', String(model.generating));
  }

  async function load() {
    const current = session();
    if (!current) { status.textContent = 'Select a session to list its pull requests.'; return; }
    model.loading = true;
    status.textContent = '';
    status.hidden = true;
    render();
    try {
      const result = await api('/api/prs', { sessionId: current.id, state: model.state });
      model.prs = result.prs || [];
      if (!model.prs.some(row => row.number === model.selected)) model.selected = null;
    } catch (error) {
      model.prs = [];
      status.textContent = error?.message || 'Could not list pull requests.';
      status.hidden = false;
    } finally {
      model.loading = false;
      render();
    }
  }

  function showMap(result) {
    model.map = result;
    $('#review-map-title').textContent = `Review map · PR #${model.selected}`;
    const frame = $('#review-map-frame');
    frame.replaceWith(Object.assign(frame.cloneNode(false), { src: result.url }));
    $('#review-map-newtab').href = result.url;
    const tickets = $('#review-map-tickets');
    tickets.replaceChildren();
    if (!result.tickets?.length) tickets.append(el('p', 'sidebar-empty', 'No GoodQA ticket is cited by this pull request\'s commits, so there is nothing to attach to.'));
    for (const ref of result.tickets || []) {
      const label = el('label', 'ticket-choice');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.checked = true;
      box.value = ref;
      label.append(box, document.createTextNode(` ${ref}`));
      tickets.append(label);
    }
    $('#review-map-result').textContent = '';
    $('#review-map-attach').disabled = !(result.tickets || []).length;
    if (!dialog.open) dialog.showModal();
  }

  open.addEventListener('click', async () => {
    const current = session();
    if (model.selected === null || model.generating || !current) return;
    model.generating = true;
    render();
    try {
      showMap(await api('/api/prs/review-map', { sessionId: current.id, number: model.selected }, 'POST', 200000));
      load();
    } catch (error) {
      notify(error?.message || 'The review map could not be generated.', true);
    } finally {
      model.generating = false;
      render();
    }
  });

  $('#review-map-attach').addEventListener('click', async () => {
    if (model.attaching || !model.map) return;
    const chosen = [...dialog.querySelectorAll('#review-map-tickets input:checked')].map(box => box.value);
    if (!chosen.length) { $('#review-map-result').textContent = 'Tick at least one ticket.'; return; }
    model.attaching = true;
    const button = $('#review-map-attach');
    button.disabled = true;
    button.textContent = 'Attaching…';
    const out = $('#review-map-result');
    try {
      const result = await api('/api/prs/review-map/attach', { mapId: model.map.mapId, tickets: chosen }, 'POST', 200000);
      out.replaceChildren(...(result.results || []).map(row => el('div', row.status === 'ATTACHED' || row.status === 'ALREADY_ATTACHED' ? '' : 'form-error',
        `${row.ticket}: ${row.status}${row.detail ? ' — ' + row.detail : ''}`)));
    } catch (error) {
      out.replaceChildren(el('div', 'form-error', error?.message || 'Attach failed.'));
    } finally {
      model.attaching = false;
      button.disabled = false;
      button.textContent = 'Attach to GoodQA tickets';
    }
  });

  stateSelect.addEventListener('change', () => { model.state = stateSelect.value; load(); });
  $('#pr-refresh').addEventListener('click', load);
  render();
  return { reload: load };
}
