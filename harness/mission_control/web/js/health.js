import { getState, subscribe, select } from './store.js';
import { el, button, age } from './ui.js';
export function mountHealth() {
  const list = document.getElementById('health-list');
  const parts = new Map();
  function render(state) {
    state.sources.forEach(source => {
      let part = parts.get(source.id);
      if (!part) {
        const row = button('health-item', '', () => select('source', source.id));
        const label = el('span'), name = el('span'), sub = el('small'), status = el('strong'), time = el('time');
        sub.append(status, time); label.append(name, sub);
        const dot = el('span', 'status-dot'); dot.setAttribute('aria-hidden', 'true');
        row.append(dot, label); list.append(row);
        part = { row, name, status, time }; parts.set(source.id, part);
      }
      const { row, name, status, time } = part;
      row.className = `health-item ${source.state}`;
      name.textContent = source.name;
      status.textContent = `${source.state} · `;
      time.textContent = age(source.checked, state.now);
      time.dateTime = source.checked;
      row.setAttribute('aria-label', `${source.name}: ${source.state}. Last checked ${age(source.checked, state.now)}. ${source.note}`);
    });
    const ids = new Set(state.sources.map(source => source.id));
    for (const [id, part] of parts) if (!ids.has(id)) { part.row.remove(); parts.delete(id); }
  }
  render(getState());
  subscribe((state, reason) => {
    if (reason === 'health') render(state);
    if (reason === 'tick') list.querySelectorAll('time').forEach(time => { time.textContent = age(time.dateTime, state.now); });
  });
}
