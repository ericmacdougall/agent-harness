export function el(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== '') node.textContent = text;
  return node;
}
export function button(className, text, action) {
  const node = el('button', className, text);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
}
export function age(ts, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - new Date(ts).getTime()) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds} s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
export function freshness(ts, now = Date.now()) {
  const minutes = (now - new Date(ts).getTime()) / 60000;
  return minutes < 5 ? 'fresh' : minutes < 30 ? 'warm' : 'stale';
}
export function stateClass(value) { return value.toLowerCase().replaceAll(' ', '-'); }
export function milestones(value) {
  return value.split(' · ').filter(Boolean).map(text => ({ done: text.startsWith('Done:'), text: text.replace(/^(Done:|Not yet:)\s*/, '') }));
}
export function progress(item) {
  const bar = el('div', 'progress-bar');
  if (item.pct === null || item.milestones_done === null || item.milestones_total === null) {
    bar.classList.add('checking');
    bar.setAttribute('aria-label', 'Progress checking; no estimate yet');
    bar.append(el('span'));
  } else {
    const parts = milestones(item.milestones);
    parts.forEach(part => bar.append(el('span', part.done ? 'complete' : '')));
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuenow', String(item.pct));
    bar.setAttribute('aria-valuemin', '0');
    bar.setAttribute('aria-valuemax', '100');
    bar.setAttribute('aria-label', `${item.initiative}: ${item.milestones_done} of ${item.milestones_total} milestones`);
  }
  return bar;
}
export function checklist(item, expanded = false) {
  const details = el('details', 'milestone-details');
  details.open = expanded;
  const count = item.milestones_done === null ? 'Checking milestones' : `${item.milestones_done} / ${item.milestones_total} milestones`;
  details.append(el('summary', '', count));
  const list = el('ul', 'checklist');
  milestones(item.milestones).forEach(part => {
    const li = el('li', part.done ? 'checked' : '');
    li.append(el('span', 'check-icon', part.done ? '✓' : '○'), el('span', '', part.text));
    li.setAttribute('aria-label', `${part.done ? 'Done' : 'Not yet'}: ${part.text}`);
    list.append(li);
  });
  details.append(list);
  return details;
}
export function eta(value, by, prefix = 'ETA') { return `${prefix} ${value || 'checking'} · est. by ${by}`; }
export function relativeTime(ts, className = '') {
  const time = el('time', className, age(ts));
  time.dateTime = ts;
  time.title = new Date(ts).toLocaleString();
  return time;
}
export function field(label, value) {
  const row = el('div', 'detail-field');
  row.append(el('dt', '', label), el('dd', '', value ?? 'Checking'));
  return row;
}
