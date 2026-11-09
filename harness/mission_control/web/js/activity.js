import { getState, subscribe, select, KINDS, pauseFeed, toggleQuiet } from './store.js';
import { el, button, age, relativeTime } from './ui.js';

export function mountActivity() {
  const list = document.getElementById('activity-list');
  const pause = document.getElementById('activity-pause');
  const buffer = document.getElementById('activity-buffer');
  const resume = document.getElementById('activity-resume');
  const rows = new Map();
  let pending = [], announceTimer;
  pause.addEventListener('click', pauseFeed);
  const quiet = document.getElementById('activity-quiet');
  quiet.addEventListener('click', toggleQuiet);
  resume.addEventListener('click', pauseFeed);
  function makeRow(event) {
    const kind = KINDS[event.kind];
    const row = button('event-row', '', () => select('event', event.id));
    row.style.setProperty('--kind-color', kind.color);
    row.dataset.eventId = event.id;
    row.setAttribute('aria-label', `${kind.label}: ${event.summary}. ${event.actor.agent || event.source}. ${event.severity} severity. Open details.`);
    const icon = el('span', 'event-icon', kind.icon);
    icon.setAttribute('aria-hidden', 'true');
    const copy = el('div', 'event-copy');
    const summary = el('div', 'event-summary', event.summary);
    const meta = el('div', 'event-meta');
    meta.append(el('span', 'kind-name', kind.label));
    for (const bit of [event.actor.agent ? event.actor.agent.slice(0, 8) : event.source, event.subject.ticket || event.subject.repo, event.count > 1 ? `×${event.count}` : '']) if (bit) meta.append(el('span', '', '·'), el('span', '', bit));
    if (event.severity !== 'info') meta.append(el('span', `severity ${event.severity}`, event.severity));
    copy.append(summary, meta);
    row.append(icon, copy, relativeTime(event.ts, 'event-time'));
    return row;
  }
  function render(state, reason) {
    const source = state.feedPaused ? state.feedSnapshot : state.events;
    const events = source.filter(event => state.filters.includes(event.kind) && (state.showQuiet || !event.quiet));
    const hidden = source.filter(event => event.quiet && !state.showQuiet).reduce((sum, event) => sum + event.count, 0);
    const wanted = new Set(events.map(event => event.id));
    for (const [id, row] of rows) if (!wanted.has(id)) { row.remove(); rows.delete(id); }
    list.querySelector('.empty-state')?.remove();
    // In-place insertion retains focus and the reader's scroll anchor.
    const previousScroll = list.scrollTop, previousHeight = list.scrollHeight;
    events.forEach((event, index) => {
      if (!rows.has(event.id)) {
        const row = makeRow(event);
        if (reason === 'event' && !state.feedPaused && !event.historic) row.classList.add('new-event');
        if (event.quiet) row.classList.add('quiet-event');
        rows.set(event.id, row);
        list.insertBefore(row, list.children[index] || null);
      }
    });
    if (previousScroll > 16) list.scrollTop = previousScroll + list.scrollHeight - previousHeight;
    if (!events.length) list.append(el('p', 'empty-state', source.length ? 'No work items match. Choose an event kind above, or show tool activity.' : 'Listening for signals…'));
    quiet.setAttribute('aria-pressed', String(state.showQuiet));
    quiet.textContent = state.showQuiet ? 'Hide tool activity' : 'Show tool activity';
    pause.textContent = state.feedPaused ? '▷ Resume feed' : 'Ⅱ Pause feed';
    pause.setAttribute('aria-pressed', String(state.feedPaused));
    buffer.hidden = !state.feedPaused;
    resume.textContent = state.buffered ? `${state.buffered} new signals · resume feed ↓` : 'Feed paused · resume ↓';
    document.getElementById('activity-summary').textContent = `${events.length} work items${hidden ? ` · ${hidden} tool and lifecycle events hidden` : ''}${state.feedPaused ? ' · paused' : ''}`;
  }
  render(getState(), 'initial');
  subscribe((state, reason) => {
    if (['event', 'filters', 'feed', 'seed'].includes(reason)) render(state, reason);
    if (reason === 'tick') list.querySelectorAll('time').forEach(time => { time.textContent = age(time.dateTime, state.now); });
    if (reason === 'event' && state.lastEvent && !state.lastEvent.historic && !state.lastEvent.quiet && !state.feedPaused && state.filters.includes(state.lastEvent.kind)) {
      pending.push(state.lastEvent);
      if (!announceTimer) announceTimer = setTimeout(() => {
        const latest = pending.at(-1);
        if (!document.hidden && !getState().feedPaused) document.getElementById('activity-announcer').textContent = `${pending.length} new ${pending.length === 1 ? 'signal' : 'signals'}. Latest: ${latest.summary}`;
        pending = []; announceTimer = null;
      }, 4500);
    }
  });
}
