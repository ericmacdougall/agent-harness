// "Needs you": the open asks main's session has for the user, each with the trail of the user's replies (read
// time, main's answer), and a history of asks resolved in the last 7 days. Ask text is agent-written, so it is only
// ever set with textContent, never parsed as HTML. A reply is an ordinary chat message to main, prefixed
// `[ask:<id>]`; main resolves the ask from it, and the next ledger read moves it to the history.
import { getState, subscribe, askReplyAccess, sendAskReply } from './store.js';
import { el, age } from './ui.js';
import { trailOf, waitingOnUser } from './adapt.js';

const BASE_TITLE = 'Mission Control';
const SENT_TEXT = { sending: 'Sending…', queued: 'Sent · waiting for main to read it', delivered: 'Read by main',
  answering: 'Read by main · answering', answered: 'Read by main · answered', failed: 'Not sent · retry from the chat panel',
  forged: 'Rejected: not signed by this dashboard' };

const time = iso => { const d = new Date(iso); return Number.isFinite(d.getTime()) ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''; };
function gap(from, to) {
  const seconds = Math.round((Date.parse(to) - Date.parse(from)) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  return seconds < 60 ? `${seconds} s after you sent it` : seconds < 3600 ? `${Math.round(seconds / 60)} min after you sent it` : `${Math.round(seconds / 3600)} h after you sent it`;
}


function renderTrail(box, trail) {
  box.replaceChildren();
  box.hidden = !trail.length;
  for (const entry of trail) {
    const mine = el('li', 'needs-trail-item');
    const head = el('div', 'needs-trail-head');
    const forged = entry.message.status === 'forged';  // planted in the store, not sent from this page (L5)
    head.append(el('span', `needs-trail-who${forged ? ' forged' : ''}`, forged ? 'Not from you' : 'You'), el('span', '', time(entry.message.ts)));
    const status = el('span', `needs-trail-status ${entry.message.status}`, SENT_TEXT[entry.message.status] || entry.message.status);
    if (entry.message.read_at) status.textContent += ` at ${time(entry.message.read_at)} (${gap(entry.message.ts, entry.message.read_at)})`;
    mine.append(head, el('p', 'needs-trail-text', entry.text), status);
    for (const reply of entry.replies) {
      const answer = el('div', 'needs-trail-reply');
      const who = el('div', 'needs-trail-head');
      who.append(el('span', 'needs-trail-who main', reply.from === 'codex' ? 'Codex' : 'Main'), el('span', '', time(reply.ts)));
      answer.append(who, el('p', 'needs-trail-text', reply.text));
      mine.append(answer);
    }
    box.append(mine);
  }
}

export function mountNeeds() {
  const open = document.getElementById('needs-button');
  const count = document.getElementById('needs-count');
  const dialog = document.getElementById('needs-dialog');
  const list = document.getElementById('needs-list');
  const history = document.getElementById('needs-history');
  const historyList = document.getElementById('needs-history-list');
  const historyCount = document.getElementById('needs-history-count');
  const drafts = new Map();   // ask id -> unsent text; kept across re-renders, cleared once the send is accepted
  const rows = new Map();
  open.addEventListener('click', () => { if (!dialog.open) dialog.showModal(); });
  document.getElementById('needs-close').addEventListener('click', () => dialog.close());

  function build(ask) {
    const row = el('li', 'needs-item');
    const top = el('div', 'needs-top');
    const kind = el('span', 'needs-kind');
    const ticket = el('span', 'ticket-id');
    const when = el('time', 'needs-age');
    top.append(kind, ticket, when);
    const text = el('p', 'needs-text');
    const why = el('p', 'needs-why');
    const trail = el('ul', 'needs-trail');
    trail.setAttribute('aria-label', 'Your replies');
    const form = el('form', 'needs-reply');
    const label = el('label', 'sr-only', `Reply to ask ${ask.id}`);
    const input = el('textarea');
    input.id = `needs-input-${ask.id}`; label.htmlFor = input.id;
    input.rows = 2; input.maxLength = 3900; input.placeholder = 'Your answer to main…';
    input.value = drafts.get(ask.id) || '';
    input.addEventListener('input', () => { drafts.set(ask.id, input.value); paint(getState()); });
    input.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); form.requestSubmit(); } });
    const send = el('button', 'needs-send', 'Reply');
    send.type = 'submit';
    const status = el('p', 'needs-status'); status.setAttribute('role', 'status');
    form.append(label, input, send);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const current = rows.get(ask.id)?.ask || ask;
      if (send.disabled) return;
      if (!sendAskReply(current, input.value)) return;
      drafts.delete(ask.id); input.value = '';
      paint(getState());
    });
    row.append(top, text, why, trail, form, status);
    return { row, kind, ticket, when, text, why, trail, input, send, status, ask };
  }

  function paintHistory(state) {
    const resolved = state.asksResolved || [];
    historyCount.textContent = String(resolved.length);
    history.hidden = !resolved.length;
    historyList.replaceChildren();
    for (const ask of resolved) {
      const item = el('li', 'needs-item resolved');
      const top = el('div', 'needs-top');
      top.append(el('span', 'needs-kind done', ask.decision ? `Resolved · ${ask.decision}` : 'Resolved'),
        el('span', 'ticket-id', [ask.ticket, ask.owner && ask.owner !== 'main' ? `from ${ask.owner}` : ''].filter(Boolean).join(' · ')),
        el('time', 'needs-age', age(ask.resolved_at, state.now)));
      item.append(top, el('p', 'needs-text', ask.text || '(no text recorded)'));
      if (ask.resolution) item.append(el('p', 'needs-why', `How: ${ask.resolution}`));
      const trail = el('ul', 'needs-trail');
      renderTrail(trail, trailOf(state.messages, ask.id));
      item.append(trail);
      historyList.append(item);
    }
  }

  function paint(state) {
    const asks = state.asks;
    const waiting = asks.filter(ask => waitingOnUser(state.messages, ask)).length;
    count.textContent = String(waiting);
    open.classList.toggle('has-asks', waiting > 0);
    open.setAttribute('aria-label', waiting ? `Needs you: ${waiting} open ask${waiting === 1 ? '' : 's'}` : 'Needs you: nothing waiting on you');
    document.title = waiting ? `(${waiting}) ${BASE_TITLE}` : BASE_TITLE;
    const wanted = new Set(asks.map(a => a.id));
    for (const [id, parts] of rows) if (!wanted.has(id)) { parts.row.remove(); rows.delete(id); drafts.delete(id); }
    list.querySelector('.empty-state')?.remove();
    if (!asks.length) list.append(el('li', 'empty-state', 'Nothing needs you right now.'));
    asks.forEach((ask, index) => {
      let parts = rows.get(ask.id);
      if (!parts) { parts = build(ask); rows.set(ask.id, parts); }
      parts.ask = ask;
      // server order (oldest first); move a row only when it is out of place, so a focused reply box keeps focus
      if (list.children[index] !== parts.row) list.insertBefore(parts.row, list.children[index] || null);
      const trail = trailOf(state.messages, ask.id);
      const answered = !waitingOnUser(state.messages, ask);
      parts.row.classList.toggle('answered', answered);
      parts.kind.textContent = answered ? 'Answered by you · waiting for main' : ask.kind === 'assumption' ? 'Assumption to confirm' : 'Question';
      parts.ticket.textContent = [ask.ticket, ask.owner && ask.owner !== 'main' ? `from ${ask.owner}` : ''].filter(Boolean).join(' · ');
      parts.when.textContent = age(ask.at, state.now);
      if (ask.at) parts.when.dateTime = ask.at;
      parts.text.textContent = ask.text || '(no text recorded)';
      parts.why.textContent = ask.why ? `Why: ${ask.why}` : '';
      parts.why.hidden = !ask.why;
      renderTrail(parts.trail, trail);
      const access = askReplyAccess(ask, state);
      const pending = trail.some(t => t.message.status === 'sending');
      parts.send.disabled = access.disabled || pending || !parts.input.value.trim();
      parts.send.textContent = trail.length ? 'Add' : 'Reply';
      parts.input.placeholder = trail.length ? 'Add to your answer…' : 'Your answer to main…';
      parts.status.textContent = access.disabled ? access.notice : '';
      parts.status.className = `needs-status ${access.disabled ? 'blocked' : ''}`;
    });
    paintHistory(state);
  }
  subscribe((state, reason) => {
    if (reason === 'tick') { for (const parts of rows.values()) parts.when.textContent = age(parts.ask.at, state.now); return; }
    if (['asks', 'chat', 'connection', 'routing', 'update'].includes(reason)) paint(state);
  });
  paint(getState());
}
