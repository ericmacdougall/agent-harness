// "Needs you": the open asks main's session has for the user. Ask text is agent-written, so it is only ever set
// with textContent, never parsed as HTML. A reply is an ordinary chat message to main, prefixed `[ask:<id>]`.
import { getState, subscribe, askReplyAccess, sendAskReply } from './store.js';
import { el, age } from './ui.js';

const BASE_TITLE = 'Mission Control';
const STATUS_TEXT = { sending: 'Sending…', queued: 'Sent to main · waiting for it to read', delivered: 'Sent to main',
  answering: 'Main is answering', answered: 'Main answered in the chat', failed: 'Not sent · retry from the chat panel' };


export function mountNeeds() {
  const open = document.getElementById('needs-button');
  const count = document.getElementById('needs-count');
  const dialog = document.getElementById('needs-dialog');
  const list = document.getElementById('needs-list');
  const drafts = new Map();   // ask id -> unsent text; kept across re-renders, cleared once the send is accepted
  const sent = new Map();     // ask id -> client key of the last reply, to show its delivery state
  const rows = new Map();
  open.addEventListener('click', () => { if (!dialog.open) dialog.showModal(); });
  document.getElementById('needs-close').addEventListener('click', () => dialog.close());

  function statusOf(state, ask) {
    const key = sent.get(ask.id);
    if (!key) return null;
    return state.messages.find(m => m.client_key === key)?.status || 'queued';
  }

  function build(ask) {
    const row = el('li', 'needs-item');
    const top = el('div', 'needs-top');
    const kind = el('span', 'needs-kind');
    const ticket = el('span', 'ticket-id');
    const when = el('time', 'needs-age');
    top.append(kind, ticket, when);
    const text = el('p', 'needs-text');
    const why = el('p', 'needs-why');
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
      const key = sendAskReply(current, input.value);
      if (!key) return;
      sent.set(ask.id, key); drafts.delete(ask.id); input.value = '';
      paint(getState());
    });
    row.append(top, text, why, form, status);
    return { row, kind, ticket, when, text, why, input, send, status, ask };
  }

  function paint(state) {
    const asks = state.asks;
    const n = asks.length;
    count.textContent = String(n);
    open.classList.toggle('has-asks', n > 0);
    open.setAttribute('aria-label', n ? `Needs you: ${n} open ask${n === 1 ? '' : 's'}` : 'Needs you: nothing open');
    document.title = n ? `(${n}) ${BASE_TITLE}` : BASE_TITLE;
    const wanted = new Set(asks.map(a => a.id));
    for (const [id, parts] of rows) if (!wanted.has(id)) { parts.row.remove(); rows.delete(id); drafts.delete(id); sent.delete(id); }
    list.querySelector('.empty-state')?.remove();
    if (!n) list.append(el('li', 'empty-state', 'Nothing needs you right now.'));
    asks.forEach((ask, index) => {
      let parts = rows.get(ask.id);
      if (!parts) { parts = build(ask); rows.set(ask.id, parts); }
      parts.ask = ask;
      // server order (oldest first); move a row only when it is out of place, so a focused reply box keeps focus
      if (list.children[index] !== parts.row) list.insertBefore(parts.row, list.children[index] || null);
      parts.kind.textContent = ask.kind === 'assumption' ? 'Assumption to confirm' : 'Question';
      parts.ticket.textContent = [ask.ticket, ask.owner && ask.owner !== 'main' ? `from ${ask.owner}` : ''].filter(Boolean).join(' · ');
      parts.when.textContent = age(ask.at, state.now);
      if (ask.at) parts.when.dateTime = ask.at;
      parts.text.textContent = ask.text || '(no text recorded)';
      parts.why.textContent = ask.why ? `Why: ${ask.why}` : '';
      parts.why.hidden = !ask.why;
      const access = askReplyAccess(ask, state);
      const status = statusOf(state, ask);
      const pending = status === 'sending';
      parts.send.disabled = access.disabled || pending || !parts.input.value.trim();
      parts.status.textContent = status ? STATUS_TEXT[status] || status : access.disabled ? access.notice : '';
      parts.status.className = `needs-status ${status || (access.disabled ? 'blocked' : '')}`;
    });
  }
  subscribe((state, reason) => {
    if (reason === 'tick') { for (const parts of rows.values()) parts.when.textContent = age(parts.ask.at, state.now); return; }
    if (['asks', 'chat', 'connection', 'routing', 'update'].includes(reason)) paint(state);
  });
  paint(getState());
}
