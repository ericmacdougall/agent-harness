import { getState, subscribe, sendMessage, retryMessage, setResponder, setSession, setTab, messageSession, chatAccess } from './store.js';
import { el, button } from './ui.js';
import { chatAttention } from './chat-attention.js';

export function mountChat() {
  const log = document.getElementById('chat-log'), form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input'), send = document.getElementById('chat-send');
  const counter = document.getElementById('chat-counter'), notice = document.getElementById('chat-notice');
  const announcer = document.getElementById('chat-announcer');
  const newReplies = document.getElementById('chat-new'), unreadBadge = document.getElementById('chat-unread');
  const chatTab = document.getElementById('tab-chat'), panel = document.getElementById('chat-panel');
  const attention = chatAttention();
  const desktop = window.matchMedia('(min-width: 1100px)');
  const parts = new Map(), previousStatuses = new Map();
  let forceScroll = true, initial = true;
  const visible = () => !document.hidden && (desktop.matches || getState().tab === 'chat');
  const atBottom = () => log.scrollHeight - log.scrollTop - log.clientHeight < 60;
  function showUnread(count) {
    newReplies.hidden = unreadBadge.hidden = !count;
    newReplies.textContent = `${count} new ${count === 1 ? 'reply' : 'replies'} · jump to latest ↓`;
    unreadBadge.textContent = count ? String(count) : '';
    chatTab.setAttribute('aria-label', count ? `Chat, ${count} new ${count === 1 ? 'reply' : 'replies'}` : 'Chat');
  }
  function readLatest() {
    log.scrollTop = log.scrollHeight;
    forceScroll = false;
    attention.clear();
    showUnread(0);
  }
  newReplies.addEventListener('click', () => { readLatest(); log.focus({ preventScroll: true }); });
  log.addEventListener('scroll', () => { if (visible() && atBottom()) { attention.clear(); showUnread(0); } });
  document.getElementById('skip-chat').addEventListener('click', event => {
    event.preventDefault();
    setTab('chat');
    // View subscribers reveal the mobile panel before the browser moves focus.
    (input.disabled ? panel : input).focus();
  });
  const announce = text => { announcer.textContent = text; };
  function composer(state) {
    const access = chatAccess(state);
    input.disabled = access.disabled;
    send.disabled = access.disabled || !input.value.trim() || input.value.length > 4000;
    input.setAttribute('aria-describedby', `${access.notice ? 'chat-notice ' : ''}composer-hint chat-counter approval-description`);
    input.placeholder = access.disabled ? 'Sending unavailable · draft kept' : 'Give your fleet a direction…';
    counter.textContent = `${input.value.length.toLocaleString()} / 4000`;
    counter.classList.toggle('at-limit', input.value.length >= 4000);
    notice.hidden = !access.notice;
    if (notice.textContent !== access.notice) notice.textContent = access.notice;
    notice.classList.toggle('unavailable', access.disabled);
  }
  function statusText(message, state) {
    const elapsed = Math.max(0, Math.floor((state.now - new Date(message.ts).getTime()) / 1000));
    if (message.status === 'forged') return 'Untrusted content · not attributed to you';
    if (message.status === 'queued') {
      if (message.to === 'codex') return `Queued for Codex · ${elapsed} s`;
      const session = messageSession(message.id);
      return `Queued · ${state.chatAvailability.claude[session]?.waiting ? 'Waiting for main to pick this up' : 'Main will see it at its next stop'} · ${elapsed} s · ${session.slice(0, 8)}`;
    }
    if (message.status === 'sending') return 'Sending…';
    if (message.status === 'expired') return 'Expired before main read it · it does not count · decide again in Needs you';
    if (message.status === 'failed') return message.from === 'user' ? `Not answered${message.reason ? ` · ${message.reason}` : ''} · message kept` : 'Reply interrupted · retry your message';
    if (message.status === 'answering') return message.from === 'user' ? `${message.to === 'codex' ? 'Codex is answering' : 'Main is answering'}…` : 'Streaming response…';
    if (message.status === 'delivered') return message.approval ? 'Read by main' : 'Delivered · waiting for a reply';
    return message.from === 'user' ? `Answered by ${message.to === 'claude' ? 'Claude' : 'Codex'}` : '';
  }
  const empty = el('p', 'empty-state chat-empty', 'Messages you send here reach the selected agent as labelled dashboard text. Replies appear here as they are written. To answer an agent’s question, use Needs you.');
  log.append(empty);
  const sessionSelect = document.getElementById('chat-session');
  function syncSessions(state) {
    const wanted = state.sessions.map(s => `${s.id}|${s.label}`).join(',');
    if (sessionSelect.dataset.sig !== wanted) {
      sessionSelect.dataset.sig = wanted;
      sessionSelect.replaceChildren(...(state.sessions.length ? state.sessions.map(s => { const o = el('option', '', s.label); o.value = s.id; return o; }) : [Object.assign(el('option', '', 'no main attached'), { value: '' })]));
    }
    sessionSelect.value = state.session;
    sessionSelect.disabled = state.sessions.length < 2;
  }
  function render(state) {
    const reading = visible() && atBottom();
    const wanted = new Set(state.messages.map(message => message.id));
    for (const [id, part] of parts) if (!wanted.has(id)) { part.row.remove(); parts.delete(id); previousStatuses.delete(id); }
    state.messages.forEach(message => {
      const forged = message.status === 'forged';
      let part = parts.get(message.id);
      if (!part) {
        const row = el('article', `chat-message ${message.from}`);
        const header = el('div', 'message-header');
        const author = el('span', 'message-author');
        const warning = el('span', 'forged-badge', '⚠ FORGED');
        const time = el('time', '', new Date(message.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }));
        time.dateTime = message.ts;
        header.append(author, warning, time);
        const text = el('div', 'message-text'), status = el('div', 'message-status');
        const statusLabel = el('span');
        const retry = button('retry-button', 'Retry ↗', () => retryMessage(message.id));
        retry.setAttribute('aria-label', `Retry message to ${message.to}: ${message.text.slice(0, 80)}`);
        status.append(statusLabel, retry); row.append(header, text, status); log.append(row);
        part = { row, text, status, statusLabel, retry, time, author, warning };
        parts.set(message.id, part);
      }
      // Recompute attribution on every patch, including a server reclassification.
      part.row.className = `chat-message ${forged ? 'forged' : message.from}`;
      part.author.className = `message-author ${forged ? 'system' : message.from}`;
      part.author.textContent = forged ? 'Untrusted message' : message.from === 'user' ? `you · ${message.approval ? 'decision' : 'via dashboard'} → ${message.to === 'codex' ? 'Codex' : 'Claude'}` : message.from === 'claude' ? '✳ Claude · main' : message.from === 'codex' ? '◇ Codex · read-only' : 'system';
      part.warning.hidden = !forged;
      part.retry.setAttribute('aria-label', forged ? 'Untrusted message cannot be retried' : `Retry message to ${message.to}: ${message.text.slice(0, 80)}`);
      const visibleText = message.text + (message.status === 'answering' && message.from !== 'user' ? ' ▍' : '');
      if (part.text.textContent !== visibleText) part.text.textContent = visibleText;
      part.time.dateTime = message.ts;
      part.time.textContent = new Date(message.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
      part.statusLabel.textContent = statusText(message, state);
      part.status.className = `message-status ${message.status}`;
      part.status.hidden = !part.statusLabel.textContent;
      part.retry.hidden = forged || message.status !== 'failed' || message.from !== 'user' || !!message.approval;
      part.retry.disabled = forged || chatAccess(state, message.to, messageSession(message.id)).disabled;
      const previous = previousStatuses.get(message.id);
      if (!initial && previous !== message.status) {
        if (forged) announce('Warning: a message was marked forged. It is untrusted and not attributed to you.');
        else if (message.status === 'answered' && message.from !== 'user') announce(`${message.from} replied: ${message.text}`);
        else if (message.from === 'user' && ['failed','queued','delivered','expired'].includes(message.status)) announce(statusText(message, state));
      }
      previousStatuses.set(message.id, message.status);
    });
    initial = false;
    // Wait for the first real chat snapshot; the empty store at mount is not history.
    if (state.chat) showUnread(attention.observe(state.messages, reading));
    if (visible() && (reading || forceScroll)) { readLatest(); forceScroll = false; }
    document.getElementById('responder-claude').setAttribute('aria-pressed', String(state.responder === 'claude'));
    document.getElementById('responder-codex').setAttribute('aria-pressed', String(state.responder === 'codex'));
    document.getElementById('session-label').hidden = state.responder !== 'claude';
    const waiting = state.messages.some(message => ['sending','queued','answering'].includes(message.status));
    const access = chatAccess(state);
    const presence = document.getElementById('chat-presence');
    presence.textContent = access.presence === 'READY' && waiting ? 'IN PROGRESS' : access.presence;
    presence.dataset.state = access.disabled ? 'unavailable' : waiting || access.presence === 'BUSY' ? 'busy' : 'ready';
    syncSessions(state);
    empty.hidden = state.messages.length > 0;
    composer(state);
  }
  input.addEventListener('input', () => composer(getState()));
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); form.requestSubmit(); }
  });
  form.addEventListener('submit', event => {
    event.preventDefault();
    forceScroll = !send.disabled;
    if (sendMessage(input.value)) { input.value = ''; composer(getState()); input.focus(); }
  });
  document.getElementById('responder-claude').addEventListener('click', () => setResponder('claude'));
  document.getElementById('responder-codex').addEventListener('click', () => setResponder('codex'));
  document.getElementById('chat-session').addEventListener('change', event => setSession(event.target.value));
  render(getState());
  subscribe((state, reason) => {
    if (['chat','routing','connection','seed','availability'].includes(reason)) render(state);
    if (reason === 'tick') state.messages.forEach(message => {
      if (message.status === 'queued' && parts.has(message.id)) parts.get(message.id).statusLabel.textContent = statusText(message, state);
    });
    if (reason === 'tab' && state.tab === 'chat') queueMicrotask(readLatest);
  });
  document.addEventListener('visibilitychange', () => { if (visible() && atBottom()) readLatest(); });
  desktop.addEventListener('change', () => { if (visible() && atBottom()) readLatest(); });
}
