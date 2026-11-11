// "Needs you": the open asks of main's session, each decided with Approve / Deny or answered in the user's own
// words, and a history of asks resolved in the last 7 days. Ask text is agent-written, so it is only ever set with
// textContent, never parsed as HTML, and it is shown whole: the digest a decision signs covers exactly this text.
// A decision is a signed server record (POST /api/approve); a reply is an ordinary chat message to main prefixed
// `[ask:<id>]`. Main resolves the ask from either, and the next ledger read moves it to the history.
import { getState, subscribe, askReplyAccess, sendAskReply, decisionAccess, decideAsk, DECISION_NOTE_MAX } from './store.js';
import { el, button, age } from './ui.js';
import { trailOf, waitingOnUser, askProgress, replyStatus, decisionOf, decisionStatus } from './adapt.js';

const BASE_TITLE = 'Mission Control';
const REPLY_MAX = 3900;

const time = iso => { const d = new Date(iso); return Number.isFinite(d.getTime()) ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''; };
function gap(from, to) {
  const seconds = Math.round((Date.parse(to) - Date.parse(from)) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  return seconds < 60 ? `${seconds} s after you sent it` : seconds < 3600 ? `${Math.round(seconds / 60)} min after you sent it` : `${Math.round(seconds / 3600)} h after you sent it`;
}
const origin = ask => [ask.ticket, !ask.owner || ask.owner === 'main' ? 'from main' : `from owner ${ask.owner.replace(/^agent-/, '').slice(0, 12)}`].filter(Boolean).join(' · ');

function replyNode(reply) {
  const answer = el('div', 'needs-trail-reply');
  const who = el('div', 'needs-trail-head');
  who.append(el('span', 'needs-trail-who main', reply.from === 'codex' ? 'Codex' : 'Main'), el('span', '', time(reply.ts)));
  answer.append(who, el('p', 'needs-trail-text', reply.text));
  return answer;
}

function renderTrail(box, trail, decision = null) {
  box.replaceChildren();
  const replies = decision?.replies || [];
  box.hidden = !trail.length && !replies.length;
  if (replies.length) {
    const item = el('li', 'needs-trail-item');
    const head = el('div', 'needs-trail-head');
    head.append(el('span', 'needs-trail-who', `You ${decision.decision === 'approve' ? 'approved' : 'denied'}`), el('span', '', time(decision.message?.ts)));
    const note = String(decision.message?.text || '').split('\nNote: ')[1];
    if (note) item.append(head, el('p', 'needs-trail-text', note), ...replies.map(replyNode));
    else item.append(head, ...replies.map(replyNode));
    box.append(item);
  }
  for (const entry of trail) {
    const mine = el('li', 'needs-trail-item');
    const head = el('div', 'needs-trail-head');
    const forged = entry.message.status === 'forged';  // planted in the store, not sent from this page (L5)
    head.append(el('span', `needs-trail-who${forged ? ' forged' : ''}`, forged ? 'Not from you' : 'You'), el('span', '', time(entry.message.ts)));
    const status = el('span', `needs-trail-status ${entry.message.status}`, replyStatus(entry.message, time, gap));
    mine.append(head, el('p', 'needs-trail-text', entry.text), status, ...entry.replies.map(replyNode));
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
  const announcer = document.getElementById('needs-announcer');
  const sections = [
    { key: 'asks', list, box: null, count: null },
    { key: 'asksStale', list: document.getElementById('needs-stale-list'), box: document.getElementById('needs-stale'), count: document.getElementById('needs-stale-count') },
    { key: 'asksFlagged', list: document.getElementById('needs-flagged-list'), box: document.getElementById('needs-flagged'), count: document.getElementById('needs-flagged-count') },
  ];
  const clearedBox = document.getElementById('needs-cleared'), clearedList = document.getElementById('needs-cleared-list');
  const clearedCount = document.getElementById('needs-cleared-count'), swept = document.getElementById('needs-swept');
  const CLEARED_WHY = { resolved: 'resolved', 'ticket-closed': 'its ticket is closed', 'owner-reassigned': 'its owner is gone and the work was reassigned', duplicate: 'duplicate of an older ask' };
  const drafts = new Map();     // ask id -> unsent text; kept across re-renders, cleared once a send is accepted
  const arming = new Map();     // ask id -> 'approve' | 'deny' while the confirm step is showing
  const announced = new Map();  // ask id -> last decision status read out
  const rows = new Map();
  open.addEventListener('click', () => { if (!dialog.open) dialog.showModal(); });
  document.getElementById('needs-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { arming.clear(); paint(getState()); });

  function build(ask) {
    const row = el('li', 'needs-item');
    const top = el('div', 'needs-top');
    const kind = el('span', 'needs-kind');
    const from = el('span', 'ticket-id');
    const id = el('span', 'needs-id', ask.id);
    id.title = 'Ask id';
    const when = el('time', 'needs-age');
    top.append(kind, from, id, when);
    const text = el('p', 'needs-text');
    text.id = `needs-text-${ask.id}`;
    const why = el('p', 'needs-why');
    const trail = el('ul', 'needs-trail');
    trail.setAttribute('aria-label', 'Your answers and main’s replies');

    const form = el('form', 'needs-answer');
    const label = el('label', 'needs-label', 'Your words (optional with a decision)');
    const input = el('textarea');
    input.id = `needs-input-${ask.id}`; label.htmlFor = input.id;
    input.rows = 2; input.maxLength = REPLY_MAX;
    input.value = drafts.get(ask.id) || '';
    input.addEventListener('input', () => { drafts.set(ask.id, input.value); paint(getState()); });
    input.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); form.requestSubmit(); }  // Enter sends the reply, never a decision
    });

    const actions = el('div', 'needs-actions');
    actions.setAttribute('role', 'group');
    actions.setAttribute('aria-label', `Decide ask ${ask.id}`);
    const current = () => rows.get(ask.id)?.ask || ask;
    const arm = decision => () => { arming.set(ask.id, decision); paint(getState()); parts.confirm.focus(); };
    const approve = button('needs-decide approve', 'Approve', arm('approve'));
    const deny = button('needs-decide deny', 'Deny', arm('deny'));
    for (const control of [approve, deny]) control.setAttribute('aria-describedby', text.id);
    const confirm = button('needs-decide confirm', '', () => {
      const decision = arming.get(ask.id);
      arming.delete(ask.id);
      if (decision && decideAsk(current(), decision, input.value)) { drafts.delete(ask.id); input.value = ''; }
      paint(getState());
      parts.status.focus();
    });
    confirm.setAttribute('aria-describedby', text.id);
    const cancel = button('needs-decide cancel', 'Cancel', () => {
      const decision = arming.get(ask.id);
      arming.delete(ask.id); paint(getState());
      (decision === 'deny' ? deny : approve).focus();
    });
    const send = el('button', 'needs-send', 'Send reply');
    send.type = 'submit';
    const badge = el('span', 'needs-badge');
    actions.append(badge, approve, deny, confirm, cancel, send);
    form.append(label, input, actions);
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (send.disabled || send.hidden) return;
      if (!sendAskReply(current(), input.value)) return;
      drafts.delete(ask.id); input.value = '';
      paint(getState());
    });
    form.addEventListener('keydown', event => {
      if (event.key === 'Escape' && arming.has(ask.id)) { event.preventDefault(); event.stopPropagation(); cancel.click(); }
    });
    const status = el('p', 'needs-status'); status.setAttribute('role', 'status'); status.tabIndex = -1;
    const hint = el('p', 'needs-hint');
    row.append(top, text, why, trail, form, status, hint);
    const parts = { row, kind, from, when, text, why, trail, input, label, send, approve, deny, confirm, cancel, badge, status, hint, ask };
    return parts;
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
        el('span', 'ticket-id', origin(ask)), el('time', 'needs-age', age(ask.resolved_at, state.now)));
      item.append(top, el('p', 'needs-text', ask.text || '(no text recorded)'));
      if (ask.resolution) item.append(el('p', 'needs-why', `How: ${ask.resolution}`));
      const trail = el('ul', 'needs-trail');
      renderTrail(trail, trailOf(state.messages, ask.id), decisionOf(state.messages, ask));
      item.append(trail);
      historyList.append(item);
    }
  }

  function paint(state) {
    const waiting = state.asks.filter(ask => waitingOnUser(state.messages, ask) && state.decisions[ask.id]?.status !== 'sending').length;
    const stale = state.asksStale.length;
    count.textContent = String(waiting);
    open.classList.toggle('has-asks', waiting > 0);
    open.setAttribute('aria-label', (waiting ? `Needs you: ${waiting} open ask${waiting === 1 ? '' : 's'}` : 'Needs you: nothing waiting on you') + (stale ? `, ${stale} stale` : ''));
    document.title = waiting ? `(${waiting}) ${BASE_TITLE}` : BASE_TITLE;
    const wanted = new Set(sections.flatMap(section => state[section.key].map(a => a.id)));
    for (const [id, parts] of rows) if (!wanted.has(id)) { parts.row.remove(); rows.delete(id); drafts.delete(id); arming.delete(id); announced.delete(id); }
    list.querySelector('.empty-state')?.remove();
    if (!state.asks.length) list.append(el('li', 'empty-state', stale ? 'Nothing new needs you. Older open asks are under Stale.' : 'Nothing needs you right now.'));
    for (const section of sections) {
      if (section.box) { section.box.hidden = !state[section.key].length; section.count.textContent = String(state[section.key].length); }
      state[section.key].forEach((ask, index) => paintAsk(state, section, ask, index));
    }
    paintCleared(state);
    paintHistory(state);
  }

  function paintCleared(state) {
    const cleared = state.asksCleared;
    clearedBox.hidden = !cleared.length;
    clearedCount.textContent = String(cleared.length);
    swept.textContent = state.asksSweptAt ? `Settled asks the sweeper hid, with the reason and its evidence. Last sweep ${age(state.asksSweptAt, state.now)}.` : '';
    clearedList.replaceChildren(...cleared.map(row => {
      const item = el('li');
      item.append(el('b', '', CLEARED_WHY[row.reason] || String(row.reason || 'cleared')), document.createTextNode(` · ${row.text || row.id} · ${row.evidence || 'no evidence recorded'} · ${age(row.at, state.now)}`));
      return item;
    }));
  }

  function paintAsk(state, section, ask, index) {
    {
      const list = section.list;
      const flagged = section.key === 'asksFlagged';
      let parts = rows.get(ask.id);
      if (!parts) { parts = build(ask); rows.set(ask.id, parts); }
      if (parts.ask.digest !== ask.digest && arming.has(ask.id)) arming.delete(ask.id);  // the text changed under a half-made decision
      parts.ask = ask;
      parts.row.classList.toggle('flagged', flagged);
      parts.row.querySelector('.needs-answer').hidden = flagged;  // not a valid ask: nothing to decide or answer
      // server order (oldest first); move a row only when it is out of place, so a focused control keeps focus
      if (list.children[index] !== parts.row) list.insertBefore(parts.row, list.children[index] || null);
      const trail = trailOf(state.messages, ask.id);
      const decision = decisionOf(state.messages, ask, state.decisions[ask.id]);
      const answered = !waitingOnUser(state.messages, ask) || decision?.live;
      parts.row.classList.toggle('answered', !!answered);
      parts.kind.textContent = flagged ? 'Untraceable' : answered ? askProgress(trail, decision) : ask.stale ? `Stale · ${ask.stale}` : ask.kind === 'assumption' ? 'Assumption to confirm' : 'Question';
      parts.kind.classList.toggle('needs-flag', flagged);
      parts.from.textContent = origin(ask);
      parts.when.textContent = age(ask.at, state.now);
      if (ask.at) parts.when.dateTime = ask.at;
      if (parts.text.textContent !== (ask.text || '(no text recorded)')) parts.text.textContent = ask.text || '(no text recorded)';
      parts.why.textContent = ask.why ? `Why: ${ask.why}` : '';
      parts.why.hidden = !ask.why;
      renderTrail(parts.trail, trail, decision);

      const reply = askReplyAccess(ask, state);
      const access = decisionAccess(ask, state);
      const armed = arming.get(ask.id) || '';
      const sending = decision?.status === 'sending' || trail.some(t => t.message.status === 'sending');
      const words = parts.input.value.trim();
      const noteTooLong = words.length > DECISION_NOTE_MAX;
      const decidable = ask.approvable && !decision?.live;
      // Controls that cannot apply to this ask are not rendered at all; ones that apply but are held back are
      // disabled and the line below says why.
      parts.approve.hidden = parts.deny.hidden = !decidable || !!armed;
      parts.confirm.hidden = parts.cancel.hidden = !decidable || !armed;
      parts.approve.disabled = parts.deny.disabled = access.disabled || sending || noteTooLong;
      parts.confirm.disabled = access.disabled || sending || noteTooLong;
      parts.confirm.textContent = armed === 'deny' ? 'Confirm deny' : 'Confirm approve';
      parts.confirm.className = `needs-decide confirm ${armed}`;
      parts.approve.setAttribute('aria-label', `Approve ask ${ask.id}`);
      parts.deny.setAttribute('aria-label', `Deny ask ${ask.id}`);
      parts.confirm.setAttribute('aria-label', `Confirm: ${armed === 'deny' ? 'deny' : 'approve'} ask ${ask.id}${words ? ' with your note' : ''}`);
      parts.badge.hidden = !decision?.live || decision.status === 'sending';
      parts.badge.textContent = decision?.decision === 'approve' ? '✓ Approved' : '✕ Denied';
      parts.badge.className = `needs-badge ${decision?.decision || ''}`;
      parts.send.hidden = !!armed;
      parts.send.disabled = reply.disabled || sending || !words;
      parts.send.textContent = trail.length || decision?.live ? 'Send more' : 'Send reply';
      parts.label.textContent = decision?.live ? 'Add to your answer' : ask.approvable ? 'Your words (optional with a decision)' : 'Your answer';
      parts.input.placeholder = decision?.live ? 'Anything main should know…' : ask.approvable ? 'Add a note, or answer in your own words…' : 'Your answer to main…';

      let line = '', tone = '';
      if (armed) { line = `${armed === 'deny' ? 'Deny' : 'Approve'} this ask? Main reads it as your decision${words ? ', with your note' : ''}. It cannot be changed here once main has read it.`; tone = 'confirm'; }
      else if (decision) { line = decisionStatus(decision, { now: state.now, waiting: !!state.chatAvailability.claude[ask.session || state.asksSession]?.waiting, time, gap }); tone = decision.status; }
      else if (flagged) { line = `${ask.flagged || 'No traceable source'}. ${ask.blocked || ''}`.trim(); tone = 'failed'; }
      else if (!ask.approvable) { line = ask.blocked || 'This ask cannot be decided here. Answer with a reply.'; tone = 'blocked'; }
      else if (access.disabled) { line = access.notice; tone = 'blocked'; }
      else if (reply.notice) { line = reply.notice; tone = 'note'; }
      if (parts.status.textContent !== line) parts.status.textContent = line;
      parts.status.className = `needs-status ${tone}`;
      parts.status.hidden = !line;
      const hint = noteTooLong && decidable ? `A note on a decision can be ${DECISION_NOTE_MAX} characters; yours is ${words.length}. Send it as a reply instead.` : '';
      parts.hint.textContent = hint;
      parts.hint.hidden = !hint;
      const spoken = decision ? `${decision.decision}:${decision.status}` : '';
      if (announced.has(ask.id) && announced.get(ask.id) !== spoken && line && announcer) announcer.textContent = `Ask ${ask.id}: ${line}`;
      announced.set(ask.id, spoken);
    }
  }
  subscribe((state, reason) => {
    if (reason === 'tick') {
      for (const parts of rows.values()) parts.when.textContent = age(parts.ask.at, state.now);
      if (dialog.open && [...state.asks, ...state.asksStale].some(ask => decisionOf(state.messages, ask)?.status === 'queued')) paint(state);  // the expiry countdown
      return;
    }
    if (['asks', 'chat', 'connection', 'routing', 'availability', 'update'].includes(reason)) paint(state);
  });
  paint(getState());
}
