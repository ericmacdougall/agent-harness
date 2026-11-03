import { openSettings } from './settings.js';
import { composerAction as resolveComposerAction, submissionMatches } from './composer.js';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {
  sessions: [], providers: [], active: null, repository: null, repoView: 'worktrees',
  selectedAgent: new Map(), expanded: new Set(), drafts: new Map(), attachments: new Map(),
  agentTranscript: null, cursor: 0, snapshot: {}, filePicker: null, confirmation: null,
  pendingRequests: new Map(), submissions: new Set(), inputActions: new Set(), stopped: false,
};
const fragment = new URLSearchParams(location.hash.slice(1));
const receivedToken = fragment.get('token') || location.hash.slice(1);
if (receivedToken) {
  sessionStorage.setItem('harness-console-token', receivedToken);
  history.replaceState(null, '', location.pathname + location.search);
}
const token = sessionStorage.getItem('harness-console-token') || '';
const session = () => state.sessions.find(item => item.id === state.active);
const running = status => ['starting', 'running', 'busy', 'thinking', 'waiting'].includes(status);
const composerAction = current => resolveComposerAction(current, state);
const sendBlocked = current => !composerAction(current).allowed;
const errorText = error => error?.message || String(error || 'Request failed.');

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path, body, method = body === undefined ? 'GET' : 'POST') {
  if (state.stopped) throw new Error('Console stopped. Reopen Agent Harness from its launcher.');
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, {
    method, headers, cache: 'no-store',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let result;
  try { result = await response.json(); }
  catch { throw new Error(`Unreadable local response (${response.status}).`); }
  if (!response.ok) {
    const error = new Error(result.error?.message || `Request failed (${response.status}).`);
    error.code = result.error?.code;
    error.status = response.status;
    throw error;
  }
  return result;
}

function notify(message, failure = false) {
  const toast = el('div', `toast${failure ? ' error' : ''}`);
  const close = el('button', '', '×');
  close.setAttribute('aria-label', 'Dismiss notification');
  close.addEventListener('click', () => toast.remove());
  toast.append(close, el('span', '', message));
  $('#toasts').append(toast);
  setTimeout(() => toast.remove(), failure ? 16000 : 8000);
}

async function act(button, work) {
  const disabled = button?.disabled;
  if (button) button.disabled = true;
  try { return await work(); }
  catch (error) { notify(errorText(error), true); }
  finally { if (button?.isConnected) button.disabled = state.stopped || disabled; }
}

function pathLabel(path) {
  if (!path) return 'Choose working directory';
  const parts = path.replaceAll('\\', '/').split('/').filter(Boolean);
  return parts.length > 3 ? `…/${parts.slice(-3).join('/')}` : path;
}

function ago(value) {
  if (!value) return 'unknown';
  const time = typeof value === 'number' ? (value < 1e12 ? value * 1000 : value) : Date.parse(value);
  if (!Number.isFinite(time)) return 'unknown';
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 10) return 'now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function connection(connected, reason) {
  if (state.stopped) return;
  $('#transport-state').classList.toggle('connected', connected);
  $('#transport-state').replaceChildren(el('i'), document.createTextNode(connected ? 'Connected' : 'Reconnecting'));
  $('#connection-banner').hidden = connected;
  if (!connected) $('#connection-banner').textContent = reason || 'Connection interrupted. Work may still be running. Reconnecting to its state…';
}

let loading = false;
let reloadAgain = false;
let stateTimer;
function scheduleState() {
  if (state.stopped) return;
  clearTimeout(stateTimer);
  stateTimer = setTimeout(() => loadState().catch(() => {}), 100);
}

async function loadState() {
  if (state.stopped) return;
  if (loading) { reloadAgain = true; return; }
  loading = true;
  const previousSessionID = state.active;
  try {
    const snapshot = await api('/api/state');
    if (state.stopped) return;
    state.snapshot = snapshot;
    state.sessions = state.snapshot.sessions || [];
    state.providers = state.snapshot.providers || [];
    if (!session()) {
      state.active = state.snapshot.activeSession || state.sessions[0]?.id || null;
      $('#chat-input').value = state.drafts.get(state.active) || '';
    }
    render();
    if (state.active !== previousSessionID) loadRepository().catch(repoError);
  } finally {
    loading = false;
    if (reloadAgain) { reloadAgain = false; scheduleState(); }
  }
}

const eventStreamController = new AbortController();
async function events() {
  let attempts = 0;
  while (!state.stopped) {
    try {
      const response = await fetch(`/api/events?after=${state.cursor}`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: eventStreamController.signal });
      if (!response.ok || !response.body) throw new Error(`Live connection unavailable (${response.status}).`);
      connection(true);
      attempts = 0;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) throw new Error('The live connection closed.');
          buffer += decoder.decode(chunk.value, { stream: true }).replaceAll('\r\n', '\n');
          if (buffer.length > 1048576) throw new Error('A live event exceeded the display limit.');
          let end;
          while ((end = buffer.indexOf('\n\n')) >= 0) {
            const lines = buffer.slice(0, end).split('\n');
            buffer = buffer.slice(end + 2);
            const data = lines.filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
            if (!data) continue;
            const event = JSON.parse(data);
            const id = event.id ?? lines.find(line => line.startsWith('id:'))?.slice(3).trim();
            if (Number.isSafeInteger(Number(id))) state.cursor = Number(id);
            if (event.type === 'gap') notify('Missed events detected. Reloading the current state.');
            if (!['heartbeat', 'keepalive'].includes(event.type)) scheduleState();
          }
        }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    } catch (error) {
      if (state.stopped) return;
      connection(false, errorText(error));
      attempts += 1;
      await new Promise(resolve => setTimeout(resolve, Math.min(1000 * 2 ** Math.min(attempts - 1, 4), 15000)));
      await loadState().catch(() => {});
    }
  }
}

function switchSession(id) {
  if (session()) state.drafts.set(state.active, $('#chat-input').value);
  state.active = id;
  state.repository = null;
  state.agentTranscript = null;
  $('#chat-input').value = state.drafts.get(id) || '';
  render();
  loadRepository().catch(repoError);
  if (state.selectedAgent.get(id)) loadAgent(state.selectedAgent.get(id));
}

function renderTabs() {
  $('#session-tabs').replaceChildren();
  for (const item of state.sessions) {
    const button = el('button', 'session-tab');
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', String(item.id === state.active));
    button.dataset.sessionId = item.id;
    button.title = `${item.title || 'Session'} · ${item.provider}\n${item.cwd || ''}`;
    button.append(el('span', `tab-provider ${item.provider}`, item.provider === 'claude' ? 'Cl' : 'Co'), el('span', 'tab-title', item.title || 'New session'));
    if (running(item.status)) button.append(el('span', 'tab-activity'));
    button.addEventListener('click', () => switchSession(item.id));
    const wrapper = el('div', 'session-tab-wrap');
    const close = el('button', 'session-tab-close', '×');
    close.setAttribute('aria-label', `Close ${item.title || 'session'}`);
    close.title = item.pendingInputs?.length ? 'Resolve stored follow-up payloads before closing this tab.' : 'Close console tab; preserve provider history';
    close.disabled = !!item.pendingInputs?.length || running(item.status) || ['unknown', 'disconnected'].includes(item.status) || item.agents?.some(agent => running(agent.status));
    close.addEventListener('click', () => act(close, async () => {
      if ((state.drafts.get(item.id) || (item.id === state.active && $('#chat-input').value)) && !window.confirm('Close this tab and discard its unsent draft? Provider history is preserved.')) return;
      await api(`/api/sessions/${encodeURIComponent(item.id)}/close`, {});
      state.drafts.delete(item.id); state.attachments.delete(item.id); state.pendingRequests.delete(item.id);
      await loadState();
    }));
    wrapper.append(button, close);
    $('#session-tabs').append(wrapper);
  }
}

const messageNodes = new Map();
let transcriptKey = '';
let deferredTranscriptUpdates = false;

function selectionIntersects(node, selection = window.getSelection()) {
  if (!selection || selection.isCollapsed) return false;
  for (let index = 0; index < selection.rangeCount; index++) {
    const range = selection.getRangeAt(index);
    if (!range.collapsed && range.intersectsNode(node)) return true;
  }
  return false;
}

function updateTextNode(element, value) {
  const text = element.firstChild;
  if (!text || text.nodeType !== Node.TEXT_NODE || element.childNodes.length !== 1) {
    element.replaceChildren(document.createTextNode(value));
    return;
  }
  if (value.startsWith(text.data)) text.appendData(value.slice(text.length));
  else text.replaceData(0, text.length, value);
}

function renderTranscript({ selectionFlush = false } = {}) {
  if (state.stopped) return;
  const current = session();
  const agentID = current && state.selectedAgent.get(current.id);
  const key = `${current?.id || ''}/${agentID || ''}`;
  const container = $('#transcript');
  const changed = key !== transcriptKey;
  const selection = window.getSelection();
  const selectionActive = !changed && selectionIntersects(container, selection);
  let outputChanged = false;
  let deferred = false;
  const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 90;
  if (changed) {
    container.replaceChildren();
    messageNodes.clear();
    transcriptKey = key;
    deferredTranscriptUpdates = false;
    $('#new-output').hidden = true;
  }
  if (!current) {
    if (!$('.welcome', container)) {
      const welcome = el('div', 'welcome');
      welcome.append(el('div', 'welcome-symbol', '↗'), el('h2', '', 'Make room for the work.'), el('p', '', 'Start a conversation with Codex or Claude Code. Keep the chat, its owners, and your working tree together.'));
      const button = el('button', 'primary-button', 'Start a session +');
      button.addEventListener('click', newSessionDialog);
      welcome.append(button);
      container.append(welcome);
    }
    return;
  }
  const messages = agentID ? state.agentTranscript?.messages || [] : current.messages || [];
  const ids = new Set();
  messages.forEach((message, index) => {
    const id = String(message.id || `${index}-${message.role}`);
    ids.add(id);
    let node = messageNodes.get(id);
    if (!node) {
      node = el('article', 'message');
      node.dataset.messageId = id;
      const header = el('div', 'message-header');
      header.append(el('span', 'message-role'), el('time', 'message-time'));
      node.append(header, el('pre', 'message-body'));
      messageNodes.set(id, node);
      container.append(node);
      outputChanged = true;
    }
    // Freeze the whole intersected message, including headers and appends.
    // Even boundary-only CharacterData edits can alter the user's copy range.
    const selected = selectionIntersects(node, selection);
    const update = (element, value) => {
      if (element.textContent === value) return;
      outputChanged = true;
      if (selected) deferred = true;
      else updateTextNode(element, value);
    };
    const role = ['user', 'assistant', 'tool', 'context', 'system'].includes(message.role) ? message.role : 'assistant';
    node.className = `message ${role}${message.streaming ? ' streaming' : ''}`;
    update($('.message-role', node), role === 'assistant' ? (current.provider === 'claude' ? 'Claude Code' : 'Codex') : role.charAt(0).toUpperCase() + role.slice(1));
    update($('.message-time', node), message.timestamp ? new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '');
    update($('.message-body', node), message.text || '');
  });
  for (const [id, node] of messageNodes) {
    if (!ids.has(id)) { node.remove(); messageNodes.delete(id); outputChanged = true; }
  }
  let empty = $('.transcript-empty', container);
  if (!messages.length) {
    if (!empty) { empty = el('div', 'transcript-empty'); container.append(empty); }
    const emptyText = agentID ? state.agentTranscript?.error || 'Loading this agent’s available transcript…' : current.error ? 'This session needs attention. Review the provider error below.' : ['starting', 'unknown', 'disconnected'].includes(current.status) ? 'Waiting for the provider connection to become ready…' : 'Send a message below to begin.';
    if (empty.textContent !== emptyText) empty.textContent = emptyText;
  } else empty?.remove();
  deferredTranscriptUpdates = deferred;
  const badge = $('#new-output');
  badge.textContent = deferred ? 'Text changed — show latest' : '↓ New output';
  if (!selectionActive && !selectionFlush && (atBottom || changed)) {
    container.scrollTop = container.scrollHeight;
    badge.hidden = true;
  } else if (outputChanged) badge.hidden = false;
}

async function loadAgent(id) {
  const current = session();
  if (!current) return;
  try {
    const result = await api(`/api/sessions/${encodeURIComponent(current.id)}/agents/${encodeURIComponent(id)}/messages`);
    if (session()?.id === current.id && state.selectedAgent.get(current.id) === id) { state.agentTranscript = result; renderTranscript(); }
  } catch (error) {
    if (session()?.id === current.id && state.selectedAgent.get(current.id) === id) { state.agentTranscript = { messages: [], error: errorText(error) }; renderTranscript(); }
  }
}

function selectAgent(id) {
  if (!session()) return;
  state.selectedAgent.set(state.active, id);
  state.agentTranscript = null;
  render();
  loadAgent(id);
}

function toggleAgent(id, expanded) {
  if (expanded ?? !state.expanded.has(id)) state.expanded.add(id);
  else state.expanded.delete(id);
  renderAgents();
}

function renderAgents() {
  const current = session();
  const agents = current?.agents || [];
  const selectedID = current && state.selectedAgent.get(current.id);
  const focusedID = document.activeElement?.dataset.agentId;
  const tree = $('#agent-tree');
  tree.replaceChildren();
  $('#agent-count').textContent = agents.length;
  if (!agents.length) tree.append(el('p', 'sidebar-empty', 'Actual owners and subagents appear here as the provider reports them.'));
  const known = new Set(agents.map(item => item.id));
  const visited = new Set();
  function append(parent, parentID, depth) {
    if (depth > 20) return;
    for (const agent of agents.filter(item => parentID ? item.parentId === parentID : !item.parentId || !known.has(item.parentId))) {
      if (visited.has(agent.id)) continue;
      visited.add(agent.id);
      const children = agents.some(item => item.parentId === agent.id);
      const expanded = state.expanded.has(agent.id);
      const button = el('button', 'agent-node');
      button.dataset.agentId = agent.id;
      button.dataset.parentId = agent.parentId || '';
      button.setAttribute('role', 'treeitem');
      button.setAttribute('aria-level', depth + 1);
      button.setAttribute('aria-selected', String(agent.id === selectedID));
      if (children) button.setAttribute('aria-expanded', String(expanded));
      button.append(el('span', 'agent-chevron', children ? expanded ? '⌄' : '›' : ''), el('span', `agent-avatar ${agent.provider || current.provider}`, (agent.name || agent.role || 'A').slice(0, 1).toUpperCase()));
      const content = el('span', 'agent-content');
      const heading = el('span', 'agent-heading');
      heading.append(el('span', 'agent-name', agent.name || agent.role || agent.id), el('span', `agent-dot ${agent.status || ''}`));
      const metadata = el('span', 'agent-meta');
      metadata.append(el('span', '', agent.model || 'Model unknown'));
      if (agent.role) metadata.append(el('span', '', agent.role));
      for (const [label, timestamp] of [['Ping', agent.lastSeen], ['Write', agent.lastWrite]]) {
        const time = el('span', '', `${label} ${ago(timestamp)}`);
        time.dataset.timestamp = timestamp || '';
        time.dataset.label = label;
        metadata.append(time);
      }
      content.append(heading, el('span', 'agent-task', agent.task || agent.status || 'No task reported'), metadata);
      button.append(content);
      button.addEventListener('click', event => {
        if (children && event.target.classList.contains('agent-chevron')) toggleAgent(agent.id);
        else selectAgent(agent.id);
      });
      parent.append(button);
      if (children && expanded) {
        const group = el('div', 'agent-children');
        group.setAttribute('role', 'group');
        append(group, agent.id, depth + 1);
        parent.append(group);
      }
    }
  }
  append(tree, null, 0);
  const selected = agents.find(item => item.id === selectedID);
  const detail = $('#agent-detail');
  detail.hidden = !selected;
  detail.replaceChildren();
  if (selected) {
    detail.append(el('h3', '', selected.name || selected.role || 'Agent'), el('p', '', selected.task || 'No task reported'));
    const actions = el('div', 'agent-detail-actions');
    for (const [label, name, allowed] of [['Pause', 'pause', selected.canPause], ['Resume', 'resume', selected.canResume], ['Stop', 'stop', selected.canStop]]) {
      const button = el('button', '', label);
      button.disabled = !allowed || !!current.restored;
      button.title = current.restored ? 'Restored history is read-only. Continue in a new session.' : allowed ? `${label} this agent` : selected.controlReason || `${label} is unavailable in this provider state.`;
      button.addEventListener('click', () => control(name, selected.id, button));
      actions.append(button);
    }
    detail.append(actions);
  }
  if (focusedID) $$('[data-agent-id]', tree).find(node => node.dataset.agentId === focusedID)?.focus({ preventScroll: true });
}

let questionsKey = '';
function renderQuestions() {
  const current = session();
  const key = `${current?.id || ''}/${!!current?.restored}/${JSON.stringify(current?.pendingQuestions || [])}`;
  if (questionsKey === key) return;
  questionsKey = key;
  $('#questions').replaceChildren();
  if (current?.restored) return;
  for (const question of current?.pendingQuestions || []) {
    const card = el('section', 'question-card');
    card.dataset.questionId = question.id;
    card.append(el('h3', '', question.title || 'Your input is needed'), el('p', '', question.prompt || question.kind || 'Choose how to continue.'));
    const actions = el('div', 'question-actions');
    if (question.questions?.length) {
      card.append(structuredQuestions(question));
      $('#questions').append(card);
      continue;
    }
    for (const choice of question.choices || []) {
      const label = typeof choice === 'string' ? choice : choice.label || choice.title || choice.value;
      const value = typeof choice === 'string' ? choice : choice.value ?? choice.id ?? label;
      const button = el('button', '', label);
      button.addEventListener('click', () => answerQuestion(question.id, value, button));
      actions.append(button);
    }
    if (!question.choices?.length || question.allowText) {
      const input = el(question.kind === 'approval' ? 'input' : 'textarea');
      input.placeholder = question.kind === 'approval' ? 'Your answer' : 'Answer as JSON using the question IDs above';
      input.setAttribute('aria-label', question.title || 'Answer');
      const button = el('button', '', 'Send answer');
      button.addEventListener('click', () => {
        if (!input.value.trim()) return;
        let value = input.value;
        if (question.kind !== 'approval') {
          try { value = JSON.parse(value); }
          catch { notify('Enter a valid JSON answer matching the question IDs.', true); return; }
        }
        answerQuestion(question.id, value, button);
      });
      actions.append(input, button);
    }
    card.append(actions);
    $('#questions').append(card);
  }
}

async function answerQuestion(questionId, answer, button) {
  const current = session();
  if (!current) return;
  await act(button, async () => {
    await api(`/api/sessions/${encodeURIComponent(current.id)}/answer`, { questionId, answer });
    await loadState();
  });
}

function structuredQuestions(pending) {
  const form = el('form', 'structured-questions');
  for (const question of pending.questions) {
    const group = el('fieldset');
    group.dataset.questionId = question.id;
    group.append(el('legend', '', question.header || question.question || 'Question'));
    if (question.header) group.append(el('p', '', question.question));
    for (const option of question.options || []) {
      const label = el('label', 'question-option');
      const input = el('input');
      input.type = 'radio'; input.name = question.id; input.value = option.label;
      const text = el('span');
      text.append(el('strong', '', option.label));
      if (option.description) text.append(el('small', '', option.description));
      label.append(input, text); group.append(label);
    }
    const freeText = el('textarea');
    freeText.placeholder = question.options?.length ? 'Or write your own answer' : 'Your answer';
    freeText.rows = 2;
    freeText.setAttribute('aria-label', `Answer ${question.header || question.question}`);
    group.append(freeText); form.append(group);
  }
  const button = el('button', 'primary-button', 'Send answers');
  button.type = 'submit'; form.append(button);
  form.addEventListener('submit', event => {
    event.preventDefault();
    const answers = {};
    for (const group of $$('fieldset', form)) {
      const answer = $('textarea', group).value.trim() || $('input:checked', group)?.value;
      if (!answer) { notify('Answer each question before submitting.', true); return; }
      answers[group.dataset.questionId] = { answers: [answer] };
    }
    answerQuestion(pending.id, answers, button);
  });
  return form;
}

function renderAttachments() {
  const current = session();
  const attachments = current ? state.attachments.get(current.id) || current.attachments || [] : [];
  $('#attachments').replaceChildren();
  for (const item of attachments) {
    const path = typeof item === 'string' ? item : item.path;
    const chip = el('span', 'attachment-chip');
    const name = el('span', '', path.replaceAll('\\', '/').split('/').pop());
    name.title = path;
    const button = el('button', '', '×');
    button.type = 'button';
    button.setAttribute('aria-label', `Remove ${name.textContent}`);
    button.addEventListener('click', () => {
      state.attachments.set(current.id, attachments.filter(candidate => candidate !== item));
      renderAttachments();
    });
    chip.append(name, button);
    $('#attachments').append(chip);
  }
}

function render() {
  if (state.stopped) return;
  renderTabs();
  const current = session();
  const selectedID = current && state.selectedAgent.get(current.id);
  const selected = current?.agents?.find(item => item.id === selectedID);
  $('#conversation-title').textContent = selected?.name || selected?.role || current?.title || 'Ready when you are';
  $('#conversation-eyebrow').textContent = selectedID ? 'AGENT TRANSCRIPT' : current ? `${current.provider.toUpperCase()} · ${current.model || 'MODEL NOT REPORTED'}` : 'YOUR WORKSPACE';
  $('#back-to-session').hidden = !selectedID;
  const status = selected?.status || current?.status || 'No session';
  $('#session-status').textContent = status;
  $('#session-status').className = `status-pill ${status}`;
  $('#cwd-label').textContent = pathLabel(current?.cwd);
  $('#cwd-button').title = current?.cwd || 'Change working directory';
  $('#composer-context').textContent = selectedID ? 'Sends to the main session' : current ? `${current.provider === 'claude' ? 'Claude Code' : 'Codex'} · ${current.effort || 'Default effort'}` : 'Choose a session to begin';
  $('#recovery-banner').hidden = !current?.restored;
  $('#chat-input').readOnly = !!current?.restored;
  $('#chat-input').placeholder = current?.restored ? 'Continue in a new session to send your next message.' : 'What would you like to build?';
  $('#cwd-button').disabled = !!current?.restored || !!current?.pendingInputs?.length;
  const action = composerAction(current);
  $('#send-message').disabled = !action.allowed || !$('#chat-input').value.trim();
  $('#send-message').textContent = action.label === 'Send message' ? '↑' : action.label;
  $('#send-message').classList.toggle('labelled-send', action.label !== 'Send message');
  $('#send-message').setAttribute('aria-label', action.label);
  $('#send-message').title = action.reason || action.label;
  $('#composer-hint').textContent = action.reason || (action.kind === 'queue' ? 'Follow-ups stay with this objective. Admission is not delivery; paused work holds the queue.' : action.label === 'Send new objective' ? 'This starts a new objective after the previous task ended.' : '');
  $('#composer-hint').hidden = !$('#composer-hint').textContent;
  $('#stop-session').hidden = !current || current.restored || !running(current.status);
  $('#pause-session').hidden = !current || current.restored || !running(current.status);
  const resumable = current && (['paused', 'disconnected'].includes(current.status) || current.status === 'idle' && current.supervision?.state === 'waiting' && current.messages?.some(message => message.role === 'user'));
  $('#resume-session').hidden = !!current?.restored || !resumable || !current.providerId;
  $('#attach-button').disabled = !current || !!current.restored;
  $('#session-error').hidden = !current?.error;
  $('#session-error').textContent = typeof current?.error === 'object' ? current.error.message || current.error.code : current?.error || '';
  const supervision = current?.supervision;
  $('#supervision').hidden = !supervision?.state || supervision.state === 'idle';
  if (supervision) {
    $('#supervision-title').textContent = `Work ${supervision.state}`;
    $('#supervision-detail').textContent = supervision.nextCheckpoint || supervision.reason || `${supervision.remainingBursts ?? 'Unknown'} continuation bursts remain`;
  }
  const usage = current?.usage;
  const tokens = usage?.totalTokens ?? usage?.total_tokens ?? null;
  $('#usage-stat').textContent = tokens === null ? 'Usage unavailable' : `${Number(tokens).toLocaleString()} tokens`;
  const active = (current?.agents || []).filter(agent => running(agent.status)).length;
  $('#tool-stat').textContent = active ? `${active} active agent${active === 1 ? '' : 's'}` : 'No active agents';
  renderTranscript();
  renderAgents();
  renderQuestions();
  renderAttachments();
  renderPendingInputs();
  if (!state.repository && current) loadRepository().catch(repoError);
}

async function control(name, agentId, button) {
  const current = session();
  if (!current) return;
  if (current.restored) return notify('Restored history is read-only. Continue in a new session.', true);
  await act(button, async () => {
    await api(`/api/sessions/${encodeURIComponent(current.id)}/control`, { action: name, agentId: agentId || '' });
    await loadState();
    if (agentId) await loadAgent(agentId);
  });
}

function selectedAttachments(current) {
  return state.attachments.get(current.id) || current.attachments || [];
}
function capturedPaths(current) {
  return selectedAttachments(current).map(item => typeof item === 'string' ? item : item.path);
}
function clearAcceptedDraft(current, request) {
  const draft = state.active === current.id ? $('#chat-input').value : state.drafts.get(current.id);
  if (draft === request.draft) {
    state.drafts.delete(current.id);
    if (state.active === current.id) $('#chat-input').value = '';
  }
  if (selectedAttachments(current) === request.attachmentSelection) state.attachments.set(current.id, []);
}
$('#composer').addEventListener('submit', async event => {
  event.preventDefault();
  const current = session();
  const input = $('#chat-input');
  const text = input.value.trim();
  const action = composerAction(current);
  if (!action.allowed || !text) return;
  if (new TextEncoder().encode(text).length > 128 * 1024) return notify('Messages are limited to 128 KiB. Your draft is preserved.', true);
  const paths = capturedPaths(current);
  const previous = state.pendingRequests.get(current.id);
  if (previous && !submissionMatches(previous, { kind: action.kind, text, attachments: paths })) {
    notify('A previous submission has an uncertain outcome. Check its admission before changing the payload or starting another objective.', true);
    return;
  }
  const request = previous || { requestId: crypto.randomUUID(), text, draft: input.value, attachments: paths, attachmentSelection: selectedAttachments(current), kind: action.kind };
  state.pendingRequests.set(current.id, request);
  state.submissions.add(current.id);
  render();
  try {
    const payload = { requestId: request.requestId, text: request.text, attachments: request.attachments };
    const result = await api(`/api/sessions/${encodeURIComponent(current.id)}/${request.kind === 'queue' ? 'inputs' : 'send'}`, payload);
    if (request.kind === 'queue' && (!result.queued || result.requestId !== request.requestId)) throw new Error('The response did not confirm this queue admission. Check its status before retrying.');
    state.pendingRequests.delete(current.id);
    if (request.kind === 'queue' && result.status === 'discarded') {
      notify('The prior local payload was discarded. Your draft is retained; check prior provider work before submitting again.');
      await loadState();
      return;
    }
    clearAcceptedDraft(current, request);
    if (request.kind === 'queue') notify(`Follow-up admitted as ${result.status || 'stored'}. Admission is not confirmation of provider delivery.`);
    await loadState();
    if (request.kind === 'send' && state.active === current.id && !selectionIntersects($('#transcript'))) $('#transcript').scrollTop = $('#transcript').scrollHeight;
  } catch (error) {
    // A retry refusal can still refer to an earlier admitted request (for example,
    // attachment bytes changed). Keep its identity until explicit reconciliation.
    if (!previous && [400, 401, 403, 404, 422].includes(error.status)) state.pendingRequests.delete(current.id);
    notify(`${errorText(error)} Your draft remains available. ${request.kind === 'queue' ? 'Use Check admission or retry the same unchanged payload.' : 'Check the session before sending again.'}`, true);
  } finally { state.submissions.delete(current.id); render(); }
});

let pendingInputsKey = '';
function renderPendingInputs() {
  const current = session();
  const entries = current?.pendingInputs || [];
  const uncertain = current && state.pendingRequests.get(current.id);
  const relevant = entries.length || composerAction(current).kind === 'queue' || uncertain?.kind === 'queue';
  $('#input-queue').hidden = !current || !relevant;
  const key = JSON.stringify([current?.id, entries, current?.work?.inputRevision, uncertain?.requestId, current && state.submissions.has(current.id), [...state.inputActions]]);
  if (key === pendingInputsKey) return;
  pendingInputsKey = key;
  const unsent = entries.filter(entry => ['queued', 'held', 'dispatching', 'unknown'].includes(entry.status)).length;
  $('#input-queue-summary').textContent = `Follow-ups · ${unsent} pending · ${entries.length} stored${current?.work?.inputRevision ? ` · objective revision ${current.work.inputRevision}` : ''}`;
  const list = $('#pending-input-list'); list.replaceChildren();
  if (uncertain?.kind === 'queue' && !state.submissions.has(current.id)) {
    const panel = el('div', 'pending-input uncertain');
    panel.append(el('strong', '', 'Admission outcome needs checking'), el('p', '', 'Your draft is retained. A retry must use the same request ID, text and attachments.'));
    const check = el('button', 'quiet-button', 'Check admission');
    check.disabled = state.inputActions.has(`${current.id}/${uncertain.requestId}/view`);
    check.addEventListener('click', () => inspectInput(current.id, uncertain.requestId, check, uncertain));
    panel.append(check); list.append(panel);
  }
  for (const entry of entries) {
    const panel = el('article', `pending-input ${entry.status}`); panel.dataset.requestId = entry.requestId;
    const title = el('div', 'pending-input-title');
    title.append(el('strong', '', entry.status), el('time', '', entry.createdAt ? new Date(entry.createdAt).toLocaleTimeString() : ''), el('span', '', `${entry.attachmentCount || 0} attachments`));
    panel.append(title, el('p', 'pending-input-preview', entry.preview || '(No preview available)'));
    if (entry.reason) panel.append(el('p', 'pending-input-reason', entry.reason));
    if (entry.deliveredInputRevision) panel.append(el('p', '', `Dispatched at objective revision ${entry.deliveredInputRevision}.`));
    const controls = el('div', 'pending-input-actions');
    const view = el('button', 'quiet-button', 'View / copy');
    view.disabled = state.inputActions.has(`${current.id}/${entry.requestId}/view`);
    view.addEventListener('click', () => inspectInput(current.id, entry.requestId, view)); controls.append(view);
    if (['queued', 'held'].includes(entry.status)) {
      const cancel = el('button', 'quiet-button', 'Cancel unsent');
      cancel.disabled = state.inputActions.has(`${current.id}/${entry.requestId}/cancel`);
      cancel.addEventListener('click', () => inputAction(current.id, entry.requestId, 'cancel', cancel, async path => {
        await api(path, undefined, 'DELETE'); notify('Unsent follow-up cancelled.');
      })); controls.append(cancel);
    } else if (['unknown', 'retained'].includes(entry.status)) {
      const discard = el('button', 'danger-button', 'Discard local payload');
      discard.disabled = state.inputActions.has(`${current.id}/${entry.requestId}/discard`);
      discard.addEventListener('click', () => confirmAction({
        title: 'Discard this local payload?', label: 'Discard local payload',
        description: 'This releases the stored message and attachment snapshots on this computer. It does NOT stop provider work or undo delivery. Files may still be needed; delivered text can remain in the current task objective until that task ends. Reconcile the outcome before discarding.',
        run: () => inputAction(current.id, entry.requestId, 'discard', discard, async path => {
          await api(`${path}/discard`, { confirm: true }); notify('Local payload discarded. Provider work was not stopped.');
        }, true),
      })); controls.append(discard);
    }
    panel.append(controls); list.append(panel);
  }
  if (!entries.length && uncertain?.kind !== 'queue') list.append(el('p', 'sidebar-empty', 'No stored follow-ups. They are dispatched in FIFO order at a safe boundary.'));
}
async function inputAction(sessionID, requestID, action, button, work, propagate = false) {
  const key = `${sessionID}/${requestID}/${action}`;
  if (state.inputActions.has(key)) return;
  state.inputActions.add(key);
  if (button) button.disabled = true;
  try {
    await work(`/api/sessions/${encodeURIComponent(sessionID)}/inputs/${encodeURIComponent(requestID)}`);
    await loadState();
  } catch (error) {
    if (propagate) throw error;
    notify(errorText(error), true);
  } finally {
    state.inputActions.delete(key);
    if (button?.isConnected) button.disabled = state.stopped;
    render();
  }
}
async function inspectInput(sessionID, requestID, button, uncertain) {
  await inputAction(sessionID, requestID, 'view', button, async path => {
    const detail = await api(path);
    $('#input-detail-status').textContent = `${detail.status}${detail.reason ? ` — ${detail.reason}` : ''}. Stored status is separate from provider completion.`;
    $('#input-detail-text').value = detail.text || '';
    const files = $('#input-detail-files'); files.replaceChildren();
    for (const file of detail.attachments || []) files.append(el('li', '', `${file.path} · ${file.size} bytes`));
    const dialog = $('#input-detail-dialog'); if (!dialog.open) dialog.showModal();
    if (uncertain && state.pendingRequests.get(sessionID)?.requestId === requestID) {
      state.pendingRequests.delete(sessionID);
      const current = state.sessions.find(item => item.id === sessionID);
      if (current && detail.status !== 'discarded') clearAcceptedDraft(current, uncertain);
      notify(`Admission reconciled as ${detail.status}. No message was resent.`);
    }
  });
}

function newSessionDialog() {
  $('#new-cwd').value = session()?.cwd || state.snapshot.cwd || state.snapshot.defaultCwd || '';
  $('#new-session-error').hidden = true;
  const savedDefault = el('option', '', 'Saved default');
  savedDefault.value = '';
  $('#provider-select').replaceChildren(savedDefault);
  const providers = state.providers.length ? state.providers : [{ id: 'codex', name: 'Codex' }, { id: 'claude', name: 'Claude Code' }];
  for (const provider of providers) {
    const option = el('option', '', `${provider.name}${provider.available === false ? ' — setup required' : ''}`);
    option.value = provider.id;
    $('#provider-select').append(option);
  }
  providerHelp();
  $('#new-session-dialog').showModal();
}

function providerHelp() {
  if (!$('#provider-select').value) {
    $('#provider-help').textContent = 'Uses the provider, profile and model configured in Settings when this session is created.';
    return;
  }
  const provider = state.providers.find(item => item.id === $('#provider-select').value);
  $('#provider-help').textContent = provider?.available === false ? `${provider.reason || 'Provider CLI unavailable.'} Install the official CLI in a supported location or on the PATH used to start the console, then restart.` : 'Uses the locally installed CLI and its existing sign-in.';
}

$('#new-session-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('#create-session').disabled = true;
  $('#new-session-error').hidden = true;
  try {
    const result = await api('/api/sessions', { provider: $('#provider-select').value, cwd: $('#new-cwd').value.trim() });
    await loadState();
    switchSession(result.id || result.session?.id || state.snapshot.activeSession);
    $('#new-session-dialog').close();
    $('#chat-input').focus();
  } catch (error) {
    $('#new-session-error').textContent = errorText(error);
    $('#new-session-error').hidden = false;
  } finally { $('#create-session').disabled = false; }
});

const repositoryRequests = new Set();
async function loadRepository(fetchRemote = false) {
  const current = session();
  if (!current) return;
  const key = `${current.id}/${current.cwd}/${fetchRemote}`;
  if (repositoryRequests.has(key)) return;
  repositoryRequests.add(key);
  try {
    const result = fetchRemote ? await api('/api/git/refresh', { sessionId: current.id }) : await api(`/api/git?sessionId=${encodeURIComponent(current.id)}`);
    if (session()?.id !== current.id || session()?.cwd !== current.cwd) return;
    state.repository = result;
    $('#repo-error').hidden = true;
    renderRepository();
  } finally {
    repositoryRequests.delete(key);
  }
}

function repoError(error) {
  state.repository = { worktrees: [], branches: [] };
  $('#repo-error').textContent = errorText(error);
  $('#repo-error').hidden = false;
  renderRepository();
}

function renderRepository() {
  if (state.stopped) return;
  const repo = state.repository;
  $('#repo-summary').textContent = repo?.root ? `${repo.branch || 'Detached HEAD'}${repo.dirty ? ' · uncommitted changes' : ''}` : 'No repository selected';
  $('#repository-list').replaceChildren();
  const rows = [...(repo?.[state.repoView] || [])].sort((a, b) => Number(!!b.current) - Number(!!a.current) || Number(!!a.prunable) - Number(!!b.prunable));
  if (!rows.length) $('#repository-list').append(el('p', 'sidebar-empty', 'Repository state appears for the selected directory.'));
  for (const row of rows) {
    const item = el('div', `repo-row${row.current ? ' current' : ''}`);
    item.append(el('span', 'repo-symbol', row.current ? '★' : state.repoView === 'worktrees' ? '◇' : '⑂'));
    const info = el('div', 'repo-info');
    info.append(el('div', 'repo-name', state.repoView === 'worktrees' ? row.branch || 'Detached HEAD' : row.name), el('div', 'repo-path', pathLabel(row.path || row.upstream || 'Local branch')));
    info.title = row.path || row.upstream || '';
    const sync = el('span', `repo-sync${row.dirty ? ' dirty' : ''}`);
    sync.textContent = [row.prunable ? 'stale' : '', row.locked ? 'locked' : '', row.dirty ? 'edited' : '', row.ahead || row.behind ? `↑${row.ahead || 0} ↓${row.behind || 0}` : row.upstream || row.remote ? 'synced' : 'local'].filter(Boolean).join(' · ');
    const actions = el('div', 'repo-actions');
    if (row.path) {
      const cwd = el('button', '', '↗');
      cwd.title = 'Use as working directory';
      cwd.setAttribute('aria-label', `Use ${row.path} as working directory`);
      cwd.addEventListener('click', () => changeCwd(row.path, cwd));
      const refresh = el('button', '', '↻');
      refresh.title = 'Safely sync this worktree';
      refresh.setAttribute('aria-label', `Sync ${row.path}`);
      refresh.addEventListener('click', () => syncRepository(row, refresh));
      const remove = el('button', '', '×');
      remove.title = row.current ? 'The current worktree cannot be removed.' : 'Remove this local copy with safety checks';
      remove.setAttribute('aria-label', `Remove ${row.path}`);
      remove.disabled = !!row.current;
      remove.addEventListener('click', () => removeWorktree(row));
      actions.append(cwd, refresh, remove);
    }
    item.append(info, sync, actions);
    $('#repository-list').append(item);
  }
}

async function syncRepository(row, button) {
  const current = session();
  if (!current) return;
  await act(button, async () => {
    const result = await api('/api/git/sync', { sessionId: current.id, path: row.path, expectedHead: row.head || state.repository.head });
    notify(result.message || 'Repository sync completed.');
    await loadRepository();
  });
}

function confirmAction(options) {
  state.confirmation = options;
  $('#confirm-title').textContent = options.title;
  $('#confirm-description').textContent = options.description;
  $('#confirm-input').value = '';
  $('#confirm-input').hidden = !options.confirmValue;
  $('#confirm-label').hidden = !options.confirmValue;
  $('#confirm-action').textContent = options.label || 'Continue';
  $('#confirm-error').hidden = true;
  $('#confirm-dialog').showModal();
}

function removeWorktree(row) {
  const current = session();
  if (!current) return;
  confirmAction({
    title: 'Remove local worktree', label: 'Remove local copy', confirmValue: row.path,
    description: `The server checks local edits, unpublished commits, locks and active directories.\n\nType this full path to confirm removal of its local copy.\n${row.path}`,
    run: async () => {
      await api('/api/git/remove', { sessionId: current.id, path: row.path, expectedHead: row.head, confirmPath: row.path });
      await loadRepository();
      notify('Local worktree removed.');
    },
  });
}

$('#confirm-form').addEventListener('submit', async event => {
  event.preventDefault();
  const options = state.confirmation;
  if (!options) return;
  if (options.confirmValue && $('#confirm-input').value !== options.confirmValue) {
    $('#confirm-error').textContent = 'The path must match exactly.';
    $('#confirm-error').hidden = false;
    return;
  }
  $('#confirm-action').disabled = true;
  try { await options.run(); $('#confirm-dialog').close(); }
  catch (error) { $('#confirm-error').textContent = errorText(error); $('#confirm-error').hidden = false; }
  finally { $('#confirm-action').disabled = state.stopped; }
});

async function changeCwd(path, button) {
  const current = session();
  if (!current) return false;
  if (current.restored) { notify('Continue in a new session before changing its working directory.', true); return false; }
  if (current.pendingInputs?.length) { notify('Resolve stored follow-up payloads before changing this session’s directory.', true); return false; }
  const result = await act(button, async () => {
    await api(`/api/sessions/${encodeURIComponent(current.id)}/cwd`, { path });
    state.repository = null;
    await loadState();
    await loadRepository();
    notify('Working directory updated for this session.');
    return true;
  });
  return result === true;
}

async function filePicker(mode = 'attachments', onChoose) {
  if (session()?.restored && !onChoose) return notify('Restored history is read-only. Continue in a new session first.', true);
  state.filePicker = { mode, selected: new Set(), path: session()?.cwd || state.snapshot.cwd || '', parent: '', onChoose, generation: 0 };
  $('#file-dialog-title').textContent = mode === 'directory' ? 'Choose working directory' : 'Choose files';
  $('#file-confirm').textContent = mode === 'directory' ? 'Use this directory' : 'Attach selected files';
  $('#file-error').hidden = true;
  $('#file-list').replaceChildren(el('p', 'sidebar-empty', 'Loading…'));
  $('#file-dialog').showModal();
  await browseFiles(state.filePicker.path);
}

async function browseFiles(path) {
  const picker = state.filePicker;
  if (!picker) return;
  const generation = ++picker.generation;
  try {
    const result = await api(`/api/files?path=${encodeURIComponent(path)}`);
    if (picker !== state.filePicker || generation !== picker.generation) return;
    picker.path = result.path;
    picker.parent = result.parent;
    $('#file-path').value = result.path;
    $('#file-up').disabled = !result.parent || result.parent === result.path;
    $('#file-error').hidden = true;
    $('#file-list').replaceChildren();
    for (const entry of result.entries || []) {
      if (picker.mode === 'directory' && !entry.directory) continue;
      const row = el('button', 'file-row');
      row.type = 'button';
      row.setAttribute('role', 'listitem');
      row.dataset.path = entry.path;
      row.setAttribute('aria-selected', String(picker.selected.has(entry.path)));
      row.append(el('span', '', entry.directory ? '▱' : '▤'), el('span', 'file-name', entry.name), el('span', 'file-size', entry.directory ? 'Folder' : bytes(entry.size)));
      row.addEventListener('click', () => {
        if (entry.directory) return browseFiles(entry.path);
        if (picker.selected.has(entry.path)) picker.selected.delete(entry.path);
        else picker.selected.add(entry.path);
        row.setAttribute('aria-selected', String(picker.selected.has(entry.path)));
        fileSelection();
      });
      $('#file-list').append(row);
    }
    if (!$('#file-list').children.length) $('#file-list').append(el('p', 'sidebar-empty', 'This directory has no selectable entries.'));
    fileSelection();
  } catch (error) {
    if (picker === state.filePicker && generation === picker.generation) {
      $('#file-error').textContent = errorText(error);
      $('#file-error').hidden = false;
    }
  }
}

function bytes(value) {
  if (!Number.isFinite(value)) return '';
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1048576).toFixed(1)} MB`;
}

function fileSelection() {
  const picker = state.filePicker;
  const count = picker.selected.size;
  $('#file-selection-count').textContent = picker.mode === 'directory' ? pathLabel(picker.path) : `${count} file${count === 1 ? '' : 's'} selected`;
  $('#file-confirm').disabled = picker.mode !== 'directory' && !count;
}

$('#file-confirm').addEventListener('click', async () => {
  const picker = state.filePicker;
  if (!picker) return;
  $('#file-confirm').disabled = true;
  try {
    if (picker.mode === 'directory') {
      if (picker.onChoose) await picker.onChoose(picker.path);
      else if (!await changeCwd(picker.path)) return;
    } else {
      if (!session()) throw new Error('Select a session first.');
      const paths = [...picker.selected];
      await api(`/api/sessions/${encodeURIComponent(state.active)}/attachments`, { paths });
      state.attachments.set(state.active, paths);
      renderAttachments();
    }
    $('#file-dialog').close();
  } catch (error) { $('#file-error').textContent = errorText(error); $('#file-error').hidden = false; }
  finally { $('#file-confirm').disabled = false; }
});

async function launchCLI(provider) {
  if (!session()) return notify('Create or select a session first.', true);
  try {
    const result = await api('/api/launch', { sessionId: state.active, provider });
    notify(result.message || result.note || `${provider === 'claude' ? 'Claude Code' : 'Codex'} launch requested. Check the new terminal window.`);
  } catch (error) { notify(errorText(error), true); }
}

$('#agent-tree').addEventListener('keydown', event => {
  const current = event.target.closest('[role=treeitem]');
  if (!current) return;
  const nodes = $$('[role=treeitem]', $('#agent-tree'));
  const index = nodes.indexOf(current);
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    nodes[Math.max(0, Math.min(nodes.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)))]?.focus();
  } else if (event.key === 'ArrowRight' && current.hasAttribute('aria-expanded')) {
    event.preventDefault();
    toggleAgent(current.dataset.agentId, true);
  } else if (event.key === 'ArrowLeft') {
    event.preventDefault();
    if (current.getAttribute('aria-expanded') === 'true') toggleAgent(current.dataset.agentId, false);
    else nodes.find(node => node.dataset.agentId === current.dataset.parentId)?.focus();
  } else if (event.key === 'Enter') {
    event.preventDefault();
    selectAgent(current.dataset.agentId);
  }
});

document.addEventListener('keydown', event => {
  if (state.stopped || $('dialog[open]') || event.isComposing || event.repeat) return;
  if ((event.ctrlKey || event.metaKey) && !event.altKey && event.code === 'Enter' && event.target === $('#chat-input')) {
    event.preventDefault();
    $('#composer').requestSubmit();
    return;
  }
  // Physical codes work with Option-generated characters and non-US layouts.
  // Leave browser commands, plain Tab and ordinary text editing to the browser.
  if (!event.altKey || !event.shiftKey || event.ctrlKey || event.metaKey || event.getModifierState('AltGraph')) return;
  const actions = {
    KeyN: newSessionDialog,
    KeyO: () => filePicker(),
    KeyW: () => filePicker('directory'),
    KeyK: () => launchCLI('codex'),
    KeyL: () => launchCLI('claude'),
    BracketRight: () => moveSession(1),
    BracketLeft: () => moveSession(-1),
  };
  if (actions[event.code]) {
    event.preventDefault();
    actions[event.code]();
  }
});

function moveSession(direction) {
  if (!state.sessions.length) return;
  const index = state.sessions.findIndex(item => item.id === state.active);
  switchSession(state.sessions[(index + direction + state.sessions.length) % state.sessions.length].id);
}

// Native copy preserves rendered block boundaries. Only cross-pane copy needs clipping.
document.addEventListener('copy', event => {
  const target = event.target instanceof Element ? event.target : event.target?.parentElement;
  if (target?.closest('input, textarea') || target?.isContentEditable) return;
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || !selection.rangeCount) return;
  const transcript = $('#transcript');
  const ranges = Array.from({ length: selection.rangeCount }, (_, index) => selection.getRangeAt(index));
  const inside = range => transcript.contains(range.startContainer) && transcript.contains(range.endContainer);
  if (ranges.every(inside) || !ranges.some(range => range.intersectsNode(transcript))) return;
  event.preventDefault();
  if (ranges.length !== 1) {
    notify('Copy cancelled. Select one continuous transcript range when copying across panes. Your clipboard and selection are unchanged.', true);
    return;
  }
  if (!event.clipboardData) {
    notify('Copy cancelled because this browser did not provide clipboard access. Your clipboard is unchanged.', true);
    return;
  }
  if (typeof selection.setBaseAndExtent !== 'function' && (typeof selection.collapse !== 'function' || typeof selection.extend !== 'function')) {
    notify('Copy cancelled because this browser cannot restore the original selection. Your clipboard and selection are unchanged.', true);
    return;
  }
  const original = ranges[0].cloneRange();
  const { anchorNode, anchorOffset, focusNode, focusOffset } = selection;
  const restored = () => selection.rangeCount === 1 && selection.anchorNode === anchorNode && selection.anchorOffset === anchorOffset && selection.focusNode === focusNode && selection.focusOffset === focusOffset;
  const restore = () => {
    try { selection.setBaseAndExtent(anchorNode, anchorOffset, focusNode, focusOffset); }
    catch { /* Standard collapse/extend below also preserves backwards direction. */ }
    if (!restored()) {
      selection.removeAllRanges();
      selection.addRange(original);
      if (!restored()) {
        selection.collapse(anchorNode, anchorOffset);
        selection.extend(focusNode, focusOffset);
      }
    }
    if (!restored()) throw new Error('The original selection could not be restored.');
  };
  const boundary = document.createRange();
  boundary.selectNodeContents(transcript);
  const clipped = original.cloneRange();
  if (clipped.compareBoundaryPoints(Range.START_TO_START, boundary) < 0) clipped.setStart(boundary.startContainer, boundary.startOffset);
  if (clipped.compareBoundaryPoints(Range.END_TO_END, boundary) > 0) clipped.setEnd(boundary.endContainer, boundary.endOffset);
  let text;
  let failed = false;
  try {
    selection.removeAllRanges();
    selection.addRange(clipped);
    const temporary = selection.rangeCount === 1 ? selection.getRangeAt(0) : null;
    if (!temporary || temporary.startContainer !== clipped.startContainer || temporary.startOffset !== clipped.startOffset || temporary.endContainer !== clipped.endContainer || temporary.endOffset !== clipped.endOffset) throw new Error('The clipped selection was not accepted.');
    text = selection.toString();
  } catch { failed = true; }
  finally {
    try { restore(); }
    catch { failed = true; }
  }
  if (failed) {
    notify('Copy cancelled because the browser could not preserve the selection. Your clipboard is unchanged; reselect the text if needed.', true);
    return;
  }
  try { event.clipboardData.setData('text/plain', text); }
  catch { notify('Copy cancelled because the browser rejected clipboard data. Your selection was restored.', true); }
});

$('#chat-input').addEventListener('input', event => {
  if (session()) state.drafts.set(state.active, event.target.value);
  $('#send-message').disabled = sendBlocked(session()) || !event.target.value.trim();
  event.target.style.height = 'auto';
  event.target.style.height = `${Math.min(event.target.scrollHeight, 220)}px`;
});
$('#continue-as-new').addEventListener('click', async () => {
  const current = session();
  if (!current?.restored) return;
  const button = $('#continue-as-new');
  await act(button, async () => {
    const result = await api(`/api/sessions/${encodeURIComponent(current.id)}/continue-as-new`, {});
    if (!result.id) throw new Error('The server did not identify a new session. Check session tabs before trying again.');
    await loadState();
    switchSession(result.id);
    notify('Continued in a new session. Review the inherited context and enter a fresh request.');
    $('#chat-input').focus();
  });
});
$('#input-detail-select').addEventListener('click', () => { $('#input-detail-text').focus(); $('#input-detail-text').select(); });
$('#new-session').addEventListener('click', newSessionDialog);
$('#welcome-start').addEventListener('click', newSessionDialog);
$('#provider-select').addEventListener('change', providerHelp);
$('#attach-button').addEventListener('click', () => filePicker());
$('#cwd-button').addEventListener('click', () => filePicker('directory'));
$('#browse-new-cwd').addEventListener('click', () => filePicker('directory', path => { $('#new-cwd').value = path; }));
$('#stop-session').addEventListener('click', event => control('stop', '', event.currentTarget));
$('#pause-session').addEventListener('click', event => control('pause', '', event.currentTarget));
$('#resume-session').addEventListener('click', event => control('resume', '', event.currentTarget));
$('#refresh-git').addEventListener('click', event => act(event.currentTarget, () => loadRepository(true)));
$('#back-to-session').addEventListener('click', () => {
  state.selectedAgent.delete(state.active);
  state.agentTranscript = null;
  render();
});
$('#new-output').addEventListener('click', () => {
  if (selectionIntersects($('#transcript'))) window.getSelection().removeAllRanges();
  renderTranscript({ selectionFlush: true });
  $('#transcript').scrollTop = $('#transcript').scrollHeight;
  $('#new-output').hidden = true;
});
let selectionFrame;
let transcriptWasSelected = false;
document.addEventListener('selectionchange', () => {
  if (state.stopped) return;
  const selected = selectionIntersects($('#transcript'));
  const needsRender = selected || transcriptWasSelected || deferredTranscriptUpdates;
  transcriptWasSelected = selected;
  if (!needsRender || selectionFrame !== undefined) return;
  selectionFrame = requestAnimationFrame(() => {
    selectionFrame = undefined;
    renderTranscript({ selectionFlush: true });
  });
});
$('#transcript').addEventListener('scroll', () => {
  const node = $('#transcript');
  if (!selectionIntersects(node) && !deferredTranscriptUpdates && node.scrollHeight - node.scrollTop - node.clientHeight < 60) $('#new-output').hidden = true;
});
$('#file-up').addEventListener('click', () => browseFiles(state.filePicker?.parent));
$('#file-path-form').addEventListener('submit', event => { event.preventDefault(); browseFiles($('#file-path').value.trim()); });
$('#shortcuts-button').addEventListener('click', () => $('#shortcuts-dialog').showModal());
$('#quit-console').addEventListener('click', () => confirmAction({
  title: 'Quit Agent Harness console?',
  label: 'Stop console',
  description: 'This stops the local console and all provider sessions and reviewers it owns. Other terminal sessions are unaffected. The saved history remains available when you reopen the console.',
  run: async () => {
    const result = await api('/api/shutdown', {});
    if (!result.stopping) throw new Error('Shutdown was not acknowledged. The console may still be running.');
    state.stopped = true;
    clearTimeout(stateTimer);
    reloadAgain = false;
    eventStreamController.abort();
    $('#transport-state').classList.remove('connected');
    $('#transport-state').textContent = 'Stopped';
    $('#connection-banner').hidden = false;
    $('#connection-banner').textContent = 'Console stopped. Reopen Agent Harness from its launcher to start again. You can close this browser tab; the displayed transcript remains readable.';
    $('#chat-input').readOnly = true;
    for (const node of $$('button, input, select, textarea')) node.disabled = true;
  },
}));
$('#settings-button').addEventListener('click', () => openSettings({ api, notify, el, refresh: loadState, filePicker, cwd: () => session()?.cwd || state.snapshot.defaultCwd || '' }));
for (const button of $$('.segmented-control button')) {
  button.addEventListener('click', () => {
    state.repoView = button.dataset.view;
    $$('.segmented-control button').forEach(item => item.setAttribute('aria-selected', String(item === button)));
    renderRepository();
  });
}
for (const button of $$('[data-close]')) button.addEventListener('click', () => button.closest('dialog').close());
for (const dialog of $$('dialog')) {
  dialog.addEventListener('click', event => {
    if (event.target !== dialog) return;
    const box = dialog.getBoundingClientRect();
    if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close();
  });
}
setInterval(() => {
  for (const node of $$('[data-timestamp]')) node.textContent = `${node.dataset.label} ${ago(node.dataset.timestamp)}`;
}, 10000);

if (!token) connection(false, 'This window has no local access token. Reopen Agent Harness from its launcher.');
else loadState().then(() => { connection(true); events(); }).catch(error => { connection(false, errorText(error)); notify(errorText(error), true); });
