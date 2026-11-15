import test from 'node:test';
import assert from 'node:assert/strict';
import './dom-shim.mjs';

const ids = ['chat-log', 'chat-form', 'chat-input', 'chat-send', 'chat-counter', 'chat-notice',
  'chat-announcer', 'chat-new', 'chat-unread', 'tab-chat', 'chat-panel', 'skip-chat',
  'chat-session', 'responder-claude', 'responder-codex', 'session-label', 'chat-presence'];
const nodes = Object.fromEntries(ids.map(id => [id, document.createElement('div')]));
for (const node of Object.values(nodes)) node.focus = () => { document.activeElement = node; };
document.getElementById = id => nodes[id] || null;
document.addEventListener = () => {};
document.hidden = false;
globalThis.window = { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
globalThis.localStorage = { getItem: () => null };
nodes['chat-input'].value = '';
Object.assign(nodes['chat-log'], { scrollHeight: 1000, clientHeight: 200, scrollTop: 100 });
const store = await import('../js/store.js');
const { mountChat } = await import('../js/chat.js');
const reply = (id, text = 'Reply', status = 'answered') => ({ id, text, status, from: 'claude', ts: '2026-11-13T12:00:00Z' });

test('mounted chat preserves reading position, counts unseen replies, reveals chat and focuses safe targets', async () => {
  let posts = 0;
  store.setChatTransport(() => { posts += 1; });
  mountChat();
  const messages = [reply('history')];
  const publish = () => store.update({ chat: {}, messages: [...messages] }, 'chat');
  publish();
  assert.equal(nodes['chat-unread'].hidden, true, 'initial history is not new');
  messages.push(reply('new', 'Part', 'answering'));
  publish();
  assert.equal(nodes['chat-unread'].textContent, '1', 'mobile hidden chat counts an incoming reply');
  assert.equal(nodes['chat-log'].scrollTop, 100, 'incoming reply does not move the reader');
  messages[1] = reply('new', 'Complete');
  publish();
  assert.equal(nodes['chat-unread'].textContent, '1', 'stream completion does not double count');
  assert.match(nodes['tab-chat'].getAttribute('aria-label'), /1 new reply/);
  store.setConnection('reconnecting');
  publish();
  assert.equal(nodes['chat-unread'].textContent, '1', 'resync keeps the unread reply');
  assert.equal(nodes['chat-presence'].dataset.state, 'unavailable');
  nodes['skip-chat'].listeners.click[0]({ preventDefault() {} });
  await Promise.resolve();
  assert.equal(store.getState().tab, 'chat');
  assert.equal(document.activeElement, nodes['chat-panel'], 'disabled composer falls back to the chat panel');
  assert.equal(nodes['chat-unread'].hidden, true);
  nodes['chat-log'].scrollTop = 100;
  messages.push(reply('later'));
  publish();
  assert.equal(nodes['chat-log'].scrollTop, 100, 'visible reader above the bottom is not pulled down');
  assert.equal(nodes['chat-new'].hidden, false);
  nodes['chat-new'].click();
  assert.equal(nodes['chat-log'].scrollTop, 1000);
  assert.equal(document.activeElement, nodes['chat-log']);
  assert.equal(nodes['chat-new'].hidden, true);
  assert.equal(posts, 0, 'presentation actions never send a message');
});
