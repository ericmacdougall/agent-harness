import test from 'node:test';
import assert from 'node:assert/strict';
import { chatAttention } from '../js/chat-attention.js';

const reply = (id, text = 'Reply', status = 'answered') => ({ id, text, status, from: 'claude' });

test('initial history is read; hidden chat counts new replies once through streaming and reconnect', () => {
  const attention = chatAttention();
  assert.equal(attention.observe([reply('old')], false), 0);
  assert.equal(attention.observe([reply('old'), reply('new', 'Start', 'answering')], false), 1);
  assert.equal(attention.observe([reply('old'), reply('new', 'Finished')], false), 1);
  assert.equal(attention.observe([reply('old'), reply('new', 'Finished')], false), 1);
  assert.equal(attention.observe([reply('old'), reply('new', 'Finished'), reply('next')], false), 2);
  attention.clear();
  assert.equal(attention.observe([reply('old'), reply('new', 'Finished'), reply('next')], false), 0);
});

test('visible readers at the bottom have no unread; readers above see later stream updates', () => {
  const attention = chatAttention();
  attention.observe([], true);
  assert.equal(attention.observe([reply('r', 'Part', 'answering')], true), 0);
  assert.equal(attention.observe([reply('r', 'More', 'answering')], false), 1);
  assert.equal(attention.observe([reply('r', 'Done')], true), 0);
});

test('own messages, untrusted messages, and removed replies never inflate the count', () => {
  const attention = chatAttention();
  attention.observe([], false);
  assert.equal(attention.observe([{ ...reply('own'), from: 'user' }, reply('forged', 'Untrusted', 'forged')], false), 0);
  assert.equal(attention.observe([reply('r')], false), 1);
  assert.equal(attention.observe([reply('r', 'Untrusted', 'forged')], false), 0);
  assert.equal(attention.observe([], false), 0);
});
