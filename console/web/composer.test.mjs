import test from 'node:test';
import assert from 'node:assert/strict';
import { composerAction, submissionMatches } from './composer.js';
import { agentControlNotice, renderAgentControlNotice } from './agent-control.js';

const context = () => ({ stopped: false, submissions: new Set() });
const session = (status = 'idle', work = { state: 'active', reviewStatus: 'none' }) => ({ id: 'session', status, work, pendingInputs: [] });

test('one active objective admits follow-ups across provider and checkpoint states', () => {
  for (const status of ['idle', 'running', 'waiting', 'paused']) {
    for (const taskState of ['idle', 'active', 'needs_review']) {
      const result = composerAction(session(status, { state: taskState, reviewStatus: 'none' }), context());
      assert.equal(result.kind, 'queue', `${status}/${taskState}`);
      assert.equal(result.allowed, true, `${status}/${taskState}`);
      assert.equal(result.label, 'Queue follow-up');
    }
  }
});

test('new and terminal objectives use ordinary send only with no retained payloads', () => {
  assert.deepEqual(composerAction(session('idle', null), context()), { kind: 'send', label: 'Send message', reason: '', allowed: true });
  for (const taskState of ['complete', 'blocked', 'handoff']) {
    const current = session('idle', { state: taskState, reviewStatus: 'pass' });
    const result = composerAction(current, context());
    assert.equal(result.kind, 'send');
    assert.equal(result.label, 'Send new objective');
    assert.equal(result.allowed, true);
    current.pendingInputs = [{ requestId: 'prior', status: 'retained' }];
    assert.equal(composerAction(current, context()).allowed, false);
  }
  assert.equal(composerAction(session('running', null), context()).allowed, false);
});

test('unknown authority, restored history and in-flight submissions never dispatch', () => {
  for (const status of ['unknown', 'disconnected', 'error']) {
    assert.equal(composerAction(session(status), context()).allowed, false);
  }
  const restored = { ...session(), restored: true };
  assert.equal(composerAction(restored, context()).allowed, false);
  const unknownReview = session('idle', { state: 'active', reviewStatus: 'unknown' });
  assert.equal(composerAction(unknownReview, context()).allowed, false);
  const busy = context(); busy.submissions.add('session');
  assert.equal(composerAction(session(), busy).allowed, false);
  const stopped = context(); stopped.stopped = true;
  assert.equal(composerAction(session(), stopped).allowed, false);
});

test('uncertain retries never change routing, text or attachment order', () => {
  const prior = { kind: 'queue', text: 'Keep the same owner', attachments: ['/selected/one', '/selected/two'] };
  assert.equal(submissionMatches(prior, structuredClone(prior)), true);
  assert.equal(submissionMatches(prior, { ...prior, kind: 'send' }), false);
  assert.equal(submissionMatches(prior, { ...prior, text: 'A different objective' }), false);
  assert.equal(submissionMatches(prior, { ...prior, attachments: [...prior.attachments].reverse() }), false);
  assert.equal(submissionMatches(prior, { ...prior, attachments: [...prior.attachments, '/selected/three'] }), false);
});

test('disabled native child controls expose accessible recovery guidance', () => {
  const reason = 'This child belongs to a stale parent authentication context.';
  const notice = agentControlNotice({ controlReason: reason });
  assert.deepEqual(notice, {
    role: 'status',
    label: 'Agent control recovery',
    reason,
    recovery: 'Quarantine this child and quiesce its writer. Reconcile messages, worktree, processes, receipts, and any in-flight effects before starting one fresh replacement from the current parent context. Do not automatically replay uncertain operations.',
  });
});

test('agent controls without a reason do not show recovery guidance', () => {
  assert.equal(agentControlNotice({ canResume: false }), null);
  assert.equal(agentControlNotice({ controlReason: '   ' }), null);
});

test('agent recovery guidance renders as a labelled status', () => {
  const createElement = (tag, className, text) => ({
    tag, className, text, dataset: {}, attributes: {}, children: [],
    setAttribute(name, value) { this.attributes[name] = value; },
    append(...children) { this.children.push(...children); },
  });
  const node = renderAgentControlNotice(createElement, { controlReason: 'Resume is denied.' });
  assert.equal(node.attributes.role, 'status');
  assert.equal(node.attributes['aria-label'], 'Agent control recovery');
  assert.equal(node.dataset.testid, 'agent-control-notice');
  assert.deepEqual(node.children.map(child => child.text), [
    'Resume unavailable',
    'Resume is denied.',
    'Quarantine this child and quiesce its writer. Reconcile messages, worktree, processes, receipts, and any in-flight effects before starting one fresh replacement from the current parent context. Do not automatically replay uncertain operations.',
  ]);
});
