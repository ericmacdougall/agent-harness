export function composerAction(current, state) {
  const terminal = ['complete', 'blocked', 'handoff'].includes(current?.work?.state);
  const kind = current?.work && !terminal ? 'queue' : 'send';
  const label = kind === 'queue' ? 'Queue follow-up' : terminal ? 'Send new objective' : 'Send message';
  let reason = '';
  if (state.stopped) reason = 'Console stopped. Reopen it from the launcher.';
  else if (!current) reason = 'Choose a session first.';
  else if (current.restored) reason = 'Restored history is read-only. Continue in a new session.';
  else if (['unknown', 'disconnected', 'error'].includes(current.status)) reason = 'Resolve the session connection before submitting. Your draft is preserved.';
  else if (current.work?.reviewStatus === 'unknown') reason = 'The prior review outcome is unknown. Reconcile it or continue in a new session.';
  else if (state.submissions.has(current.id)) reason = 'A submission is in progress.';
  else if (kind === 'send' && current.pendingInputs?.length) reason = 'Resolve all stored follow-up payloads before starting a new objective.';
  else if (kind === 'send' && ['starting', 'running', 'busy', 'thinking', 'waiting'].includes(current.status)) reason = 'Wait for the current provider turn.';
  return { kind, label, reason, allowed: !reason };
}

export function submissionMatches(previous, next) {
  return previous.kind === next.kind && previous.text === next.text && JSON.stringify(previous.attachments) === JSON.stringify(next.attachments);
}
