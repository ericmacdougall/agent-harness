const RECOVERY = 'Quarantine this child and quiesce its writer. Reconcile messages, worktree, processes, receipts, and any in-flight effects before starting one fresh replacement from the current parent context. Do not automatically replay uncertain operations.';

export function agentControlNotice(agent) {
  const reason = agent?.controlReason?.trim();
  if (!reason) return null;
  return {
    role: 'status',
    label: 'Agent control recovery',
    reason,
    recovery: RECOVERY,
  };
}

export function renderAgentControlNotice(createElement, agent) {
  const notice = agentControlNotice(agent);
  if (!notice) return null;
  const recovery = createElement('div', 'agent-control-notice');
  recovery.setAttribute('role', notice.role);
  recovery.setAttribute('aria-label', notice.label);
  recovery.dataset.testid = 'agent-control-notice';
  recovery.append(
    createElement('strong', '', 'Controls unavailable'),
    createElement('p', '', notice.reason),
    createElement('p', '', notice.recovery),
  );
  return recovery;
}
