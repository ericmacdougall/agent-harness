// DEMO TRANSPORT. Replace this module with SSE + the chat POST adapter.
// Event objects below are the mc.event/1 wire contract, without UI-only fields.
const iso = (seconds = 0) => new Date(Date.now() - seconds * 1000).toISOString();
const stamp = () => new Date().toISOString();
export function createSeed() {
  const initiatives = [
    { id: 'mission', initiative: 'Mission control', state: 'In progress', milestones_done: 3, milestones_total: 5, pct: 60, owner: 'c-01', ticket: 'HAR-142', milestones: 'Done: Event contract · Done: Fleet store · Done: Live topology · Not yet: Mobile command channel · Not yet: Accessibility pass', next_step: 'Finish the mobile command channel', next_eta: '~35 min', full_eta: '~2 h', note: 'The core loop is working. Checking the small-screen experience next.', updated: iso(65), estimate_by: 'owner c-01' },
    { id: 'stream', initiative: 'A stream you can trust', state: 'In review', milestones_done: 4, milestones_total: 5, pct: 80, owner: 'x-02', ticket: 'HAR-138', milestones: 'Done: Event envelope · Done: Replay cursor · Done: Backoff · Done: Duplicate protection · Not yet: Soak test', next_step: 'Complete the reconnect soak test', next_eta: '~20 min', full_eta: '~45 min', note: 'Replay and duplicate protection passed. Final review is running.', updated: iso(128), estimate_by: 'owner x-02' },
    { id: 'auth', initiative: 'Safer session boundaries', state: 'At risk', milestones_done: 2, milestones_total: 4, pct: 50, owner: 'c-03', ticket: 'HAR-131', milestones: 'Done: Threat review · Done: Scope tokens · Not yet: Rotation checks · Not yet: Session isolation', next_step: 'Resolve the token rotation edge case', next_eta: '~1 h', full_eta: '~4 h', note: 'Rotation can overlap a reconnect. Needs a coordinator decision.', updated: iso(480), estimate_by: 'main' },
    { id: 'release', initiative: 'A quieter path to release', state: 'Partly proven', milestones_done: 2, milestones_total: 5, pct: 40, owner: 'x-04', ticket: 'HAR-129', milestones: 'Done: Build gate · Done: Preview deploy · Not yet: Rollback proof · Not yet: Release notes · Not yet: Staging smoke', next_step: 'Prove the rollback path in staging', next_eta: '~50 min', full_eta: '~3 h', note: 'Preview is healthy; rollback still needs evidence.', updated: iso(220), estimate_by: 'owner x-04' },
    { id: 'tickets', initiative: 'Ticket checkpoints', state: 'Checking', milestones_done: null, milestones_total: null, pct: null, owner: 'c-05', ticket: 'HAR-125', milestones: 'Not yet: Reconcile existing checkpoints · Not yet: Validate ticket mapping · Not yet: Check delivery evidence', next_step: 'Reconcile the latest GoodQA snapshot', next_eta: '~15 min', full_eta: null, note: 'Progress stays indeterminate until the source is reconciled.', updated: iso(720), estimate_by: 'main' },
    { id: 'runner', initiative: 'Mobile runner handoff', state: 'Blocked', milestones_done: 1, milestones_total: 4, pct: 25, owner: 'x-06', ticket: 'HAR-119', milestones: 'Done: Handoff contract · Not yet: Restore runner · Not yet: Device tests · Not yet: Record evidence', next_step: 'Restore the dropped runner', next_eta: null, full_eta: null, note: 'The runner stopped reporting 38 minutes ago. Reassign before continuing.', updated: iso(2280), estimate_by: 'main' },
    { id: 'collector', initiative: 'Every work log, connected', state: 'Done', milestones_done: 4, milestones_total: 4, pct: 100, owner: 'c-08', ticket: 'HAR-112', milestones: 'Done: Claude WAL collector · Done: Codex WAL collector · Done: Normalize events · Done: Verify replay', next_step: 'Watch collector health', next_eta: null, full_eta: 'complete', note: 'Both runtimes are reporting against the shared event contract.', updated: iso(1640), estimate_by: 'owner c-08' },
  ];
  const owners = [
    { agent_id: 'c-01', runtime: 'claude', type: 'builder', ticket: 'HAR-142', task: 'Building the command channel', state: 'live', last_item: { at: iso(34), event: 'wal', note: 'Composer layout verified at 390 px' }, initiative_id: 'mission' },
    { agent_id: 'x-02', runtime: 'codex', type: 'reviewer', ticket: 'HAR-138', task: 'Soaking the reconnect loop', state: 'live', last_item: { at: iso(82), event: 'wal', note: 'Replay cursor survived 40 reconnects' }, initiative_id: 'stream' },
    { agent_id: 'c-03', runtime: 'claude', type: 'builder', ticket: 'HAR-131', task: 'Tracing token rotation', state: 'live', last_item: { at: iso(480), event: 'ticket', note: 'Flagged a session overlap edge case' }, initiative_id: 'auth' },
    { agent_id: 'x-04', runtime: 'codex', type: 'builder', ticket: 'HAR-129', task: 'Proving the rollback path', state: 'live', last_item: { at: iso(151), event: 'push', note: 'Pushed the staging rollback check' }, initiative_id: 'release' },
    { agent_id: 'c-05', runtime: 'claude', type: 'researcher', ticket: 'HAR-125', task: 'Waiting on the ticket snapshot', state: 'idle', last_item: { at: iso(1020), event: 'wal', note: 'Snapshot reconciliation queued' }, initiative_id: 'tickets' },
    { agent_id: 'x-06', runtime: 'codex', type: 'builder', ticket: 'HAR-119', task: 'Runner connection interrupted', state: 'DROPPED', last_item: { at: iso(2280), event: 'owner', note: 'Heartbeat lost; last checkpoint saved' }, initiative_id: 'runner' },
    { agent_id: 'x-07', runtime: 'codex', type: 'reviewer', ticket: 'HAR-142', task: 'Checking keyboard navigation', state: 'live', last_item: { at: iso(12), event: 'wal', note: 'Focus order checked across the HUD' }, initiative_id: 'mission' },
    { agent_id: 'c-08', runtime: 'claude', type: 'builder', ticket: 'HAR-112', task: 'WAL collectors shipped', state: 'done', last_item: { at: iso(1640), event: 'release', note: 'Collector checks passed; handoff complete' }, initiative_id: 'collector' },
  ];
  const templates = [
    ['wal', 'c-01', 'Mobile composer now clears the keyboard', 'mission', 'harness', 'info'],
    ['push', 'x-04', '3 commits pushed to feat/release-gates', 'release', 'harness', 'info'],
    ['ticket', 'c-03', 'Token rotation needs a coordinator decision', 'auth', 'harness', 'warn'],
    ['deploy', 'x-04', 'Preview is healthy · all smoke checks passed', 'release', 't2-dev', 'info'],
    ['wal', 'x-02', 'Replay cursor held through 40 reconnects', 'stream', 'harness', 'info'],
    ['release', 'c-08', 'WAL collectors v0.8.2 ready for handoff', 'collector', 'collectors', 'info'],
    ['owner', 'x-06', 'Runner dropped · checkpoint preserved', 'runner', 'harness', 'high'],
    ['system', 'main', 'GitHub collector is behind its check interval', null, 'harness', 'warn'],
  ];
  const events = templates.map((item, i) => eventFrom(item, owners, iso(i * 35 + 9)));
  const sources = [
    { id: 'claude', name: 'Claude WALs', state: 'ok', checked: iso(8), note: 'Collector is reading local work logs.' },
    { id: 'codex', name: 'Codex WALs', state: 'ok', checked: iso(12), note: 'Collector is reading local work logs.' },
    { id: 'github', name: 'GitHub', state: 'stale', checked: iso(184), note: 'Polling is delayed. Push events may arrive late.' },
    { id: 'goodqa', name: 'GoodQA tickets', state: 'ok', checked: iso(18), note: 'Ticket snapshot is current.' },
    { id: 't2', name: 't2-dev', state: 'error', checked: iso(423), note: 'Health endpoint returned 503. Last known deployment evidence is retained.' },
    { id: 'file', name: 'Initiatives file', state: 'ok', checked: iso(5), note: 'Coordinator file parsed successfully.' },
  ];
  const messages = [
    { id: 'msg-failed', from: 'user', text: 'Re-run the staging smoke checks.', ts: iso(260), status: 'failed', to: 'codex' },
    { id: 'msg-user', from: 'user', text: 'What needs my attention?', ts: iso(90), status: 'answered', to: 'claude' },
    { id: 'msg-main', from: 'claude', text: 'Two things to watch: session token rotation and the dropped mobile runner. The rest of the fleet is moving. I’d unblock the runner first.', ts: iso(78), status: 'answered', to: 'claude' },
  ];
  return { initiatives, owners, events, sources, messages, sessions: ['main', 'review'] };
}
function eventFrom([kind, agent, summary, initiative, repo, severity = 'info'], owners, ts = stamp()) {
  const owner = owners.find(item => item.agent_id === agent);
  return { schema: 'mc.event/1', id: crypto.randomUUID(), ts, kind, source: kind === 'wal' ? `${owner?.runtime || 'claude'}-wal` : kind === 'ticket' ? 'goodqa' : kind === 'push' || kind === 'release' ? 'github' : kind === 'deploy' ? 't2-dev' : 'coordinator', actor: { runtime: owner?.runtime || 'claude', session: 'workspace-main', agent }, subject: { repo, branch: kind === 'push' ? 'feat/release-gates' : 'main', ticket: owner?.ticket || null, initiative }, summary, severity };
}
export function createMock(adapter, seed) {
  let connection = 'live', failNext = false, eventTimer, healthTimer, serial = 0, running = false;
  const timers = new Set();
  const delay = ms => new Promise(resolve => { const timer = setTimeout(() => { timers.delete(timer); resolve(); }, ms); timers.add(timer); });
  const templates = [
    ['wal','c-01','Verified the composer at phone width','mission','harness'],
    ['push','x-04','Pushed a rollback checkpoint to staging','release','harness'],
    ['wal','x-07','Keyboard focus reaches every panel','mission','harness'],
    ['ticket','c-03','Added evidence to the rotation edge case','auth','harness','warn'],
    ['deploy','x-04','Preview deployment passed its smoke checks','release','t2-dev'],
    ['owner','x-02','Reviewer checkpoint · reconnect test still running','stream','harness'],
    ['release','x-04','Release candidate v0.9.0-rc.2 assembled','release','harness'],
    ['wal','x-02','Replay cursor verified without duplicate events','stream','harness'],
    ['chat','main','Coordinator is reviewing the fleet checkpoints','mission','harness'],
    ['system','main','Collector sweep complete · 2 sources need attention',null,'collectors','warn'],
  ];
  function emit() {
    if (connection !== 'live') return;
    adapter.event(eventFrom(templates[serial++ % templates.length], seed.owners));
  }
  function schedule() {
    clearTimeout(eventTimer);
    if (!running || document.hidden) return;
    eventTimer = setTimeout(() => {
      emit();
      if (serial % 9 === 0 && connection === 'live') { emit(); emit(); }
      schedule();
    }, 1200 + Math.random() * 1700);
  }
  function visibility() { schedule(); }
  return {
    start() {
      running = true;
      schedule();
      document.addEventListener('visibilitychange', visibility);
      healthTimer = setInterval(() => {
        if (connection === 'live' && !document.hidden) {
          seed.sources = seed.sources.map(source => source.state === 'ok' ? { ...source, checked: stamp() } : source);
          adapter.sources(seed.sources);
        }
      }, 16000);
    },
    stop() { running = false; clearTimeout(eventTimer); clearInterval(healthTimer); timers.forEach(clearTimeout); document.removeEventListener('visibilitychange', visibility); },
    burst() { for (let i = 0; i < 8; i++) emit(); },
    setConnection(value) { connection = value; adapter.connection(value); },
    setFailNext(value) { failNext = value; },
    async sendChat(message, { session }) {
      const shouldFail = failNext;
      failNext = false;
      let replyId;
      const check = () => {
        if (connection !== 'live') {
          adapter.patchMessage(message.id, { status: 'failed' });
          if (replyId) adapter.patchMessage(replyId, { status: 'failed' });
          return false;
        }
        return true;
      };
      await delay(500);
      if (!check()) return;
      if (shouldFail) { adapter.patchMessage(message.id, { status: 'failed' }); return; }
      adapter.patchMessage(message.id, { status: message.to === 'claude' ? 'queued' : 'delivered' });
      adapter.event(eventFrom(['chat', message.to === 'claude' ? 'main' : 'x-07', `Dashboard message routed to ${message.to === 'claude' ? `Claude / ${session}` : 'Codex'}`, 'mission', 'harness'], seed.owners));
      await delay(message.to === 'claude' ? 6500 : 600);
      if (!check()) return;
      const lower = message.text.toLowerCase();
      let reply = lower.includes('runner') ? 'The mobile runner x-06 has dropped. Its last checkpoint is preserved on HAR-119. I would reassign the device tests, then verify the handoff before resuming.' : lower.includes('smoke') || lower.includes('release') ? 'The preview passed its smoke checks. The release is still partly proven: rollback evidence is the next gate. I would keep the release behind that gate until the staging check passes.' : lower.includes('attention') || lower.includes('status') ? 'Two initiatives need attention: session boundaries are at risk, and the mobile runner is blocked. Mission control is at 3 of 5 milestones; stream reliability is ready for its final soak test.' : 'I’ve noted your direction. My next step would be to check the open checkpoints, unblock the mobile runner, and keep the rotation edge case visible. This is a mock reply; no agent work has been started.';
      if (message.to === 'claude' && session === 'review') reply = `From the review session: ${reply}`;
      if (!reply.includes('mock reply')) reply += ' This is a simulated response.';
      replyId = crypto.randomUUID();
      const response = { id: replyId, from: message.to, text: message.to === 'codex' ? '' : reply, ts: stamp(), status: message.to === 'codex' ? 'answering' : 'answered', to: message.to };
      adapter.patchMessage(message.id, { status: 'answering' });
      adapter.message(response);
      if (message.to === 'codex') {
        const tokens = reply.match(/\S+\s*/g) || [];
        let text = '';
        for (const token of tokens) {
          await delay(65);
          if (!check()) return;
          text += token;
          adapter.patchMessage(replyId, { text });
        }
        adapter.patchMessage(replyId, { status: 'answered' });
      }
      adapter.patchMessage(message.id, { status: 'answered' });
    },
  };
}
