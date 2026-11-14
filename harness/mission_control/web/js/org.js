// The org graph's pure model (goodqa#15950): validation, the pyramid layout, colors, the event-to-cue table and
// the list view's tree. No DOM and no THREE here, so node tests cover it directly.

export const SCHEMA = 'mc.orggraph/1';
export const UNKNOWN = 'unknown';
const ID = /^[A-Za-z0-9_:#.-]{1,80}$/;
const KINDS = ['user', 'coordinator', 'owner', 'subagent', 'reviewer', 'work'];
const LIVE = new Set(['live', 'working', 'quiet', 'observed']);

// One color per node type. Severity and escalation use a separate warm ramp drawn as a halo and rings, never as the
// node's own fill, so type and alarm are read independently.
export const TYPE_COLORS = Object.freeze({
  user: { label: 'You (inbox)', color: '#f4b5d4' },
  coordinator: { label: 'Coordinator (main)', color: '#eaff9e' },
  owner: { label: 'Owner', color: '#9ebfff' },
  subagent: { label: 'Sub-agent', color: '#7edbca' },
  reviewer: { label: 'Reviewer', color: '#d4b5ff' },
  work: { label: 'Work item', color: '#f1c782' },
  repo: { label: 'Repository', color: '#c7c9ce' },
});
export const DONE_COLOR = '#7c8580';
export const SEVERITY_COLORS = Object.freeze({ critical: '#ff4d4d', high: '#ff6b5b', warn: '#ffa94d', medium: '#ffa94d' });
export const ESCALATION_COLORS = Object.freeze(['', '#ffd166', '#ff9f43', '#ff5c5c']);  // index = ladder steps taken (3 = 3+)
export const severityColor = severity => SEVERITY_COLORS[String(severity || '').toLowerCase()] || '';
export const escalationColor = level => (level > 0 ? ESCALATION_COLORS[Math.min(3, level)] : '');

// Every event type the user listed, its real source, and the cue the scene draws. A row with source "no source"
// would be shown in the legend as missing; none is today, but some sources are sparse (noted).
export const EVENT_MAP = Object.freeze([
  { id: 'dag', label: 'Work item added, moved or changed', source: 'GoodQA ticket links and status (org graph changes: added, moved, progress, dag)', cue: 'ring on the work item; a spark along a new dependency' },
  { id: 'subagent-spawn', label: 'Sub-agent spawned', source: 'transcript meta + ah owners (change: spawned)', cue: 'spark from the parent down to the new node' },
  { id: 'subagent-finish', label: 'Sub-agent finished', source: 'ah owners state (change: finished)', cue: 'spark from the node back up to its owner' },
  { id: 'subagent-assign', label: 'Sub-agent assigned', source: 'ah owners ticket (change: assigned)', cue: 'spark from the agent to its work item' },
  { id: 'reviewer-spawn', label: 'Reviewer spawned', source: 'transcript meta + ah owners (change: spawned, kind reviewer)', cue: 'spark from the parent to the reviewer' },
  { id: 'reviewer-working', label: 'Reviewer working', source: 'ah owners state (change: state)', cue: 'ring on the reviewer' },
  { id: 'reviewer-verdict', label: 'Reviewer approved or rejected', source: 'WAL review / review_result verdict (sparse: few reviews write one)', cue: 'green or red spark from the reviewer to what it reviews' },
  { id: 'review-return', label: 'Task back to its owner with review status', source: 'reviewer finished (change: finished) + its verdict when recorded', cue: 'spark from the reviewer up to the owner' },
  { id: 'owner-message', label: 'Owner messages a sub-agent or reviewer', source: 'owner transcript SendMessage target (change: message)', cue: 'spark from the owner to the recipient' },
  { id: 'coordinator', label: 'Coordinator spawns or messages an owner', source: 'transcript meta + main transcript SendMessage (changes: spawned, message)', cue: 'spark from the coordinator to the owner' },
  { id: 'git', label: 'Git branch, push or merge', source: 'GitHub events: PushEvent, CreateEvent branch, merged PullRequestEvent', cue: 'spark into the repository node' },
  { id: 'progress', label: 'Initiative, epic or task progress', source: 'WAL result/check/commit/deploy + GoodQA status and comments', cue: 'ring on the work item, or on the agent when no item is shown' },
  { id: 'inbox', label: 'New item in your inbox', source: 'WAL ask (Needs you)', cue: 'spark from the coordinator up to you' },
  { id: 'decision', label: 'Your decision back to the coordinator', source: 'WAL ask_resolved', cue: 'spark from you down to the coordinator' },
]);

const str = (value, max = 160) => String(value ?? '').slice(0, max);
const known = value => (value && value !== UNKNOWN ? str(value, 80) : UNKNOWN);

export function normalize(raw) {
  if (!raw || raw.schema !== SCHEMA || !Array.isArray(raw.nodes)) return null;
  const nodes = [];
  const ids = new Set();
  for (const node of raw.nodes.slice(0, 400)) {
    if (!node || !ID.test(String(node.id)) || !KINDS.includes(node.kind) || ids.has(node.id)) continue;
    ids.add(node.id);
    nodes.push({ ...node, id: String(node.id), label: str(node.label, 40), model: known(node.model), effort: known(node.effort),
      advisor_model: known(node.advisor_model), machine: known(node.machine), task: str(node.task), mission: str(node.mission),
      title: str(node.title, 120), state: str(node.state, 24) || UNKNOWN, layer: Number.isInteger(node.layer) ? node.layer : 0,
      escalation: Number.isInteger(node.escalation) ? node.escalation : 0 });
  }
  const edges = (Array.isArray(raw.edges) ? raw.edges : []).filter(e => e && ids.has(e.from) && ids.has(e.to)).slice(0, 800);
  const changes = (Array.isArray(raw.changes) ? raw.changes : []).slice(0, 120);
  return { generated: str(raw.generated, 40), seq: Number(raw.seq) || 0, nodes, edges, changes, counts: raw.counts || {},
    gaps: (Array.isArray(raw.gaps) ? raw.gaps : []).map(g => str(g, 300)).slice(0, 10) };
}

const ring = (count, radius, offset = 0) => Array.from({ length: count }, (_, i) => {
  const a = offset + (i / Math.max(count, 1)) * Math.PI * 2;
  return [Math.cos(a) * radius, Math.sin(a) * radius];
});

export const LEVELS = Object.freeze({ user: 3.3, coordinator: 2.5, owner: 1.25, agent: 0, epic: -0.6, work0: -1.15, step: 0.8 });

// The pyramid: you, then main at the apex, owner pods on a ring below, each pod's sub-agents and reviewers clustered
// on the next plane, and the work DAG on deeper planes: a held item directly under its holder, next-in-line items
// around the item they depend on, one plane per DAG step.
export function layout(graph, repos = []) {
  const pos = new Map();
  if (!graph) return pos;
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  pos.set('user', [0, LEVELS.user, 0]);
  pos.set('coordinator', [0, LEVELS.coordinator, 0]);
  const owners = graph.nodes.filter(n => n.kind === 'owner')
    .sort((a, b) => (LIVE.has(b.state) - LIVE.has(a.state)) || a.id.localeCompare(b.id));
  const podRadius = Math.max(2.1, owners.length * 0.62);
  const pods = new Map([['', [0, 0]]]);  // agents with no known owner cluster under the coordinator
  ring(owners.length, podRadius, -Math.PI / 2).forEach(([x, z], i) => { pods.set(owners[i].id, [x, z]); pos.set(owners[i].id, [x, LEVELS.owner, z]); });
  const members = new Map();
  for (const node of graph.nodes) {
    if (node.kind !== 'subagent' && node.kind !== 'reviewer') continue;
    const pod = pods.has(node.owner) ? node.owner : '';
    if (!members.has(pod)) members.set(pod, []);
    members.get(pod).push(node);
  }
  for (const [pod, list] of members) {
    const [cx, cz] = pods.get(pod);
    const workers = list.filter(n => n.kind === 'subagent' || !byId.has(n.reviews) || byId.get(n.reviews)?.kind === 'owner');
    const radius = workers.length > 1 ? Math.min(0.95, 0.35 + workers.length * 0.12) : 0;
    ring(workers.length, radius, -Math.PI / 2).forEach(([x, z], i) => pos.set(workers[i].id, [cx + x, LEVELS.agent, cz + z]));
    // A reviewer paired with a sub-agent sits beside it, slightly outward from the pod centre.
    for (const reviewer of list.filter(n => !workers.includes(n))) {
      const target = pos.get(reviewer.reviews);
      if (!target) continue;
      const dx = target[0] - cx, dz = target[2] - cz, len = Math.hypot(dx, dz) || 1;
      pos.set(reviewer.id, [target[0] + (dx / len) * 0.32 + 0.12, LEVELS.agent + 0.12, target[2] + (dz / len) * 0.32]);
    }
  }
  // Work items, shallowest first, so each item can be placed relative to an item already placed.
  const work = graph.nodes.filter(n => n.kind === 'work').sort((a, b) => a.layer - b.layer);
  const into = new Map();  // work id -> incoming edge source (next/depends/parent)
  for (const edge of graph.edges) {
    if (['next', 'parent'].includes(edge.kind)) into.set(edge.to, edge.from);
    if (edge.kind === 'depends' && !into.has(edge.from)) into.set(edge.from, edge.to);
  }
  const holderOf = new Map(graph.edges.filter(e => e.kind === 'works_on').map(e => [e.to, e.from]));
  const siblings = new Map();
  for (const item of work) {
    const y = item.layer < 0 ? LEVELS.epic : LEVELS.work0 - item.layer * LEVELS.step;
    const holder = pos.get(holderOf.get(item.id));
    if (holder) { pos.set(item.id, [holder[0], y, holder[2]]); continue; }
    const anchorId = into.get(item.id);
    const anchor = pos.get(anchorId) || (pods.get(item.owner) ? [pods.get(item.owner)[0], 0, pods.get(item.owner)[1]] : [0, 0, 0]);
    const n = (siblings.get(anchorId) || 0) + 1;
    siblings.set(anchorId, n);
    const a = n * 2.1, r = 0.42 + Math.floor(n / 6) * 0.25;
    pos.set(item.id, [anchor[0] + Math.cos(a) * r, y, anchor[2] + Math.sin(a) * r]);
  }
  repos.slice(0, 6).forEach((repo, i) => {
    const a = (i / Math.max(repos.length, 1)) * Math.PI * 2 + 0.4;
    pos.set(`repo:${repo}`, [Math.cos(a) * (podRadius + 1.4), LEVELS.owner + 0.4, Math.sin(a) * (podRadius + 1.4)]);
  });
  return pos;
}

export function nodeColor(node) {
  if (node.kind === 'work' && node.done) return DONE_COLOR;
  return TYPE_COLORS[node.kind]?.color || '#c7c9ce';
}

// The fields the user asked to see, per node type, as [label, value] pairs (also the list view and the inspector).
export function describe(node, byId = new Map()) {
  const name = id => (id && byId.get(id) ? `${byId.get(id).label} (${byId.get(id).kind})` : id || UNKNOWN);
  const agent = [['Model', node.model], ['Effort', node.effort], ['Advisor', node.advisor_model],
    ['Machine', node.machine === UNKNOWN ? UNKNOWN : `${node.machine}${node.machine_source ? ` (${node.machine_source})` : ''}`],
    ['Last activity', node.last_activity || UNKNOWN]];
  const alarm = [];
  if (node.severity && node.severity !== 'info') alarm.push(['Severity', node.severity]);
  if (node.escalation) alarm.push(['Escalation', `${node.escalation} step${node.escalation > 1 ? 's' : ''}${node.escalation_to ? ` to ${node.escalation_to}` : ''}${node.escalation_reason ? ` · ${node.escalation_reason}` : ''}`]);
  switch (node.kind) {
    case 'user': return [['Open asks', String(node.inbox ?? 0)]];
    case 'coordinator': return [['State', node.state], ...agent];
    case 'owner': return [['Mission', node.mission || UNKNOWN], ['State', node.state], ...agent, ['Ticket', node.ticket || '—'], ...alarm];
    case 'subagent': return [['Task', node.task || UNKNOWN], ['Owner', name(node.owner)], ['State', node.state], ...agent, ['Ticket', node.ticket || '—'], ...alarm];
    case 'reviewer': return [['Task', node.task || UNKNOWN], ['Reviews', node.reviews === UNKNOWN ? `unknown (no matching parent and ticket)` : `${name(node.reviews)} · by ${node.pairing_source}`],
      ['Owner', name(node.owner)], ['State', node.state], ...agent, ['Ticket', node.ticket || '—'], ...alarm];
    case 'work': return [['Title', node.title || UNKNOWN], ['Status', node.status || UNKNOWN], ['DAG step', node.layer < 0 ? 'parent (epic)' : String(node.layer)],
      ['Placed by', { held: 'held by an agent', blocks: 'next in line (depends on an item above)', blocked_by: 'prerequisite', parent: 'parent ticket' }[node.via] || node.via],
      ['Held by', (node.holders || []).map(name).join(', ') || '—'], ...(node.stale ? [['Data', 'last read failed; showing the previous copy']] : []),
      ...(node.read ? [] : [['Data', 'not read yet']])];
    default: return [];
  }
}

// The list view: the same nodes as a tree (coordinator > owners > their agents > their work), in reading order.
export function tree(graph) {
  if (!graph) return [];
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const workOf = new Map();
  for (const edge of graph.edges) if (edge.kind === 'works_on') { if (!workOf.has(edge.from)) workOf.set(edge.from, []); workOf.get(edge.from).push(edge.to); }
  const placed = new Set();
  const item = node => { placed.add(node.id); return { node, children: [] }; };
  const withWork = entry => { for (const id of workOf.get(entry.node.id) || []) if (byId.get(id) && !placed.has(id)) entry.children.push(dag(byId.get(id))); return entry; };
  const dag = node => {
    const entry = item(node);
    for (const edge of graph.edges) if ((edge.kind === 'next' || edge.kind === 'parent') && edge.from === node.id && byId.get(edge.to) && !placed.has(edge.to)) entry.children.push(dag(byId.get(edge.to)));
    return entry;
  };
  const roots = [];
  if (byId.get('user')) roots.push(item(byId.get('user')));
  const coord = byId.get('coordinator') ? item(byId.get('coordinator')) : null;
  if (coord) roots.push(coord);
  const owners = graph.nodes.filter(n => n.kind === 'owner').sort((a, b) => (LIVE.has(b.state) - LIVE.has(a.state)) || a.id.localeCompare(b.id));
  for (const owner of owners) {
    const entry = item(owner);
    for (const agent of graph.nodes.filter(n => (n.kind === 'subagent' || n.kind === 'reviewer') && n.owner === owner.id)) entry.children.push(withWork(item(agent)));
    withWork(entry);
    (coord ? coord.children : roots).push(entry);
  }
  for (const node of graph.nodes) if ((node.kind === 'subagent' || node.kind === 'reviewer') && !placed.has(node.id)) (coord ? coord.children : roots).push(withWork(item(node)));
  const rest = graph.nodes.filter(n => n.kind === 'work' && !placed.has(n.id));
  if (rest.length) roots.push({ node: { id: 'work:other', kind: 'group', label: 'Other work items' }, children: rest.map(n => (placed.has(n.id) ? null : dag(n))).filter(Boolean) });
  return roots;
}

const VERDICT_OK = /\b(ACCEPT|ACCEPTED|APPROVE|APPROVED|PASS)\b/;
const VERDICT_BAD = /\b(BLOCK|BLOCKED|REJECT|REJECTED|FAIL)\b/;

// A cue: what to animate for one org-graph change or one mc.event/1 event. `from`/`to` are node ids that must exist
// in the layout; `ring` pulses a node. Returns null when the event has nothing to point at.
export function cueForChange(change, graph) {
  const has = id => id && graph?.nodes.some(n => n.id === id);
  const color = kind => TYPE_COLORS[kind]?.color || '#eaff9e';
  switch (change?.type) {
    case 'spawned': return has(change.node) ? { map: change.kind === 'reviewer' ? 'reviewer-spawn' : change.kind === 'owner' ? 'coordinator' : 'subagent-spawn', from: has(change.from) ? change.from : 'coordinator', to: change.node, color: color(change.kind) } : null;
    case 'finished': return has(change.node) ? { map: change.kind === 'reviewer' ? 'review-return' : 'subagent-finish', from: change.node, to: has(change.to) ? change.to : 'coordinator', color: color(change.kind) } : null;
    case 'state': return has(change.node) ? { map: change.kind === 'reviewer' ? 'reviewer-working' : 'subagent-finish', ring: change.node, color: color(change.kind) } : null;
    case 'assigned': return has(change.node) ? { map: 'subagent-assign', from: change.node, to: has(`work:${change.ticket}`) ? `work:${change.ticket}` : null, ring: change.node, color: color('work') } : null;
    case 'message': return has(change.from) && has(change.to) ? { map: change.from === 'coordinator' ? 'coordinator' : 'owner-message', from: change.from, to: change.to, color: color(graph.nodes.find(n => n.id === change.from)?.kind) } : null;
    case 'added': case 'moved': case 'progress': return has(change.node) ? { map: change.type === 'progress' ? 'progress' : 'dag', ring: change.node, color: color('work') } : null;
    case 'dag': return has(change.edge?.from) && has(change.edge?.to) ? { map: 'dag', from: change.edge.from, to: change.edge.to, color: color('work') } : null;
    case 'changed': return has(change.node) ? { map: change.field === 'escalation' ? 'progress' : 'subagent-assign', ring: change.node, color: change.field === 'escalation' ? escalationColor(change.value) || '#ffd166' : color(change.kind) } : null;
    default: return null;
  }
}

export function cueForEvent(event, graph) {
  if (!event || event.historic) return null;
  const has = id => id && graph?.nodes.some(n => n.id === id);
  const agent = event.actor?.agent;
  const summary = String(event.summary || '');
  const ticketNode = event.subject?.ticket ? `work:${String(event.subject.ticket).replace(/^GoodQA\s+/, '')}` : '';
  if (event.kind === 'push' || event.kind === 'release') {
    return event.subject?.repo ? { map: 'git', from: 'coordinator', to: `repo:${event.subject.repo}`, color: '#9ebfff', merge: /merged PR/.test(summary) } : null;
  }
  if (event.kind === 'wal') {
    const fromMain = !agent || agent === 'main';
    if (/^ask:/.test(summary)) return { map: 'inbox', from: 'coordinator', to: 'user', color: TYPE_COLORS.user.color };
    if (/^ask_resolved:/.test(summary)) return { map: 'decision', from: 'user', to: 'coordinator', color: TYPE_COLORS.user.color };
    if (/^review(_result)?:/.test(summary) && has(agent)) {
      const node = graph.nodes.find(n => n.id === agent);
      const target = node?.reviews && has(node.reviews) ? node.reviews : node?.owner && has(node.owner) ? node.owner : null;
      const verdict = VERDICT_BAD.test(summary) ? 'rejected' : VERDICT_OK.test(summary) ? 'approved' : '';
      return { map: 'reviewer-verdict', from: agent, to: target, ring: target ? null : agent, color: verdict === 'rejected' ? '#ff6b5b' : verdict === 'approved' ? '#7edb8a' : TYPE_COLORS.reviewer.color, verdict };
    }
    if (event.quiet) return has(agent) ? { map: 'progress', ring: agent, color: '#c7c9ce', quiet: true } : null;
    if (has(ticketNode)) return { map: 'progress', from: has(agent) ? agent : null, to: ticketNode, ring: ticketNode, color: TYPE_COLORS.work.color };
    if (has(agent)) return { map: 'progress', ring: agent, color: '#eaff9e' };
    return fromMain ? { map: 'progress', ring: 'coordinator', color: '#eaff9e' } : null;
  }
  if (event.kind === 'ticket' || event.kind === 'deploy' || event.kind === 'initiative') {
    if (has(ticketNode)) return { map: 'progress', ring: ticketNode, color: TYPE_COLORS.work.color };
    if (event.subject?.repo && has(`repo:${event.subject.repo}`)) return { map: 'git', ring: `repo:${event.subject.repo}`, color: '#7edbca' };
    return null;
  }
  if (event.kind === 'owner' && has(agent)) return { map: 'subagent-finish', ring: agent, color: TYPE_COLORS.owner.color };
  return null;
}

// Recent repositories from push events, newest first, for the git ring.
export function repos(events) {
  const out = [];
  for (const event of events || []) {
    const repo = (event.kind === 'push' || event.kind === 'release') && event.subject?.repo;
    if (repo && !out.includes(repo)) out.push(repo);
    if (out.length >= 6) break;
  }
  return out;
}

export function ageText(iso, now = Date.now()) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return UNKNOWN;
  const s = Math.max(0, Math.round((now - t) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
}
