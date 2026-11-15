// Owner panel layout (goodqa#15920). The server gives each row a role that mirrors the owner cap (tier_gate):
// 'live' holds a slot now, 'parked' is waiting/handoff/returned/done/DROPPED/finishing, 'helper' is a reviewer,
// red-team, click-tester, fixer or similar that never counts. This module only groups; it never re-decides a role.

export const UNLINKED = 'unlinked';
const WORKING = /^(live|working|quiet|observed)/;

export const isHelper = owner => owner.role === 'helper';
const helperActive = owner => WORKING.test(owner.state || '');
export const needsAttention = owner => Boolean(owner.severe || owner.decision_required);

// The headline: live owners from `ah owners` (the number the owner cap counts) and, apart, live Codex owners.
export function ownerCounts(owners = []) {
  const counts = { live: 0, codexLive: 0, parked: 0, helpers: 0, attention: 0, total: owners.length };
  for (const owner of owners) {
    if (owner.role === 'live') owner.source === 'ah' ? counts.live++ : counts.codexLive++;
    else if (owner.role === 'helper') counts.helpers++;
    else counts.parked++;
    if (needsAttention(owner)) counts.attention++;
  }
  return counts;
}

// Groups by initiative. Each group: live owners with their working helpers shown, parked owners that need a decision
// (shown, never counted), then one fold holding the other parked owners
// (with all their helpers), finished helpers of live owners and helpers that serve no listed owner. Every row lands in
// exactly one place, so nothing is hidden for good.
export function ownerGroups(owners = [], initiatives = []) {
  const byId = new Map(owners.map(owner => [owner.agent_id, owner]));
  const groups = new Map();
  const group = id => {
    if (!groups.has(id)) {
      const item = initiatives.find(i => i.id === id);
      groups.set(id, { id, label: item ? item.initiative : 'Not linked to an initiative', live: [], decide: [], parked: [], loose: [], attention: 0, liveCount: 0, codexLive: 0, foldCount: 0 });
    }
    return groups.get(id);
  };
  const entries = new Map();
  for (const owner of owners) {
    if (isHelper(owner)) continue;
    const g = group(owner.initiative_id || UNLINKED);
    const entry = { owner, helpers: [], doneHelpers: [] };
    entries.set(owner.agent_id, entry);
    // liveCount: ah slot holders (the headline's unit); codexLive apart, so group headings sum to the headline
    if (owner.role === 'live') { g.live.push(entry); owner.source === 'ah' ? g.liveCount++ : g.codexLive++; }
    // a parked owner that needs main's decision never folds away: it shows under the live owners, uncounted
    else if (owner.decision_required) g.decide.push(entry);
    else { g.parked.push(entry); g.foldCount++; if (needsAttention(owner)) g.attention++; }
  }
  for (const helper of owners) {
    if (!isHelper(helper)) continue;
    const entry = helper.serves && byId.get(helper.serves) && entries.get(helper.serves);
    if (!entry) { const g = group(helper.initiative_id || UNLINKED); g.loose.push(helper); g.foldCount++; if (needsAttention(helper)) g.attention++; continue; }
    const g = group(entry.owner.initiative_id || UNLINKED);
    const shown = entry.owner.role === 'live' || entry.owner.decision_required;
    if (shown && helperActive(helper)) entry.helpers.push(helper);
    else if (shown) { entry.doneHelpers.push(helper); g.foldCount++; if (needsAttention(helper)) g.attention++; }
    else { entry.helpers.push(helper); g.foldCount++; if (needsAttention(helper)) g.attention++; }
  }
  const order = new Map(initiatives.map((item, index) => [item.id, index]));
  return [...groups.values()].sort((a, b) => (b.live.length > 0) - (a.live.length > 0)
    || (a.id === UNLINKED) - (b.id === UNLINKED) || (order.get(a.id) ?? 1e9) - (order.get(b.id) ?? 1e9));
}

// Every count below is stated through the owners gate `g` (adapt.gate(state, 'owners')), so a read that is unknown,
// partial or stale never shows a plain number (PR 234 v7 audit T242-3, T242-4).
export function foldLabel(group, g) {
  return `Parked / history (${g.count(group.foldCount)})${group.attention ? ` · ${g.count(group.attention)} need attention` : ''}`;
}

export function groupHeading(group, g) {
  return `${group.label} · ${g.count(group.liveCount)} live${group.codexLive ? ` · ${g.count(group.codexLive)} live Codex` : ''}`
    + `${group.decide.length ? ` · ${g.count(group.decide.length)} need a decision` : ''}`;
}

export const groupEmpty = g => g.none('No live owner in this initiative.', 'live owners in this initiative');

// T242-5, a declared window: the server lists a finished owner (done, handoff, returned...) only while it was active in
// the last 6 h (collectors.Owners). Older ones are left out on purpose, and every count of parked or history says so.
export const HISTORY_WINDOW = 'owners finished over 6 h ago are not listed';

export function summaryLine(counts, g, { session = '' } = {}) {
  return [`${g.count(counts.live)} live ${counts.live === 1 ? 'owner' : 'owners'} per ah owners${session ? ` (session ${session.slice(0, 8)})` : ''}`,
    `${g.count(counts.codexLive)} live Codex`, `${g.count(counts.parked)} parked or history`, `${g.count(counts.helpers)} helpers`,
    counts.attention ? `${g.count(counts.attention)} need attention` : '', g.current ? '' : g.note(''), HISTORY_WINDOW].filter(Boolean).join(' · ');
}
