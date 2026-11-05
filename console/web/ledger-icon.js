// Local-ledger sync icon (docs/ledger.md): a small marker beside each session and in the repository summary
// that says whether the repository's local ticket ledger is synced to GoodQA. The label is text, the glyph is
// different per state, and the colour only adds to them (never the sole signal).

export const MAX_DIRS = 32;
export const REFRESH_MS = 60000;

const GLYPH = { synced: '✓', tracked: '✓', pending: '↑', 'local-only': '◐', diverged: '⚠', unknown: '?' };

// The label for a state; null means "show nothing" (no ledger, or a repository GoodQA tracks without one).
export function ledgerLabel(info) {
  const state = info && typeof info.state === 'string' ? info.state : 'unknown';
  switch (state) {
    case 'none': return null;
    case 'synced': return 'Ledger: synced';
    case 'tracked': return 'Ledger: tracked by GoodQA';
    case 'local-only': return 'Ledger: local only';
    case 'diverged': return 'Ledger: diverged from GoodQA';
    case 'pending': {
      const n = Number.isInteger(info.unsynced) && info.unsynced > 0 ? info.unsynced : 0;
      return n === 1 ? 'Ledger: 1 change not synced' : n ? `Ledger: ${n} changes not synced` : 'Ledger: changes not synced';
    }
    default: return 'Ledger: status unknown';
  }
}

export function ledgerState(info) {
  const state = info && typeof info.state === 'string' ? info.state : 'unknown';
  return GLYPH[state] || state === 'none' ? state : 'unknown';
}

// One shared, fixed-position label element: the tab strip clips overflow, so a label drawn inside it would be cut off.
function attachTooltip(icon, label) {
  if (typeof document === 'undefined' || typeof icon.addEventListener !== 'function') return; // no DOM (node tests)
  const tip = () => {
    let node = document.getElementById('ledger-tooltip');
    if (!node) {
      node = document.createElement('div');
      node.id = 'ledger-tooltip';
      node.className = 'ledger-tooltip';
      node.hidden = true;
      document.body.append(node);
    }
    return node;
  };
  const show = () => {
    const node = tip();
    node.textContent = label; // text only, never markup
    const box = icon.getBoundingClientRect();
    node.hidden = false;
    node.style.top = `${Math.round(box.bottom + 4)}px`;
    node.style.left = `${Math.max(4, Math.min(Math.round(box.left), window.innerWidth - node.offsetWidth - 4))}px`;
  };
  const hide = () => { tip().hidden = true; };
  icon.addEventListener('mouseenter', show);
  icon.addEventListener('focus', show);
  icon.addEventListener('mouseleave', hide);
  icon.addEventListener('blur', hide);
  icon.addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
}

// An element for the state, or null when there is nothing to show. `el(tag, className, text)` is the app's
// element helper.
export function renderLedgerIcon(el, info) {
  const label = ledgerLabel(info);
  if (label === null) return null;
  const state = ledgerState(info);
  const icon = el('span', `ledger-icon ledger-${state}`, GLYPH[state]);
  icon.dataset.ledgerState = state;
  icon.setAttribute('role', 'img');
  icon.setAttribute('aria-label', label);
  icon.title = label;
  icon.tabIndex = 0; // reachable by keyboard; the label shows on focus as well as on hover
  attachTooltip(icon, label);
  return icon;
}

// The unique, absolute working directories to ask about, at most MAX_DIRS.
export function ledgerDirs(sessions, repoRoot) {
  const seen = new Set();
  for (const item of [...(sessions || []).map(s => s && s.cwd), repoRoot]) {
    if (typeof item === 'string' && item.startsWith('/') && item.length < 4096) seen.add(item);
    if (seen.size >= MAX_DIRS) break;
  }
  return [...seen];
}

// Keeps the latest state per directory, refreshing on demand and every REFRESH_MS. `api(path, body)` posts.
export function createLedgerTracker({ api, onChange, setTimer = setInterval, clearTimer = clearInterval }) {
  const states = new Map();
  let dirs = [];
  let busy = false;
  let timer = null;

  async function refresh() {
    if (busy || !dirs.length) return;
    busy = true;
    try {
      const result = await api('/api/ledger/sync-state', { cwds: dirs });
      let changed = false;
      for (const dir of dirs) {
        const next = result && result.states && result.states[dir] ? result.states[dir] : { state: 'unknown' };
        const before = states.get(dir);
        if (!before || before.state !== next.state || before.unsynced !== next.unsynced) changed = true;
        states.set(dir, next);
      }
      if (changed) onChange();
    } catch {
      for (const dir of dirs) if (!states.has(dir)) states.set(dir, { state: 'unknown' });
    } finally {
      busy = false;
    }
  }

  return {
    get: dir => states.get(dir) || null,
    track(next) {
      const key = JSON.stringify(next);
      const changed = key !== JSON.stringify(dirs);
      dirs = next;
      if (changed) refresh();
      if (!timer) timer = setTimer(refresh, REFRESH_MS);
    },
    refresh,
    stop() { if (timer) clearTimer(timer); timer = null; },
  };
}
