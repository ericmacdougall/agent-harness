// Test helper: the server's dataset reads for a hand-built page state. FEEDS is read from the real collectors module
// (truth_scenarios.py --feeds), never restated here, and readsFor() composes it the way collectors.Truth does, from the
// state's Source health rows and ledger parts. Scenarios that run the real server use its own `reads` instead.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('./truth_scenarios.py', import.meta.url));
const run = spawnSync(process.env.PYTHON || 'python3', ['-I', SCRIPT, '--feeds'], { encoding: 'utf8', timeout: 60000 });
if (run.status !== 0) throw new Error(`truth_scenarios.py --feeds failed: ${run.stderr || run.error}`);
export const FEEDS = JSON.parse(run.stdout);
export const SOURCES = [...new Set(Object.values(FEEDS).flat().filter(id => !id.startsWith('ledger:')))].sort();
const ORDER = ['current', 'partial', 'stale', 'unknown'];
const rank = truth => (ORDER.includes(truth) ? ORDER.indexOf(truth) : 3);

function fact(state, id) {
  if (id.startsWith('ledger:')) {
    const part = state.ledger?.[id.slice(7)] || {};
    return { id, truth: ORDER[rank(part.truth)], at: part.at || '', error: part.error || '' };
  }
  const row = (state.sources || []).find(s => s.id === id);
  if (!row) return { id, truth: 'unknown', at: '', error: '' };
  return { id, truth: ORDER[rank(row.truth)], at: row.truth === 'unknown' ? '' : row.okAt || '', error: row.status === 'ok' ? '' : row.detail || row.status };
}
export function readsFor(state) {
  return Object.fromEntries(Object.entries(FEEDS).map(([dataset, ids]) => {
    const facts = ids.map(id => fact(state, id));
    return [dataset, { truth: ORDER[Math.max(...facts.map(f => rank(f.truth)))], facts }];
  }));
}
export const withReads = state => ({ ...state, reads: readsFor(state) });
// One Source health row per source, all current, as the server reports them (epoch seconds).
export const healthRows = (at, names = SOURCES) => names.map(name => ({ name, status: 'ok', checked: at, ok_at: at, truth: 'current', detail: '' }));
