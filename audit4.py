"""Audit step 4: tier the candidates in audit3.json. A = spec marker or open PR or a WAL work event (intent/scope/decision/result/handoff/check/commit/requirement/risk/blocker)
in an agent WAL touched in 48 h; C = only other WAL mentions. Writes reopen_plan.json (tier A plus the named tickets)."""
import json, collections
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
cand = json.load(open(H + 'audit3.json'))
tier = {}
for i, v in cand.items():
    ws = [w.split(':')[0] for w in v['why']]
    tier[i] = 'A' if any(w in ('WALwork', 'spec-marker', 'PR') for w in ws) else 'C'
c = collections.Counter(tier.values())
print('tier A', c['A'], 'tier C', c['C'])
print('A by project', collections.Counter(cand[i]['proj'] for i in tier if tier[i] == 'A').most_common(5))
print('A by ledger', sorted(collections.Counter(cand[i]['ledger'] for i in tier if tier[i] == 'A').items()))
named = (15382, 15372, 15361, 14798, 15434, 15510, 15545)
for n in named:
    hit = [(i, tier[i], cand[i]['why'][:2]) for i in cand if cand[i]['n'] == n and cand[i]['slug'] == 'goodqa']
    print(n, hit if hit else 'NOT a candidate')
json.dump({i: cand[i] for i in tier if tier[i] == 'A'}, open(H + 'reopen_plan.json', 'w'), indent=1)
json.dump({i: cand[i] for i in tier if tier[i] == 'C'}, open(H + 'tierC.json', 'w'), indent=1)
