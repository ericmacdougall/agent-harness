"""Fold the remaining foldable tickets project by project, then count that project's open tickets (cheap list, not the full dump). One rate-limited job at a time."""
import subprocess, sys, json, time
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
import gq
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
order = sys.argv[1:] or ['work-tracker-automatic', 'parent-proof', 'goodqa', 'parentproof-app', 'poopyduck-app', 'hawkeye-app', 'harness']


def count(slug):
    P = projects[slug]
    n = 0
    cur = None
    while True:
        a = {'projectId': P['id'], 'closed': False, 'limit': 100, 'fields': ['id']}
        if cur:
            a['cursor'] = cur
        d = gq.call('list_issues', a)
        n += len(d.get('issues', []))
        cur = d.get('nextCursor')
        if not cur or not d.get('issues'):
            return n


for p in order:
    print('=== FOLD', p, time.strftime('%H:%M:%S'), flush=True)
    if not __import__('os').path.exists(T + 'plan15-%s.jsonl' % p):
        r = subprocess.run(['python3', '-I', H + 'mkfold2.py', p, '--create'], capture_output=True, text=True)
        print(r.stdout[-400:], flush=True)
    r = subprocess.run(['python3', '-I', T + 'consol13.py', T + 'plan15-%s.jsonl' % p], capture_output=True, text=True, cwd=T)
    print(r.stdout[-300:], r.stderr[-200:], flush=True)
    print('COUNT', p, count(p), time.strftime('%H:%M:%S'), flush=True)
print('RUNFOLDS_DONE', flush=True)
