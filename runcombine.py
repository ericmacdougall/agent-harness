"""Verbatim combine of guard-skipped tickets, project by project, then count each project's open tickets. One rate-limited job at a time."""
import subprocess, sys, json, time, os
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
import gq
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
order = sys.argv[1:] or ['parent-proof', 'goodqa', 'work-tracker-automatic', 'parentproof-app', 'poopyduck-app', 'hawkeye-app', 'harness']


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
    print('=== COMBINE', p, time.strftime('%H:%M:%S'), flush=True)
    r = subprocess.run(['python3', '-I', H + 'mkcombine2.py', p, '--create'], capture_output=True, text=True)
    print(r.stdout[-500:], r.stderr[-200:], flush=True)
    if os.path.exists(T + 'plan16-%s.jsonl' % p):
        r = subprocess.run(['python3', '-I', T + 'consol15.py', T + 'plan16-%s.jsonl' % p], capture_output=True, text=True, cwd=T)
        print(r.stdout[-200:], r.stderr[-200:], flush=True)
    print('COUNT', p, count(p), time.strftime('%H:%M:%S'), flush=True)
print('RUNCOMBINE_DONE', flush=True)
