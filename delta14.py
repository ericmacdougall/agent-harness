import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
a = {json.loads(l)['id']: json.loads(l) for l in open(T + 'open_now13.jsonl')}
b = {json.loads(l)['id']: json.loads(l) for l in open(T + 'open_now14.jsonl')}
audit = {json.loads(l)['id'] for l in open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/restore_audit.jsonl') if '"keep-reopened"' in l}
audit |= {json.loads(l)['id'] for l in open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/reopen_audit.jsonl') if '"reopened"' in l}
new = [b[i] for i in b if i not in a]
gone = [a[i] for i in a if i not in b]
mine = [r for r in new if r['id'] in audit]
other = [r for r in new if r['id'] not in audit]
print('now', len(b), 'before', len(a), 'new', len(new), '(audit reopens kept:', len(mine), ', filed by others/bots:', len(other), ') gone', len(gone))
for r in other:
    print('  new', r['_proj'], r['number'], (r.get('reporter') or {}).get('name'), r['title'][:70])
