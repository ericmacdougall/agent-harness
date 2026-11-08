import json, collections
exec(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/elig.py').read().split('STAT =')[0])
STAT = {'triage', 'backlog', 'todo'}
byid = {o['id']: o for o in O}
E = [o for o in O if not o['prot'] and o['status'] in STAT and (o['agent'] or o['noise'] or mark(o)) and o['type'] != 'epic'
     and o['proj'].split('/')[0] not in ('p51-media', 'petafiliate')]
print(len(E))
c = collections.Counter()
for o in E:
    p = o['parent']
    c['noise' if o['noise'] else ('parent-open' if p in byid else ('parent-closed' if p else 'no-parent'))] += 1
print(c)
print(collections.Counter(o['proj'] for o in E).most_common())
json.dump(E, open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/elig4.json', 'w'))
