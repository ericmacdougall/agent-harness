import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
E = json.load(open(T + 'elig6.json'))
O = {o['id']: o for o in json.load(open(T + 'classes6.json'))}
ch = lambda o: {'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj']}
noise = [o for o in E if o['noise'] or o['proj'].endswith('qac-acceptance-disposable')]
nid = {o['id'] for o in noise}
out = []
if noise:
    out.append({'kind': 'noise', 'umbrella': None, 'note': 'bot/test noise (deadman, liveness, runner slugs, disposable acceptance-test project), no human comment.', 'children': [ch(o) for o in noise]})
by = collections.defaultdict(list)
for o in E:
    if o['id'] in nid:
        continue
    p = O.get(o['parent'])
    if p:
        by[p['id']].append(o)
for pid, lst in sorted(by.items(), key=lambda x: -len(x[1])):
    p = O[pid]
    out.append({'kind': 'parent', 'umbrella': {'id': pid, 'number': p['n'], 'slug': p['proj'].split('/')[1]}, 'note': '', 'children': [ch(o) for o in lst]})
with open(T + 'plan6p.jsonl', 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print(len(out), 'groups;', sum(len(g['children']) for g in out), 'children;', 'noise', len(noise))
