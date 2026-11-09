import json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
O = json.load(open(T + 'classes6.json'))
done = set()
for f in ('done5.jsonl', 'done10.jsonl', 'done11.jsonl'):
    try:
        for l in open(T + f):
            j = json.loads(l)
            if j['result'] == 'closed':
                done.add(j['id'])
    except FileNotFoundError:
        pass
N = [o for o in O if o['noise'] and not o['prot'] and o['status'] in ('triage', 'backlog', 'todo') and o['id'] not in done
     and 'yates' not in o['proj'] and o['proj'].split('/')[1] != 'optinrouter']
kids = [{'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj']} for o in N]
note = 'bot noise class (runner/brief slug titles, liveness and deadman alerts, [Lane] and QA-bot mirrors, outreach batch notices), status never advanced past triage/backlog/todo, no owner, no human comment in 14 days.'
open(T + 'plan12-noise.jsonl', 'w').write(json.dumps({'kind': 'noise', 'umbrella': None, 'note': note, 'children': kids}) + '\n')
print(len(kids))
