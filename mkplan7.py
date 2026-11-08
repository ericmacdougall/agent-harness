import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
J = json.load(open(T + 'join6.json'))
O = json.load(open(T + 'classes5.json'))
rows = []
for o in O:
    k = o['proj'].split('/')[1] + '#' + str(o['n'])
    if k in J['merged'] and k in J['rt']:
        rows.append((o, k))
print(len(rows), collections.Counter(tuple(o['prot']) for o, k in rows), collections.Counter(o['proj'] for o, k in rows))
for o, k in rows[:5]:
    print(k, o['status'], o['title'][:70], J['merged'][k][:2], J['rt'][k][:2])
ok = [(o, k) for o, k in rows if not set(o['prot']) - {'pr-or-commit', 'wal-72h'} and o['type'] != 'epic']
print('eligible', len(ok))
kids = [{'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj'],
         'note': 'done: merged PR %s and REALLY_TESTED %s name this ticket.' % (','.join(sorted(set(J['merged'][k]))[:3]), ','.join(str(x) for x in sorted(set(J['rt'][k]))[:3]))} for o, k in ok]
open(T + 'plan7.jsonl', 'w').write(json.dumps({'kind': 'done', 'umbrella': None, 'note': '', 'children': kids}) + '\n')
