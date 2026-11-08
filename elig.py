import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
O = json.load(open(T + 'classes4.json'))
MARK = {'plan-20261023', 'runner-brief', 'bug-triaged', 'brief-held', 'brief-ready', 'brief-published', 'needs-brief', 'cleanup', 'needs-recovery', 'runner-active',
        'needs-postship-flow', 'ux-review', 'epic', 'coordinator-assigned', 'autopilot-successor', 'fleet-liveness', 'cleanup-2026-11', 'breadth', 'phase', 'component',
        'fixing', 'datasuite', 'datasuite-parity', 'datasuite-m1', 'optin-datasuite-20261023', 'hawkeye-parity', 'parity-20261022', 'capability-gap', 'eric-ask-gap',
        'coordinator-instruction-20261023', 'timbar-fit', 'idem'}


def mark(o):
    return any(l in MARK or l.startswith(('cleanup:', 'idem:', 'plan-', 'eric-asks-audit')) for l in o['labels'])


STAT = {'triage', 'backlog', 'todo'}
cnt = collections.Counter()
for o in O:
    if o['prot']:
        k = 'protected'
    elif o['proj'].split('/')[0] in ('p51-media', 'petafiliate') and not o['agent']:
        k = 'human-org-human'
    elif o['status'] not in STAT:
        k = 'active-status(' + o['status'] + ')'
    elif o['agent'] or o['noise']:
        k = 'ELIG-agent'
    elif mark(o):
        k = 'ELIG-token-agent-marker'
    else:
        k = 'human-keep'
    cnt[k] += 1
for k, v in cnt.most_common():
    print(v, k)
