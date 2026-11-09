"""Read-only: direction of the duplicates link between alert 14887 and live ticket 15558."""
import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
plan = json.loads(open(T + 'plan21-goodqa.jsonl').readline())
live = plan['umbrella']['id']
a = [c for c in plan['children'] if c['n'] == 14887][0]['id']
for name, i in (('alert 14887', a), ('live 15558', live)):
    r = gq.call('call_api', dict(method='GET', path='/issues/%s/links' % i))
    print(name, {k: [(x.get('issue') or x).get('id', '')[:8] for x in v] for k, v in r.items() if v}, 'id', i[:8])
