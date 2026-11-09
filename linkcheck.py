"""Read-only: shape of GET /issues/{id}/links for an alert ticket, and the live ticket's id."""
import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
live = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=15558))['issue']
print('live', live['id'], live['status'], live['title'])
r = [json.loads(l) for l in open(T + 'open_now11.jsonl') if '"number": 14887' in l][0]
print('alert id', r['id'])
for path in ('/issues/%s/links' % r['id'], '/v1/issues/%s/links' % r['id']):
    out = gq.call('call_api', dict(method='GET', path=path))
    print(path, json.dumps(out)[:400])
