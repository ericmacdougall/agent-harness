"""Get the open count under 300: #14360 (fleet alert) -> duplicate of #15558; #15558 -> duplicate of the area live ticket #15532 (the liveness bot follows duplicate chains up to 3 hops,
so alerts still land on an open ticket). Links first, then the closes. Backoff via gq."""
import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']


def issue(n):
    return gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=n))['issue']


a14360, a15558, a15532 = issue(14360), issue(15558), issue(15532)
print(a14360['status'], a15558['status'], a15532['status'], a15532['title'][:60])
assert a15532['status'] not in ('done', 'wont_fix', 'duplicate', 'cancelled')
for child, parent in ((a14360, a15558), (a15558, a15532)):
    print('link', child['number'], '->', parent['number'], json.dumps(gq.call('call_api', dict(method='POST', path='/issues/%s/links' % child['id'], body={'relatedIssueId': parent['id'], 'kind': 'duplicates'})))[:100])
r = gq.call('bulk_update_issues', {'items': [
    {'issueId': a14360['id'], 'status': 'duplicate', 'note': 'goodqa#14977: closed as a duplicate of goodqa#15558 (combined fleet alerts), which now follows to goodqa#15532. goodqa_liveness.py notes it there. NOT done.'},
    {'issueId': a15558['id'], 'status': 'duplicate', 'note': 'goodqa#14977: folded into the area live ticket goodqa#15532 (Runner, fleet, lanes and harness). Its member list and the 76 alert rows stay readable here; the liveness bot follows this duplicate to goodqa#15532 (chain of up to 3 hops) and posts its aggregate note there. NOT done.'}]})
print(json.dumps(r)[:200])
