import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
for term in ('never lose', 'never-lose', 'neverlose'):
    r = gq.call('search_issues', dict(orgId=P['orgId'], search=term, projectId=P['id'], limit=10, fields=['number', 'title', 'status']))
    for i in r.get('issues', []):
        print(term, '|', i)
