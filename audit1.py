"""Audit step 1 (read-only): inspect #15545 and the six named tickets for owner / spec / PR markers, to design the audit."""
import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
for n in (15545, 15382, 15372, 15361, 14798, 15434, 15510):
    r = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=n))
    i = r.get('issue', r)
    cs = gq.call('get_issue_comments', {'issueId': i['id']}).get('comments', [])
    txt = ' '.join((c.get('body') or '') for c in cs) + ' ' + (i.get('description') or '')
    print(n, i['status'], 'assignee', (i.get('assignee') or {}).get('name'), 'owner', i.get('currentOwnerId'), 'agentKey', i.get('assignedAgentApiKeyId'), 'labels', [l for l in i['labels'] if not l.startswith('idem:')][:8],
          'comments', len(cs), 'spec' in txt.lower(), 'PR' in txt or 'pull/' in txt, 'upd', i['updatedAt'][:16], 'closedAt', (i.get('closedAt') or '')[:16])
    stamps = [c['createdAt'][:16] for c in cs if 'cleanup-2026-11' in (c.get('body') or '')]
    print('   fold stamps', stamps)
