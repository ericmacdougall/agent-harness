"""Build consol12 (stale agent-claim rule) and plan12s from the tickets consol10 skipped as owner-v2.
Rule (main): an agent assignment key on a todo ticket protects it only if the ticket had activity within 48h; otherwise it is a stale claim and the ticket may be umbrella-merged, noting the stale key in the close comment.
Human assignee/owner/developer still block."""
import json, collections, datetime as D
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
s = open(T + 'consol10.py').read()
old = "    if i.get('assigneeId') or i.get('currentOwnerId') or i.get('developerId') or (i.get('assignedAgentApiKeyId') and i['status'] == 'todo' and not noise):\n        return c, i, 'owner-v2', []"
assert old in s
new = """    if i.get('assigneeId') or i.get('currentOwnerId') or i.get('developerId'):
        return c, i, 'human-owner', []
    stale_key = ''
    if i.get('assignedAgentApiKeyId') and not noise:
        import datetime as _D
        if i.get('updatedAt', '') >= (_D.datetime.now(_D.timezone.utc) - _D.timedelta(hours=48)).isoformat():
            return c, i, 'agent-claim-active-48h', []
        stale_key = ' Stale agent claim removed from consideration: assignedAgentApiKeyId %s had no activity for 48h.' % str(i['assignedAgentApiKeyId'])[:8]
    c['stale_key'] = stale_key"""
s = s.replace(old, new)
s = s.replace("'recent-human-or-unknown-comment-14d'", "'recent-human-or-unknown-comment-14d'")
for a, b in [("done10.jsonl", "done12.jsonl"), ("closes10.tsv", "closes12.tsv"), ("snapshots10", "snapshots12"), ("bulk_errors10", "bulk_errors12"), ("ledger10|", "ledger12|")]:
    s = s.replace(a, b)
# note the stale key in the close comment
s = s.replace("items = [{'issueId': c['id'], 'status': 'wont_fix', 'note': '%s (goodqa#14977 under-300 push): %s Reopen", "items = [{'issueId': c['id'], 'status': 'wont_fix', 'note': '%s (goodqa#14977 under-300 push): %s' + c.get('stale_key', '') + ' Reopen")
s = s.replace("' Reopen by setting status back to \\'%s\\'; snapshot kept.' % (TAG, tail, i['status'])}", "' Reopen by setting status back to \\'%s\\'; snapshot kept.' % (TAG, tail, i['status'])}")
open(T + 'consol12.py', 'w').write(s)
import ast
ast.parse(s)
# plan: the owner-v2 skipped ids, regrouped as in plan6p
skipped = set()
for l in open(T + 'done10.jsonl'):
    j = json.loads(l)
    if j.get('why') == 'owner-v2':
        skipped.add(j['id'])
out = []
for l in open(T + 'plan6p.jsonl'):
    g = json.loads(l)
    kids = [c for c in g['children'] if c['id'] in skipped]
    if kids and g['umbrella']:
        g['children'] = kids
        out.append(g)
with open(T + 'plan12s.jsonl', 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print(len(skipped), 'owner-v2 skipped;', sum(len(g['children']) for g in out), 'children in', len(out), 'groups')
