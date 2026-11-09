import json, glob, sys, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
for f in glob.glob(T + 'snapshots7/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        iid = j['issue']['id']
        i = gq.call('get_issue', {'issueId': iid})['issue']
        if i['status'] == 'done':
            gq.call('update_issue', {'issueId': iid, 'patch': {'status': j['issue']['status']}})
            gq.call('comment_on_issue', {'issueId': iid, 'body': 'cleanup-2026-11d (goodqa#14977): reopened. The earlier close as done had a merged PR and a REALLY_TESTED entry but no deploy or live record, and done means deployed live and tested live. It stays open until live proof exists.', 'operationId': str(uuid.uuid4())})
        print(i['number'], i['status'], '->', gq.call('get_issue', {'issueId': iid})['issue']['status'])
