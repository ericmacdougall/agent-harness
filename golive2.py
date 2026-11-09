import sys, uuid, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
# 2) N2 first on #15484
iid = [json.loads(l)['id'] for l in open(T + 'open_now7.jsonl') if '"number": 15484' in l and '"_proj": "goodqa"' in l][0]
i = gq.call('get_issue', {'issueId': iid})['issue']
n2 = """FIRST (could break the live site): N2. The deploy check (`npm run deploy` -> `media-sync.mjs verify`) verifies the media in the SOURCE tree, not in the built output. Sequence that ships a site with no media: `MEDIA_SKIP=1 npm run build` (build without media), then `npm run media:pull` (media now present in the source tree), then `npm run deploy` without rebuilding. verify passes and wrangler deploys dist/ that contains no audio or video. Found by the delta red-team (agent a35115287773e8686, hypothesis, not yet reproduced against the real build).
Fix: verify the built asset directory (dist/client) against the manifest tree hash, or have prebuild write a marker file (with the tree hash) into the build output and have deploy refuse a dist/ without a matching marker. Also refuse MEDIA_SKIP builds from producing dist/ at all unless an explicit local-only flag is set.
Verify by: run the sequence above on a synthetic repo; after the fix `npm run deploy` must fail with a clear message.

"""
desc = n2 + (i.get('description') or '')
print(str(gq.call('update_issue', {'issueId': i['id'], 'patch': {'description': desc, 'priority': 'high'}}))[:80])
