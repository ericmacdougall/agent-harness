import sys, uuid, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
# 1) window post
body = """t2-course freeze window OPEN (owner ab8a7d1b), GO from main (recorded in main's WAL). Nobody pushes to ericmacdougall/t2-course until I post DONE. Plan unchanged: fresh mirror, N1 name check of all 38,218 media names, git-filter-repo of the four media prefixes, secret scan, force-push of main only (new branch chore/media-to-r2-v2 pushed normally, old chore/media-to-r2 deleted), PR for the rebased change, size re-read. Rollback: dropbox:Backups/repo-archives-private/t2-course-prerewrite-20261109T051935Z (full mirror bundle, sha256 2e73fe3a8b70...). After DONE every clone must be re-cloned, not pulled."""
print(str(gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': body, 'operationId': str(uuid.uuid4())}))[:50])
# 2) N2 first on #15484
iss = [p for p in [gq.call('get_issue_by_number', {'projectSlug': 'goodqa', 'number': 15484})]][0]
i = iss.get('issue', iss)
n2 = """FIRST (could break the live site): N2. The deploy check (`npm run deploy` -> `media-sync.mjs verify`) verifies the media in the SOURCE tree, not in the built output. Sequence that ships a site with no media: `MEDIA_SKIP=1 npm run build` (build without media), then `npm run media:pull` (media now present in the source tree), then `npm run deploy` without rebuilding. verify passes and wrangler deploys dist/ that contains no audio or video. Found by the delta red-team (agent a35115287773e8686, hypothesis, not yet reproduced against the real build).
Fix: verify the built asset directory (dist/client) against the manifest tree hash, or have prebuild write a marker file (with the tree hash) into the build output and have deploy refuse a dist/ without a matching marker. Also refuse MEDIA_SKIP builds from producing dist/ at all unless an explicit local-only flag is set.
Verify by: run the sequence above on a synthetic repo; after the fix `npm run deploy` must fail with a clear message.

"""
desc = n2 + (i.get('description') or '')
print(str(gq.call('update_issue', {'issueId': i['id'], 'patch': {'description': desc, 'priority': 'high'}}))[:80])
