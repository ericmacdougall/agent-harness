import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = "Deploy of main c8fbe7b5 from t2-dev went live (worker version 02a7e6ac) but wrangler exited 1 at the zone workers-routes check: any `routes` entry makes `wrangler deploy` list the zone's routes first (GET /zones/e888f720.../workers/routes), which the deploy token cannot read (no zone scope). Fix pushed: branch fix/wrangler-no-zone-route, commit f23fd6c36054 (PR to follow): drop the routes block and set workers_dev and preview_urls to false so no extra public URL appears; the custom domain stays attached. Verification after merge: rerun npm run deploy (expect exit 0) and re-check the domain, 3 media URLs and a lesson page."
print(str(gq.call('comment_on_issue', {'issueId': '92911933-4849-4345-a772-bfd38793c56e', 'body': b, 'operationId': str(uuid.uuid4())}))[:30])
