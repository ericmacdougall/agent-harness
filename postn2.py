import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = """MANUAL DEPLOY RULE for t2-course until the N2 deploy gate merges (goodqa#15484): deploy ONLY with `npm ci && npm run media:pull && npm run build && npm run deploy`. Never build with MEDIA_SKIP. Never run `npm run media:pull` after a build and then deploy without rebuilding. Media is no longer in git; `npm run deploy` alone cannot tell a MEDIA_SKIP build from a verified one yet. The same rule is in the t2-course README on branch chore/media-to-r2-v2 (PR #49).
N2 fix: branch fix/media-deploy-marker, commit 9a71aa13d620, stacked on chore/media-to-r2-v2 (PR #49). prebuild records the media check, postbuild stamps dist/.media-marker.json, deploy runs a gate that needs an ok marker and a valid media tree and never honors MEDIA_SKIP. Tests: `node --test tests/media-deploy-gate.test.mjs` -> 5 pass (5 of 5 fail against the previous script)."""
print(str(gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': b, 'operationId': str(uuid.uuid4())}))[:30])
