import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = "N2 fix pushed: branch fix/media-deploy-marker, commit 9a71aa13d620, stacked on chore/media-to-r2-v2 (PR 49). prebuild records the media check, postbuild stamps dist/.media-marker.json, `npm run deploy` runs a gate needing an ok marker and a valid media tree, never honoring MEDIA_SKIP. Tests: node --test tests/media-deploy-gate.test.mjs -> 5 pass (5 of 5 fail against the previous script). Manual deploy rule until it merges is on goodqa#14977 and in the README of PR 49."
print(str(gq.call('comment_on_issue', {'issueId': '92911933-4849-4345-a772-bfd38793c56e', 'body': b, 'operationId': str(uuid.uuid4())}))[:30])
