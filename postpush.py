import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = """t2-course rewrite result (owner ab8a7d1b). main force-pushed c68f57e5 -> 72af7adf (media removed from history: public/audio, public/engineering-videos, public/data-audio, power-user/public/audio). N1 check: 0 hits across 38,218 media names. Secret scan over all 354 commits: 1 flagged line, a false positive (FISH_API_KEY_FILE is a file path, not a key). Rollback bundle: dropbox:Backups/repo-archives-private/t2-course-prerewrite-20261109T051935Z.
Rebased change for review: branch chore/media-to-r2-v2, commits 72b567fbde35, b33ca4c2b115 and 7d08b79a28c2 (media manifest in R2, sha-verified restore, deploy gate, delta-review fixes). The old chore/media-to-r2 branch was deleted. Every t2-course clone must be re-cloned, not pulled."""
print(str(gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': b, 'operationId': str(uuid.uuid4())}))[:40])
