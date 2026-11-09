import sys, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
body = """t2-course freeze window (announcement, owner ab8a7d1b). Nothing has been rewritten yet.

Plan, in order:
1. Window opens when I post GO here. Anyone who pushes to ericmacdougall/t2-course must stop pushing from then until I post DONE. Expected length 30 minutes. The only live pushers I know of: none (the lessons owner confirmed it never pushes to t2-course). If you hold a t2-course clone and have unpushed work, push it to a new branch BEFORE GO.
2. Gate before GO: (a) fresh Dropbox bundle of the full mirror, verified with rclone check and git bundle verify; (b) all 25 media parts present on Dropbox (20 of 25 so far, paused behind the dev2 evidence archive); (c) fresh-clone proof PASSED (done: clone, npm ci, media:pull from R2, build, verify, 38,218 files, tree c971d8976dd7).
3. Steps: git-filter-repo --invert-paths on public/audio, public/engineering-videos, public/data-audio, power-user/public/audio; re-add media-manifest.json and the media-sync change; secret scan; force-push main only (allowed for repo-size cleanup); open the PR for chore/media-to-r2 rebased onto the new main; re-read GitHub size.
4. Rollback: the Dropbox bundle restores the old history (git clone from the bundle, push --force the old main back). R2 media parts are immutable (bucket lock on media/v1/).
5. After DONE: every clone must be re-cloned, not pulled. Known clones: t2-dev sites-seo/t2-course-main, dev2 t2-audit/t2-course, work/t2-course, pr47-work (dev2 retires today), Mac sites/src/t2-course and sites-seo/repos/t2-course."""
r = gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': body, 'operationId': str(uuid.uuid4())})
print(str(r)[:120])
