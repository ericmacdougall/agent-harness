DRAFT - NOT SENT. For the user to review and submit. Prepared by owner ab8a7d1b, 2026-11-09 (goodqa#14977). Supersedes github-support-purge-draft.md (bugtracker only).

To: GitHub Support (Contact Support > Repository > "Remove cached/dangling objects")
Account: ericmacdougall
Repositories: ericmacdougall/t2-course (private), ericmacdougall/bugtracker (private)

Subject: Request to garbage-collect unreachable objects and purge hidden pull refs after history rewrites (two repositories)

Hello,

We rewrote the history of two private repositories to remove large files. In both, the size GitHub reports stays high because old objects remain reachable only through hidden refs that we cannot delete ourselves.

1) ericmacdougall/t2-course
   - 2026-11-09: main was force-pushed from c68f57e5a8fa0a956da720e876b4ad3d002fd365 to 72af7adf736190dba58a042c248f488a8f1ad626. The rewrite removed about 6.2 GB of audio and video (public/audio, public/engineering-videos, public/data-audio, power-user/public/audio; 38,218 files, now stored in object storage).
   - GitHub reported 5,755,192 KB before the rewrite and still 5,755,192 KB right after it. A fresh clone is now a 28 MiB pack.
   - The old commits are still reachable through 48 hidden pull request refs: refs/pull/1/head through refs/pull/48/head (PR numbers 1-48, all merged or closed before the rewrite; PR 49 is new and is on the rewritten history).
   - Please remove the pre-rewrite objects that are no longer reachable from any branch or tag, including those held only by refs/pull/1..48, and run a server-side garbage collection. If the refs cannot be dropped, tell us whether the pull requests must be deleted and recreated.

2) ericmacdougall/bugtracker (optional, lower priority)
   - History was rewritten on 2026-11-05; on 2026-11-08 one tag and 818 stale branches were deleted, and on 2026-11-09 we deleted 1,293 hidden refs we were able to delete (archive, backup and gorunner namespaces older than 14 days). GitHub now reports about 886,928 KB, which is under our 1 GB target, so this repository no longer blocks us.
   - About 1,264 refs/pull/* refs and 298 refs/gorunner/* refs still pin pre-rewrite objects (a mirror held offline is about 3.2 GB). If you can purge unreachable pre-rewrite objects, it would shrink the server copy further. Example: commit 3a15b41cd4c1 still returns its tree through the REST API.

Request, both repositories:
1. Remove objects not reachable from any branch or tag, including those held only by the hidden refs above, and run garbage collection.
2. Tell us whether hidden refs/pull/* refs can be pruned, or whether the pull requests must be deleted and recreated.
3. Confirm when cached views (commit and blob URLs) for the removed objects stop resolving.

No sensitive data is believed to be in the objects; the goal is repository size and hygiene. Verified full-mirror bundles are held offline for both repositories, so no data will be lost.

Thank you.
