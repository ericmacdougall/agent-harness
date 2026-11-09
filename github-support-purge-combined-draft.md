DRAFT - NOT SENT. For the user to review and submit. Prepared by owner ab8a7d1b, 2026-11-09 (goodqa#14977). Covers t2-course only; bugtracker was left out because GitHub now reports it under 1 GB (886,928 KB). Supersedes github-support-purge-draft.md.

To: GitHub Support (Contact Support > Repository > "Remove cached/dangling objects")
Account: ericmacdougall
Repository: ericmacdougall/t2-course (private)

Subject: Request to garbage-collect unreachable objects and purge hidden pull refs after a history rewrite

Hello,

We rewrote the history of ericmacdougall/t2-course to remove large media files. The size GitHub reports stays high because the old objects remain reachable only through hidden pull request refs that we cannot delete ourselves.

- 2026-11-09: main was force-pushed from c68f57e5a8fa0a956da720e876b4ad3d002fd365 to 72af7adf736190dba58a042c248f488a8f1ad626. The rewrite removed about 6.2 GB of audio and video (public/audio, public/engineering-videos, public/data-audio, power-user/public/audio; 38,218 files, now stored in object storage).
- GitHub reported 5,755,192 KB before the rewrite and still 5,755,192 KB right after it. A fresh clone is now a 28 MiB pack.
- The old commits are still reachable through 48 hidden pull request refs: refs/pull/1/head through refs/pull/48/head (PR numbers 1-48, merged or closed before the rewrite; later pull requests are on the rewritten history).

Request:
1. Remove the pre-rewrite objects that are no longer reachable from any branch or tag, including those held only by refs/pull/1 to refs/pull/48, and run a server-side garbage collection.
2. If those refs cannot be dropped, tell us whether the pull requests must be deleted and recreated.
3. Confirm when cached views (commit and blob URLs) for the removed objects stop resolving.

No sensitive data is believed to be in the objects; the goal is repository size and hygiene. A verified full-mirror bundle of the pre-rewrite repository is held offline, so no data will be lost.

Thank you.
