#!/bin/bash
# on t2-dev: the push step. 1) force-push main only (lease on the old tip) 2) push chore/media-to-r2-v2 normally with the final media-sync.mjs 3) delete the old remote chore/media-to-r2
set -u
cd /home/eric/gq-branch-clean/tcr || exit 1
OLD=c68f57e5a8fa0a956da720e876b4ad3d002fd365
cd mirror.git
H=$(git rev-parse main)
echo "NEW_MAIN $H"
[ "$H" = "72af7adf736190dba58a042c248f488a8f1ad626" ] || { echo "UNEXPECTED_NEW_MAIN stop"; exit 2; }
REMOTE_MAIN=$(git ls-remote git@github.com:ericmacdougall/t2-course.git refs/heads/main | cut -f1)
[ "$REMOTE_MAIN" = "$OLD" ] || { echo "REMOTE_MAIN_MOVED $REMOTE_MAIN stop"; exit 2; }
git push --force-with-lease="refs/heads/main:${OLD}" git@github.com:ericmacdougall/t2-course.git "${H}:refs/heads/main" 2>&1 | tail -4
echo "AFTER_PUSH remote main: $(git ls-remote git@github.com:ericmacdougall/t2-course.git refs/heads/main | cut -c1-12)"
cd ../work
git config user.name "Claude Sonnet 5.5"; git config user.email noreply@anthropic.com
cp /home/eric/gq-branch-clean/media-sync.mjs scripts/media-sync.mjs
git add scripts/media-sync.mjs
git commit -q -m "fix(media): delta-review fixes for tar listing and prefix check" -m "Why: the delta red-team found push refuses new files when a name has escapes, a prefix check without trailing slash, and push crashing without a cache dir." -m "What: tar listing uses literal quoting, member prefix check requires a trailing slash, push creates the cache dir." -m "Testing: \`node --check scripts/media-sync.mjs\` -> syntax ok, exit 0." -m "Refs: GoodQA #14977"
git log --oneline -4
git push git@github.com:ericmacdougall/t2-course.git chore/media-to-r2-v2 2>&1 | tail -2
git push git@github.com:ericmacdougall/t2-course.git :refs/heads/chore/media-to-r2 2>&1 | tail -2
echo PUSH_DONE
