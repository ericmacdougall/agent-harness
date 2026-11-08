#!/usr/bin/env bash
# Runs on t2-dev. New branch with the same tree as gated ship2 7a459f86, without the "cherry picked from" lines that the
# commit policy refuses after trailers. Published ship2 is left alone (no rewrite). Stops unless the tree is identical.
set -u
BASE=c6bb4238161bed2a83b74fb10382734ee224566b
WANT_TREE=d41096637ea8187badeff246d2d9830e7dec734f
ID=(-c user.name="Eric MacDougall" -c user.email="eric@Mac-2.lan")
cd "$HOME/wt/q3-ship2" || exit 2
[ -z "$(git status --porcelain)" ] || { echo DIRTY; exit 2; }
git switch -q -c claude/qac-q3-s3-ship3 "$BASE" || exit 2
git "${ID[@]}" cherry-pick bf98467080..9560780be6471a0a4588444cda6c2e2b48650212 >/dev/null || { echo PICK_FAILED_1; git status --short | head; exit 3; }
git "${ID[@]}" cherry-pick e8868c64d7144881ea6a73df21d574aa3c220e26 >/dev/null || { echo PICK_FAILED_2; git status --short | head; exit 3; }
git "${ID[@]}" cherry-pick e27659514951daa6bc1aefa882b27eb525a71bba >/dev/null || { echo PICK_FAILED_3; git status --short | head; exit 3; }
TREE=$(git rev-parse 'HEAD^{tree}'); echo "HEAD $(git rev-parse HEAD) TREE $TREE COUNT $(git rev-list --count "$BASE"..HEAD)"
[ "$TREE" = "$WANT_TREE" ] || { echo TREE_MISMATCH; exit 4; }
git log --format='%h %s' "$BASE"..HEAD | cut -c1-90
python3 "$HOME/.claude/hooks/commit_policy.py" check-range --repo . --base "$BASE" --head HEAD 2>&1 | tail -20
git push -q origin claude/qac-q3-s3-ship3 2>&1 | grep -v '^remote:' | tail -1
echo "REMOTE $(git ls-remote origin refs/heads/claude/qac-q3-s3-ship3 | cut -f1)"
echo SHIP3_END
