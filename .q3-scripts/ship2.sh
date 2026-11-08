#!/usr/bin/env bash
# Runs on t2-dev. Ship candidate 2: origin/main + S3a (bf98467080..9560780be647) + privacy fix e8868c64d714,
# branch claude/qac-q3-s3-ship2 in ~/wt/q3-ship2; node_modules reused from ~/wt/q3-s3a-ship (same lockfile).
# Then tsc gate (compared to base errors) and focused + regression vitest files. Logs ~/wt/aab3-ship2.*.log
set -u
R=$HOME/repos/bugtracker; T=$HOME/wt/q3-ship2; S=$HOME/wt/q3-s3a-ship; L=$HOME/wt/aab3-ship2
cd "$R" && git fetch -q origin || exit 2
BASE=$(git rev-parse origin/main); echo "BASE $BASE"
[ -d "$T" ] || git worktree add -q -b claude/qac-q3-s3-ship2 "$T" "$BASE" || exit 2
cd "$T" || exit 2
if [ "$(git rev-parse HEAD)" = "$BASE" ]; then
  # Two separate picks: "A..B C" would walk C's ancestors too.
  git -c user.name="Eric MacDougall" -c user.email="eric@Mac-2.lan" cherry-pick -x bf98467080..9560780be6471a0a4588444cda6c2e2b48650212 >/dev/null || { echo CHERRY_PICK_FAILED; git status --short | head; exit 3; }
  git -c user.name="Eric MacDougall" -c user.email="eric@Mac-2.lan" cherry-pick -x e8868c64d7144881ea6a73df21d574aa3c220e26 >/dev/null || { echo CHERRY_PICK_FAILED; git status --short | head; exit 3; }
fi
cd "$T" || exit 2
git diff --quiet "$BASE" c6bb4238161bed2a83b74fb10382734ee224566b -- pnpm-lock.yaml && echo LOCK_SAME || { echo LOCK_DIFFERS; exit 4; }
( cd "$S" && find . -name node_modules -type d -prune -not -path "*/node_modules/*" ) | while read -r d; do
  mkdir -p "$(dirname "$T/$d")"; [ -e "$T/$d" ] || cp -a "$S/$d" "$T/$d"
done
echo "HEAD $(git rev-parse HEAD) TREE $(git rev-parse HEAD^{tree})"
git push -q origin claude/qac-q3-s3-ship2 2>&1 | grep -v '^remote:' | tail -1
bash "$HOME/wt/aab3-tsc-gate.sh" "$T" "$L.tsc.log"; grep "error TS" "$L.tsc.log"
for f in test/qac-run-reports-s3a.test.ts test/qac-ai-thread-invite-link.test.ts test/qac-workflow-drafts-s1.test.ts test/qac-workflow-drafts-s2.test.ts \
         test/automations-waits-drafts.test.ts test/automation-schedule-trigger.test.ts test/commander-actions.test.ts \
         test/commander-history-sharing.test.ts test/invite-link-authz.test.ts test/invite-link-creator-authority-project-channel.test.ts \
         test/invite-link-race.test.ts test/invite-link-old-client-contract.test.ts; do
  b=$(basename "$f" .test.ts)
  timeout 1500 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-ship2-$b" --lane qacq3 --ttl 1600 -- \
    pnpm --filter @bugtracker/api exec vitest run "$f" > "$L.$b.log" 2>&1
  rc=$?; echo "$b rc=$rc $(sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ +Tests ' | tr -s ' ')"
  [ $rc = 0 ] || sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ FAIL ' | head -6 | cut -c1-220
done
timeout 900 pnpm --filter @bugtracker/web exec vitest run src/components/messaging/channel-header-words.test.tsx src/components/messaging/conversation-header-responsive.test.tsx src/components/messaging/add-people-dialog.test.tsx > "$L.web.log" 2>&1
echo "web rc=$? $(sed 's/\x1b\[[0-9;]*m//g' "$L.web.log" | grep -E '^ +Tests ' | tr -s ' ')"
echo "PORCELAIN $(git status --porcelain | wc -l)"
echo SHIP2_END
