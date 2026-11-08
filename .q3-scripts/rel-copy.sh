#!/usr/bin/env bash
# dev2, one direction to t2-dev. No credentials are copied: only release records, the wave state, the epoch and small receipts.
# --ignore-existing keeps anything already on t2-dev. Three secret-shaped files of run 20261105T155628Z are left behind by name.
set -u
H=$HOME/repos/harness
cd "$H" || exit 2
flock -n locks/gq-promote.lock -c true || { echo LOCK_HELD_NOT_COPYING; exit 75; }
rsync -a --ignore-existing --stats \
  --exclude 'deploys/20261105T155628Z/migrate-dry.txt' --exclude 'deploys/20261105T155628Z/ship.log' --exclude 'deploys/20261105T155628Z/migrate-apply.txt' \
  biz/release-waves/ t2-dev:repos/harness/biz/release-waves/ 2>&1 | grep -E 'Number of regular files transferred|Total transferred file size|rsync error'
echo "WAVES_RC=$?"
# Epoch: dev2 value, so t2-dev continues above it. The lock file itself is local and empty.
ssh -o BatchMode=yes t2-dev 'mkdir -p ~/repos/harness/locks ~/sc ~/ipc ~/rw ~/release-evidence; : >> ~/repos/harness/locks/gq-promote.lock; chmod 600 ~/repos/harness/locks/gq-promote.lock'
rsync -a --ignore-existing locks/gq-promote.epoch t2-dev:repos/harness/locks/gq-promote.epoch
# Receipts only: the full 50G stays on dev2 (t2-dev has 39G free).
cd "$HOME/release-evidence" || exit 2
rsync -a --ignore-existing --prune-empty-dirs --max-size=5M --stats \
  --include '*/' --exclude 'node_modules/' --include 'smoke-*.json' --include 'smoke-*.head' --include 'smoke-*.log' --include 'smoke.sh' --exclude '*' \
  ./ t2-dev:release-evidence/ 2>&1 | grep -E 'Number of regular files transferred|Total transferred file size|rsync error'
echo "EVIDENCE_RC=$?"
# Verify the record that matters, byte for byte, without printing contents.
RD=biz/release-waves/deploys/20261108T213956Z
cd "$H" || exit 2
L=$(find "$RD" -type f -exec sha256sum {} + | sort -k2 | sha256sum | cut -c1-16)
R=$(ssh -o BatchMode=yes t2-dev "cd ~/repos/harness && find $RD -type f -exec sha256sum {} + | sort -k2 | sha256sum | cut -c1-16")
echo "RECORD_HASH dev2=$L t2=$R $([ "$L" = "$R" ] && echo SAME || echo DIFFERENT)"
L=$(sha256sum biz/release-waves/waves.db | cut -c1-16); R=$(ssh -o BatchMode=yes t2-dev 'sha256sum ~/repos/harness/biz/release-waves/waves.db | cut -c1-16')
echo "WAVES_DB dev2=$L t2=$R $([ "$L" = "$R" ] && echo SAME || echo DIFFERENT)"
echo "DEPLOYS dev2=$(ls biz/release-waves/deploys | wc -l) t2=$(ssh -o BatchMode=yes t2-dev 'ls ~/repos/harness/biz/release-waves/deploys | wc -l')"
echo "EPOCH dev2=$(cat locks/gq-promote.epoch) t2=$(ssh -o BatchMode=yes t2-dev 'cat ~/repos/harness/locks/gq-promote.epoch')"
echo "RECEIPTS t2=$(ssh -o BatchMode=yes t2-dev 'find ~/release-evidence -name "smoke-*.json" | wc -l') dev2=$(find ~/release-evidence -maxdepth 2 -name 'smoke-*.json' | wc -l)"
echo COPY_END
