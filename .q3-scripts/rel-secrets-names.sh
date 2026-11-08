#!/usr/bin/env bash
# Existence, mode and owner of the release credentials only. Never reads or prints their contents. Public key fingerprints only.
cd "$HOME/repos/harness" || exit 2
echo "HOST $(hostname)"
OP=$(sed -n 's/^OPERATOR_KEY_FILE=//p' biz/release-waves/ship.conf 2>/dev/null | head -1)
echo "OPERATOR_KEY_FILE path: ${OP:-unset}"
for f in "$OP" "$HOME/.config/goodqa/rw-ship-main-push.env" "$HOME/.ssh/bugtracker-main-deploy" "$HOME/.ssh/bugtracker-main-deploy.pub" "$HOME/.ssh/config" \
  "$HOME/.config/goodqa/user-token" biz/release-waves/waves.db biz/release-waves/ship.conf; do
  [ -n "$f" ] || continue
  [ -e "$f" ] && echo "present $(stat -c '%a %U %s' "$f") $f" || echo "absent  $f"
done
[ -e "$HOME/.ssh/bugtracker-main-deploy.pub" ] && ssh-keygen -lf "$HOME/.ssh/bugtracker-main-deploy.pub" | cut -d' ' -f1-2
echo "SSH_APP $(ssh -o BatchMode=yes -o ConnectTimeout=8 ubuntu@107.181.240.13 'echo ok' 2>&1 | tail -1 | cut -c1-80)"
echo "SSH_PROXMOX $(ssh -o BatchMode=yes -o ConnectTimeout=8 root@100.83.24.47 'echo ok' 2>&1 | tail -1 | cut -c1-80)"
grep -n 'OPERATOR_KEY_FILE' config/goodqa-release/bin/rw-ship.sh | head -4 | cut -c1-170
echo "CTL_DIFF"; diff -q bin/selfhost-ctl.py config/goodqa-release/bin/selfhost-ctl.py; git log -1 --format='%h %cI' -- bin/selfhost-ctl.py
grep -n 'S=\|RW_LANE_ROOT' config/goodqa-release/bin/rw-runtime.sh | head -8 | cut -c1-170
echo "RELEASE_BINDING_NAMES"; cut -c1-120 config/goodqa-release/bin/RELEASE_BINDING | head -8
