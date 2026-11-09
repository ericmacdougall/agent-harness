#!/usr/bin/env bash
# t2-dev release kit. Usage: ship.sh <release name> <full sha> <evidence dir name> "<description>". DEPLOYS TO PRODUCTION.
# Same unit as the dev2 ships (~/ship15096.sh on dev2). Refuses unless the sha is the origin/main tip and the smoke receipt exists.
# Needs ~/.config/goodqa/rw-ship-main-push.env with a deploy key registered on GitHub.
set -u
R=${1:?release name}; S=${2:?full sha}; E=$HOME/release-evidence/${3:?evidence dir name}; D=${4:?description}
H=$HOME/repos/harness; RW=$H/config/goodqa-release/bin/rw-ship.sh; J=$E/smoke-${S:0:12}.json
[[ "$S" =~ ^[0-9a-f]{40}$ ]] || { echo NOT_A_FULL_SHA; exit 2; }
[ -s "$J" ] || { echo MISSING_SMOKE_RECEIPT; exit 3; }
[ -r "$HOME/.config/goodqa/rw-ship-main-push.env" ] || { echo NO_MAIN_PUSH_ENV; exit 4; }
KEY=$(sha256sum "$RW" | cut -d' ' -f1)
cd "$HOME/repos/bugtracker" || exit 2
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$S" ] || { echo "TIP_MOVED $(git rev-parse origin/main)"; exit 5; }
cd "$H" || exit 2
python3 bin/rw register-release "$R" "$S" --runtime "$H" --repo "$HOME/repos/bugtracker" --source-proof "$J" --proof-sha256 "$(sha256sum "$J" | cut -d' ' -f1)" 2>&1 | tail -3 | cut -c1-300
U=gq-ship-$(date -u +%m%d-%H%M%S)
echo "$U" > "$HOME/release-last-unit"
systemd-run --user --collect --no-block --unit="$U" --service-type=oneshot --working-directory="$H" \
  -p TimeoutStartSec=60min -p KillMode=control-group -p UMask=0077 \
  -E HOME="$HOME" -E PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" -E RW_LANE_ROOT="$H" \
  -E RW_SHIP_SMOKE="$J" -E DEPLOY_TARGET=selfhost -E SELFHOST_APP=ubuntu@107.181.240.13 -E SELFHOST_DIR=/opt/goodqa/infra/selfhost/app \
  /usr/bin/sg docker -c "$(printf '%q ' /usr/bin/python3 -I -B "$H/bin/rw" exec-main-push-env --keyed "$RW" "$KEY" \
  -- /usr/bin/bash "$RW" "$R" "$S" "$D")" 2>&1 | tail -1
# The systemd user manager on t2-dev started (Nov 5) before eric joined the docker group, so user units lack it and
# the promote build boundary cannot reach /var/run/docker.sock. sg applies eric's existing docker membership to this
# one unit; it grants nothing new (dev2 units had the group directly).
echo "unit=$U  watch: journalctl --user -u $U -f"
