#!/usr/bin/env bash
# goodqa#14903 S3a release of 30c7e41b20bb (run on dev2 after main GO, waiver mgw-d946559c1828). Same pattern as ~/ship15096.sh.
# Rollback target e13e368802b3. Migration 14911 is expand-only; rw-ship exits 8 rather than auto-rollback after it applies.
set -u
S=30c7e41b20bbed1f46a3d078aaaf35e74feba72d
E=/home/eric/release-evidence/goodqa-14903-30c7e41
R=goodqa-14903-qac-run-reports
RW=/home/eric/repos/harness/config/goodqa-release/bin/rw-ship.sh
KEY=$(sha256sum "$RW" | cut -d' ' -f1)
J=$E/smoke-30c7e41b20bb.json
[ -s "$J" ] || { echo MISSING_SMOKE_RECEIPT; exit 3; }
cd /home/eric/repos/bugtracker || exit 2
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$S" ] || { echo "TIP_MOVED $(git rev-parse origin/main)"; exit 5; }
cd /home/eric/repos/harness || exit 2
python3 bin/rw register-release "$R" "$S" --runtime /home/eric/repos/harness --repo /home/eric/repos/bugtracker --source-proof "$J" --proof-sha256 "$(sha256sum "$J" | cut -d' ' -f1)" 2>&1 | tail -3 | cut -c1-300
U=gq-ship-14903-$(date -u +%H%M%S)
echo "$U" > /home/eric/w14903-unit
systemd-run --user --collect --no-block --unit="$U" --service-type=oneshot --working-directory=/home/eric/repos/harness \
  -p TimeoutStartSec=60min -p KillMode=control-group -p UMask=0077 \
  -E HOME=/home/eric -E PATH=/home/eric/.local/bin:/usr/local/bin:/usr/bin:/bin -E RW_LANE_ROOT=/home/eric/repos/harness \
  -E RW_SHIP_SMOKE="$J" -E DEPLOY_TARGET=selfhost -E SELFHOST_APP=ubuntu@107.181.240.13 -E SELFHOST_DIR=/opt/goodqa/infra/selfhost/app \
  /usr/bin/python3 -I -B /home/eric/repos/harness/bin/rw exec-main-push-env --keyed "$RW" "$KEY" \
  -- /usr/bin/bash "$RW" "$R" "$S" "goodqa 14903 QAC S3a run reports dark with migration 14911, invite refusals, plus 1297 1298 1299 1300 1302" 2>&1 | tail -1
echo "unit=$U"
