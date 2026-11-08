#!/usr/bin/env bash
# dev2. Pre-copy checks: secret-shaped content by file path only (no matching text), sizes, and what rw-ship still needs.
cd "$HOME/repos/harness" || exit 2
P='gh[pousr]_[A-Za-z0-9]{20}|github_pat_|BEGIN [A-Z ]*PRIVATE KEY|gq_[A-Za-z0-9_]{20}|bt_[A-Za-z0-9_]{20}|goodqa_[A-Za-z0-9_]{20}|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}'
echo "SECRET_SHAPED_DEPLOYS"; grep -rlIE "$P" biz/release-waves 2>/dev/null | cut -c1-120 | head -20; echo "count $(grep -rlIE "$P" biz/release-waves 2>/dev/null | wc -l)"
echo "SECRET_SHAPED_EVIDENCE_SMALL"; find ~/release-evidence -type f -size -5M -not -path '*/node_modules/*' -print0 2>/dev/null | xargs -0 grep -lIE "$P" 2>/dev/null | cut -c1-120 | head -10
echo "SIZES"; find biz/release-waves -type f | wc -l; ls biz/release-waves | tr '\n' ' '; echo; ls biz/release-waves/deploys | wc -l
find ~/release-evidence -type f -size -5M -not -path '*/node_modules/*' -printf '%s\n' 2>/dev/null | python3 -c "import sys;v=[int(x) for x in sys.stdin];print('evidence under 5M, no node_modules: files',len(v),'MB',sum(v)//1048576)"
echo "CONF_SHA $(sha256sum biz/release-waves/ship.conf | cut -c1-16)"
echo "T2_ROUTE $(ssh -o BatchMode=yes -o ConnectTimeout=8 t2-dev 'hostname' 2>&1 | tail -1 | cut -c1-80)"
echo "GH_USE"; grep -nE '(^|[^a-zA-Z_./-])gh (pr|api|auth|run|repo)' config/goodqa-release/bin/rw-ship.sh bin/rw-rollback.sh | cut -c1-140 | head -8; grep -cE "'gh'|\"gh\"" bin/rw
echo "SSH_CONFIG_USE"; grep -n 'ssh/config' config/goodqa-release/bin/rw-ship.sh | cut -c1-170 | head -4
echo "HOLD"; grep -nE 'HOLD|hold file|ship\.hold|\.hold' config/goodqa-release/bin/rw-ship.sh | cut -c1-170 | head -8
echo "STATE_CMD"; grep -nE "def cmd_state|'state'|\"state\"" bin/selfhost-ctl.py | cut -c1-140 | head -6
echo "LOCK_HOLDER"; ls -la locks | cut -c1-90; cat locks/gq-promote.epoch 2>/dev/null; flock -n locks/gq-promote.lock -c 'echo LOCK_FREE' || echo LOCK_HELD
systemctl --user list-timers --no-legend 2>/dev/null | grep -iE 'rw|ship|release|wave|gq' | cut -c1-130 | head -8
systemctl --user list-units --no-legend 2>/dev/null | grep -iE 'gq-ship|rw-' | cut -c1-110 | head -8
crontab -l 2>/dev/null | grep -iE 'rw|ship|release' | cut -c1-140 | head -5
