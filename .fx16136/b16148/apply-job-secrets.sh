#!/bin/bash
# apply-job-secrets.sh -- goodqa#16148 spec v4 AC-11 (lead rulings R3, R4). Runs on the release runner.
#
#   RW_LANE_ROOT=<lane root> infra/selfhost/app/apply-job-secrets.sh --check | apply | restore
#
# Under the one deploy lock rw-ship.sh takes (<lane root>/locks/gq-promote.lock; flock -n, exit 75 when held) and
# never while a release is in flight (gq-promote.inflight.json present, exit 75), it streams two scripts to the app
# VM as root, exactly as rw-ship streams selfhost-ctl.py (nothing is installed on the VM):
#   1. derive-job-secrets.py: creates the goodqa-jobsecret group, the 0711 secrets dir and the 0440 file from
#      api.env. Anything but `written` or `unchanged` stops here with nothing else applied (exit 2).
#   2. apply-job-secrets-host.py: the job-dispatcher mount and group_add in the live compose.yaml and the
#      JOB_ENVFILE key line in dispatcher.env (backups, validation, marked-line restore).
# A mutating run bumps the deploy epoch, so an rw-ship run that started earlier loses its authority (fencing).
# Containers are not recreated: the next release's dispatcher recreate picks the mount up.
# Output: the VM's status lines (names and status only; no value is ever read here). APPLY_SSH overrides ssh (tests).
set -uo pipefail
LOCK_REL=locks/gq-promote.lock
HERE="$(cd "$(dirname "$0")" && pwd)"
say(){ printf 'apply-job-secrets: %s\n' "$*"; }
MODE="${1:-}"
case "$MODE" in --check|apply|restore) ;; *) say "REFUSED usage: apply-job-secrets.sh --check|apply|restore"; exit 2;; esac
S="${RW_LANE_ROOT:-}"
[ -n "$S" ] && [ -d "$S" ] || { say "REFUSED: RW_LANE_ROOT is not set to the lane root"; exit 2; }
case "$(realpath -m "$S")/" in */.scratch/*|/tmp/*) [ "${APPLY_TEST_MODE:-}" = 1 ] || { say "REFUSED: runner root must be permanent"; exit 2; };; esac
shconf(){ sed -n "s/^$1=//p" "$S/biz/release-waves/ship.conf" 2>/dev/null | head -1; }
APP="$(shconf SELFHOST_APP)"; DIR="$(shconf SELFHOST_DIR)"; ENVD="$(shconf SELFHOST_ENV_DIR)"
DIR="${DIR:-/opt/goodqa/infra/selfhost/app}"; ENVD="${ENVD:-/etc/goodqa}"
[ -n "$APP" ] || { say "REFUSED: SELFHOST_APP is not set in biz/release-waves/ship.conf"; exit 2; }
SSH="${APPLY_SSH:-ssh}"
LOCKF="$S/$LOCK_REL"; EPOCHF="${LOCKF%.lock}.epoch"; INFL="${LOCKF%.lock}.inflight.json"; HOLDER="${LOCKF%.lock}.holder"
mkdir -p "$(dirname "$LOCKF")"
exec 8>>"$LOCKF" || { say "REFUSED: cannot open the deploy lock $LOCKF"; exit 2; }
flock -n 8 || { say "REFUSED: the deploy lock is held ($(head -c 200 "$HOLDER" 2>/dev/null | tr '\n' ' ')): nothing done"; exit 75; }
[ -e "$INFL" ] && { say "REFUSED: a release is in flight ($INFL): nothing done"; exit 75; }
if [ "$MODE" != --check ]; then
  E0=$(tr -dc 0-9 < "$EPOCHF" 2>/dev/null); EPOCH=$(( ${E0:-0} + 1 ))
  printf '%s\n' "$EPOCH" > "$EPOCHF.$$" && mv -f "$EPOCHF.$$" "$EPOCHF"
  printf 'apply-job-secrets pid=%s host=%s started=%s epoch=%s what=%s\n' "$$" "$(hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EPOCH" "$MODE" > "$HOLDER"
  trap 'grep -q "^apply-job-secrets pid=$$ " "$HOLDER" 2>/dev/null && rm -f "$HOLDER"' EXIT
fi
vm(){ "$SSH" -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$APP" "$1" < "$2"; }
case "$MODE" in
  --check)
    vm "sudo python3 -I - --check" "$HERE/derive-job-secrets.py"
    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q --check' "$DIR" "$ENVD"
    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
  apply)
    OUT=$(vm "sudo python3 -I -" "$HERE/derive-job-secrets.py" 2>/dev/null); RC=$?
    printf '%s\n' "$OUT" | head -3
    case "$RC:$OUT" in
      "0:job secret github-app-private-key: written"|"0:job secret github-app-private-key: unchanged") ;;
      *) say "REFUSED: derive did not report written or unchanged (rc $RC): nothing else applied"; exit 2;;
    esac
    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q apply --stamp %q' "$DIR" "$ENVD" "$(date -u +%Y%m%dT%H%M%SZ)"
    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
  restore)
    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q restore' "$DIR" "$ENVD"
    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
esac
