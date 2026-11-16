"""goodqa#16148 spec v4 AC-8: the rw-ship unhold gate. usage: python3 rwship-patch.py <rw-ship.sh>"""
import sys

p = sys.argv[1]
t = open(p).read()


def rep(old, new):
    global t
    n = t.count(old)
    assert n == 1, (n, old[:90])
    t = t.replace(old, new)


# 1. helpers, in the self-host block after sh_fail_rollback
rep('''    dbx "$NAME" deploy-unverified "${v:--}" "$1 and the rollback was not confirmed (live ${v:-unreadable}); run $RD"; exit 8; }
fi
''', r'''    dbx "$NAME" deploy-unverified "${v:--}" "$1 and the rollback was not confirmed (live ${v:-unreadable}); run $RD"; exit 8; }
  # JOB-SECRET UNHOLD GATE (goodqa#16148 spec v4 AC-8). intelligence-worker is released only when (a) derive-job-secrets.py,
  # streamed from the BOUND release commit (never this working tree) and only when its blob is the derive-blob the release
  # binding records, wrote or kept the key file; (b) dispatcher.env names it exactly once; (P3) a hardened trial boot of THIS
  # dispatcher image reads a fixed fake key ok; and after the switch (c) the RECREATED dispatcher logged the key ok. Only
  # status words cross: no value, no log text, no derive reason.
  JS_DERIVE_PATH=infra/selfhost/app/derive-job-secrets.py
  js_derive(){ local c b got out rc
    case "${BWHY:-}" in OK*) ;; *) echo REFUSED-unbound; return 0;; esac
    c=$(sed -n 's/^commit \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1)
    b=$(sed -n 's/^derive-blob \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1)
    [ -n "$c" ] && [ -n "$b" ] || { echo REFUSED-no-derive-blob; return 0; }
    got=$(git -C "$REPO" rev-parse -q --verify "$c:$JS_DERIVE_PATH" 2>/dev/null)
    [ -n "$got" ] || { echo REFUSED-not-in-bound-commit; return 0; }
    [ "$got" = "$b" ] || { echo REFUSED-blob-mismatch; return 0; }
    out=$(set -o pipefail; git -C "$REPO" cat-file blob "$b" | timeout 120 ssh -o ConnectTimeout=15 -o BatchMode=yes "$SH_APP" 'sudo python3 -I -' 2>/dev/null); rc=$?
    case "$rc:$out" in
      "0:job secret github-app-private-key: written") echo written;;
      "0:job secret github-app-private-key: unchanged") echo unchanged;;
      "2:job secret github-app-private-key: REFUSED "*) case "$out" in *$'\n'*|*$'\r'*) echo garbled;; *) echo REFUSED-derive;; esac;;
      124:*|255:*) echo unreachable;;
      *) echo garbled;; esac; }
  js_blob(){ sed -n 's/^derive-blob \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1; }
  js_refuse(){ say "REFUSED (job-secret unhold gate, exit 2): $1. intelligence-worker is not released; nothing migrated or switched"
    dbx "$NAME" deploy-failed "$BEFORE" "job-secret unhold gate: $1; nothing went live; run $RD"; exit 2; }
  js_rehold(){ # js_rehold <stamp>: pin this release with intelligence-worker held, recreate ONLY the dispatcher and its guard
    local HJ="" k
    for k in "${!JOBKEYS[@]}"; do
      if [ "${JOBKEYS[$k]}" = JOB_IMAGE_INTELLIGENCE_WORKER ]; then HJ="$HJ --job-hold ${JOBKEYS[$k]}"; else HJ="$HJ --job-image ${JOBKEYS[$k]}=${JOBREFS[$k]}"; fi
    done
    vmctl pin --stamp "$1" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP"$HJ$HOLDARGS$GUARDARGS > "$RD/pin-$1.txt" 2>&1 || return 1
    NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin-$1.txt")" fp); NEW_WEB=$NEW_API
    vmctl up-dispatcher --timeout "$SH_UP_TIMEOUT" > "$RD/up-$1.txt" 2>&1 && grep -q '^UP_OK' "$RD/up-$1.txt"; }
  js_nohold(){ KEEP=1; say "HOLD NOT RE-APPLIED (exit 8): $1. intelligence-worker may be released without a verified key. A person must hold it now: SELFHOST_JOB_HOLD=intelligence-worker,transcribe in ship.conf and re-run, or selfhost-ctl.py pin ... --job-hold JOB_IMAGE_INTELLIGENCE_WORKER then up-dispatcher (run $RD)"
    dbx "$NAME" deploy-unverified "$(live_sha)" "$1; HOLD NOT RE-APPLIED: intelligence-worker released without a verified GITHUB_APP_PRIVATE_KEY file; run $RD"; exit 8; }
  js_hold_fail(){ # js_hold_fail <why>: gate (c) failed after the switch. Re-hold FIRST (dispatcher only), then roll back as usual
    say "$1: re-holding intelligence-worker (job-dispatcher and its guard only) before anything else"
    rb_guard "re-holding intelligence-worker ($1)" api || lost "re-hold refused ($1); intelligence-worker is NOT re-held"
    infl rehold
    js_rehold "${STAMP}h" || js_nohold "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
    say "intelligence-worker re-held (stack ${NEW_API:-unreadable})"
    [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1 (intelligence-worker was re-held)"
    rb_guard "rolling back ($1)" api || lost "rollback refused ($1); intelligence-worker is re-held"
    infl rollback
    vmctl restore --stamp "${STAMP}h" > "$RD/restore-${STAMP}h.txt" 2>&1 || {
      KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1; intelligence-worker is re-held at this release, but the re-hold did not restore. A person must look now: $RD/rollback.json"
      dbx "$NAME" deploy-unverified "$(live_sha)" "$1; intelligence-worker re-held, rollback not done (re-hold restore failed); run $RD"; exit 8; }
    NEW_API=$PIN_FP; NEW_WEB=$PIN_FP
    if ! vmctl restore --stamp "$STAMP" > "$RD/restore.txt" 2>&1; then
      head -3 "$RD/restore.txt" | cut -c1-300 | tee -a "$LOG"
      js_rehold "${STAMP}h2" || js_nohold "$1, then the rollback did not restore and the second re-hold failed"
      KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1; the previous stack did not restore, intelligence-worker is re-held at this release. A person must look now: $RD/rollback.json"
      dbx "$NAME" deploy-unverified "$(live_sha)" "$1; intelligence-worker re-held, rollback not done; run $RD"; exit 8
    fi
    local v="" rc; vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up-rollback.txt" 2>&1; rc=$?
    say "rollback up: $(grep -m1 '^UP_' "$RD/up-rollback.txt" | cut -c1-300) (rc=$rc)"
    if [ $rc = 0 ]; then for i in $(seq 1 18); do v=$(live_sha); [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && break; sleep 10; done
      if [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ]; then say "ROLLED BACK: live API is $v again (the previous pins, intelligence-worker as it was)"; dbx "$NAME" deploy-failed "$v" "$1; intelligence-worker re-held, then rolled back to the previous stack $RB_API; run $RD"; exit 5; fi; fi
    KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1, then the restore did not come back healthy at $BEFORE (live API ${v:-unreadable}). A person must look now: $RD/rollback.json"
    dbx "$NAME" deploy-unverified "${v:--}" "$1 and the rollback was not confirmed (live ${v:-unreadable}); run $RD"; exit 8; }
fi
''')

# 2. pre-switch gates (a), (b), trial: after the job refs are known, before the audit record and the migrations
rep('''    JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
  done
  mkdir -p audit/selfhost-deploys
''', r'''    JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
  done
  DISP_PRE=""
  if held intelligence-worker; then
    if [ -n "$RBIND" ]; then JSD=$(js_derive); else JSD=skipped-unbound; fi
    say "job secret (intelligence-worker held, not gated): derive $JSD"; JSGATE="held derive=$JSD"
  else
    say "job secret gate: intelligence-worker is released by this run; derive blob $(js_blob | cut -c1-12)"
    JSD=$(js_derive); say "job secret gate (a) derive from the bound commit: $JSD"
    case "$JSD" in written|unchanged) ;; *) js_refuse "(a) derive-job-secrets.py did not write or keep the key file ($JSD)";; esac
    JSK=$(jget "$(vmctl envfile-key 2>/dev/null | grep -m1 '^{')" count)
    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}"
    [ "$JSK" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), not once"
    DREF=goodqa-job-dispatcher@$(python3 -c 'import json,sys
try: print(json.loads(sys.argv[1]).get(sys.argv[2]) or "")
except Exception: print("")' "$REMOTEIDS" "$IMG_DISP")
    JST=$(jget "$(vmctl trial-boot --image "$DREF" --stamp "$STAMP" 2>/dev/null | grep -m1 '^{')" status)
    say "job secret gate: trial boot of $DREF: ${JST:-unreadable}"
    [ "$JST" = ok ] || js_refuse "the trial boot of the new dispatcher image did not read the key file (${JST:-unreadable})"
    DISP_PRE=$(jget "$(vmctl disp-boot 2>/dev/null | grep -m1 '^{')" id)
    JSGATE="released derive=$JSD key-lines=1 trial=ok"
  fi
  mkdir -p audit/selfhost-deploys
''')
rep('''"$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/''', '''"$SH_BEFORE" "$HOLDNOTE" "$JSGATE" > "audit/selfhost-deploys/''')
rep('''name, sha, stamp, host, ids, before, holds = sys.argv[1:8]''', '''name, sha, stamp, host, ids, before, holds, jsgate = sys.argv[1:9]''')
rep(''''jobHolds': holds.split()}''', ''''jobHolds': holds.split(), 'jobSecretGate': jsgate}''')

# 3. the fingerprint of this run's own pin, for the re-hold rollback
rep('''  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; infl switch-api
''', '''  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; PIN_FP=$NEW_API; infl switch-api
''')

# 4. gate (c): after the guard check, before the version check
rep('''    case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) ;; *) sh_fail_rollback "the running guard does not report the transcription hold";; esac
  fi
''', '''    case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) ;; *) sh_fail_rollback "the running guard does not report the transcription hold";; esac
  fi
  if ! held intelligence-worker; then   # goodqa#16148 AC-8 (c): the RECREATED dispatcher (a new container) logged the key ok
    DID=""; DST=""; for i in 1 2 3 4 5 6; do DB=$(vmctl disp-boot 2>/dev/null | grep -m1 '^{'); DID=$(jget "$DB" id); DST=$(jget "$DB" status)
      [ -n "$DID" ] && [ "$DID" != "$DISP_PRE" ] && [ "$DST" = ok ] && break; sleep 5; done
    say "job secret gate (c) dispatcher boot line: ${DST:-unreadable} (container ${DID:0:12}, before the switch ${DISP_PRE:0:12})"
    if [ -z "$DID" ] || [ "$DID" = "$DISP_PRE" ]; then js_hold_fail "the job-dispatcher was not recreated by the switch (gate c)"; fi
    [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
  fi
''')
open(p, 'w').write(t)
print('patched')
