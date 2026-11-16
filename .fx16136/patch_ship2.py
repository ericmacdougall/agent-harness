"""goodqa#16136 D1: detect the guard's GUARD_HELD_ENV support by behaviour (run after patch_ship.py). python3 patch_ship2.py FILE"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:90])
    t = t.replace(old, new)


rep('''  if held transcribe; then
    if grep -q GUARD_HELD_ENV "$RD/src/apps/job-dispatcher/src/create-guard-main.ts" 2>/dev/null; then
      GUARDARGS=" --guard-hold TRANSCODER_MODE=transcribe"; HOLDNOTE="$HOLDNOTE transcribe(guard)"
    else
      HOLDNOTE="$HOLDNOTE transcode(whole image)"; say "transcode held: guard lacks GUARD_HELD_ENV in this release, so the whole transcode image stays on its current pin"
    fi
  fi
''', '''  # transcribe held: transcode is built provisionally; after the build, the built dispatcher image's guard is probed
  # (AC-17/D1: by behaviour, never by source text). Only a guard that implements GUARD_HELD_ENV refuses to start on a
  # malformed value; any other outcome holds the whole transcode image instead.
''')
rep('''    if held "$J" || { [ "$J" = transcode ] && held transcribe && [ -z "$GUARDARGS" ]; }; then''',
    '''    if held "$J"; then''')
rep('''  rm -rf "$RD/src" "$RD/tmp"
''', '''  if held transcribe; then
    timeout 60 docker run --rm --network none --read-only --tmpfs /tmp --entrypoint node_modules/.bin/tsx -e GUARD_ENV=dev \\
         -e JOB_IMAGE_SCAN=goodqa-scan@sha256:0000000000000000000000000000000000000000000000000000000000000000 \\
         -e GUARD_HELD_ENV=TRANSCODER_MODE "$IMG_DISP" src/create-guard-main.ts > "$RD/guard-probe.txt" 2>&1; prc=$?
    if [ "$prc" != 0 ] && [ "$prc" != 124 ] && grep -q 'GUARD_HELD_ENV must be' "$RD/guard-probe.txt"; then
      GUARDARGS=" --guard-hold TRANSCODER_MODE=transcribe"; HOLDNOTE="$HOLDNOTE transcribe(guard)"
      say "guard probe: the built guard refuses a malformed GUARD_HELD_ENV (rc=$prc), so transcription is held at the guard and MP4 runs"
    else
      HOLDNOTE="$HOLDNOTE transcode(whole image)"
      say "transcode held: guard lacks GUARD_HELD_ENV in this release (probe rc=$prc), so the whole transcode image stays on its current pin"
      NJI=(); NJK=()
      for i in "${!JOBIMGS[@]}"; do [ "${JOBKEYS[$i]}" = JOB_IMAGE_TRANSCODE ] && { docker image rm "${JOBIMGS[$i]}" >/dev/null 2>&1; continue; }
        NJI+=("${JOBIMGS[$i]}"); NJK+=("${JOBKEYS[$i]}"); done
      JOBIMGS=("${NJI[@]}"); JOBKEYS=("${NJK[@]}"); HOLDARGS="$HOLDARGS --job-hold JOB_IMAGE_TRANSCODE"
    fi
  fi
  rm -rf "$RD/src" "$RD/tmp"
''')
rep('''    [ "$JOK" = OK ] || sh_fail_rollback "job image refs do not resolve after the switch ($JOK)"
  fi
''', '''    [ "$JOK" = OK ] || sh_fail_rollback "job image refs do not resolve after the switch ($JOK)"
  fi
  if [ -n "$GUARDARGS" ]; then        # D1: the running guard itself must say it enforces the hold
    GH=""; for i in 1 2 3 4 5 6; do GH=$(vmctl guard-log 2>/dev/null | grep -m1 '^{'); case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) break;; esac; sleep 2; done
    say "guard startup log: $(printf '%s' "$GH" | cut -c1-200)"
    case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) ;; *) sh_fail_rollback "the running guard does not report the transcription hold";; esac
  fi
''')
open(p, 'w').write(t)
print('patched ship D1')
