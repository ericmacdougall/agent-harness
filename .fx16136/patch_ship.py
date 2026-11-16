"""Patch infra/release-harness/rw-ship.sh for goodqa#16136. python3 patch_ship.py FILE"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:90])
    t = t.replace(old, new)


rep('''SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 15)''', '''SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 30); SH_VM_MIN_FREE_GB=$(shconf SELFHOST_VM_MIN_FREE_GB 20)''')
rep('''$SH_MIN_FREE_GB G needed to build three images; nothing built or switched"''', '''$SH_MIN_FREE_GB G needed to build seven images; nothing built or switched"''')

# hold parsing: before anything is built (the promote api step builds too)
rep('''  TAG=${SHA:0:12}-$STAMP; IMG_API=goodqa-api:$TAG; IMG_WEB=goodqa-web:$TAG; IMG_DISP=goodqa-job-dispatcher:$TAG
''', '''  TAG=${SHA:0:12}-$STAMP; IMG_API=goodqa-api:$TAG; IMG_WEB=goodqa-web:$TAG; IMG_DISP=goodqa-job-dispatcher:$TAG
  # JOB IMAGES (goodqa#16136): the dispatcher's four job images are built and loaded with the app images and pinned as
  # goodqa-<job>@<image id on the VM>. SELFHOST_JOB_HOLD (default intelligence-worker,transcribe; "none" = no hold) keeps a
  # kind on its current pin (intelligence-worker), or holds transcription at the guard (GUARD_HELD_ENV) while MP4 runs.
  JHOLD=$(shconf SELFHOST_JOB_HOLD intelligence-worker,transcribe); [ "$JHOLD" = none ] && JHOLD=""
  for h in ${JHOLD//,/ }; do case "$h" in intelligence-worker|transcribe) ;; *)
    say "ABORT: SELFHOST_JOB_HOLD has an unknown kind '$(printf '%s' "$h" | tr -dc 'a-z0-9-' | cut -c1-40)' (allowed: intelligence-worker, transcribe, none); nothing built or switched"
    dbx "$NAME" deploy-failed "$BEFORE" "bad SELFHOST_JOB_HOLD; nothing went live; run $RD"; exit 2;; esac; done
  held(){ case ",$JHOLD," in *",$1,"*) return 0;; esac; return 1; }
''')

# job specs after the archive (the transcribe hold needs the release's own guard source)
rep('''  IFS='|' read -r -a BSARR <<< "$BSPECS"''', '''  JOBIMGS=(); JOBKEYS=(); HOLDARGS=""; GUARDARGS=""; HOLDNOTE=""
  if held transcribe; then
    if grep -q GUARD_HELD_ENV "$RD/src/apps/job-dispatcher/src/create-guard-main.ts" 2>/dev/null; then
      GUARDARGS=" --guard-hold TRANSCODER_MODE=transcribe"; HOLDNOTE="$HOLDNOTE transcribe(guard)"
    else
      HOLDNOTE="$HOLDNOTE transcode(whole image)"; say "transcode held: guard lacks GUARD_HELD_ENV in this release, so the whole transcode image stays on its current pin"
    fi
  fi
  for j in "scan apps/scan-worker/Dockerfile JOB_IMAGE_SCAN" "transcode apps/transcoder/Dockerfile JOB_IMAGE_TRANSCODE" \\
           "intelligence-worker apps/intelligence-worker/Dockerfile JOB_IMAGE_INTELLIGENCE_WORKER" \\
           "suggest-fix-worker apps/suggest-fix-worker/Dockerfile JOB_IMAGE_SUGGEST_FIX_WORKER"; do
    read -r J F K <<< "$j"
    if held "$J" || { [ "$J" = transcode ] && held transcribe && [ -z "$GUARDARGS" ]; }; then
      HOLDARGS="$HOLDARGS --job-hold $K"; [ "$J" = transcode ] || HOLDNOTE="$HOLDNOTE $J"; continue; fi
    BSPECS="$BSPECS|$J $F goodqa-$J:$TAG"; JOBIMGS+=("goodqa-$J:$TAG"); JOBKEYS+=("$K")
  done
  say "job images: building ${JOBIMGS[*]:-none}; held:${HOLDNOTE:- none}"
  IFS='|' read -r -a BSARR <<< "$BSPECS"''')

# VM free disk before the transfer; transfer, id check and record include the job images
rep('''  say "images to $SH_APP: docker save | docker load"
  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" | ''', '''  VMFREE=$(vmctl disk 2>/dev/null | grep -m1 '^{' | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
  [ "${VMFREE:-0}" -ge "$SH_VM_MIN_FREE_GB" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, $SH_VM_MIN_FREE_GB G needed before loading seven images; nothing switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${VMFREE:-?}G free on the VM (needs $SH_VM_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
  say "images to $SH_APP: docker save | docker load"
  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" | ''')
rep('''  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP"; do''', '''  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do''')
rep('''  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" 2>/dev/null | grep -m1 '^{')''',
    '''  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" 2>/dev/null | grep -m1 '^{')''')
rep('''  say "images on $SH_APP, ids match: $(printf '%s ' $LOCALIDS | cut -c1-400)"
''', '''  say "images on $SH_APP, ids match: $(printf '%s ' $LOCALIDS | cut -c1-400)"
  JOBARGS=""; JOBREFS=()
  for i in "${!JOBIMGS[@]}"; do
    ref=$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(sys.argv[2].split(":")[0] + "@" + r[sys.argv[2]])' "$REMOTEIDS" "${JOBIMGS[$i]}") || { say "ABORT: no VM image id for ${JOBIMGS[$i]}"; dbx "$NAME" deploy-failed "$BEFORE" "job image id unreadable; nothing went live; run $RD"; exit 3; }
    JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
  done
''')
rep('''  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
import json, sys
name, sha, stamp, host, ids, before = sys.argv[1:7]
print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'deploymentId': 'selfhost-' + stamp,
                  'images': dict(l.split('=', 1) for l in ids.split('\\n') if l), 'previous': json.loads(before or '{}')}, indent=1, sort_keys=True))''',
    '''  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
import json, sys
name, sha, stamp, host, ids, before, holds = sys.argv[1:8]
print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'deploymentId': 'selfhost-' + stamp,
                  'images': dict(l.split('=', 1) for l in ids.split('\\n') if l), 'previous': json.loads(before or '{}'),
                  'jobHolds': holds.split()}, indent=1, sort_keys=True))''')
rep('''  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" >/dev/null 2>&1''', '''  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" "$PROMOTED" >/dev/null 2>&1''')

# pin with the job args; post-switch job ref check
rep('''--disp "$IMG_DISP"$SETENV_ARGS > "$RD/pin.txt" 2>&1; rc=$?''', '''--disp "$IMG_DISP"$SETENV_ARGS$JOBARGS$HOLDARGS$GUARDARGS > "$RD/pin.txt" 2>&1; rc=$?''')
rep('''  [ $rc -eq 0 ] && grep -q '^UP_OK' "$RD/up.txt" || sh_fail_rollback "the new stack did not come up healthy"
''', '''  [ $rc -eq 0 ] && grep -q '^UP_OK' "$RD/up.txt" || sh_fail_rollback "the new stack did not come up healthy"
  if [ ${#JOBREFS[@]} -gt 0 ]; then   # goodqa#16136: the pinned job refs must still resolve, each to its own digest
    JR=$(vmctl image-ids "${JOBREFS[@]}" 2>/dev/null | grep -m1 '^{')
    JOK=$(python3 -c 'import json,sys
try: r=json.loads(sys.argv[1])
except Exception: print("UNREADABLE"); sys.exit()
bad=[k for k in sys.argv[2:] if r.get(k)!=k.split("@",1)[1]]; print("OK" if not bad else "UNRESOLVED "+" ".join(bad))' "$JR" "${JOBREFS[@]}")
    say "job image refs on the VM: $JOK"
    [ "$JOK" = OK ] || sh_fail_rollback "job image refs do not resolve after the switch ($JOK)"
  fi
''')
open(p, 'w').write(t)
print('patched ship')
