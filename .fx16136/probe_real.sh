#!/bin/bash
# goodqa#16136 D1 real probe on t2-dev: the rw-ship guard probe against real built dispatcher images (new guard, old guard).
set -u
OUT=~/repos/fx-16136/probe-real.txt; : > "$OUT"
say(){ echo "$(date -u +%H:%M:%SZ) $*" | tee -a "$OUT"; }
say "host $(hostname) df: $(df -h / | tail -1 | tr -s ' ')"
FREE=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$FREE" -ge 30 ] || { say "STOP: ${FREE}G free < 30G"; exit 11; }
probe(){ img=$1
  P=~/repos/fx-16136/probe-${img//[:\/]/_}.txt
  timeout 60 docker run --rm --network none --read-only --tmpfs /tmp --entrypoint node_modules/.bin/tsx -e GUARD_ENV=dev \
       -e JOB_IMAGE_SCAN=goodqa-scan@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
       -e GUARD_HELD_ENV=TRANSCODER_MODE "$img" src/create-guard-main.ts > "$P" 2>&1; prc=$?
  if [ "$prc" != 0 ] && [ "$prc" != 124 ] && grep -q 'GUARD_HELD_ENV must be' "$P"; then v=SUPPORTED; else v=NOT_SUPPORTED; fi
  PO=$(grep -m2 -E "Error|GUARD_HELD_ENV|listening" "$P" | cut -c1-240)
  say "probe $img: rc=$prc verdict=$v"; printf '%s\n' "$PO" | sed 's/^/    /' | tee -a "$OUT"
}
startline(){ img=$1; held=$2
  L=$(timeout 15 docker run --rm --network none --read-only --tmpfs /tmp --entrypoint node_modules/.bin/tsx -e GUARD_ENV=dev \
      -e JOB_IMAGE_SCAN=goodqa-scan@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
      -e GUARD_HELD_ENV="$held" "$img" src/create-guard-main.ts 2>&1 | grep -m1 'listening'); say "startup $img held='$held': ${L:-<no listening line>}"
}
build(){ dir=$1 tag=$2
  say "build $tag from $dir ($(git -C "$dir" rev-parse --short=12 HEAD))"
  s=$(date +%s); nice -n 5 docker buildx build --platform linux/amd64 -f "$dir/apps/job-dispatcher/Dockerfile" -t "$tag" --load "$dir" > ~/repos/fx-16136/probe-build-${tag//[:\/]/_}.log 2>&1; rc=$?
  say "build $tag rc=$rc in $(( $(date +%s) - s ))s"; return $rc
}
OLD=~/repos/fx-16136/probe-old
[ -d "$OLD" ] || git -C ~/repos/fx-16136/bugtracker worktree add -q --detach "$OLD" origin/main
build ~/repos/fx-16136/bt-guard fx16136-guard:new && { probe fx16136-guard:new; startline fx16136-guard:new TRANSCODER_MODE=transcribe; startline fx16136-guard:new ''; }
build "$OLD" fx16136-guard:old && { probe fx16136-guard:old; startline fx16136-guard:old ''; }
docker image rm fx16136-guard:new fx16136-guard:old >/dev/null 2>&1
git -C ~/repos/fx-16136/bugtracker worktree remove --force "$OLD"
say "done; df: $(df -h / | tail -1 | tr -s ' ')"
