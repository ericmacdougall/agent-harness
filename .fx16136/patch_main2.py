"""goodqa#16136 AC-18 port fix: main's rw-image-jobs.py owns at most three image commands (RESOURCE_ADMITTED maxJobs=3).
Keep the app plan as main has it and build the job images in further plans of at most three, each with the same
all-success barrier; the id recheck covers every receipt except images a transcode hold removed on purpose."""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, (t.count(old), old[:90]); t = t.replace(old, new)


rep('''  python3 - "$RD" "$SHA" "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" "$GATE_RECEIPT" "${JOBSPECS[@]}" <<'PY_PLAN' || exit 3''',
    '''  python3 - "$RD" "$SHA" "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" "$GATE_RECEIPT" "${JOBSPECS[@]}" <<'PY_PLAN' || exit 3''')
rep('''for spec in sys.argv[8:]:                  # goodqa#16136: the dispatcher job images, built from the same context
    app, dockerfile, image = spec.split('=', 2)
    jobs.append(dict(name=app, image=image, argv=['nice', '-n', '5', 'docker', 'buildx', 'build', '--platform', 'linux/amd64', '--pull',
                                                  '-f', dockerfile, '--label', 'org.opencontainers.image.revision='+sha, '-t', image, '--load', rd+'/src']))
json.dump(dict(sha=sha, recordDir=rd, jobs=jobs), open(rd+'/build-plan.json', 'w'))
PY_PLAN
  TMPDIR=$RD/tmp python3 infra/release-harness/rw-image-jobs.py --plan "$RD/build-plan.json" &
  BUILD_DRIVER=$!
  wait "$BUILD_DRIVER"; rc=$?; BUILD_DRIVER=""
  [ "$rc" = 0 ] || { say "ABORT: image jobs rc=$rc (terminal results in jobs.json)"; dbx "$NAME" deploy-failed "$BEFORE" "image jobs rc=$rc; nothing went live; run $RD"; exit 3; }
''', '''json.dump(dict(sha=sha, recordDir=rd, jobs=jobs), open(rd+'/build-plan.json', 'w'))
# goodqa#16136: the dispatcher job images, built from the same context in further plans of at most three jobs each,
# because rw-image-jobs.py owns at most three image commands (RESOURCE_ADMITTED maxJobs=3).
specs = sys.argv[8:]
for n, start in enumerate(range(0, len(specs), 3), 1):
    batch = []
    for spec in specs[start:start + 3]:
        app, dockerfile, image = spec.split('=', 2)
        batch.append(dict(name=app, image=image, argv=['nice', '-n', '5', 'docker', 'buildx', 'build', '--platform', 'linux/amd64', '--pull',
                                                       '-f', dockerfile, '--label', 'org.opencontainers.image.revision='+sha, '-t', image, '--load', rd+'/src']))
    d = '%s/job-images-%d' % (rd, n)
    __import__('os').makedirs(d, exist_ok=True)
    json.dump(dict(sha=sha, recordDir=d, jobs=batch), open(d+'/build-plan.json', 'w'))
PY_PLAN
  for PLAN in "$RD/build-plan.json" "$RD"/job-images-*/build-plan.json; do
    [ -f "$PLAN" ] || continue
    TMPDIR=$RD/tmp python3 infra/release-harness/rw-image-jobs.py --plan "$PLAN" &
    BUILD_DRIVER=$!
    wait "$BUILD_DRIVER"; rc=$?; BUILD_DRIVER=""
    [ "$rc" = 0 ] || { say "ABORT: image jobs rc=$rc (terminal results in $(dirname "$PLAN")/jobs.json)"; dbx "$NAME" deploy-failed "$BEFORE" "image jobs rc=$rc; nothing went live; run $RD"; exit 3; }
  done
''')
rep('''  python3 - "$RD/jobs.json" <<'PY_IDS' || exit 3
import json, subprocess, sys
for job in json.load(open(sys.argv[1]))['jobs']:
    now''', '''  python3 - "$RD" "${HOLDARGS}" <<'PY_IDS' || exit 3
import glob, json, subprocess, sys
rd, holds = sys.argv[1:3]
jobs = [j for f in [rd + '/jobs.json'] + sorted(glob.glob(rd + '/job-images-*/jobs.json')) for j in json.load(open(f))['jobs']]
for job in jobs:
    if job['name'] == 'transcode' and '--job-hold JOB_IMAGE_TRANSCODE' in holds: continue   # removed on purpose by the hold
    now''')
open(p, 'w').write(t); print('patched ship batches')
