import sys
p = sys.argv[1]; t = open(p).read()
old = "\n## Permanent runtime contract (`RW_LANE_ROOT`)\n"
assert t.count(old) == 1
t = t.replace(old, '''
## Job images (goodqa#16136)

The job-dispatcher starts four job images (scan, transcode, intelligence-worker, suggest-fix-worker). Each is an exact
`JOB_IMAGE_*` value in the create-guard's `&job-images` block of `infra/selfhost/app/compose.yaml`; the dispatcher inherits
that block. This `rw-ship.sh` builds those images from the release SHA, loads them with the app images, and pins each as
`goodqa-<job>@<image id on the VM>`. `selfhost-ctl.py pin` refuses a pin unless every release-managed ref resolves on the
host, and it requires the containerd image store. `state` reports `jobs`, `jobs_held` and `jobs_missing`.

- Holds: `SELFHOST_JOB_HOLD` in `biz/release-waves/ship.conf` defaults to `intelligence-worker,transcribe`; `none` lifts it.
  A held image keeps its current line, marked `# held`. `transcribe` is held at the guard (`GUARD_HELD_ENV=TRANSCODER_MODE=
  transcribe`) while MP4 runs. If the release's own guard does not refuse a malformed `GUARD_HELD_ENV` (probed by running
  the built image), the whole transcode image is held instead. Lifting a hold is main's decision.
- Not every entry point rebuilds job images. The harness copy `~/repos/harness/bin/rw-ship.sh` (used by `ship-fast`,
  `wave-loop` and `wave-revert-ship`) re-pins only the four service image lines. A release through it keeps whatever job
  pins `compose.yaml` already has; goodqa#16146 AC-7 covers that entry point.
- Never run `docker image prune -a` on the app host. The job images are loaded, never pushed, so a pruned job image
  cannot be pulled back: its kind stops launching until the next full release. `state.jobs_missing` and goodqa#16150 watch
  for that.
''' + old)
open(p, 'w').write(t)
print('readme ok')
