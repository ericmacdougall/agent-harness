# PR review packet (delta 1): bugtracker release-harness job images, review F1 and F2 (goodqa#16136)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-rh, draft PR #1370 (base branch base/release-bound-14377 = b3604eaec1c6)
Expected HEAD: be8623fd8db64377ffbef0332fb2cc8933360b8b (annotated tag release-16136-rh2 peels to it)
Delta base: c6b303aee61cdeba2ff8e3784764d6d5c3bb1e74 (the previous packet pr-rh.md, sha256 db84b2cd…; tag release-16136-rh is unchanged)
Delta commit: be8623fd8db6, a fast-forward on c6b303ae
Findings addressed: F1 and F2 of receipt bth-pr73-v1 (BLOCK on bugtracker-harness PR #73, which stages these files). F3 is evidence for the restage packet.

## Scope of the delta
Three files:
- infra/release-harness/rw-ship.sh
- infra/release-harness/selfhost-ctl.py
- infra/release-harness/test_rw_ship_selfhost.py

## F1: one canonical SELFHOST_JOB_HOLD
- Before: validation split on commas and spaces, but held() matched ",$JHOLD,". So "intelligence-worker, transcribe" was accepted, and held transcribe was then false: no probe, no guard hold, transcription released.
- Now the value must be exactly `none` or match `^(intelligence-worker|transcribe)(,(intelligence-worker|transcribe))*$`. held() reads the same validated string.
- Anything else is refused with exit 2 before any build ("nothing built or switched"), and the deploy-failed state is recorded.
- The printed value replaces every character outside [a-z0-9,-] with `?`, so whitespace and control characters are never echoed raw.
- An empty value falls back to the default hold through shconf. It never releases a kind.

## F2: a VM disk gate on the runtime's own data roots, failing closed
- `selfhost-ctl.py disk` measures the runtime's own data roots:
  - docker's root, from `docker info -f {{.DockerRootDir}}`. It must be an absolute path.
  - with the containerd image store only, the `root` line of `containerd config dump`, single- or double-quoted, absolute.
- Each root is measured with `df -Pk`, and exactly one data row is required. The output is `{"free_gb": min, "paths": {root: GiB}}`.
- Any root that cannot be resolved or measured gets REFUSED (exit 3). rw-ship then has no number and stops with NO DISK on the VM, exit 11, before anything is loaded.
- rw-ship needs max(SELFHOST_VM_MIN_FREE_GB, ceil(2 x the summed `docker image inspect -f {{.Size}}` of every image it loads)). It logs "VM image store: <json>; need NG (...)".
- An unreadable size refuses.
- Prod, read-only, checked from t2-dev: DockerRootDir is /var/lib/docker, the store is io.containerd.snapshotter.v1, and `containerd config dump` gives root = '/var/lib/containerd'. Both roots are on /.

## Evidence (t2-dev, `df -h /`: 40G free)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py --deselect <4 baseline ThroughputProcess tests, as in pr-rh.md>
95 passed, 4 deselected in 219.03s (0:03:39)
PASSED infra/release-harness/test_rw_ship_selfhost.py::test_real_compose_resolves_anchor_for_both_services
pytest exit 0
```

The same four ThroughputProcess tests fail at base b3604eae and are deselected here, exactly as in pr-rh.md.

Failing first: the new tests, run against the c6b303ae scripts with `-k "job_hold or vm_disk"`, gave 16 failed and 6 passed (exit 1). The 16 failures:
- the 8 non-canonical hold values: comma-space, space, tab, trailing-comma, leading-comma, empty-item, trailing-space, only-comma;
- containerd root full, docker root full;
- containerd unresolved, both variants;
- stat failure;
- 2 x incoming bytes;
- unreadable size;
- reported roots.

The 6 that passed are regression guards that the old code also met: " none", "none ", the canonical two-kind hold, and the existing default, bad-value and low-VM-disk tests.

New fixture pieces in the test file:
- a fake `containerd`, whose config dump root sits under FAKE_STATE, or fails, or prints no root;
- a fake VM-side `df` that answers for the two roots from FAKE_STATE/vmdf-*; every other call goes to the real df;
- fake docker image sizes.

## Risks
- `containerd config dump` reads containerd's default config path. A containerd started with a non-default `--config` would report the default root. On prod it is the default.
- 2 x the incoming bytes is conservative, because layers already present are not subtracted. It may refuse a load that would have fit; it never approves one that does not.
- Restage: bugtracker-harness PR #73 must now bind be8623fd8db6, through tag release-16136-rh2. That restage packet follows separately.
