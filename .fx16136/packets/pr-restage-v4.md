# PR review packet v4: bugtracker-harness restage of the job-image runtime (goodqa#16136); delta over v3: rebind to bugtracker rh6

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker-harness (the lane harness), branch fix/16136-job-images, draft PR #73
Base: 1786659bb29d39c8facf1b2ed88fdd8d45d4845d (origin/main)
Expected HEAD: d71f73bbcc2511df03e40cf6fa88759ecfd6f773
Supersedes: pr-restage-v3.md (9a79849c, at 19cb8368). The v3 review-finding answers (F1, F2, F3), the RELEASE_BINDING correction and the prod headroom note still hold.

Commits (base..HEAD):
- 82b0fb2a9c5a: restage at bugtracker c6b303ae
- 6c7a0aa8d821: restage at bugtracker be8623fd8db6 (review F1/F2) and rebind
- 19cb8368bc4c: rebind to bugtracker 04dd4b1f6dcf
- aab3a36aa110: restage the hold-as-launch-block runtime (bugtracker 618b289d8199, tag rh4): rw-ship.sh and selfhost-ctl.py
- 83679c394192: restage selfhost-ctl with the hold value check (bugtracker 18fa30fb8f8a, tag rh5, review note E4)
- d71f73bbcc25: restage selfhost-ctl with the job line value check (bugtracker c4a1d054fb53, tag rh6, review note G3)

Upstream: bugtracker c4a1d054fb53e0e0b9661c9c088046d7596e7b51, tag release-16136-rh6, PR #1370 (packet pr-rh-v4.md). Spec v2.3 (core 0de4b5ea) ACCEPTed by both delta reviewers and attached (comment 13e3d9ae).

## Scope
Three files: config/goodqa-release/bin/rw-ship.sh, config/goodqa-release/bin/selfhost-ctl.py, config/goodqa-release/bin/RELEASE_BINDING (line 2 names commit c4a1d054fb53; the rw-ship.sh and selfhost-ctl.py hash lines changed; the other three unchanged).

## Upstream byte equality (t2-dev, at d71f73bb)
sha256 and `git hash-object` of each staged file next to `git -C bugtracker show c4a1d054fb53:infra/release-harness/<f>` and the RELEASE_BINDING line:

| Staged file | staged = upstream = binding sha256 | git blob |
|---|---|---|
| bin/rw-runtime.sh | 2107e0bbd273… EQUAL | 3070e6a3de5d |
| bin/rw-ship.sh | 2f6b81d5c659… EQUAL | 90d8bf65a5d3 |
| bin/selfhost-ctl.py | e1aab26e9c9c… EQUAL | 58861fa3d567 |
| bin/rw-rollback.sh | 2fc968e3eb29… EQUAL | 59f34a89a1a1 |
| biz/prod-db-pool-20261013/ship-fast.sh | a812832784af… EQUAL | 37f769161902 |

## Behaviour on these exact bytes
- Bugtracker at c4a1d054 (staged rw-ship.sh and selfhost-ctl.py byte-identical): `RW_REAL_COMPOSE=1 python -m pytest -q -rA infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_ac13_count.py` with the 4 baseline ThroughputProcess deselects: 127 passed, exit 0 (log t2-dev ~/repos/fx-16136/g-green.txt).
- At aab3a36a (rh4 bytes, `cmp` identical): the job, hold, guard, transcribe, VM-disk and real-compose subset, 61 passed, exit 0 (log ~/repos/fx-16136/f3-v4.txt).
- Lane harness at d71f73bb:

```
$ python -B -m pytest -q -p no:cacheprovider bin/test_goodqa_staged_rw_ship_keyed.py
4 passed in 13.76s
$ python -B bin/test-goodqa-release-unit.py
Ran 15 tests in 2.594s
OK
```

## Risks
- The behaviour change rides in from upstream: a held kind's line is `"" # held` and the dispatcher answers 501 for it (pr-rh-v4.md claims 1 to 4). No guard change; bugtracker PR #1369 stays at 3e478c28.
- AC-21 is a pre-deploy step: a read-only check that none of the four live DO job refs resolves on the prod host, recorded before go.
- Nothing is merged or deployed; live proofs AC-11 to AC-15 need an authorized deploy.
