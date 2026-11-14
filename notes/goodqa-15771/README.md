# goodqa#15771 review evidence (PR 240, proxmox_pool ops-watch check)

These files are the review evidence for PR 240. They are kept with the code so that a review snapshot can inspect them.

The evidence comes in two sets, and each states which code it ran against:

1. **Branch evidence at a3b054087e8a5e74417c508d30f7f3572a39c4de** (the code commit before `origin/main` was merged in). Every log below except the two post-merge files was generated at that commit, from a separate clean worktree checked out there. It shows this branch's behaviour: tests, mutants, renderer fidelity, the live probe, rehearsal, rollback and failing-first. It does **not** cover the merged code.
2. **Merged-code verification at 57a50ddabf33d0ff759e1ee7885d851c6514303d**, the merge of `origin/main` 98e33c5d into the branch. This is in the section "Post-merge verification" below. These are the only logs that ran against the merged code.

Redactions, applied by the copy step to the branch logs and scripts (the post-merge files are described in their own section):
- IPv4 addresses → `<ip>`
- tailnet names → `<tailnet-host>`
- the hypervisor alias and its login → `<pve-host>` and `<login>@<pve-host>`
- the Mac's hostname → `<mac-host>`
- the home path → `~`
- the account name → `<user>`

Logs are stored as `.txt` because the repository's `.gitignore` excludes `*.log`. Nothing else was changed. The probe output contains no raw remote rows, only parsed counts and alert fields.

## Spec
- `spec-amend-1c.md`: the amendment as submitted for plan re-review (sha256 c71204b3187eed59324931b11650218fcae2b970e931922b92a53402187fab02 before redaction). It covers the inventory, the status rule (AC-9 to AC-11), bounded capture (AC-12), container coverage proven from source versus live (AC-13), the rehearsal (AC-14), rollback (AC-15), negative cases NEG-7 to NEG-11, and the resource budget. Its evidence figures were taken at c8873639; the logs here repeat them at a3b05408.

## Branch evidence: logs at a3b05408 (`logs/`)

| File | What it shows | Result |
|---|---|---|
| `tests.txt` | `python3 -B -m unittest -v tests.test_ops_watch tests.test_ops_watch_proxmox tests.test_deploy_drift` | Ran 211, OK, exit 0 |
| `mutations.txt` | 16 in-memory mutants of ops_watch.py, including M16 (the r5 non-sticky overflow bug) | 16 of 16 killed, exit 0 |
| `renderer-fidelity.txt` | test renderer `pvesm_list()` against live `pvesm list local` (AC-13, L1) | byte_identical=True, 25 rows, exit 0 |
| `live-probe.txt` | `check_proxmox_pool` with the real runner, read-only, one ssh call | 2.8 s; all five `##RC` lines 0; high 93.5%; allocation complete; 1.8x |
| `rehearsal-and-rollback.txt` | one-pool rehearsal through run_once (good, deliberately failed, good) and the rollback (`proxmox_pools: []`, then re-enabled) (AC-14, AC-15) | volume alert continuous; no sample from the failed read; disabled = 0 ssh calls, samples kept |

## Branch evidence: failing-first logs (`logs/failing-first/`), each against the head named inside it
| File | Finding | Against | Result |
|---|---|---|---|
| `r2-f1-reproducer-old.txt` / `r2-f1-reproducer-new.txt` | r2 F1: container and unused-disk volumes missing | db2f6b11 / fix | 2 of 2 under-report (provisioned 1536 instead of 1836) / 0 of 2 |
| `r2-new-tests-on-db2f6b11.txt` | r2 F1 tests on the old parser | db2f6b11 | 21 failures of 55 |
| `r3-du-status.txt` | r3 F1: du without status trusted | 2e8d6f29 | 6 of 6 failed |
| `1b-f3-bounded-capture.txt`, `1b-f3-memory.txt` | plan 1b F3: output buffered before the cap | 7bb3aa29 | 5 of 5 errored; 8 MiB flood peak 24.0 MiB at 7bb3aa29 against 1.4 MiB with the cap |
| `r5-f1-overflow-order.txt` | r5 F1: overflow reset by a later chunk | c8873639 | run() returned (0, data) instead of (-1000, '') in both orders |

## Post-merge verification at 57a50dda (`logs/`)

`origin/main` was merged into the branch with no rebase. Commit 57a50ddabf33d0ff759e1ee7885d851c6514303d has tree 49a9debd9b393622c150f4a6ac9258331b6dc5a5 and parents 634bf51d (the branch after the r6 PASS) and 98e33c5d2977ea5b73b55bb00e96d2a30139b44b (the `origin/main` tip, which is also the merge base with main).

| File | What it shows | Result |
|---|---|---|
| `r7-t2dev-tests.txt` | The six ops_watch and drift modules on t2-dev: `python3 -B -m unittest -v tests.test_ops_watch tests.test_ops_watch_proxmox tests.test_ops_watch_capabilities tests.test_ops_watch_forward tests.test_ops_watch_point_events tests.test_deploy_drift`, run on the exact tree from `git archive 57a50dda`. The sha256 of the 8 files under test match the commit. | Ran 256, OK, exit 0; 0 failures, errors or skips |
| `merge-57a50dda-remerge.diff` | `git show --remerge-diff 57a50dda`: how each conflict was resolved, compared with git's own automatic merge (conflicts in ops_watch.py and docs/ops-watch.md; one jump test re-anchored on `--`) | 182 lines |

Also checked at 57a50dda, with output not kept here: `tests.test_ops_watch_proxmox` on the Mac gave Ran 81, OK (73 from the branch and 8 from main), and `scripts/mutate.py` gave 16 of 16 killed.

The remerge diff is committed verbatim, because editing it would make it unusable as a diff. It contains no address or tailnet name. Its paths and host aliases are text already present in `docs/ops-watch.md` on main. The t2-dev log filters out only the code's own `ops-watch testhost:` progress lines.

## Scripts (`scripts/`)
These are the evidence scripts, with the host redacted; put the real alias back to rerun the live ones.
- `mutate.py`: in-memory mutants
- `renderer_fidelity.py`: renderer against live output
- `live_probe.py`: live read-only probe
- `rehearsal.py`, `rollback_rehearsal.py`: rehearsal and rollback through run_once
- `failing_first_f1.py`: r2 reproducer
- `f3_memory_demo.py`: capture memory comparison
- `tests_on_module.py`: tests against an earlier ops_watch.py

None of them writes to the hypervisor.
