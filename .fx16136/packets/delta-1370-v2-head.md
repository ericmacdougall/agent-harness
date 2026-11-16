# PR review packet (delta only): PR #1370 receipt pr1370-v1 BLOCK fixes F1, F2, F3, plus harness PR 73 receipt bth-pr73-v4b F1

Tickets: GoodQA goodqa#16136 (F1, F2, F3, 73-F1) and GoodQA goodqa#16148 (the installer derive-blob line, lead ruling option 1).
Sources:
- main's exact-head receipt receipts/bugtracker-pr1370-v1.md, BLOCK: F1 and F2 are fail-open release gates, and F3 asks for evidence.
- receipts/bth-pr73-v4b.md F1, which main folded into this batch because it touches the same file.

Repo: ericmacdougall/bugtracker
Reviewed before: #1370 at c4a1d054fb53e0e0b9661c9c088046d7596e7b51 (fix/16136-job-images-rh)
Expected HEAD: c1d221810a20926ddc869ad010b10faea8a4c4d5 (#1370, fast-forward)

Commits in this delta:
- 1b80fe608be fix(release-harness): fail closed on AC-13 records it cannot read (F1)
- dda2b2c6959 fix(release-harness): refuse an unknown image store and off-env job keys (F2, 73-F1)
- c1d221810a2 feat(release-harness): record an optional derive-blob binding line (goodqa#16148 installer, ported here because rh carries its own install-d2.sh)

## Claims to verify
1. **F1, ac13-count.py.** A record the matcher cannot vouch for is counted as `unknown` by reason. The reasons are:
   - malformed: a line holding `{` that is not a JSON object;
   - orphan completion;
   - invalid status or time: a launch completion whose statusCode is not an int in 100-599 (a bool is not one), or whose time is not a number;
   - no completion: a launch start never completed, or superseded by a reused reqId.

   An unknown counts when its time is inside the window or it has no usable time. Any counted unknown gives verdict INCONCLUSIVE with exit 1, never PASS. A real failure still wins as FAIL. A non-launch request (GET /healthz) still pairs and counts nothing.
2. **F2, selfhost-ctl.py `store_is_containerd`.** It returns True or False only for a readable, non-empty JSON list of string lists. A non-zero rc, a timeout or OSError, empty output, non-JSON, `null`, `{}`, `[]` or a non-pair list raises Refused. So the VM disk gate (`disk` verb, rw-ship exit 11 "VM image store: unresolved") and `pin` both stop, and the store is never read as classic. A real classic DriverStatus still gets the "is not containerd" refusal.
3. **73-F1, `job_lines`.** It tracks the 4-space key a line sits under inside each service. A JOB_IMAGE_* line counts only under the create-guard's `environment:`, so under `labels:` it is refused, held or not.

   **73-F1, `presence_check`.** It compares every JOB_IMAGE_* key, held ones included, in the RESOLVED compose:
   - a held key resolves to "" in `services.<svc>.environment`;
   - this applies to both the guard and the dispatcher;
   - parity is exact: no missing key and no extra key;
   - an environment that is not a mapping is refused.
4. **Test fixture.** The fake `docker compose config` now resolves JOB_IMAGE_* lines by their sub-key (environment or labels) and turns "" into an empty string, as compose does. `resolved-drop-held` simulates a resolved dispatcher env without the held key.
5. **Installer (goodqa#16148, same change as the gate PR).**
   - `install-d2.sh` writes `derive-blob <40hex>` as the 8th binding field when the candidate commit holds infra/selfhost/app/derive-job-secrets.py as a regular blob.
   - `validate_binding` accepts exactly that one optional last line, equal to the blob at the bound commit.
   - It refuses, read-only, a missing file, a mismatching blob, a duplicate, an unknown 8th field, and the line out of place.
   - A candidate without the file still installs a 7-field binding. rh has no unhold gate yet, so this changes nothing at rh's rw-ship.
6. Every fix has failing-first tests and broken variants, and no earlier assertion was changed.

## F3: evidence, commit-bound (t2-dev, 31G free)
Fail first, new tests on the c4a1d054 source:
```
$ pytest -q test_ac13_count.py                                         (c4a1d054 ac13-count.py)
7 failed, 9 passed in 1.28s
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"   (c4a1d054 selfhost-ctl.py)
14 failed, 2 passed, 121 deselected in 24.50s
$ pytest -q test_rw_ship_selfhost.py -k "labels or held_key_pin_passes or dropping_a_held"   (c4a1d054 selfhost-ctl.py)
3 failed, 1 passed, 137 deselected in 2.62s
$ pytest -q test_install_d2_upgrade.py -k derive                        (c4a1d054 install-d2.sh)
2 failed, 6 passed, 41 deselected in 7.45s
```
At HEAD c1d221810a20926ddc869ad010b10faea8a4c4d5 (rerun with exit status):
```
$ pytest -q test_ac13_count.py
16 passed in 1.54s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
16 passed, 125 deselected in 14.22s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "labels or held_key_pin_passes or dropping_a_held"
4 passed, 137 deselected in 1.34s
exit 0
$ pytest -q test_install_d2_upgrade.py test_installed_binding_upgrade.py test_install_fixture_sparse.py
54 passed in 59.86s
exit 0
```
Broken variants of ac13-count.py, each against `test_ac13_count.py`:
```
A1 orphan skipped            3 failed, 13 passed
A2 malformed skipped         1 failed, 15 passed
A3 invalid skipped           1 failed, 15 passed
A4 open launch skipped       1 failed, 15 passed
A5 unknown passes            6 failed, 10 passed
A6 bool status admitted      1 failed, 15 passed
```
For F2 the broken variant is the c4a1d054 source (14 failed above). The installer variants were run against the identical gate-branch installer, with `-k derive`:
```
I1 no blob check             2 failed, 6 passed
I2 any 8th field             1 failed, 7 passed
I3 duplicates admitted       1 failed, 7 passed
I4 no line written           1 failed, 7 passed
```
Regression, same command at both heads:
```
$ pytest -q test_ac13_count.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_selfhost_ctl.py
c4a1d054: 945 failed   HEAD: 945 failed   (failing test ids identical: `comm` of the sorted FAILED lists is empty both ways)
```
Those 945 failures exist on c4a1d054 itself, before this delta. They are:
- 940 in test_selfhost_ctl.py: the ctl answers `usage: ... invalid choice` for verbs that test file expects, so the test file does not match rh's ctl;
- 4 ThroughputProcess cases in test_rw_ship_selfhost.py;
- test_rw_release_authority_d2.py::test_ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin: PIN2 lacks job args. The same break exists on 1371 and is fixed in the gate PR.

They are listed here so they are not mistaken for this delta. They are not fixed here.

**AC-4 real-guard path: PENDING, and the release is gated on it.**
- `PENDING_REAL_TEST p16136-ac4-real-guard` (WAL w65f256f1e2a).
- The check: load a goodqa-<job> image locally and create it as repo@<image id> through the REAL job-dispatcher-create-guard, on an owned lab or staging host; the create must be allowed and the container start.
- Not run: t2-dev is at 31G free, at its 30G floor for heavy Docker work. It needs a lab host with room. Until it has a REALLY_TESTED entry, 1370 must not ship with job images released.

## Delta diff (c4a1d054..c1d22181)
