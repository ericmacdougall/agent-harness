# PR review packet: ops_watch capabilities subcommand for the fabd installer gate (agent-harness PR 228, GoodQA goodqa#15835)

Base: 1eba3e291c1f8bac2613e74515a360ecb933eeb8 (origin/main, the merge of PR 230, and the merge base; use `--snapshot-base 1eba3e291c1f8bac2613e74515a360ecb933eeb8`). Head: 6ea3789fd39c90ca186ca864467cb9f57f01afe8 (branch af9e-ops-capabilities; it is a plain merge of origin/main 1eba3e29 into the previously reviewed head a8fbf5361532418e2258f533cd401b4038bccb16, no history rewritten, no conflict; the PR's own diff against main is unchanged). Claude-authored: `--author-harness claude`.
Changed code paths: harness/hooks/ops_watch.py (the `capabilities()` function, a `capabilities` subparser, an early branch in `main()`), tests/test_ops_watch_capabilities.py (new), tests/mutants_ops_capabilities.py (new), notes/goodqa-15835/ (spec.md, review-opus.md, review-sonnet.md). The last two commits add only spec text and review reports after the code at 1dde69e0.

## Outcome
`python3 ops_watch.py capabilities` prints one capability per line and exits 0: `emit`, and `forward-foreign-critical` while the forwarder code (goodqa#15827) exists. The fabd installer runs `grep -qx forward-foreign-critical` on the probed script and refuses MODE=unit and MODE=live without it (unless its logged override is set). The probe runs before any home, config, state or ring access, so it works with HOME unset, creates no file, and an old copy without the subcommand fails closed (argparse exit 2, nothing on stdout).

## Design (read ops_watch.py capabilities and main)
A name is listed only while the code behind it exists (`forward_foreign` and `queue_events` are defined); the branch in `main()` sits before `Path.home()` and before any config load. Nothing else in `main()` or `run_once` changed.

## Spec, reviews, decisions
Spec attached to goodqa#15835 (comment 60973894). Labelled owner assumptions (none is a user decision): D1 plain names one per line so `grep -qx` is exact; D2 the probe is pure; D3 a capability is listed only while its code exists. Requested by the Fabric owner and approved by main (follow-up PR after PR 227 merged). Reviews: Opus adversarial ACCEPT at eddc5be7 (three lows fixed or stated: the run_once wiring is now proved by a run_once-driven test; capability is not liveness; HOME resolved before the probe, now fixed). Sonnet acceptance: BLOCK at eddc5be7 with a confirmed read-only finding, BLOCK at 1dde69e0 for one bookkeeping item (the follow-up ticket number), then stated that a delta adding only that number counts as ACCEPT; the final commit adds exactly that (goodqa#15837). The reviewer's accept is therefore conditional on that statement and was recorded on that basis; no review was rerun after the last commit. Stage acceptances, not PR signoff.
KNOWN LIMITS (spec Risks, follow-up goodqa#15837 linked to goodqa#15805): the probe proves the PROBED FILE only. Confirmed read-only on t2-dev: the ops-watch service runs `~/.agent-harness/bin/ops_watch.py run` (a Nov 5 copy), not the hooks copy that install.sh probes; `install()` renders the unit from `Path(__file__)`, so the unit points at whichever copy last ran `install --apply`. Until the unit is re-pointed, a passing gate on the hooks copy does not prove the timer's copy forwards. The installer should probe the unit's script (from `systemctl --user show -p ExecStart ops-watch.service`, launchd ProgramArguments on the Mac) and require the timer active; the t2-dev install runs `ops_watch.py install --apply` and the live test checks the unit's ExecStart path. Also: capability is not delivery (a host with the default config, comment mode none and no deadman, passes) and not liveness.

## Failing-first and risk table
`python3 -B -m unittest tests.test_ops_watch_capabilities`: 7 tests (exact line and exit 0, one name per line with no decoration or duplicates, no file created under HOME, listed only while the code exists, works with no home, the forwarder is wired into run_once and a foreign critical reaches the digest post, the listed capability is real). `python3 -B tests/mutants_ops_capabilities.py`: the parent commit a810795d (no subcommand) and 8 controlled broken variants each fail the tests (9 of 9, none "not applied"): capability not listed, listed without the code check, decorated line, non-zero exit, probe writes under home, forwarder not called by run_once, home resolved before the probe, duplicate line. Highest-risk cases: a false claim (listed without the code, partial revert caught by the run_once test), a side effect or failure of the probe (no-home and no-file tests), a decorated line that breaks `grep -qx`.

Risk and rollback: revert the commits; the change only adds a read-only subcommand.

## Validation (exact head 6ea3789fd39c90ca186ca864467cb9f57f01afe8 = the reviewed head merged with origin/main 1eba3e29, run in the owner worktree)
$ python3 -B -m unittest tests.test_ops_watch tests.test_ops_watch_point_events tests.test_ops_watch_forward tests.test_ops_watch_capabilities
Ran 160 tests in 137.140s
OK
exit 0
(the run at the exact head; the older runs below were at the reviewed head before the merge)
$ python3 -B -m unittest tests.test_ops_watch_capabilities
Ran 7 tests in 0.733s
OK
exit 0
$ python3 -B -m unittest tests.test_ops_watch tests.test_ops_watch_point_events tests.test_ops_watch_forward tests.test_ops_watch_capabilities
Ran 158 tests in 112.130s
OK
exit 0
(run at eddc5be7, before the two test additions in 1dde69e0)
$ python3 -B tests/mutants_ops_capabilities.py
a810795d (no subcommand) FAILS (good); all 8 broken variants FAILS (good); none PASSES, none NOT APPLIED; exit 0
