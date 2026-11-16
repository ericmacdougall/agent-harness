# PR review packet v4 (whole PR): bugtracker release-harness job images (goodqa#16136); delta over v3: the hold becomes a launch block, E4, G3, AC-13 matcher (G1, G2)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-rh, draft PR #1370
Base: b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254 (tag release-bound-14377)
Expected HEAD: c4a1d054fb53e0e0b9661c9c088046d7596e7b51 (annotated tag release-16136-rh6, object dce449da, peels to it; rh3 -> 04dd4b1f, rh4 -> 618b289d, rh5 -> 18fa30fb unmoved)
Supersedes: pr-rh-v3.md (59ca711e, at 04dd4b1f). Every v3 claim (AC-1 to AC-10, AC-16, AC-17, AC-19, F1, F2), its evidence, the base note and the fp pin still hold, except where listed below.

Commits (base..HEAD):
- a6eaed755b37 fix: job images
- c6b303aee61c fix: guard probe exit code and full output
- be8623fd8db6 fix: canonical job holds and a fail-closed VM disk gate (F1, F2)
- 04dd4b1f6dcf test: pin the fp comparison to b3604eae
- 618b289d8199 fix: make a job hold block launches (new)
- 8685613897a7 test: name the job-hold test for what it asserts (new)
- f8bc21cea83 fix: accept an empty job image only as a hold (new, E4)
- 18fa30fb8f8a feat: add the AC-13 dispatcher response matcher (new, E/E3/F)
- 94b655ea1e5 fix: refuse job lines that are not a pin or a hold (new, G3)
- c4a1d054fb53 fix: pair each held transcription with its API line (new, G1, G2)

Spec: v2.3, core 0de4b5ea (frozen e10a03d4, diff from v2.2 cb71b07b), ACCEPTed by both delta reviewers (Opus adversarial cdbc2624, Sonnet acceptance 3634472e) and attached (comment 13e3d9ae). G1 to G3 are those reviews' code notes; the spec text for them (per-launch pairing, replicas, the job line grammar) and Sonnet's two minor notes go into the next spec edit, so the attached v2.3 AC-13 text still says "by count": the code is stricter than the text. The source of the semantic change is main's ruling relayed by the lead, not the user.

## Scope
Six files under infra/release-harness: rw-ship.sh (wording only), selfhost-ctl.py, README.md, test_rw_ship_selfhost.py, ac13-count.py (new), test_ac13_count.py (new).

## Claims to verify (new or changed)
1. AC-20 / AC-10(a) changed: `--job-hold KEY` writes `      KEY: "" # held` (HELD_VALUE), and the pin self-check expects that value. No guard or dispatcher change: the guard drops empty values from its allowlist (create-guard-main.ts:75), the dispatcher answers 501 "no image configured for job kind" without invoking docker (server.ts:112-117; test server.test.ts:115), the production digest checks skip empty values (config.ts:126, create-guard-main.ts:77), and the API treats 501 as definitive_not_started (job-dispatch.ts:112): intelligence jobs are re-queued with attempts restored and availableAt +60 s, at most 10 per cron tick. PR #1369 stays at 3e478c28.
2. AC-17 changed: the whole-transcode hold empties the transcode line the same way.
3. NEG-15: with the old held images present on the host, the held kinds still resolve to "" on both services after a release; no docker command after the switch names an old held ref; "" is never an image argument.
4. NEG-16 (E4, G3): selfhost-ctl refuses, with a named error, an empty value ("" or '') without `# held`, a `# held` line whose value is not "", "" or `# held` on scan or suggest-fix, and `--job-hold` of scan or suggest-fix (HOLDABLE_KEYS = intelligence-worker, transcode). G3: a non-held line must be a digest-pinned ref, plain (today's format, kept accepted) or in matching quotes (JOB_PIN_VALUE_RE); a bare `KEY:`, `~`, `null`, `${X:-}`, a quoted `${...}`, a tag ref and mismatched quotes are refused with "must be a digest-pinned image ref or \"\" # held".
5. AC-13 (E, E3, F): ac13-count.py pairs Fastify `request completed` statusCode with the `incoming request` URL by reqId in order, counts only POST /jobs/KIND/run, and reads no body, header or env value. 2xx ok; 501 excluded only on a `--held-empty` kind; a transcode 422 excluded only with `--guard-held-transcribe` and only when matched one-to-one to its own API `transcribe: failed to launch job` line whose 422 body names `TRANSCODER_MODE=transcribe is held on this guard`, within --pair-seconds (default 5), greedily in time order over the window widened by the tolerance (G1: a launch straddling the window edge pairs; an unmatched 422 or held line inside the window fails); `--refusals` repeats per api replica or takes one `docker compose logs --timestamps api` file, the JSON reports api_replicas and `--api-replicas N` fails a mismatch (G2); untimed launch-failure lines fail; every other non-2xx fails; `--require-2xx` floors; `--mode pre` positive control. Limit: the API line carries no job id, so pairing is by time; per-job pairing needs guard refusal logging (goodqa#16178, main's call).

## Changed assertions (main's new hold semantics; none deleted)

| Test | Old assertion | New assertion |
|---|---|---|
| test_default_holds_intelligence_worker | held intelligence line == BASE_JOBS[INTEL] (old DO ref) | == "" |
| test_ctl_job_hold_keeps_line_and_skips_presence, renamed test_ctl_job_hold_empties_line_and_skips_presence | want[INTEL] = BASE_JOBS[INTEL] | want[INTEL] = "" |
| test_transcribe_hold_without_guard_support_holds_transcode | transcode == BASE_JOBS (2 asserts) | == "" |
| test_transcribe_hold_string_present_behaviour_absent_holds_transcode | transcode == BASE_JOBS (2 asserts) | == "" |
| test_held_line_marked_and_excluded_from_jobs_missing | line `KEY: <old ref> # held` | line `KEY: "" # held` |
| test_canonical_job_hold_holds_every_named_kind | held kinds == BASE_JOBS (2 asserts) | == "" |
| rw-ship message checks (whole-transcode hold) | "the whole transcode image stays on its current pin" | "the whole transcode image is held, its line emptied" |

## Evidence (t2-dev, `df -h /` about 42G free)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_ac13_count.py --deselect <4 baseline ThroughputProcess tests>
127 passed, 4 deselected in 241.12s (0:04:01)
pytest exit 0
```
Log: t2-dev ~/repos/fx-16136/g-green.txt. The same 4 baseline deselects as v3.

Failing first:

| Run | Result |
|---|---|
| hold tests (`-k "held or hold or unholding"`) against 04dd4b1f scripts | 10 failed, 20 passed |
| the 4 new hold tests against 04dd4b1f scripts | 3 failed, 1 passed (test_held_value_never_reaches_docker is a regression guard) |
| renamed test against 04dd4b1f selfhost-ctl.py | 1 failed |
| 9 E4 tests against 618b289d ctl | 8 failed, 1 passed (the accept control) |
| 7 matcher tests with no tool | 7 failed |
| matcher broken variants at 18fa30fb: 501 always held / no pairing / any 422 held / any launch failure held / untimed lines ignored | each 1 failed |
| 7 G3 refusal cases against 18fa30fb ctl | 7 failed (3 accept cases passed) |
| 3 new G1/G2 matcher tests against the 18fa30fb matcher | 3 failed, 6 passed |
| matcher broken variants at c4a1d054: no time tolerance / no window widening / replicas collapsed / 501 always held / any launch failure held | each 1 failed |

Blobs at HEAD: rw-ship.sh 90d8bf65a5d3 (sha256 2f6b81d5c659…), selfhost-ctl.py 58861fa3d567 (sha256 e1aab26e9c9c…).

## Risks
- A held kind now answers 501 instead of 422: the intelligence backlog is preserved (definitive_not_started, 60 s re-queue); a held transcription (whole-transcode hold only) is marked failed once, as today.
- Unholding is a release; a rollback restores the earlier held "" line. AC-21 (pre-deploy): none of the four live DO refs may resolve on the host before go, else stop.
- AC-13 held-transcription pairing is by time (±5 s), not job id (goodqa#16178).
- Unchanged from v3: ac1-build-time PENDING_REAL_TEST, AC-4 real guard path, live proofs AC-11 to AC-15 need an authorized deploy; F2 notes.
