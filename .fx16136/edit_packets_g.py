import os
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'packets')


def edit(name, pairs):
    p = os.path.join(D, name); t = open(p).read()
    for o, n in pairs:
        assert t.count(o) == 1, (name, t.count(o), o[:70]); t = t.replace(o, n)
    open(p, 'w').write(t)


edit('pr-rh-v4.md', [
    ('delta over v3: the hold becomes a launch block, E4, AC-13 matcher', 'delta over v3: the hold becomes a launch block, E4, G3, AC-13 matcher (G1, G2)'),
    ('Expected HEAD: 18fa30fb8f8a5a52daafab8adc0e96fa8a0d09fc (annotated tag release-16136-rh5, object 9ca57164, peels to it; rh3 -> 04dd4b1f and rh4 -> 618b289d unmoved)',
     'Expected HEAD: c4a1d054fb53e0e0b9661c9c088046d7596e7b51 (annotated tag release-16136-rh6, object dce449da, peels to it; rh3 -> 04dd4b1f, rh4 -> 618b289d, rh5 -> 18fa30fb unmoved)'),
    ('- 18fa30fb8f8a feat: add the AC-13 dispatcher response matcher (new, E/E3/F)\n',
     '- 18fa30fb8f8a feat: add the AC-13 dispatcher response matcher (new, E/E3/F)\n'
     '- 94b655ea1e5 fix: refuse job lines that are not a pin or a hold (new, G3)\n'
     '- c4a1d054fb53 fix: pair each held transcription with its API line (new, G1, G2)\n'),
    ('Spec: v2.3, core 0de4b5ea (frozen e10a03d4, diff from v2.2 cb71b07b). Spec v2.3 review is PENDING (delta briefs sent to the Opus adversarial and Sonnet acceptance reviewers); v2.2 (core ddce2e82) was ACCEPTed by both.',
     'Spec: v2.3, core 0de4b5ea (frozen e10a03d4, diff from v2.2 cb71b07b), ACCEPTed by both delta reviewers (Opus adversarial cdbc2624, Sonnet acceptance 3634472e) and attached (comment 13e3d9ae). G1 to G3 are those reviews\' code notes; the spec text for them (per-launch pairing, replicas, the job line grammar) and Sonnet\'s two minor notes go into the next spec edit, so the attached v2.3 AC-13 text still says "by count": the code is stricter than the text.'),
    ('4. NEG-16 (E4): selfhost-ctl refuses, with a named error, an empty value ("" or \'\') without `# held`, a `# held` line whose value is not "", "" or `# held` on scan or suggest-fix, and `--job-hold` of scan or suggest-fix (HOLDABLE_KEYS = intelligence-worker, transcode).',
     '4. NEG-16 (E4, G3): selfhost-ctl refuses, with a named error, an empty value ("" or \'\') without `# held`, a `# held` line whose value is not "", "" or `# held` on scan or suggest-fix, and `--job-hold` of scan or suggest-fix (HOLDABLE_KEYS = intelligence-worker, transcode). G3: a non-held line must be a digest-pinned ref, plain (today\'s format, kept accepted) or in matching quotes (JOB_PIN_VALUE_RE); a bare `KEY:`, `~`, `null`, `${X:-}`, a quoted `${...}`, a tag ref and mismatched quotes are refused with "must be a digest-pinned image ref or \\"\\" # held".'),
    ('a transcode 422 excluded only with `--guard-held-transcribe` and only when the count equals the API `transcribe: failed to launch job` lines in the window whose 422 body names `TRANSCODER_MODE=transcribe is held on this guard`; every other non-2xx fails; `--require-2xx` floors; `--mode pre` positive control. Limit (disclosed in AC-13): pairing is by count in a window, not by job id; per-job pairing needs guard refusal logging (goodqa#16178, main\'s call).',
     'a transcode 422 excluded only with `--guard-held-transcribe` and only when matched one-to-one to its own API `transcribe: failed to launch job` line whose 422 body names `TRANSCODER_MODE=transcribe is held on this guard`, within --pair-seconds (default 5), greedily in time order over the window widened by the tolerance (G1: a launch straddling the window edge pairs; an unmatched 422 or held line inside the window fails); `--refusals` repeats per api replica or takes one `docker compose logs --timestamps api` file, the JSON reports api_replicas and `--api-replicas N` fails a mismatch (G2); untimed launch-failure lines fail; every other non-2xx fails; `--require-2xx` floors; `--mode pre` positive control. Limit: the API line carries no job id, so pairing is by time; per-job pairing needs guard refusal logging (goodqa#16178, main\'s call).'),
    ('115 passed, 4 deselected in 252.77s (0:04:12)', '127 passed, 4 deselected in 241.12s (0:04:01)'),
    ('Log: t2-dev ~/repos/fx-16136/e4-green.txt.', 'Log: t2-dev ~/repos/fx-16136/g-green.txt.'),
    ('| matcher broken variants: 501 always held / no pairing / any 422 held / any launch failure held / untimed lines ignored | each 1 failed |',
     '| matcher broken variants at 18fa30fb: 501 always held / no pairing / any 422 held / any launch failure held / untimed lines ignored | each 1 failed |\n'
     '| 7 G3 refusal cases against 18fa30fb ctl | 7 failed (3 accept cases passed) |\n'
     '| 3 new G1/G2 matcher tests against the 18fa30fb matcher | 3 failed, 6 passed |\n'
     '| matcher broken variants at c4a1d054: no time tolerance / no window widening / replicas collapsed / 501 always held / any launch failure held | each 1 failed |'),
    ('selfhost-ctl.py 21e41c6f0399 (sha256 e3c08584d3c3…)', 'selfhost-ctl.py 58861fa3d567 (sha256 e1aab26e9c9c…)'),
    ('- AC-13 held-transcription pairing is by count, not job id (goodqa#16178).', '- AC-13 held-transcription pairing is by time (±5 s), not job id (goodqa#16178).'),
])

edit('pr-restage-v4.md', [
    ('delta over v3: rebind to bugtracker rh5', 'delta over v3: rebind to bugtracker rh6'),
    ('Expected HEAD: 83679c39419267155cafa3417cca2c01264a9e84', 'Expected HEAD: d71f73bbcc2511df03e40cf6fa88759ecfd6f773'),
    ('- 83679c394192: restage selfhost-ctl with the hold value check (bugtracker 18fa30fb8f8a, tag rh5, review note E4)\n',
     '- 83679c394192: restage selfhost-ctl with the hold value check (bugtracker 18fa30fb8f8a, tag rh5, review note E4)\n'
     '- d71f73bbcc25: restage selfhost-ctl with the job line value check (bugtracker c4a1d054fb53, tag rh6, review note G3)\n'),
    ('Upstream: bugtracker 18fa30fb8f8a5a52daafab8adc0e96fa8a0d09fc, tag release-16136-rh5, PR #1370 (packet pr-rh-v4.md). Spec v2.3 (core 0de4b5ea) review is PENDING; v2.2 was ACCEPTed by both reviewers.',
     'Upstream: bugtracker c4a1d054fb53e0e0b9661c9c088046d7596e7b51, tag release-16136-rh6, PR #1370 (packet pr-rh-v4.md). Spec v2.3 (core 0de4b5ea) ACCEPTed by both delta reviewers and attached (comment 13e3d9ae).'),
    ('(line 2 names commit 18fa30fb8f8a;', '(line 2 names commit c4a1d054fb53;'),
    ('## Upstream byte equality (t2-dev, at 83679c39)', '## Upstream byte equality (t2-dev, at d71f73bb)'),
    ("`git -C bugtracker show 18fa30fb8f8a:infra/release-harness/<f>`", "`git -C bugtracker show c4a1d054fb53:infra/release-harness/<f>`"),
    ('| bin/selfhost-ctl.py | e3c08584d3c3… EQUAL | 21e41c6f0399 |', '| bin/selfhost-ctl.py | e1aab26e9c9c… EQUAL | 58861fa3d567 |'),
    ('- Bugtracker at 18fa30fb (staged rw-ship.sh and selfhost-ctl.py byte-identical): `RW_REAL_COMPOSE=1 python -m pytest -q -rA infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_ac13_count.py` with the 4 baseline ThroughputProcess deselects: 115 passed, exit 0 (log t2-dev ~/repos/fx-16136/e4-green.txt).',
     '- Bugtracker at c4a1d054 (staged rw-ship.sh and selfhost-ctl.py byte-identical): `RW_REAL_COMPOSE=1 python -m pytest -q -rA infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_ac13_count.py` with the 4 baseline ThroughputProcess deselects: 127 passed, exit 0 (log t2-dev ~/repos/fx-16136/g-green.txt).'),
    ('- Lane harness at 83679c39:', '- Lane harness at d71f73bb:'),
    ('4 passed in 16.53s', '4 passed in 13.76s'),
    ('Ran 15 tests in 2.851s', 'Ran 15 tests in 2.594s'),
])
print('packets edited')
