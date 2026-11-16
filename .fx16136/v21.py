import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, (t.count(old), old[:80])
    t = t.replace(old, new)


rep('F9-F11 are handled here as well.', 'F9-F11 are handled here as well. v2.1 (delta on accepted v2 core 947e6547): '
    "transcription held by a guard mode hold (main's decision, relayed by the lead 2026-11-15), the same-release coupling, "
    'AC-12 blocking rule, the intelligence TARGET_MISMATCH citation, the AC-13 floor for held kinds, and Opus build notes B1-B7.')
rep('- Project Intelligence, Suggest Fix, recording transcripts and frame extraction start running too, but complete only once their missing env keys are provisioned.',
    '- Suggest Fix and frame extraction start running too, but complete only once their missing env keys are provisioned. Project Intelligence and recording transcription stay HELD (not launched): intelligence to keep its backlog re-queueable, transcription so that nothing launches toward a VERTEX_AI_* path (the no-Vertex rule; goodqa#16144 owns the replacement provider).')
rep("| transcode, transcribe and frames modes | transcript, frames | \"Could not start the transcription job\" | the container starts, then fails closed on GCP_PROJECT (transcribe) or API_PUBLIC_URL (frames); the user still sees a failed transcript | transcripts and frames produced |",
    "| transcode, transcribe mode | transcript | \"Could not start the transcription job\" | HELD by the guard mode hold (AC-16): the guard refuses the create, so the user sees exactly today's failed transcript, and no transcription container starts | after goodqa#16144 picks a non-Vertex provider and goodqa#16148 lands |\n"
    "| transcode, frames mode | frames | \"Could not start\" (frames) | the container starts, then fails closed on API_PUBLIC_URL; frames stay failed | frames produced |")
rep('- In: a harness PR restaging', '- In: a bugtracker main PR to apps/job-dispatcher create-guard adding GUARD_HELD_ENV (the mode hold, AC-16), with selfhost-ctl managing its one line in the create-guard block.\n- In: a harness PR restaging')

# AC-2 B2
rep('which runs only with RW_REAL_COMPOSE=1 on t2-dev and fails rather than skips when that is set.',
    'which runs only with RW_REAL_COMPOSE=1 on t2-dev and fails rather than skips when that is set; the evidence is the `pytest -rA` line showing it PASSED, never SKIPPED.')
# AC-6 B4
rep('`state` reports `jobs` (each JOB_IMAGE_* value) and `jobs_missing` (every job ref that does not resolve to its own digest).',
    '`state` reports `jobs` (each JOB_IMAGE_* value), `jobs_held` (keys pinned with --job-hold, marked `# held` on their compose line) and `jobs_missing` (every non-held job ref that does not resolve to its own digest; held refs never appear there, so goodqa#16150 does not alert on them).')
# AC-9 B1
rep('The comparison uses names only, read with `cut -d= -f1`; no value is read.',
    "The comparison uses names only, read with `grep -oE '^[A-Za-z_][A-Za-z0-9_]*='` (never `cut`, which would print a line without `=` whole); no value is read.")
# AC-10 TARGET_MISMATCH citation
rep('Until then it is labelled TARGET_MISMATCH: intelligence not restored.',
    'Until then it is labelled TARGET_MISMATCH: intelligence not restored. Main accepted this hold (AC-10a) on 2026-11-15, relayed by the lead; lifting it is main\'s call once goodqa#16148 is live.')
# AC-11 B5
rep('Any Level 1 failure blocks the ship.',
    'Any Level 1 failure blocks the ship. A Level 1 failure found after deploy keeps goodqa#16136 open and is fixed forward; rollback is used only if api, web or dispatcher health is harmed (rolling back puts every kind back to 422).')
# AC-12 blocking rule + held kinds
rep('transcribe, frames, suggest-fix and intelligence: TARGET_MISMATCH until the env ticket lands;',
    'frames and suggest-fix: TARGET_MISMATCH until goodqa#16148 lands; transcribe and intelligence are HELD and have no Level 2 check here;')
rep('A Level 2 failure caused only by a missing env key does not fail this ticket.',
    'A Level 2 failure caused only by a missing env key does not fail this ticket; a Level 2 failure for any other reason blocks.')
# AC-13 floors
rep('at least 1 2xx for each of scan, transcode and suggest-fix (from AC-11); and the held intelligence route still shows its 422s, labelled as held.',
    'at least 1 2xx for each of scan, transcode (MP4 creates) and suggest-fix (from AC-11). Held kinds have no floor: the intelligence route still shows its 422s, and held transcription creates show as transcode-route 422s with the guard hold reason, each labelled as held and excluded from the zero count.')

# new ACs
rep('\n## Negative cases\n', '''
- AC-16: Transcription mode hold at the guard. With `GUARD_HELD_ENV=TRANSCODER_MODE=transcribe` in the create-guard environment, the guard refuses any `/containers/create` whose `Env` would make the transcoder run transcription, and allows every other create unchanged (MP4 default, frames, the other three images). Matching uses the worker's own parse: apps/transcoder/src/index.ts:475 reads `process.env.TRANSCODER_MODE === 'transcribe'` (exact, no trim, no case fold, no alias), and a container's effective value for a repeated Env key is the last one. The guard refuses fail-closed on a superset: any `TRANSCODER_MODE` entry whose value trimmed and lower-cased is `transcribe`, and any create with the held key repeated. The guard's matcher and the worker's mode check are exported functions, with one table-driven test asserting that every value the worker treats as transcription is refused by the guard. Set from ship.conf `SELFHOST_JOB_HOLD` (default `intelligence-worker,transcribe`); rw-ship passes `--guard-hold TRANSCODER_MODE=transcribe`; selfhost-ctl writes the single `GUARD_HELD_ENV` line in the create-guard block; the deploy record and the run log name the active holds. Verify by: on t2-dev, `pnpm --filter @bugtracker/job-dispatcher exec vitest run test/create-guard.test.ts test/held-env.test.ts` fails before the bugtracker main change and passes after, plus pytest `test_guard_hold_line_written_and_recorded`. Source: inferred: from ticket:GoodQA goodqa#16136 -- main ruled transcription held at the guard so its user-visible state stays exactly as today

- AC-17: Same-release coupling. The release-script fix and the guard change reach production in the same release. rw-ship checks the release source it just archived: if `transcribe` is held and that source's create-guard does not implement GUARD_HELD_ENV, it holds the whole transcode image (`--job-hold JOB_IMAGE_TRANSCODE`) and says "transcode held: guard lacks GUARD_HELD_ENV". So MP4 waits and no transcription container can start. The production ship sha carries everything on bugtracker main since 7e66a853 (including PR 1364, and S1 if merged); that is stated in the deploy note. Verify by: pytest `test_transcribe_hold_without_guard_support_holds_transcode` and `test_transcribe_hold_with_guard_support_pins_transcode`. Source: inferred: from ticket:GoodQA goodqa#16136 -- main's coupling condition, so transcription never launches unheld in between

- AC-18: Forward-port. The same release-script change, rebased onto bugtracker main's infra/release-harness (which has no JOB_IMAGE handling yet), is opened as its own PR and linked from goodqa#16146. Verify by: the PR link comment on goodqa#16146 and its focused test output. Source: inferred: from ticket:GoodQA goodqa#16136 -- review note B6, a later restage to main must keep the fix

- AC-19: Runbook. The infra/release-harness README states that ship-fast and wave-loop (bin/rw-ship.sh) do not rebuild job images, so they keep whatever job pins compose.yaml has, and that `docker image prune -a` must never run on the app host. The same note is commented on goodqa#16146. Verify by: the README diff and the ticket comment. Source: inferred: from ticket:GoodQA goodqa#16136 -- review note B7

## Negative cases
''')
rep('a bare id; the old DO ref.', 'a bare id; the old DO ref; a key given to both --job-image and --job-hold.')
rep('Verify by: pytest `test_ctl_job_images_refusals_change_nothing` (9 cases).', 'Verify by: pytest `test_ctl_job_images_refusals_change_nothing` (9 cases) and `test_ctl_job_hold_keeps_line_and_skips_presence`.')
rep('\n## Resource budget', '''- NEG-12 (AC-16): Each variant is refused by the guard while transcribe is held: `transcribe`, `Transcribe`, `TRANSCRIBE`, ` transcribe`, `transcribe ` (with tab and newline variants), and `TRANSCODER_MODE` repeated with `transcribe` last or first. MP4 (no TRANSCODER_MODE), `frames` and an unrelated key with the value `transcribe` are allowed. Verify by: one vitest case per variant in test/held-env.test.ts. Source: inferred: from ticket:GoodQA goodqa#16136 -- main's normalization condition
- NEG-13 (AC-16): With GUARD_HELD_ENV unset or empty, the guard's behavior is exactly today's: the whole existing create-guard test suite passes unchanged, and a transcription create is allowed. A malformed GUARD_HELD_ENV (no `=`, an unknown key, more than one pair) makes the guard refuse to start, the same way it refuses with no job images. Verify by: vitest `held-env unset is a no-op` and `malformed held env refuses startup`. Source: inferred: from ticket:GoodQA goodqa#16136 -- the hold must not change anything when off
- NEG-14 (AC-16): An unknown or malformed SELFHOST_JOB_HOLD token (anything but `intelligence-worker`, `transcribe` or `none`) stops the release before any build, and `--guard-hold` with any value other than `TRANSCODER_MODE=transcribe` is refused by selfhost-ctl with nothing changed. Verify by: pytest `test_bad_job_hold_value_refuses_before_building` and `test_ctl_guard_hold_refusals`. Source: inferred: from ticket:GoodQA goodqa#16136 -- review note B3

## Resource budget''')
open(p, 'w').write(t)
print('v2.1 written')
