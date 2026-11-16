"""goodqa#16136 spec v2.2 -> v2.3 (review notes D, E/E3, E1, E2, E4, F, G from both v2.2 reviewers, relayed by the lead)."""
import os
D = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(D, 'spec-16136-v2.md'); t = open(p).read()
SRC = "main's ruling relayed by the lead 2026-11-16"


def rep(o, n, cnt=1):
    global t
    assert t.count(o) == cnt, (t.count(o), o[:80]); t = t.replace(o, n)


i = t.index('Revision: v2.'); j = t.index('\n', i)
t = t[:j] + (' v2.3 (delta on v2.2 core ddce2e82, both reviews ACCEPT with notes): the hold test is named for what it asserts (D); '
             'AC-13 is computed by the committed matcher infra/release-harness/ac13-count.py, where 501 is expected only on a '
             'held-empty kind and 422 only on held transcription paired one-to-one with the API launch-failure lines that carry '
             'the guard reason (E, E3, F); "" is accepted only with `# held` on a holdable key (E4, NEG-16); a whole-transcode '
             'hold makes transcode TARGET_MISMATCH for AC-11 to AC-13 (E2); a pre-deploy read-only check that no current DO job '
             'ref resolves on the host (E1, AC-21); the Reviews table is re-rendered by spec_flow at attach (G). Source of the '
             'v2.3 change: the v2.2 reviewers\' notes, relayed by the lead 2026-11-16; not the user.') + t[j:]
rep('test_ctl_job_hold_keeps_line_and_skips_presence', 'test_ctl_job_hold_empties_line_and_skips_presence', 2)

i = t.index('- AC-13:'); j = t.index('\n', i)
t = t[:i] + (
    '- AC-13: Dispatcher response counts are computed by infra/release-harness/ac13-count.py from the read-only dispatcher container log '
    '(`docker logs --timestamps`). It pairs each Fastify `request completed` line (its `statusCode`) with the `incoming request` line of the same '
    'reqId (its URL), in order, and counts only POST /jobs/KIND/run; it reads no request body, header or env value. '
    'Positive control (`--mode pre`), over a 30-minute window before deploy: at least one 422 (about 6 expected), proving the matcher sees launch failures. '
    'After deploy (`--mode post`), over 30 minutes, the run PASSES only if: every non-held kind has zero non-2xx responses (a 501, 422, 429, 5xx '
    'or any other non-2xx on scan, suggest-fix, or an unheld transcode is a failure); scan, transcode (MP4 creates) and suggest-fix each have at least one 2xx '
    '(from AC-11, `--require-2xx`); a 501 is excluded as held only on a kind whose line is `"" # held` (`--held-empty`, today intelligence-worker); '
    'a transcode 422 is excluded as held transcription only with `--guard-held-transcribe`, and only when the number of such 422s in the window equals '
    'the number of API container lines `transcribe: failed to launch job` in the same window whose 422 body carries the guard reason '
    '`TRANSCODER_MODE=transcribe is held on this guard` (F: one-to-one by count and window; the API prints the dispatcher\'s 422 body, which holds the '
    'guard\'s 403 reason, at apps/api/src/modules/recordings/routes.ts defaultTranscribeSpawner, first 300 chars kept by job-dispatch.ts; neither the guard '
    'nor the dispatcher logs a refusal itself, and the product API stores only "Could not start the transcription job", so no job-id pairing exists without a '
    'code change); a launch-failure line for any other reason, or without a readable timestamp, is a failure. Exit 0 PASS, 1 FAIL, 2 unreadable input. '
    'Verify by: pytest infra/release-harness/test_ac13_count.py, and in the live-test record both matcher runs (exact commands, windows, JSON output). '
    'Source: inferred: from ticket:GoodQA goodqa#16136 -- review C7, Sonnet item 7, and the v2.2 review notes E/E3/F') + t[j:]

rep("Source: inferred: from ticket:GoodQA goodqa#16136 -- main's coupling condition, so transcription never launches unheld in between",
    "If the whole-transcode hold fires, transcode is TARGET_MISMATCH for AC-11, AC-12 and AC-13 (no MP4 proof is possible), that is stated in the deploy "
    "note, and goodqa#16136 stays open until a release with GUARD_HELD_ENV support pins transcode. Source: inferred: from ticket:GoodQA goodqa#16136 -- "
    "main's coupling condition, so transcription never launches unheld in between; v2.2 review note E2")

rep("(a hold must not depend on an image being absent)",
    "(a hold must not depend on an image being absent)\n"
    "- AC-21: Pre-deploy rollback safety (E1). Before go, a read-only `docker image inspect` on the production host of each of the four JOB_IMAGE_* refs in "
    "the live compose (today's DO registry refs) is recorded on the ticket, and none resolves. If any resolves, stop: a rollback to the first release's "
    "backup restores those refs and that image could then launch unheld. Verify by: the recorded command and its four results in the deploy note. "
    "Source: inferred: from ticket:GoodQA goodqa#16136 -- v2.2 review note E1")

i = t.index('- NEG-15 (AC-20):'); j = t.index('\n', i)
t = t[:j] + ("\n- NEG-16 (AC-20): selfhost-ctl refuses, with a named error and no change, a compose JOB_IMAGE_* line whose value is empty (`\"\"` or `''`) "
    "without `# held`, a `# held` line whose value is not `\"\"`, `\"\"` or `# held` on scan or suggest-fix, and `--job-hold` of scan or suggest-fix. "
    "Verify by: pytest `test_empty_job_value_needs_marker_and_holdable_key` (6 cases), `test_held_empty_lines_on_holdable_keys_are_accepted`, "
    "`test_job_hold_refuses_a_non_holdable_kind` (2 cases). Source: inferred: from ticket:GoodQA goodqa#16136 -- v2.2 review note E4") + t[j:]
open(p, 'w').write(t); print('v2.3 written')
