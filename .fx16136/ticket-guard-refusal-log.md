Follow-up from goodqa#16136 (spec v2.3 AC-13, review note F; filed at the lead's request).

Problem: neither the job-dispatcher create-guard nor the dispatcher logs a create refusal.
- The guard answers HTTP 403 with `job-dispatcher-create-guard: refused (<reason>)` (apps/job-dispatcher/src/create-guard.ts, around lines 794 and 823) and writes nothing to its log.
- The dispatcher returns 422 `{error}` (server.ts:171) without logging the message.
- Fastify's `request completed` line carries only the status code.
- The product API stores only the fixed text "Could not start the transcription job".

So AC-13 can exclude a held transcription only by pairing its count, in a time window, with the API's `transcribe: failed to launch job` lines (recordings/routes.ts, defaultTranscribeSpawner). That pairing cannot match each refusal to its job.

Proposed change: the guard writes one JSON line to stdout for each refusal, with the reason and the requested image's kind. Optionally it also adds the attachment or run id from the create request's Cmd args, which are not secret. It must never write an Env value. ac13-count.py `--refusals` would then pair one-to-one by line instead of by count.

Acceptance:
- A refused create produces exactly one log line naming the reason.
- No Env value appears in that line (a test with a fake value proves it).
- The matcher pairs refusals by line.

Constraints:
- This moves PR 1369 (bugtracker fix/16136-guard-held-env, currently 3e478c28).
- Main decides whether and when.

Source: wal: lead af3f19d2 relay, 2026-11-16 ("File (a), guard logging per refusal, as a follow-up ticket linked from #16136"). This is not the user's request.
