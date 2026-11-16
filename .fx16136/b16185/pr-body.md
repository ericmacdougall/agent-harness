## goodqa#16185: a docker failure message carries a category, never stderr

A failed `docker run` used to send docker's stderr, or `err.message`, to three places: the 422 body, the API log and the job's `lastErrorMessage`. Both can echo the full argv, and the argv holds every `-e KEY=VALUE` job secret.

### Change (apps/job-dispatcher)
- `describeDockerFailure` always produces `docker run failed: CATEGORY (stderr N bytes)`. CATEGORY is one of `guard_refused`, `image_not_found`, `invalid_reference`, `daemon_unreachable` or `other`.
- At most one allow-listed first line is appended:
  - **Held-mode guard refusals** are rebuilt from constants, so the hold reason survives exactly. goodqa#16136 AC-13 pairs on that text.
  - **Any other allowed line:**
    - secret-source values are removed from the full stderr, longest first;
    - the line is dropped if any 8-byte window remains of a value in raw, base64 (three alignments), hex, JSON-escaped or decimal-byte form, or with backslashes removed;
    - it is also dropped if a value under 8 bytes appears as a whole token, or if the line holds non-ASCII;
    - what survives is cut to 200 characters.
- Only the dispatcher's base env for the kind counts as a secret source. The server passes those values, and the caller's allow-listed request env is never redacted (goodqa#16148 P1). If `dockerRunDetached` is called without a list, every env value is treated as secret.
- `err.message` and `err.cmd` are never used. The log for an unexpected error carries the error name only.

### Tests (t2-dev)
- Dispatcher suite: `npx vitest run` -> 315 passed, 14 skipped. `npx tsc --noEmit` -> exit 0.
- `test/docker-failure-message.test.ts`: 34 failures on origin/main e9449087, 0 after the fix.
- NEG-5: two broken variants each fail the suite. Returning `err.message` gives 15 failures; logging the merged env on a refusal gives 1.
- Real engine: the real dispatcher, the real docker CLI and the real create-guard with a hold were run on t2-dev. The held refusal returns a 422 with the exact held text, and no 8-character window of the fake marker appears in any body or log line.

### Residual risk and deferrals
- Residual risk, accepted in the spec: a secret under 8 bytes that sits inside a longer token is not detected.
- Deferred by the lead's ruling Q1: the cross-constant test, which matches the real held reason from held-env.ts through the real guard against goodqa#16136 ac13-count.py HELD_TAG. It is a pre-merge condition of the first PR to land after goodqa#16136 1369 and 1371. In this PR the held text is a literal.

Refs: GoodQA #16185, GoodQA #16148 (spec v4, AC-7, NEG-5, NEG-11, NEG-17)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_011PwJaRQM1UYqY3vZNrYjVv
