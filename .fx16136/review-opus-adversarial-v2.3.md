# Adversarial delta review: goodqa#16136 spec v2.3 (delta only)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15

Inputs (verified):
- `spec-v2.2-to-v2.3.diff`, sha256 `cb71b07b0db02357f63589ad8b1388b3b2b72ccbcd7aba7609f51ee94a7be943`
- `spec-16136-v2.3.frozen.md`, sha256 `e10a03d4e834a4fe4d67ba826b839007c2bcc53007328db944dfb5f3a91717e2`
- the author's live `.fx16136/spec-16136-v2.md`, same sha256 before recording

Code read (read-only, t2-dev): bugtracker `infra/release-harness/ac13-count.py` at 18fa30fb (its docstring, `launches`, `refusal_count`, `main`).

No production access. No probes.

## Verdict: ACCEPT (recorded against core 0de4b5ea), with build notes G1 to G3

## AC-13, note F: can a non-held transcode failure hide in the pairing?

In the steady state, no:
- A non-held MP4 transcode 422 adds one to the dispatcher's transcode-422 count. It produces no API line that has both the `transcribe: failed to launch job` prefix and the guard-hold reason: its spawner logs a different prefix, and its body carries a docker or daemon reason.
- The counts then differ, and the run FAILs.
- A guard false-positive on an MP4 create also fails: it would carry the reason but not the `transcribe:` prefix.
- A 429 or 5xx on transcode is a non-2xx on an unheld kind, so it fails.
- Users cannot inject the reason text: it comes from a fixed server-side string.

Two holes remain, and both come from pairing by count with the same window applied independently to two logs:

- **G1 (window boundary; can hide one failure).** The dispatcher's `request completed` time and the API's log time for the same launch differ by milliseconds to seconds.
  - Suppose a held-transcription launch has its dispatcher 422 just before `--since`, so it is not counted, while its API line falls just after, so it is counted.
  - Suppose also that a non-held MP4 422 falls inside the window.
  - Then transcode 422 = 1 and API held lines = 1. The counts are equal and the MP4 failure is excluded as held.
  - The same can happen at `--until`.
  - Fix: pair one-to-one by time. Each counted transcode 422 must be matched greedily to a distinct API held line within a stated tolerance (for example ±5 s), and any unmatched record on either side is a failure. Equivalently, widen the API window by the tolerance and require every dispatcher 422 to find its partner. Add a pytest for the boundary swap.
- **G2 (replicas; fails closed, but falsely).** The api service runs two replicas. `--refusals` takes one log, so `docker logs` of one container misses the other replica's lines. The count then mismatches and the run FAILs although everything is held. Use `docker compose logs --timestamps api` (both replicas) or one `--refusals` per replica, and have the JSON output record how many replica logs were read.

Neither hole affects safety: transcription stays held by the guard either way. G1 matters because AC-13 is acceptance evidence that could pass while one MP4 launch failed. That is unlikely, since it needs a coincidence within seconds of a boundary, and it is a build-time fix.

## AC-21 (no DigitalOcean (DO) ref resolves before deploy): sound

Inspecting the exact ref string is sufficient. On the containerd store, a `repo@digest` resolves only through a same-repo name record (probe P2 and P3 in my v1 review), and the guard matches the exact string. So a DO image present under some other name could neither pass this check nor be launched through that ref. The stop-if-any-resolves rule is the right action.

## NEG-16 (E4): mostly closed, one gap

- **G3.** NEG-16 refuses `""` and `''` without `# held`. Other YAML forms also resolve to empty or unset:
  - a bare `KEY:` (YAML null)
  - `~`
  - `null`
  - a `${VAR}` or `${VAR:-}` interpolation that resolves empty

  In compose environment maps, a null value means "take it from the invoking shell". Under `sudo` that value is usually absent, so the variable is unset. zod then defaults it to `''`, making the kind silently held without a marker, or unexpectedly pinned if the variable exists.

  Fix:
  - Refuse every value form other than a quoted `goodqa-JOB@sha256:<64 hex>` or `"" # held`.
  - Have the real-compose test assert that each resolved JOB_IMAGE_* value on both services is either the pin or `""`, with the marker present in the text.
  - Add the cases `KEY:`, `KEY: ~`, `KEY: null` and `KEY: ${X:-}` to `test_empty_job_value_needs_marker_and_holdable_key`.

## Rest of the delta

- AC-17's E2 text is closed: under a whole-transcode hold, transcode is TARGET_MISMATCH and the ticket stays open.
- AC-13 now fails on any non-2xx for non-held kinds and accepts a 501 only for a held-empty kind (E3 closed).
- Renaming the hold test to `…empties_line…` matches what it asserts (D).
- `--guard-held-transcribe` and `--held-empty transcode` are made mutually exclusive in code (lines 97-98), which is correct.

## Not examined

- the rest of 18fa30fb (only ac13-count.py was read)
- `test_ac13_count.py`
- production
