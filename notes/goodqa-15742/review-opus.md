# Spec review (adversarial) of goodqa#15742 spec (ah install-files)

Reviewer: native agent a0c568dfa08e7eb86 (Opus), WAL ids w9763fa270d1 (first pass, BLOCK: H1 merged code not enforced, H2 a rerun accepts the breakage of an unknown outcome, M1 to M7, lows), w6ab35c503d8 (v2, BLOCK: H1 still open because the proof and the bytes came from the caller's object store, which git does not hash-check on read), and the v3 confirmation (ACCEPT).
Final text reviewed: v3 at 1db08bfb plus the fresh-repository-per-run change that answers the reviewer's last medium (a fetch into an existing cache skips objects it holds, so a pre-planted forged parent commit would pass) and the AC-5 start-row wording; the spec at the attached sha is the final text.

Findings closed by testable ACs and NEGs: H1 (no --repo, fresh fetched repository, fsckObjects, commit graph off, re-hashed objects), H2 (unfinished-run refusal, --resume with the original baseline), M1 (deny probes, genuinely broken guard fixtures), M2 (two-phase install, guard last), M3 (rollback only over the run's own new sha), M4 (one quoted remote command), M5 (.ah-install subdirectory, atomic stale lock takeover), M6 (required ticket, main-only through AC-9, A2 for main to confirm), M7 (interrupted auto-rollback is unknown). AC-9 is stated as accident prevention.

Verdict: ACCEPT
