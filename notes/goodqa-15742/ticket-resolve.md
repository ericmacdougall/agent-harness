Follow-up to goodqa#15742 (ah install-files), spec review finding. A host with an unfinished run refuses every new install until `--resume RUN_ID` or `--rollback RUN_ID` succeeds. If neither can (both backup copies missing or tampered, host rebuilt) only a hand edit of install-audit.jsonl frees it.

Proposal: main-only `ah install-files --resolve RUN_ID --ticket T --reason R`: read every live sha on the host, append a definite `resolved` row only when each file matches that run's old or new sha (or is absent where the run created it), otherwise refuse and name the file.

Acceptance: tests for matching, mismatching, absent-created and tampered-backup cases; a mutant that resolves without comparing shas; NEG for a non-main caller.
