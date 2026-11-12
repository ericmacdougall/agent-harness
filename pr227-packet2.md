# PR review packet 2 (delta for receipt r1): ops_watch forwards foreign critical ring events (agent-harness PR 227, GoodQA goodqa#15827)

Base: 42a5f99f06b4342d7cc3050d80d32e1f57c46016 (origin/main; use `--snapshot-base 42a5f99f06b4342d7cc3050d80d32e1f57c46016`). Head: bec229722865f1c6b327ea4c05c286d6efa48bc6 (branch af9e-opswatch-forward). Claude-authored: `--author-harness claude`. Previous packet: pr227-packet.md (head 184990d801a7f7bba45ffbbb0336d3b9b7ff4f28, receipt r1 = BLOCK). Everything in that packet still holds except where this delta says otherwise.
Delta commits: c8d1e2b1 (F1, F3, F4), bec22972 (a test and a mutant for the three-low-runs branch, the interval text, delta review reports).
Changed code paths in the delta: harness/hooks/ops_watch.py (forward_foreign, _parse_slots, emit), tests/test_ops_watch_forward.py, tests/mutants_ops_forward.py, notes/goodqa-15827/ (spec.md D3, D5, limits, review-opus-r1-delta.md, review-sonnet-r1-delta.md).

## Receipt r1 findings and fixes
- F1 (Medium-High): `read_ring` returns [] on any OSError, so one failed read after `fwd_seq` was set looked like a recreated ring, saved `fwd_seq` 0 and replayed up to 1024 rows into the digest and the deadman mail on the next good read. Fix (spec D5): an empty, missing-file or unreadable ring read after a forward is UNKNOWN: `forward_foreign` returns early and leaves `fwd_seq` and `fwd_active` as they are. A real reset needs a positive signal: the ring file's device and inode differ from the stored `fwd_ring`, or the visible top sequence stayed below the stored position on three consecutive runs (`fwd_low`, persisted); one low read (a torn newest slot) is not a reset. A first run with no ring file yet sets `fwd_seq` 0, so rows that appear later are all new.
- F2 (Medium): tests and mutants. New tests: the ring path is a directory then restored (nothing resent, position not lowered), an empty ring then restored (nothing resent), one torn newest slot (nothing resent), a clear made while the ring was unreadable (still forwarded afterwards), a ring truncated in place (same inode) is noticed on the third run. Mutants (18 of 18 plus origin/main fail): empty or unreadable read treated as a reset, one low read resets, three low runs never reset, ring reset ignored, and the earlier ones.
- F3 (Low): a clear row is forwarded for a key in `fwd_active` whatever its flags (an expiry clear from `expire_point_events` carries `detail.updated` and still closes the raise); the refresh skip now applies to RAISE rows only. Test and mutant: expiry clear skipped.
- F4 (Low, pre-existing, fixed because it was cheap): `emit()` now refuses a non-string host, source or key (ValueError), and `_parse_slots` skips a stored row that has one, so a row with an unhashable key can no longer crash `latest_by_key` at the top of `run_once`. Tests: an unhashable-key row in the ring and the emit check; mutants: emit accepts a non-string key, reader accepts a non-string key.

## Reviews of the delta
Opus adversarial at c8d1e2b1: ACCEPT (read-only static review plus the suite; holds: unknown reads keep the position, dev:inode reset, `fwd_low` persists because run_once always ends in save_state, a torn newest slot cannot lower the visible top because each write replaces the oldest slot, first-run and upgrade paths). Lows L5 to L7 (truncate in place or a reused inode is caught only by the three-run counter, which ops-watch's own writes can mask; read_ring precedes os.stat; a real truncate delays forwarding up to three runs) are stated limits; a ring epoch stored in the file would close them (follow-up tc-3681e74939600c170a7e6ec1c064effc). Sonnet acceptance: ACCEPT, with an ad-hoc in-place truncation delivered on the third run; its two asks were done in bec22972 (a committed test and a mutant for the three-low-runs branch; the stated interval corrected: the t2-dev ops-watch timer runs every 10 minutes, so a same-inode reset can delay a Fabric alert by up to about 30 minutes). Spec re-attached (comment 76881982). Stage acceptances, not PR signoff.

## Failing-first
`python3 -B tests/mutants_ops_forward.py`: origin/main and all 18 controlled broken variants fail the tests, none passes, none "not applied" (exit 0). The new empty-ring and unreadable-ring tests fail against the previous implementation (c8d1e2b1's parent 0f19e3b5 resets to fwd_seq 0 and resends).

Risk and rollback: revert the commits; the change only adds queue entries and now refuses to guess on an unreadable ring. Residual limits are in the spec Risks (ring epoch L5 to L7, source dropped from the queued copy, foreign host label, key cap).

## Validation (exact head bec229722865f1c6b327ea4c05c286d6efa48bc6, code as at c8d1e2b1 plus tests, run in the owner worktree)
$ python3 -B -m unittest tests.test_ops_watch tests.test_ops_watch_point_events tests.test_ops_watch_forward tests.test_ahd tests.test_ah_ahd_writes tests.test_alerts_disposed_owner tests.test_dispose_guard
Ran 269 tests in 190.092s
OK (skipped=1)
exit 0
(run at c8d1e2b1; bec22972 adds one test in the forwarding suite, which then ran: `python3 -B -m unittest tests.test_ops_watch_forward` Ran 20 tests, OK)
$ python3 -B tests/mutants_ops_forward.py
origin/main (no fix) FAILS (good); all 18 broken variants FAILS (good); none PASSES, none NOT APPLIED; exit 0
