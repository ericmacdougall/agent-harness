# PR review packet 2 (delta for receipt r1): the guard refuses scp and rsync into a remote harness path (agent-harness PR 219, GoodQA goodqa#15759)

Base: 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b (origin/main; use `--snapshot-base 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b`). Head: e1c2c6c551988a82f562d86ce07a9e1e0d73e722 (branch af9e-scp-gap). Claude-authored: `--author-harness claude`. Previous packet: pr219-packet.md (head 9dd379243f67dd7b6b8549c3e6d3e8c5dbcaac4b, receipt r1 = BLOCK). Everything in that packet still holds except where this delta says otherwise.
Delta commits: c2d3377f (F1 to F3), e1c2c6c5 (sshpass -P from the delta review, plus review reports).
Changed code paths in the delta: harness/hooks/command_guard.py (remote_copy_dest, _relative_tail, RSYNC_VALUE_FLAGS, WRAPPERS_SIMPLE, WRAPPER_VALUE_OPTS, the wrapper branch), tests/test_command_guard_scp_dest.py, tests/mutants_scp_dest.py, notes/goodqa-15759/ (spec.md AC-1, review-opus-r1-delta.md, review-sonnet-r1-delta.md, ticket-heuristic-parents.md).

## Receipt r1 findings and fixes
- F1 (High): `rsync -R`, `--relative` and `--files-from` rebuild the source path under the destination, so `rsync -R .claude/hooks/command_guard.py t2-dev:` wrote the incident file while only `~` and `~/command_guard.py` were judged. Fix: for rsync with `-R`, `--relative` or `--files-from`, `dest + '/' + source tail` (cut at the first `/./` marker, a leading `/` and `./` stripped) is judged as both a named target (log and unknown tiers) and a write root (ancestor tier for a recursive copy); `--files-from` (the sources are in a file the guard cannot read) is judged as hidden: the destination itself is a write root, so a harness location or its ancestor is refused while `proj/` and `/tmp/` pass. BLOCKED tests: all four forms of the receipt plus `--relative`, a `/./` marker and two `--files-from` forms; ALLOWED: `rsync -R src/app.py host:~/proj/`, `rsync -aR ./proj/x.py host:~/`. Mutants: `-R` path not rebuilt, `--files-from` not hidden.
- F2 (Low): `sshpass` is unwrapped like `sudo` (WRAPPERS_SIMPLE, its `-p`, `-P`, `-f` and `-d` values skipped; `-e` takes none). Tests: sshpass with -p, -f, -e and -P blocked, an sshpass download and an sshpass copy to /tmp allowed. Mutants: sshpass not unwrapped, prompt value not skipped. The independent delta review found `-P` missing in c2d3377f; fixed in e1c2c6c5.
- F3 (Low): the missing rsync value flags are added (`--zc`, `--zl`, `--compress-choice`, `--log-file-format`, `--copy-as`, `--checksum-seed`, `--max-alloc`, `--early-input`, `--dparam`, `-@`); `rsync --zc zstd host:~/.claude/hooks/command_guard.py ./` is a download and passes. Mutant: compress-choice value not skipped. The operand-position heuristic itself (a remote operand after a local one is an upload target) is KNOWN and ticketed with local `cp --parents` as tc-1f84b2d5587016b4a9b21bca3fcab869. One BLOCKED form that relied on `--max-alloc` as an unknown flag now uses `--some-future-opt 1G`.

## Reviews of the delta
Opus adversarial (read only, about 40 extra forms, plus one harmless dry-run rsync in t2-dev /tmp): ACCEPT at c2d3377f, no bypass of the -R handling (tails, /./ markers, .., //, ~/./, globs, quotes, two sources, absolute sources), no false positives, one low (sshpass -P) fixed afterwards; GNU rsync 3.2.7 on t2-dev rejects abbreviated long options, so `--relat` stays allowed. Sonnet acceptance of the amended AC-1: ACCEPT. Spec re-attached (comment f5ae7db1). Stage acceptances, not PR signoff.

## Failing-first
`python3 -B tests/mutants_scp_dest.py`: origin/main (no fix) fails the tests, and all 20 controlled broken variants fail the tests, none passes (16 earlier, now 20 with the -R, files-from, sshpass and compress-choice variants and the sshpass prompt variant).

Risk and rollback: revert the commits; the rule only adds refusals for scp and rsync with a remote destination that names protected harness paths, plus unwrapping sshpass. Disclosed limits unchanged (sftp batch, tar over ssh, a variable in the remote path, a directory source not expanded); the guard is accident prevention, not an access control.

## Validation (exact head e1c2c6c551988a82f562d86ce07a9e1e0d73e722, run in the owner worktree)
$ python3 -B -m unittest tests.test_command_guard_scp_dest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup
Ran 232 tests in 102.419s
OK
exit 0
$ python3 -B tests/mutants_scp_dest.py
origin/main (no fix) FAILS (good); all 20 broken variants FAILS (good); none PASSES
