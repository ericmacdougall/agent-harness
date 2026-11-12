# PR review packet 2 (delta for receipt r1): the guard blocks shell reads of the GoodQA token and lease keys (agent-harness PR 221, GoodQA goodqa#15785)

Base: 617cfed675c5f66e0ec8a892f69a11cfa8209b84 (merge base with origin/main; use `--snapshot-base 617cfed675c5f66e0ec8a892f69a11cfa8209b84`). Head: bfc145253ea6e5c18c86e98d10d045f6ec59b725 (branch af9e-gq-credential-paths). Claude-authored: `--author-harness claude`. Previous packet: pr221-packet.md (head a65fdcbd331382437f77fe73cfd1707b89901869, receipt r1 = BLOCK). Everything in that packet still holds except where this delta says otherwise.
Delta commits since a65fdcbd: 3c2f6549 (F1, F2), f7dcb5b7 and 41a7c1e0 (gaps found by the two delta reviews), b0311fc6 and bfc14525 (spec text and review reports only).
Changed code paths in the delta: harness/hooks/command_guard.py (policy list credential_parent_dirs, Compiled.cred_parent_dirs, under_cred_parent, read_creds, the find -exec branch, ARCHIVE_CMDS and its dispatch, _count_only), tests/test_command_guard_gq_credentials.py, tests/mutants_gq_credentials.py (new), notes/goodqa-15785/ (spec.md, review-opus-r1-delta.md, review-sonnet-r1-delta.md).

## Receipt r1 findings and fixes
- F1 (Medium, credential leak): recursive readers of the two parent directories (`~/.config/goodqa`, `~/.agent-harness/gq-browser`) still printed the token and lease keys. Fix: a policy list `credential_parent_dirs` (additive only, like the other credential lists). A directory that holds a credential among harmless files is refused (secret_dump, rule credential-file) to: a recursive grep, rg, ag or ack naming it, its ancestor or a key directory (`gq-browser/<16 hex>`) inside it; a find -exec reader on it; an archive or compressor given it (tar, bsdtar, gtar, pax, zip, 7z, cpio, gzip, bzip2, xz, zstd); a copy tool (scp, rsync, curl). Count-only searches (`grep -rc`, `rg -c`, `-l`, `--files`), `ls`, `find -name`, `config.json` and the lease file stay allowed.
- F2 (Low): every blocking test now asserts the `[secret_dump/` rule id, not only the verdict.
- Found by the delta reviews and fixed (all with tests that failed before): a recursive search with NO path operand searches the working directory, so it judges the working directory (`cd ~/.config/goodqa && rg .`, `cd ~ && grep -r tok`, a key directory as cwd); only a piped `rg`, `ag` or `ack` is exempt (it reads stdin), GNU `grep -r` is judged even in a pipeline; a key directory inside gq-browser is judged for walkers, archives and copy tools; `bsdtar` and `pax` were never dispatched to the credential check (now are); `rg --files` counts like `-l`.
- Stated limits (spec Risks, plainly): `cp -r`, `cp -R` and `ditto` of either directory to a readable place and a read of the copy in another command (a copy is not a print); names fed through a pipe (`find DIR | cpio -o`, `find DIR -type f | xargs cat`); a script walking the directory (`python3 -c` with `os.walk`); a glob inside an already known key directory; `cd -`; and the implied-target gap for the OTHER credential directories (`~/.ssh`, `~/.aws`), which this change does not close (follow-up tc-86300f3467037db6c7b7cf1d28b64f33). This is accident prevention, not an access control.

## Reviews of the delta
Opus adversarial: BLOCK at 3c2f6549 (H1 the no-path search, M1 cpio, M2 bsdtar and pax, M3 xargs), ACCEPT at f7dcb5b7 (about 45 forms, text only) with lows L1 (a piped GNU grep) and L2 (rg --files) fixed in 41a7c1e0. Sonnet acceptance: BLOCK at 3c2f6549 (a key directory not judged), BLOCK at f7dcb5b7 for one argument (the working directory judged without the key-directory rule), with the stated condition that adding it with tests and mutants green counts as ACCEPT with no further round; done in 41a7c1e0 and recorded as ACCEPT on that basis; no review was rerun at 41a7c1e0. Spec re-attached (comment 84f6acb8). Stage acceptances, not PR signoff.

## Failing-first
`python3 -B tests/mutants_gq_credentials.py`: origin/main and 16 controlled broken variants each fail the tests (17 of 17, none "not applied"): token regex removed, key regex removed, samples removed, parent directories removed, recursive readers ignore the parents, search with no path not judged, key directory as cwd ignored, grep exempt when piped, rg --files treated as a print, walkers ignore a key directory, archives not treated as walking, pax and compressors not treated as archives, archive tools not dispatched, copy tools ignore the parents, find -exec ignores the parents, key directory contents not covered. The directory forms in the new tests failed on the previous heads (12 of 13 on a65fdcbd, 8 more on 3c2f6549, the cwd and key-directory forms on f7dcb5b7).

Risk and rollback: revert the commits; the change only adds refusals for commands that name these two directories, a recursive search from inside or above them, or an archive or copy of them.

## Validation (exact head bfc145253ea6e5c18c86e98d10d045f6ec59b725, code as at 41a7c1e0, run in the owner worktree)
$ python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup tests.test_command_guard_gq_credentials
Ran 232 tests in 90.295s
OK
exit 0
$ python3 -B tests/mutants_gq_credentials.py
origin/main (no change) FAILS (good); all 16 broken variants FAILS (good); none PASSES, none NOT APPLIED; exit 0
