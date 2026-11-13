# PR review packet 3 (delta for receipt r3): the guard blocks shell reads of the GoodQA token and lease keys (agent-harness PR 221, GoodQA goodqa#15785)

Base: 1bce208c9c4594d8fb516c5a501d559d043e0da8 (origin/main, the merge of PR 228, and the merge base; use `--snapshot-base 1bce208c9c4594d8fb516c5a501d559d043e0da8`). Head: da424fdef6d7c193a9164ae52784b2fade820c81 (branch af9e-gq-credential-paths; a plain merge of origin/main 1bce208c into ea36daa29929937f9b7021d7c252ea3411784e65, which carries the r3 fixes; no history rewritten, no conflict). Claude-authored: `--author-harness claude`. Previous packets: pr221-packet.md (a65fdcbd, r1 BLOCK), pr221-packet2.md (b3d900ef, r3 BLOCK on the exact head). Everything in them still holds except where this delta says otherwise.
Delta commits since b3d900ef: 3c5f458d (r3 F1 and F2), ea36daa2 (two gaps found by an independent attack review of 3c5f458d), da424fde (the merge of main).
Changed code paths in the delta: harness/hooks/command_guard.py (read_creds, _local_destinations, _grep_directories_recurse, the per-tool skip_next sets, the no-existing-path working-directory check), tests/test_command_guard_gq_credentials.py, tests/mutants_gq_credentials.py, notes/goodqa-15785/spec.md.

## Receipt r3 findings and fixes
- F1 (Medium, over-blocks): the ancestor-or-equal directory rule ran on copy and archive destinations, so `scp host:f ~/`, `rsync -a host:x/ ~/`, `wget -P ~ URL`, `tar -xzf p.tgz -C ~` and `tar -xf x -C /` were refused as credential reads. Fix: the rule applies to SOURCE operands only. `_local_destinations` skips: the last operand of scp, rsync and sftp; the values of `wget -P/-O` and `curl -o/-D/-c`; every operand of tar, bsdtar, gtar and pax in extract or list mode (new-style `-xzf` and old-style `tar xzf`, including `-C DIR`); the output archive of zip and 7z. tar in create mode keeps `-C DIR` as a source. The skipped words are still judged as files by name (a credential file as an operand still blocks). Neighbour tests (they failed first): the five commands above plus `scp host:file .`, `rsync -a host:dotfiles/ ~/`, `rsync -a host:x/ ~/.config/`, `wget --directory-prefix=~`, `curl -o ~/x.txt`, `tar tf`, `tar -tf p.tgz -C ~`, `bsdtar -xf x.tar -C ~`, `pax -r -f x.tar`, `unzip x.zip -d ~`, `zip ~/out.zip project.txt`.
- F2 (Low): a no-path search slipped through when an option takes a separate value. Fix: the per-tool option lists (rg -t, -T, --type, --max-depth, -j, -M and more; grep -d, -D, --exclude-dir; ag --depth) and `grep -d recurse` and `--directories=recurse` as recursive; and, found by the attack review, a fail-closed rule instead of ever-growing lists: a recursive search whose operands include NO existing path (or none at all) is also judged on the working directory, so any option I do not list (`rg --color always tok`, `rg --engine pcre2 tok`, `grep --binary-files text tok`, `ag --color-match 1 tok`, `ack --ignore-dir x tok`) cannot hide it. Tests for each, and neighbours that stay allowed (`cd ~ && rg --hidden tok /tmp`, `cd ~/project && rg --engine pcre2 tok`, a count-only search, a piped rg).
- Found by an independent attack review of 3c5f458d and fixed in ea36daa2 (both with tests that failed first): `zip -r - DIR` and `7z a -so x DIR` (the bare `-` and the 7z placeholder were taken as the archive and the credential directory skipped as a destination): zip treats a bare `-` as the archive operand, 7z skips only the archive word after its command letter and judges everything after it.
- F3 (evidence): the real output is attached below, at the exact code (ea36daa2; da424fde adds only the merge of main, after which `python3 -B -m unittest tests.test_command_guard_gq_credentials tests.test_worktree_inuse` ran 25 tests OK).
- Stated limits (spec Risks, unchanged in kind): `cp -r`, `cp -R` and `ditto` of either directory and a later read of the copy in another command; names fed through a pipe (`find DIR | cpio -o`, `find DIR -type f | xargs cat`); a script walking the directory; `cd -`; the implied-target gap for `~/.ssh` and `~/.aws` (tc-86300f3467037db6c7b7cf1d28b64f33); a file literally named like the pattern that exists in the working directory defeats the existing-path test (accident prevention, not an access control).

## Reviews
Opus adversarial attack review of 3c5f458d: BLOCK (the zip and 7z stdout gap, the unlisted option values), both fixed in ea36daa2; read-only static review plus about 40 forms through check(); it also confirmed that the F1 destinations are allowed and that create mode is never read as extract mode (`tar --crea`, `tar cf`, `tar -c -f - -C ~/.config goodqa`, `pax -w -x ustar`, `bsdtar -c` all block). No review ran at ea36daa2 or da424fde: this packet and its receipt are the final check of the delta (stage acceptances earlier, not PR signoff).

## Validation (real output, owner worktree, code at ea36daa29929937f9b7021d7c252ea3411784e65)
$ python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup tests.test_command_guard_gq_credentials tests.test_worktree_inuse tests.test_worktree_hooks_rule tests.test_ah_worktree_remove
Ran 327 tests in 266.432s
OK (skipped=2)
exit 0
$ python3 -B tests/mutants_gq_credentials.py   (exit 0; every line is FAILS (good); none PASSES, none NOT APPLIED)
origin/main (no change) FAILS (good)
token regex removed FAILS (good)
key regex removed FAILS (good)
samples removed FAILS (good)
parent directories removed FAILS (good)
recursive readers ignore the parents FAILS (good)
archives not treated as walking FAILS (good)
walkers ignore a key directory inside FAILS (good)
destinations are judged like sources FAILS (good)
no destinations are recognised FAILS (good)
tar extract mode is not recognised FAILS (good)
the last scp operand is not a destination FAILS (good)
grep -d recurse is not recursive FAILS (good)
zip - is not the archive operand FAILS (good)
7z sources after the archive are skipped FAILS (good)
an unlisted option value does not fail closed FAILS (good)
search with no path operand not judged FAILS (good)
no-path search ignores a key directory as cwd FAILS (good)
grep exempt when piped FAILS (good)
rg --files treated as a print FAILS (good)
pax and compressors not treated as archives FAILS (good)
archives not dispatched to the credential check FAILS (good)
copy tools ignore the parents FAILS (good)
find -exec ignores the parents FAILS (good)
key directory contents not covered FAILS (good)
(25 checks: origin/main and 24 broken variants. The per-tool skip_next list entries have no mutant of their own: the fail-closed working-directory rule makes removing an entry unobservable, so they are defence in depth.)
$ python3 -B -m unittest tests.test_command_guard_gq_credentials tests.test_worktree_inuse   (at da424fde, after the merge of main)
Ran 25 tests in 4.568s
OK (skipped=1)
exit 0

Risk and rollback: revert the commits; the change only adds refusals for commands that name these two directories, a recursive search from inside or above them, or an archive or copy that reads them.
