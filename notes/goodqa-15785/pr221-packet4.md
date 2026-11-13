# PR review packet 4 (rescue delta for receipt r4): the guard reads search, tar and copy options the way the tools do (agent-harness PR 221, GoodQA goodqa#15785)

Base: 1bce208c9c4594d8fb516c5a501d559d043e0da8 (origin/main and the merge base; use `--snapshot-base 1bce208c9c4594d8fb516c5a501d559d043e0da8`). Head: d6098dc0efef3bb52770ba0a51cfaa79bd63d6d7 (branch rescue-221-gq-creds, one commit on top of da424fdef6d7c193a9164ae52784b2fade820c81, the r4-reviewed head of af9e-gq-credential-paths; no history rewritten). Claude-authored (rescue at Opus high): `--author-harness claude`. Previous packets: pr221-packet.md (r1), pr221-packet2.md (r3), harness-pr221-packet3.md (r4, BLOCK at da424fde). Everything in them still holds unless this delta says otherwise.
Delta commit: d6098dc0 fix(command_guard): parse search, tar and copy options like the tools.
Changed code paths: harness/hooks/command_guard.py (new `OptScan`, `_scan_options`, the per-tool option tables `SEARCH_TABLES` and `_COPY_TABLES`, `RECURSIVE_SEARCHERS` and `_tar_mode`; in the guard class, the search branch of `read_creds`, `_count_only`, `_grep_recursive_long`, `_grep_directories_recurse`, `_local_destinations` for scp/rsync/sftp and tar/pax, and the count-only check for a credential on stdin), tests/test_command_guard_gq_credentials.py, tests/mutants_gq_credentials.py, notes/goodqa-15785/spec.md (AC-1 and Risks).

## Validation (real output from the rescue worktree, code at d6098dc0efef3bb52770ba0a51cfaa79bd63d6d7)
$ python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup tests.test_command_guard_gq_credentials tests.test_worktree_inuse tests.test_worktree_hooks_rule tests.test_ah_worktree_remove
Ran 332 tests in 115.238s
OK (skipped=2)
exit 0

$ python3 -B tests/mutants_gq_credentials.py   (origin/main plus 48 broken variants; every line must say FAILS (good))
```
origin/main (no change)                    FAILS (good)
token regex removed                        FAILS (good)
key regex removed                          FAILS (good)
samples removed                            FAILS (good)
parent directories removed                 FAILS (good)
recursive readers ignore the parents       FAILS (good)
archives not treated as walking            FAILS (good)
walkers ignore a key directory inside      FAILS (good)
destinations are judged like sources       FAILS (good)
no destinations are recognised             FAILS (good)
tar extract mode is not recognised         FAILS (good)
the last scp operand is not a destination  FAILS (good)
grep -d recurse is not recursive           FAILS (good)
zip - is not the archive operand           FAILS (good)
7z sources after the archive are skipped   FAILS (good)
an uncertain search is not judged on the cwd FAILS (good)
an uncertain search judges only operands   FAILS (good)
an unknown long option is certain          FAILS (good)
an unknown short letter is certain         FAILS (good)
long option values are not free words      FAILS (good)
short option values are not free words     FAILS (good)
a separate long value is not consumed      FAILS (good)
an attached value letter takes the next word FAILS (good)
a value letter never takes the next word   FAILS (good)
an attached pattern option is not seen     FAILS (good)
a long pattern option is not seen          FAILS (good)
count-only reads letters of values         FAILS (good)
count-only trusts an uncertain scan        FAILS (good)
grep --dereference-recursive is not recursive FAILS (good)
grep -d abbreviations are not recursive    FAILS (good)
pt is not recursive                        FAILS (good)
tar value letters do not end a cluster     FAILS (good)
tar create abbreviations not seen          FAILS (good)
tar read abbreviations not seen            FAILS (good)
tar two modes read as one                  FAILS (good)
tar old-style first word ignored           FAILS (good)
copy option values are operands            FAILS (good)
copy destination skipped without a real source FAILS (good)
a word after an unknown copy option is a source FAILS (good)
a remote operand is not a source           FAILS (good)
search with no path operand not judged     FAILS (good)
no-path search ignores a key directory as cwd FAILS (good)
grep exempt when piped                     FAILS (good)
rg --files treated as a print              FAILS (good)
pax and compressors not treated as archives FAILS (good)
archive tools not dispatched to the credential check FAILS (good)
copy tools ignore the parents              FAILS (good)
find -exec ignores the parents             FAILS (good)
key directory contents not covered         FAILS (good)
```
exit 0 (49 lines, all FAILS (good); none PASSES, none NOT APPLIED)

Failing first. The new test file was copied into a tree of the old guard; these are the real last lines.
- At da424fde (the r4 head), `python3 -B -m unittest tests.test_command_guard_gq_credentials` gives `FAILED (failures=38)`:
  - 18 in the pattern and flag parsing group;
  - 9 in the unknown-option-before-a-path group (r4 F1);
  - 5 single copy operands (r4 F3);
  - 3 tar create cases (r4 F2);
  - 3 neighbours that da424fde over-blocks: `tar -xzfarchive.tgz -C ~`, `tar --extr -f x.tar -C ~` and `rsync -a host:x/ ~/ --log-file /tmp/rsync.log`.

  The commit message says 37. One more attack test (`--lab --max-count`) was added after that count was taken and before the commit.
- At b3d900ef (the r3 head), the same run gives `FAILED (failures=71)`. That includes all 13 r3 F2 no-path option cases, the 11 unlisted-option cases and the 9 r3 F1 destination neighbours (`scp host:file ~/`, `tar -xzf pkg.tgz -C ~` and the rest). The r3 attacks are therefore still covered at the rescue head.
- Some tests also pass on da424fde: `cd /tmp && grep -r --regexp=token DIR`, `tar -f - -c -Vt DIR`, `pax -rw DIR /tmp/x`, `rsync -a /tmp/ ~/` and similar. They are regression tests, and each one kills a mutant.

## Receipt r4 findings and how they are closed

### F1 (material; same class as r3 F2)

The finding: an unknown option followed by an existing path stopped the working-directory check. The fix no longer lists option values; an unknown option now fails closed.

How the new parse works:
- `_scan_options` walks the arguments the way getopt does, with a per-tool table. Tables exist for grep (the union of GNU and BSD grep), rg, ag and ack.
- A recognised option that takes a value consumes it, whether the value is separate or attached (`-etok`, `-rnA3`, `--regexp=PAT`).
- The first free word is the pattern, unless an option supplied one.
- Any option that is not in the table makes the scan uncertain. That covers an unknown letter, an unknown long name, an abbreviation (`--group`, `--regex=`) and an optional-valued option given without `=` (BSD `--context`, ag `-A`/`-B`/`-C`, ack `-C`).
- When the scan is uncertain, `read_creds` judges every free word. That includes the presumed pattern and the values that recognised options took after the unknown one. Example: in `grep -r -e tok --lab -m DIR`, `--lab` takes `-m` as its value, so grep searches DIR.
- An uncertain recursive search is also judged on the working directory, whatever its operands.

A missing table entry can therefore only over-block. It can never hide a path.

Tests for F1:
- `cd ~ && grep -r -e tok --group-separator /tmp`
- `cd ~ && grep -r --group-separator x --group-separator /tmp tok`
- `cd ~ && rg -uu -e tok --hostname-bin /bin/hostname`
- `cd ~ && grep -r --group /tmp tok`
- `cd ~ && grep -r -e tok -Q /tmp`
- `cd ~ && ag --color-ma 1 tok /tmp`
- `cd ~ && ack --ignore-d x tok /tmp`
- `cd ~ && rg -e tok -g /tmp`
- the two `--lab` forms, run from /tmp

### Other gaps of the same class, found while closing F1

Each one is fixed, and each one's test fails at da424fde.
- An attached pattern made the guard read the path as the pattern. `grep -e. TOKEN`, `grep -ie. TOKEN`, `rg -e. TOKEN` and `grep --regex=. TOKEN` printed the token and were allowed. This affected every credential file, not only the GoodQA ones.
- `cd /tmp && grep -r -etoken DIR` was allowed.
- Count-only letters were read from option values. Affected: `grep -r -ec DIR`, `grep -r -e --count . DIR`, `rg -e --files . DIR`, `grep -r --lab -c . DIR`, and the stdin path `grep -ec < TOKEN`.
- grep did not count `--dereference-recursive`, `--recur`, `--dir=rec` or `-drec` as recursive.
- pt walks directories by default but was treated as non-recursive (`pt tok DIR`, `cd ~ && pt tok`).
- `sls -Path TOKEN -Pattern .` was allowed.

### F2: tar create mode misread as extract

`_tar_mode` now reads the letters the way tar does:
- A value letter takes the rest of its cluster, so `-Vt` is a volume label, not list mode. The value letters are the union of GNU tar and bsdtar: b C f F g H I K L N s T V X. For pax they are b f o p s x B E G T U.
- The old-style first word (`tar xzf`) is a bundle of letters.
- Any abbreviation of a long create, append, update, catenate, concatenate or delete option means create mode.
- An abbreviation of extract, get, list, diff or compare of two or more letters means read mode.

Operands are skipped only when exactly one mode is found and that mode is read. Create mode, two modes, or no mode skips nothing.

Refused: `tar --cre -f - -Vt DIR` (the reviewer's case), `tar --app -f x.tar -Vx DIR`, `tar -Vt --create -f - DIR`, `tar -f - -c -Vt DIR`, `tar --cre -tf - DIR` and `pax -rw DIR /tmp/x`.

Still allowed: `tar -zxvf`, `tar -xzfarchive.tgz -C ~`, `tar --extract`, `tar --extr`, `tar -x -f x.tar -C ~` and every r3 extract neighbour.

### F3: a single rsync or scp operand skipped as the destination

- Option values are no longer counted as operands. rsync: `--exclude`, `-e`, `--log-file` and its other value options. scp and sftp: `-P`, `-i`, `-o`, `-F`, `-J`, `-l`, `-S`, `-c`, `-X` and `-D`.
- The last operand is skipped as the destination only when another operand is a real source: a remote `host:path`, or an existing local path that does not directly follow an unknown option.

Refused: `rsync -a --exclude foo DIR/`, `rsync -a -e ssh DIR/`, `scp -i key DIR/`, `rsync -a --exc /tmp DIR/` and `rsync -a nosuchsrc-15785 DIR/`.

Still allowed: `scp -P 22 host:file ~/`, `rsync -avz --exclude .git host:x/ ~/`, `rsync -a -e ssh host:x/ ~/`, `rsync -a host:x/ ~/ --log-file /tmp/rsync.log` and `rsync -a /tmp/ ~/`.

### Mutants

There are 25 new mutants and 48 in total, all killed. One old mutant, "an unlisted option value does not fail closed", was replaced because the line it changed is gone.

Each new rule has its own killing mutant:
- uncertain scan judges the working directory;
- uncertain scan judges all free words;
- an unknown long option and an unknown short letter each make the scan uncertain;
- values consumed by long and by short options become free words;
- a separate long value is consumed;
- an attached value letter does not take the next word, and a value letter at the end of a cluster does;
- attached and long pattern options;
- count-only comes only from option letters, and never from an uncertain scan;
- `--dereference-recursive` and abbreviations of `-d recurse`;
- pt;
- tar: value letters, create abbreviations, read abbreviations, two modes, and the old-style first word;
- copy tools: the option tables, the real-source rule, the after-unknown rule and the remote source.

### Over-blocks (stated in the spec Risks)

- From a home directory (or `~/.config`, `~/.agent-harness`, `/`), a recursive search that uses an option the tables do not know is refused even when it names a harmless path. Examples: `cd ~ && ack --python tok /tmp`, `cd ~ && rg --colour always tok /tmp`. To avoid it, cd into the project or count with `-c`.
- The existing-path check on the working directory stays as defence in depth and has no mutant. When the scan is certain and the named path is missing, the tool fails; it does not search the working directory.

## Reviews and state
- No review has run on d6098dc0. This packet and its receipt are the check.
- The spec reviews were already stale at da424fde: the r3 edits changed the core hash to 0dd1ff85, while the reviews are bound to abc6eaee. This delta edits AC-1 and Risks again, so the spec needs fresh reviews before `spec_flow.py attach`.
- The owner branch af9e-gq-credential-paths is untouched (the owner is paused). Main decides whether to fast-forward it to d6098dc0 or point PR 221 at rescue-221-gq-creds.

Risk and rollback: revert d6098dc0. The change adds refusals and narrows when destinations are skipped. The fail-closed over-blocks are limited to two cases: a recursive search from a credential ancestor directory that uses an option the tables do not know, and a tar command whose mode is in doubt.
