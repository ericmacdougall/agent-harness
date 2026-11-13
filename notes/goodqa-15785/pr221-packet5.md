# PR review packet 5 (rescue delta for receipt r5): the most dangerous reading of tool options (agent-harness PR 221, GoodQA goodqa#15785)

Base: 1bce208c9c4594d8fb516c5a501d559d043e0da8 (the merge base; use `--snapshot-base 1bce208c9c4594d8fb516c5a501d559d043e0da8`; origin/main has since moved to 83b993d9, which does not touch these files). Head: 12a3d2219dbc52adf9afbf6ee0cbe87f8cd4686c. Both rescue-221-gq-creds and af9e-gq-credential-paths point at it; the owner branch was fast-forwarded from d6098dc0 with a plain push and no history was rewritten. Claude-authored (rescue at Opus high): `--author-harness claude`. Previous packet: pr221-packet4.md (d6098dc0, r5 BLOCK). Everything in it still holds unless this delta says otherwise.
Delta commit: 12a3d221 fix(command_guard): take the most dangerous reading of tool options.
Changed code paths: harness/hooks/command_guard.py:
- the per-tool `count_short`, `count_long`, `read_short` and `read_long` table entries;
- `OptScan.read_values` and `_scan_options`;
- `_count_only(name, scan)` and its three callers (search, stdin, find -exec);
- `STDIN_SEARCHERS`;
- `OPTION_SOURCES` and `_options_from_environment`;
- `_tar_mode` (rewritten) and `_TAR_VALUE_ALL`, `_TAR_VALUE_ANY`, `_PAX_VALUE_ALL`, `_PAX_VALUE_ANY` and `_TAR_FLAG_LONGS`;
- `read_creds` (judging the read values);
- `_local_destinations` (per-tool wget and curl flags; tar under options from the environment).

Also changed: tests/test_command_guard_gq_credentials.py, tests/mutants_gq_credentials.py (which now takes a list of replacements so that one mutant can break two layers) and notes/goodqa-15785/spec.md (AC-1).

## Validation (real output from the rescue worktree, code at 12a3d2219dbc52adf9afbf6ee0cbe87f8cd4686c)
$ python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup tests.test_command_guard_gq_credentials tests.test_worktree_inuse tests.test_worktree_hooks_rule tests.test_ah_worktree_remove
Ran 337 tests in 122.792s
OK (skipped=2)
exit 0

$ python3 -B tests/mutants_gq_credentials.py   (origin/main plus 65 broken variants; every line must say FAILS (good))
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
count-only letters shared by every tool    FAILS (good)
count-only long names shared by every tool FAILS (good)
find -exec count-only read naively         FAILS (good)
stdin count-only read naively              FAILS (good)
grep --dereference-recursive is not recursive FAILS (good)
grep -d abbreviations are not recursive    FAILS (good)
pt is not recursive                        FAILS (good)
tar value letters do not end a cluster     FAILS (good)
tar create abbreviations not seen          FAILS (good)
tar read abbreviations not seen            FAILS (good)
tar two modes read as one                  FAILS (good)
tar old-style first word ignored           FAILS (good)
tar create stops at any value letter       FAILS (good)
GNU tar -s read as a value letter          FAILS (good)
bsdtar -H read as a value letter           FAILS (good)
bsdtar -L read as a value letter           FAILS (good)
TAR_OPTIONS ignored                        FAILS (good)
search options from the environment ignored FAILS (good)
option read values not judged              FAILS (good)
attached short read value not collected    FAILS (good)
separate short read value not collected    FAILS (good)
attached long read value not collected     FAILS (good)
separate long read value not collected     FAILS (good)
pt trusted to read a pipe                  FAILS (good)
curl -O read as a destination              FAILS (good)
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
exit 0 (66 lines, all FAILS (good); none PASSES, none NOT APPLIED)

Failing first: the new test file, copied into a tree of the guard at d6098dc0 (the r5 head), gives `FAILED (failures=22)`:
- all 7 count-only cases;
- all 4 read-value cases;
- all 5 sweep cases;
- 6 of the 10 tar cases: `-sc` twice, `-Lc`, `-Hc`, and both TAR_OPTIONS forms.

The other 4 tar cases also pass on d6098dc0 and stay as regressions: `c0f`, `-f -x -c`, `--file -x -c` and `bsdtar -Hcf -`.

## Receipt r5 findings and how they are closed

### F1 (material): `_count_only` applied grep's letters to every tool

Each option table now has its own count-only letters and long names:

| Tool | Count-only letters | Count-only long names |
|---|---|---|
| grep (GNU and BSD agree) | c q l L | count, quiet, silent, files-with-matches, files-without-match |
| rg | c q l (no `L`; rg `-L` is --follow) | count, count-matches, quiet, files-with-matches, files-without-match, files |
| ag | c l L | count, files-with-matches, files-without-matches (not `--silent`, which only silences log messages) |
| ack | c l L | count, files-with-matches, files-without-matches |

A tool with no table (pt, select-string) is never count-only, and neither is an uncertain scan. All three callers use the same rule: the search itself, the credential-on-stdin check and the find -exec body. The find -exec caller was missed in packet 4: it still read cqlL naively.

Refused (all allowed at d6098dc0):
- `rg -L . DIR`
- `rg -uuL tok DIR`
- `cd ~ && rg -L tok`
- `cd ~ && ag --silent tok`
- `ag --silent tok DIR`
- `find DIR -exec rg -L . {} +`
- `rg -L . < TOKEN`

Mutants: the tool's letters, the long names, the find -exec caller and the stdin caller each have one.

### F2 (material): letters whose meaning differs between tar implementations hid a create letter

`_tar_mode` now uses two readings.

The maximal reading decides create:
- Letters stop only at a letter that takes a value in every tar (C f T X).
- Every word is read, including a word that may be an option value.
- Any abbreviation of a long create, append, update, catenate, concatenate or delete option counts as create.

The minimal reading decides extract or list:
- Letters stop at a letter that takes a value in any tar (b C f F g H I K L N s T V X; for pax, b f o p s x B E G T U).
- A word that may be the value of the option before it never counts. Such a word is one that follows a cluster ending in a value letter, follows a long option not known to take no value, or is one of the old-style values.

Operands are skipped only when the minimal reading shows read and no reading shows create. An old-style first word that is not all letters (`c0f`) gives None. TAR_OPTIONS, named in the command or set in the environment, also gives skip-nothing.

Refused:
- `tar -sc -V -x -f - ~`
- `tar -sc -V -x -f - DIR`
- `tar -Lc -C -x -f - DIR`
- `tar -Hc -f -x ~`
- `tar c0f - DIR`
- `tar -f -x -c DIR`
- `tar --file -x -c DIR`
- `bsdtar -Hcf - DIR`
- `TAR_OPTIONS=-cV tar -x -f - DIR`
- `export TAR_OPTIONS=-cV; tar -x -f - DIR`

Still allowed: every r3 and r4 extract neighbour, plus `tar -f x.tar -x -C ~`, `tar -xv --strip-components=1 -f x.tar -C ~` and `tar --verbose -x -f x.tar -C ~`.

Each reading is enough on its own. If a read letter is an option in every reading, tar really is in read mode, and an added create would make tar exit with "more than one mode". If a create letter is visible in any reading, the guard skips nothing. A mutant that breaks only one layer is therefore masked by the other. The tar mutants for the r5 letters (s, H, L, create stops at any value letter, create abbreviations) each break both layers at once, and all of them are killed.

### F3 (minor): a file opened through an option value was not judged

`OptScan.read_values` collects the values of grep `-f`/`--file`/`--exclude-from`, rg `-f`/`--file`/`--ignore-file` and ag `-p`/`--path-to-ignore`, whether separate or attached. `read_creds` judges each one by file name.

Refused: `grep -f TOKEN notes.txt`, `grep --file=TOKEN notes.txt`, `grep -fTOKEN notes.txt` and `rg --ignore-file TOKEN tok /tmp`.

Still allowed: `grep -f patterns.txt notes.txt`.

There is a mutant for each of the four ways a value is collected and one for the judging itself.

## Sweep: every count-only, mode and destination decision checked for a letter clash between tools or implementations

1. Count-only: per tool, as in F1. Fixed: rg `-L` and ag `--silent`. Checked: grep GNU and BSD agree on c q l L and their long names; ack has no `-q`.
2. Option values in the search scan, value letters against flags:
   - GNU grep (`A:B:C:D:d:e:f:m:X:`) and BSD/macOS grep (`A:B:C:D:d:e:f:m:`) agree. `X` takes a value in GNU and is invalid in BSD (grep exits), so treating it as a value letter is safe.
   - BSD `--context` takes an optional value, so it is known only in the `--context=N` form.
   - ag and ack each have one implementation. Their optional-valued `-A`/`-B`/`-C` forms are uncertain.
   - In rg, `-d` and `-.` are newer letters that older versions reject as invalid.
   - No letter is a value letter in one implementation and a flag in another.
3. Recursion: grep `-r`/`-R` agree in GNU and BSD. rg, ag, ack and pt are always treated as recursive (ag `-n` and ack `-n` turn recursion off, so treating them as recursive fails closed). Reading the recursion letters naively from every cluster can only over-detect.
4. Reading stdin instead of the working directory: rg, ag and ack read a pipe when no path is given. Fixed: pt is not trusted to do so (most dangerous reading); `cd ~ && echo x | pt tok` is refused.
5. tar modes and value letters: fixed as in F2. Checked across GNU tar, bsdtar (libarchive, macOS) and busybox tar. Mode letters: c r u A create; x t d read; pax r and w (`-rw` is create). No letter is a mode in one implementation and a different mode in another.
6. Options from outside the command line: fixed, a new class. TAR_OPTIONS, GREP_OPTIONS (BSD grep honours it), RIPGREP_CONFIG_PATH, ACK_OPTIONS/ACKRC and an .ackrc in the home or working directory make the reading uncertain, unless `--noenv` is given for ack.
   - Refused: `cd /tmp && RIPGREP_CONFIG_PATH=/tmp/rgc rg DIR`, `cd /tmp && GREP_OPTIONS=-e. grep -r DIR` and `cd /tmp && ACK_OPTIONS=--match=. ack DIR`.
   - None of these variables is set in this session, and there is no ~/.ackrc.
7. wget and curl destinations: fixed. The flags are now per tool. curl `-O` is --remote-name (it takes no value, so the next word is a URL or source), wget `-c` is --continue, and curl `-P` is --ftp-port. Only options that name a written file are skipped:
   - wget: -P, -O, -o, -a;
   - curl: -o, -D, -c, --output-dir.

   `curl -O file:///Users/eric/.config/goodqa/` is refused.
8. scp, rsync and sftp: checked, no clash. OpenSSH scp and sftp, rsync 3.x and openrsync have the same value letters. The only risk would be a value letter that some implementation treats as a flag, because that would remove a real destination. None was found. Every copy-tool word is still judged, and only the last operand is skipped, and only beside a real source.
9. zip and 7z: checked, no clash. Only the first non-dash word of zip is skipped (the archive, or the value of an option before it), and only the archive word after the 7z command letter.

Over-blocks added and accepted under the most-dangerous rule:
- A search run from a home directory whose command text names one of the option variables (`cd ~ && grep -r GREP_OPTIONS docs`).
- tar where a mode word may be an option value (`tar -x --exclude -c ...`).
- `cd ~ && echo x | pt tok`.

## Reviews and state
- No review has run on 12a3d221. This packet and its receipt are the check.
- The spec reviews are stale. They were stale already, and AC-1 changed again in this delta, so the spec needs fresh reviews before `spec_flow.py attach`.
- Not merged, not live.

Risk and rollback: revert 12a3d221, or reset both branches to d6098dc0 with a new commit, never a force push. The change only adds refusals and narrows count-only and destination skips.
