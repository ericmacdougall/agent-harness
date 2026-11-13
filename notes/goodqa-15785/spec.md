# Spec: command_guard: block reads of GoodQA user-token and gq-browser key files

Ticket: GoodQA goodqa#15785
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a command-text guard rule with no UI; the proof is the real guard decision on the commands in the tests)
Sign-off: main
Review-policy: standard

## Outcome

An agent shell can no longer print the user's GoodQA user token (`~/.config/goodqa/user-token`, which acts as the user) or a minted gq-browser lease key (`~/.agent-harness/gq-browser/16-hex/key`, valid for up to 24 hours) into a transcript with cat, head, base64 and the other readers the guard already treats as secret reads. The gq-browser client keeps reading the files in-process.

## Scope

- In: two entries in `credential_path_regexes` in harness/hooks/command_guard.py; a test file; the docs line in docs/gq-browser.md and the AC-8 pin in tests/test_gq_browser.py belong to agent-harness PR 220 (O1 updates them to "command guard refuses" once this lands).
- Out: a Python script or any program that reads the file itself (the guard sees command text only; accident prevention, not an access control); other GoodQA files; changing the refusal text or the secret_dump mode.

## Acceptance criteria

- AC-1: a shell read (cat, head -c, tail, base64, strings, less, xxd, grep, sed, awk) of the user-token path or of a gq-browser `16-hex/key` path, in the forms `~/...`, `$HOME/...`, an absolute path and a quoted path, is blocked with the secret_dump rule, and so is a glob that expands to either file (`cat ~/.agent-harness/gq-browser/*/key`, `cat ~/.config/goodqa/*`, `cat ~/.config/goodqa/user-tok*`), because both paths are also credential samples; the two directories that HOLD them (`~/.config/goodqa`, `~/.agent-harness/gq-browser`, a policy list `credential_parent_dirs`) are refused to a recursive reader (grep -r, rg, ag), to a find -exec reader, to an archive or compressor given the directory (tar, bsdtar, pax, zip, 7z, gzip and similar), to a recursive search that names no path while the working directory is, or contains, either directory (`cd ~/.config/goodqa && rg .`, `cd ~ && grep -r tok`), and to a copy tool that sends them (scp, rsync, curl), while `grep -rc` (count only), `ls`, `find -name`, `cat config.json` and the lease file stay allowed. The ancestor-or-equal directory rule applies to SOURCE operands only (receipt r3 F1): the local destination of scp, rsync and sftp (the last operand), the value of `wget -P` and `-O` and of `curl -o`, `-D` and `-c`, every operand of tar, bsdtar, gtar and pax in extract or list mode (including `-C DIR`, new-style and old-style `tar xzf`), and the output archive of zip and 7z are not read as a source tree, so `scp host:f ~/`, `rsync -a host:x/ ~/`, `wget -P ~ URL`, `tar -xzf p.tgz -C ~` and `tar -xf x -C /` stay allowed; they are still judged as files by name, and tar in create mode keeps `-C DIR` as a source. A search is read the way the tool reads it (receipts r3 F2 and r4 F1): a getopt walk with a per-tool option table (grep as the union of GNU and BSD grep, rg, ag, ack) consumes the value of a recognised option, separate or attached (`-etok`, `-rnA3`, `--regexp=PAT`), takes the first free word as the pattern unless an option gave one, and reads count-only letters (`-c`, `-l`, `-q`) only from option letters, never from a value (`grep -ec FILE` prints). An option the table does not know (an unknown letter or long name, an abbreviation such as `--group` or `--regex=`, an optional-valued option without `=`) makes the search UNCERTAIN and fails closed: every free word, the presumed pattern and option values included, is judged, and a recursive search is judged on the working directory whatever its operands, so `cd ~ && grep -r -e tok --group-separator /tmp` and `cd ~ && rg -uu -e tok --hostname-bin /bin/hostname` are refused. `grep -r`, `-R`, `--recursive`, `--dereference-recursive` and their abbreviations, and `-d`/`--directories` with any abbreviation of `recurse`, are recursive; rg, ag, ack and pt always are; when no existing path remains the working directory is judged. Count-only letters and long names are each tool's own (receipt r5 F1: rg `-L` is --follow and ag `--silent` only silences logs, so neither is count-only), for the search, its stdin form and a find -exec body. A file a search opens as an option value (`grep -f FILE`, `--file=FILE`, rg `--ignore-file`) is judged by name (receipt r5 F3). Where tar implementations disagree, the most dangerous reading wins (receipt r5 F2): create is read from the maximal reading (letters stop only at a value letter of every tar, C f T X, so GNU `-s` and bsdtar `-H`/`-L` do not hide a later `c`; every word counts; any abbreviation of a long create, append, update, catenate or delete option), extract or list from the minimal reading (letters stop at a value letter of any tar; a word that may be the value of the option before it never counts), and tar, bsdtar, gtar and pax skip their operands only when the minimal reading shows read and no reading shows create; an old-style first word that is not all letters (`c0f`) skips nothing. A tool that may take options from outside its command line (TAR_OPTIONS, GREP_OPTIONS, RIPGREP_CONFIG_PATH, ACK_OPTIONS, ACKRC or an .ackrc, named in the command or set in the environment) is read as uncertain: tar skips nothing and a search fails closed. The destination options of wget and curl are per tool (curl `-O` takes no value), and pt is not trusted to read a pipe. The last operand of scp, rsync, sftp and ditto is a destination only when another operand is a real source, a remote `host:path` or an existing local path, and the copy tool's own table recognised every option; recognised option values (`--exclude foo`, `-e ssh`, `-i key`, scp `-P 22`) are not operands (receipt r4 F3: `rsync -a --exclude foo DIR/` is refused). Every skip needs positive proof (receipt r6): a word is exempt from the name rule or the tree rule only when a search walk is certain (the pattern word, option words and the values of pattern, glob and number options), a copy, fetch or archive rule proves it a destination, or it is the remote side of scp, rsync or sftp; count-only exempts the searched operands only, never a file an option value opens (r6 F4: `rg -c --ignore-file TOKEN tok /tmp`). curl and wget output options are destinations only when a walk with the tool's own table recognised every option (r6 F1: `curl -H -o file://DIR` gives -o to -H, so the file URL is read). Every word is judged by name together with every value inside it: the text after `=`, `@`, `<` or `!`, every attached value of a short option cluster, ugrep's `---F`, socat's `FILE:F,`, and a file URL raw, percent-decoded and with curl's `{}` sets expanded (r6 F2: `ack --files-from=TOKEN`, `tar -T~/TOKEN`, `curl file:///.../%67oodqa/user-token`). ack reads an .ackrc in the working directory or any parent, /etc/ackrc, ~/.ackrc and ~/.config/ack/ackrc, and pt (no table) is always uncertain (r6 F3). The grep table covers ugrep 7, the agent shell's grep: a letter whose arity differs between implementations (ugrep -X, -J, -M, -O, -Z) is unknown, and `--group-separator` is known only with `=`; `GREP_PATH` directories are searched for `-f FILE`. A glob or brace word is judged on every expansion, also against the credential directories; tar relative operands are judged under every `-C`/`--directory` base; a tar letter no known tar accepts puts the mode in doubt; a command a tool runs from an option value (tar -I, --use-compress-program, --to-command, --checkpoint-action=exec=, rsync -e, scp and sftp -S and `-o ProxyCommand=`, zip -TT, rg --pre, ack/ag/ugrep --pager, ugrep --filter) is judged like `sh -c` text. find (bfs, the agent shell's find) takes start directories anywhere among its primaries, a body that is an archiver, shell, interpreter or wrapper (`env cat`, `xargs cat`, `sh -c`, `python3 -c`) is a reader, and the words of each body are judged as their own command. A reader of a NAME LIST is judged on the command that prints the names (r6 sweep): xargs or parallel running a reader, tar/bsdtar `-T`, zip `-@`, cpio, pax, rsync `--files-from`, ack `-x`, 7z `@list`, curl `-K`, wget `-i` and sftp batch input, fed by an earlier pipeline stage, a `< <(..)` redirect, a here-string, a heredoc or a `<(..)` argument; a reader whose arguments come from `$(..)` or backquotes; and a `while read` or `for` loop whose input lists names, whose variable is bound to the credential file. A producer lists a credential name when a word names a credential file, a credential directory, an ancestor of one, or (a lister or recursive search with no existing path) the working directory is one. Every block above carries the secret_dump credential rule, and the tests assert the rule id, not only the verdict. Verify by: `python3 -B -m unittest tests.test_command_guard_gq_credentials`. Source: ticket:GoodQA goodqa#15785
- AC-2: neighbouring files and non-reading commands stay allowed: `cat ~/.config/goodqa/config.json`, `ls ~/.config/goodqa`, `ls ~/.agent-harness/gq-browser`, the lease file in a key directory, a key directory whose name is not 16 hex characters, a file named `keys`, `echo user-token`, and docs that mention the name. Verify by: the same suite. Source: ticket:GoodQA goodqa#15785
- AC-3: existing credential behaviour does not change. Verify by: `python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup`. Source: inferred: from ticket:GoodQA goodqa#15785 -- the change adds two patterns and must not alter other verdicts.

## Negative cases

- NEG-1 (AC-1): a glob that expands to the key (`*/key`, `*/k*`) or to the token (`user-tok*`, `user-to?en`, `goodqa/*`) still blocks, and a reader with an option before the path (`head -c 5`, `sed -n 1p`) or a path spelled with `$HOME` or an absolute home still blocks. Source: ticket:GoodQA goodqa#15785
- NEG-2 (AC-2): a key directory named with fewer than 16 hex digits, a `keys` file and `user-token.md` are not credential files and stay allowed (no false refusal of ordinary docs and neighbours). Source: inferred: from ticket:GoodQA goodqa#15785 -- they anchor the exact file names.
- NEG-3 (AC-1): the broken variant with the two patterns removed fails the tests (failing-first control, run against the unchanged code: 26 failures). Source: ticket:GoodQA goodqa#15785
- NEG-4 (AC-1): the r6 findings and sweep (`curl -H -o file://DIR`, `ack --files-from=TOKEN`, a parent .ackrc, `rg -c --ignore-file TOKEN`, bfs start directories after the expression, `find ... | xargs -n 1 cat`, `cat $(find ~/.config -name user-token)`, `... | while read f; do cat "$f"; done`) are refused with the secret_dump rule; each new check has a killing mutant in tests/mutants_gq_credentials.py. Source: ticket:GoodQA goodqa#15785
- NEG-5 (AC-2): option values and destinations that do not read a credential stay allowed (`rsync -a --progress host:x/ ~/`, `scp -s host:f ~/`, `curl --output-dir ~ -O URL`, `cd ~ && grep -rn --exclude='.*' foo /tmp`, `git ls-files | xargs cat`, `find ~/proj -type f | tar -czf /tmp/p.tgz -T -`, `find ~/.config/goodqa -type f | xargs ls -l`). Source: inferred: from ticket:GoodQA goodqa#15785 -- the guard must not refuse ordinary transfers, archives and name lists.

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.01 GB (method: source and tests only)
Network: 0 MB (method: none)
Wall time: 5 min
Cap and kill: none needed (short focused tests; no heavy step)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A program reads the token by a path the text rule cannot see (a script, a variable in the path): stated limit, the guard sees command text only; the sanctioned reader is the in-process client.
- Stated limits of a text guard, the same as for the existing credential files: `cp -r`, `cp -R` and `ditto` of either directory to a readable place and a later read of the copy in another command (a copy is not a print), names fed through a pipe (`find DIR | cpio -o`, `find DIR -type f | xargs cat`: the pipeline form of a find -exec reader, which is refused), a script walking the directory (`python3 -c` with `os.walk`), `cp` of the file to a readable name and a later `cat` of the copy in another command, `export TOK=$(cat F)` and a later `echo $TOK`, an archive of the directory piped to a reader, and a glob inside a key directory whose 16-hex name the agent already knows (`cat .../0123456789abcdef/*`). `ls ~/.agent-harness/gq-browser/*` stays allowed.
- The implied-target gap (a recursive search with no path operand) existed for every credential directory, not only these two; the new rule judges the working directory against the two GoodQA parent directories only, and the other credential directories (`~/.ssh`, `~/.aws`) keep their current behaviour (follow-up ticket to extend the check to `credential_dirs`). `cd - && rg tok` is allowed because the previous directory is unknown; `rg --files` (names only) is treated like `rg -l`; a no-path `rg`, `ag` or `ack` that is not first in a pipeline reads its input and is not judged, while GNU `grep -r` with no path walks the working directory even with a pipe and is judged everywhere; the working directory is judged for a key directory inside gq-browser as well.
- Fail-closed over-blocks (receipt r4 F1): from the home directory (or `~/.config`, `~/.agent-harness`, `/`), a recursive search with an option the tables do not know is refused even when it names a harmless path (`cd ~ && ack --python tok /tmp`, `cd ~ && rg --colour always tok /tmp`); the fix for the user is `cd` to the project or count with `-c`. A tar whose mode is in doubt (no mode letter, a one-letter long abbreviation, two modes) skips nothing, so its `-C ~` is judged as a source and refused.
- A false refusal of a legitimate command naming the file: mitigation, the regexes anchor the exact file names and the neighbour cases are pinned.

## Domain checklist

Domains: auth

The ticket protects an authentication secret from being printed; it adds no sign-up, login, recovery, invite or session flow, and no account, money, delete, device or release behaviour.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed; two path patterns only)
Domain-gate: lookalike-identifier waived (no identifier handling; the guard matches fixed file names)
Domain-gate: request-device-binding waived (no approval or login flow involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed by this change)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup or response text for an account is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (nothing is deleted)
Domain-gate: unpushed-work-detection waived (nothing is deleted)
Domain-gate: dry-run-diff waived (nothing is deleted)
Domain-gate: scope-pinning waived (nothing is deleted)
Domain-gate: cross-host-approval-portability waived (no approval or deletion is involved)
Domain-gate: idempotent-retry waived (a stateless text rule; a rerun gives the same verdict)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (a stateless text rule with nothing to recover)
Domain-gate: grant-durability waived (no grant or approval is created)
Domain-gate: remote-exec-audit waived (no remote execution is added)
Domain-gate: factory-reset-guard waived (no wipe or unenroll path is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money flow or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payment is involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate is changed)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is produced)
Domain-gate: self-update-e2e waived (the install of the guard is the normal harness batch install)
Domain-gate: transport-proof waived (no integration transport is added)
Domain-gate: rollback-not-blocked waived (no release or rollback path is touched)
Domain-gate: staging-exists waived (a local guard rule; the harness batch install is rehearsed by its own process)

## Reviews

Spec core sha256: `abc6eaee443198e2f55a06da9cec48905f416066555bf9231755210ebda6b0ac`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | stale |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | stale |
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
