# Holds guard and tamper evidence

GoodQA goodqa#14543 (rules batch B1). Files: `harness/hooks/holds_guard.py` (PreToolUse hook), `holds.py` (status
and lifts), `holds.json` (policy), `integrity.py` and `integrity_policy.json` (tamper evidence), plus a row in
`hooks_manifest.json` that `doctor.py check` runs.

## Threat model

The guard protects against **accidental** damage by a cooperating agent:

- touching a held project (yates / apex_app_pos, Petfiliate, OptinRouter);
- editing the installed hooks, `holds.json`, `holds.state.json` or the settings that wire the hooks by mistake;
- reading a credential by mistake (member.key, `*.secret`, SSH private keys, `~/.aws`, the rclone config, Keychains);
- force pushing or switching an existing git remote;
- a hold lifted without a real user instruction.

It is **not** a defense against a deliberately malicious agent or user. That agent can run a script file, compute
strings at run time, plant a pty, or edit anything the same Unix user can edit. Tampering is covered by
**detection, not prevention**: see [Tamper evidence](#tamper-evidence). A review finding that only applies to a
deliberately malicious agent is recorded under [Residual](#residual-not-chased) and is not blocking.

## Rollout mode

The guard ships in **warn mode** (`holds_guard_policy.json`, `"mode": "warn"`): where it would deny, it prints a
`systemMessage` saying so and lets the call proceed. A missing or invalid file means enforce, so damaging the file can
not switch the guard down. Change the mode in a reviewed branch and `install.py`, never in the live directory.

- `doctor.py check` reads the same file. In warn mode a deny canary is satisfied by the "would deny" message and the
  row reads `WIRED-WARN` (a pass); `rules-report` reads `ALERT-ONLY`. In enforce mode only a real deny passes, and a
  guard that stays silent or crashes is `CANARY_FAIL` in both modes.
- Every would-deny appends one line to `~/.agent-harness/state/holds-warn.jsonl` (0600; rotated to `.1` at 1 MiB):
  `{schema, at, rule, tool, hash}`. It holds the rule kind, the tool name and a sha256 prefix of the tool input, never
  the command. Read it before the flip: `jq -r .rule ~/.agent-harness/state/holds-warn.jsonl | sort | uniq -c`.
  Equal hashes are the same call repeated. A failure to write the line does not change the answer.

## What is enforced

| Area | Denied | Allowed |
| --- | --- | --- |
| Holds | a path-like or URL-like operand, redirect or working directory naming a held project; every operand of a host verb (ssh, ping, docker, psql ...); file tools on a held path; GoodQA calls whose project, ticket or ref fields (or a `name#N` value) name a held project | the held name as plain text: the pattern or program of grep, rg, sed, awk or jq, an echo, a commit message, a `--note`/`--source`, a branch name (`gh --head/--base`), an agent brief; **reading** a memory note whose file name holds the word (`~/.claude/projects/<p>/memory/feedback-do-not-touch-yates.md`; writing it stays denied) |
| Credentials | reading verbs (cat, cp, base64, grep, python3 ...) and file tools on credential paths; recursive readers (grep -r, rg, tar, cp -r, find -exec) over the home directory or above | `ssh -i key`, public keys, `known_hosts`, `~/.ssh/config`, listing names (`ls`, `find` without -exec) |
| Protected harness files | any write (see below) to the installed hooks directory, `~/.claude/settings.json`, `~/.claude/settings.local.json`, any `.claude/settings.json` / `.claude/settings.local.json` (project level), or a destructive verb on a directory containing them (`~/.claude`, `~`, a `.claude` directory) | reading them in any way; running an installed hook script by path |
| Push safety | `git push` with `-f`/`--force*`/`--mirror`/`+refspec`; `git remote set-url/rename/remove`, `remote.*.url` / `url.*.insteadOf` writes, `git -c` overrides of those keys | plain pushes, `git remote add` |

**GoodQA calls by id are not matched.** `holds.json` has `"projects": []` for all three holds, because only the user
can supply the project ids, so `{"projectId": "<uuid>"}` or `{"issueId": "<uuid>"}` of a held project is allowed; only
a name, slug or `name#N` is denied (goodqa#14647).

### The protected-set allowlist

Bash analysis for the protected set is an **allowlist for writes to protected paths only**. For every segment of a
command (pipelines, `&&`, `;`, `sh -c`, `eval`, heredocs fed to shells or interpreters, `$(...)` bodies) the guard
collects the operands: positionals, `--opt=value` values, `-o`/`--output`/`of=`/`-C`/`-t` values, redirect targets,
`$(...)` bodies used as words, and the paths named by the producer of an `xargs` pipeline. If one of them resolves
(tilde, variables, braces, globs, symlinks, the simulated `cd`/`pushd`/`popd`/`cd -` directory) into the protected
set, the command is allowed only when its verb is a **pure reader**:

- always readers: cat, head, tail, less (without `-o`), grep, rg, ls, wc, stat, file (without `-C`), diff, cmp, jq,
  du, readlink, realpath, sha256sum, echo, printf, test ...;
- conditional readers: sort without `-o`, uniq with one operand, xxd without `-r` and with one operand, base64 without
  `-o`, sed/awk without in-place flags or `w`/`print >` programs, find without `-delete`/`-fprint*` and whose `-exec`
  runs a reader, tar in list mode, unzip `-l/-p/-t`, rclone ls/lsl/cat/check, git read-only subcommands
  (status, log, diff, show, blame, ls-files, rev-parse, add, commit ...) without `--output`;
- `python3`/`node` running an **installed hook script by path** (wal_note.py, deliver.py, holds.py ...), and inline
  `-c` code that makes no write call;
- copy verbs (cp, rsync, scp, ditto, install) count only their destination, so copying a hook *out* is allowed;
- named read-only checkers, from any checkout: `doctor.py check` / `rules-report` (`--settings`, `--hooks-dir`, `--ssh`
  forms), `integrity.py verify`, `holds.py status`, `python3 -m json.tool` with one operand (a second is its output),
  `py_compile` and `pyflakes`, `ruff check` without `--fix`/`--output-file`, `prettier --check` and `npx prettier
  --check` without `--write`, `shellcheck`;
- `rm` of only `__pycache__` or `*.pyc` under the hooks directory (the hook launch writes them; they are not hashed).

A bare `.` counts as the working directory only for verbs that can write a tree (`rm`, `mv`, `cp`, `chmod`, `find`,
`tar`, `git` ...), so `gh pr view 5 -q .` and `python3 x.py .` from the home directory are ordinary commands.

Everything else touching the set is denied with the path and the safe alternative: **edit the file in a branch
worktree and run install.py** (which installs and records integrity); project settings are changed by the user.
A non-reader verb whose working directory is inside the hooks directory is denied too. Inline code (`python3 -c`,
heredocs, `node -e`) is denied only when it makes a write call (open with a write mode, write_text, shutil, os.remove
...) and names a protected path as a whole quoted string or builds `'.claude'`/`'hooks'`; `os.system`/`subprocess`
strings are checked as commands.

**Commands that do not touch the protected set are not analysed for writes at all**, so ordinary work is
unaffected. Session transcripts are no longer in the protected set: a lift now also needs the off-host backup copy.

### Failure modes

The hook runs as `python3 -I -S ~/.claude/hooks/holds_guard.py` (no `PYTHONPATH`, user site or site module; the guard
inserts its own directory to find `holds.py` and `provenance.py`), with `timeout: 10` and `onFailure: "block"`, so a
crash of the interpreter or a hook timeout blocks the call. Inside the guard, unparseable input, a wrongly typed
field, an oversized command (64 000 characters), too deep nesting, a brace expansion over 4096 words, any crash and
the internal 4 s deadline produce a deny with a message. The deadline exception is a `BaseException`, so no
`except Exception` inside the checks can swallow it. A missing or invalid `holds.json` falls back to the built-in
holds; the file can only add holds.

Measured cost on 2553 real agent commands (Mac, Python 3.9): median 1.3 ms, p99 6.7 ms, max 16 ms per decision;
about 150 ms per hook process including interpreter start.

## How to lift a hold

1. The user sends Claude the message `lift hold <id>` (the whole message; "please" in front and a final "." or "!"
   are tolerated; any negation or condition refuses).
2. Any agent (main included) runs
   `python3 ~/.claude/hooks/holds.py lift <id> --source 'user:<session>/<uuid> "lift hold <id>"'`
   (find the uuid with `provenance.py find-user --session <session> --text 'lift hold <id>'`).
3. `holds.py` checks the uuid is a human-typed message with exactly that phrase in the **local transcript**, then
   that the same uuid and phrase are in the **off-host transcript backup** (rclone, `lessons-dropbox:Backups/agent-logs/
   <host>/.claude/projects/<project>/<session>.jsonl`, the layout `harness/bin/log-backup.sh` writes; it honours
   `LOG_BACKUP_REMOTE` and `LOG_BACKUP_HOST`). If the message is not backed up yet it refuses with the next step:
   `run the backup now: ~/.agent-harness/bin/log-backup.sh, then retry`. If the backup is unreachable it refuses
   (fail closed). Nothing is cached; the copy goes to a private temporary directory that is removed.
4. It writes `holds.state.json` and runs `integrity.py record`, so the lift is part of the mirrored record.

On every hook call `lifted_ids()` re-verifies each state entry against the local transcript (cheap). A state entry
without a matching integrity record still counts as lifted ("lifted-but-unrecorded") and `integrity.py verify`
reports `holds.state.json` as CHANGED with that note.

### Known limits of a lift (goodqa#14646)

A hold is lifted whole; there is no lift for part of a project. Two defects are known and not fixed yet:

- **A long session can not lift.** `provenance.find_user` stops after 200 matching lines counted from the start of the
  transcript, so in a session with more than 200 human turns a later `lift hold <id>` is refused with "that message
  uuid is not a human message containing the excerpt" and `provenance.py find-user` returns nothing. Workaround: send
  `lift hold <id>` as an early message of a **new session**, run `~/.agent-harness/bin/log-backup.sh`, then run
  `holds.py lift` with that session id and message uuid.
- **A lifted hold can re-lock while `status` still says LIFTED.** The guard re-verifies against the local transcript on
  every call; `holds.py status` only reads the state file. If the transcript was pruned, or its message sits past the
  200 lines, the guard treats the hold as active. The guard is the truth: test with a payload naming the held project
  (`printf '%s' '{"tool_name":"Read","tool_input":{"file_path":"/x/<id>/y"}}' | python3 -I -S
  ~/.claude/hooks/holds_guard.py`). Workaround: the user sends `lift hold <id>` again in a new session and the lift is
  repeated as above; it replaces the old state entry.

## Tamper evidence

`integrity.py record` hashes (sha256) every installed hook file named in `hooks_manifest.json` (`integrity_files`,
equal to `install.HOOKS`, plus the manifest's hook scripts), `holds.json`, `holds.state.json` and the `hooks` object
of `settings.json` (`settings-hooks`). The record `{schema, host, at, digest, files}` goes to every mirror:

- **ssh mirrors** from `integrity_policy.json` (dev2, whose host shuts down on 2026-11-09). To add T2 once it is a
  harness host, move the `mirrors_example` entry `{"kind": "ssh", "host": "t2", "dir": "~/.agent-harness/integrity"}`
  into `mirrors`. Until then GoodQA is the mirror that survives, and a dead ssh entry costs one failed call per run. Appended to
  `~/.agent-harness/integrity/<host>.jsonl` on the mirror, under flock, 0700 directory and 0600 file. The remote side
  is a small inline Python program run as `python3 -c <program> --local append|latest <dir> <host>` (the `--local`
  marker means a mirror never hops on), over `ssh -o BatchMode=yes -o ConnectTimeout=8` with a subprocess timeout;
- **GoodQA**: a comment on the registered ticket goodqa#14593 "Harness integrity mirror" (hashes and a timestamp only),
  posted and read with `~/.claude/goodqa-p0p1/gq.py`. The read pages `order=desc` (newest page first, as measured on
  the live API; the comments inside a page run oldest to newest) and skips archived comments, so the ticket can grow
  without the newest record falling off. A malformed page, or no record in the newest 10 pages of 100, is unreachable,
  not a stale comparison. A post counts only when the reply is JSON with `comment.id`.

**Host label.** A record is keyed by a stable id, not the host name, because a Mac's host name follows the network:
`mac-<sha256 prefix of the hardware UUID>` or `linux-<sha256 prefix of /etc/machine-id>`, with `HARNESS_HOST_ID` as an
override and the host name as the last resort. Print it with `integrity.py host-id`. `host_aliases` in
`integrity_policy.json`, keyed by that id, lists earlier labels of the machine, so a record written under an old name
(`Mac-2`) still verifies until the next `record`; the id is tried first and an alias is read only when a mirror has
nothing under the id. Aliases are explicit because two machines can share a host name. `holds.py` looks for the
transcript backup under `LOG_BACKUP_HOST` alone when it is set, otherwise under the id, its aliases and the current host
name, which is what `log-backup.sh` writes by default. To put new backups under the stable label too, run that script
with `LOG_BACKUP_HOST="$(python3 ~/.claude/hooks/integrity.py host-id)"`.

**Time budget.** `record` and `verify` share one budget of 45 s, under the deadman's 60 s: each ssh call gets at most
15 s (with `ServerAliveInterval=5`, `ServerAliveCountMax=2`), each GoodQA call 20 s, and the ssh mirrors leave 22 s for
GoodQA. When the budget is spent the remaining mirrors count as unreachable, so `verify` ends UNVERIFIABLE (exit 0).

`install.py --apply` runs `integrity.py record` after a successful install (a mirror failure only warns). `holds.py
lift` runs it after writing the state.

`integrity.py verify [--alert] [--json]` recomputes and compares with the newest record of this host on any
reachable mirror:

| Result | Exit | Meaning |
| --- | --- | --- |
| MATCH | 0 | nothing changed since the last record |
| UNVERIFIABLE | 0 | no mirror reachable or no record yet: a warning, not a change |
| CHANGED | 1 | lists each key with expected and actual hashes |

With `--alert`, verify emits **transition-only** alert events: one `raise` (severity `high`) per changed key
(`hooks:<file>`, `holds.json`, `holds.state.json`, `settings-hooks`), a `warning` raise for key `mirror` when
unverifiable, re-raised only when severity rises, and a `clear` (severity `info`, message `cleared`) when the key
matches again. Its own last state is kept in `~/.agent-harness/integrity/alert-state.json`, so an hourly run never
repeats an alert. Event schema 1: `{schema, at, host, source: "harness-integrity", event: raise|clear, severity, key,
message (<= 512 chars, control characters removed), detail (<= 4 KiB; changed[] with expected/actual and the mirror)}`.
An alert that could not be delivered, for any reason including a `ValueError` from `ops_watch.emit` or a broken module,
makes verify exit 3 on MATCH (CHANGED stays 1, and only CHANGED is 1) and is retried on the next run.

Delivery is one function, `integrity.deliver()`: when `~/.claude/hooks/ops_watch.py` is installed it calls
`ops_watch.emit(event, home=...)` (the ops-watch ring `~/.agent-harness/state/alerts.jsonl`, goodqa#14591); until then it appends
the line to the deadman reserve file `~/.agent-harness/reserve/alerts-in.jsonl` (0700 directory, 0600 file). It never
writes the ring directly. `doctor.py check` runs `integrity.py verify --json` (skip with `--no-integrity`): CHANGED
fails the check (exit 1), UNVERIFIABLE warns.

### For ops-watch / G10

The deadman runs, every 3600 s with a 60 s timeout:

    python3 /Users/eric/.claude/hooks/integrity.py verify --alert

Exit 0 on MATCH and UNVERIFIABLE, 1 on CHANGED, 3 when an alert could not be delivered. This repository adds no timer.

## Measured false-deny rate

Payload strings only, nothing executed, against a sandbox copy of the hooks directory and a fake HOME, enforce
semantics. Corpus A is the independent reviewer's random sample of 3000 from 23,993 unique Bash commands of 497
transcripts (skewed to harness development, where the data-versus-target heuristic is weakest); B is its 111
hand-written commands.

**A: 26 of 3000 denied (0.87 %).** 16 are correct or by design (15 real accesses to a held project, 1 write of a memory
note named after a hold). **10 are false or arguable (0.33 %, was 18 before the last round):** 6 inline scripts that
edit a worktree file and hold `~/.claude/hooks/...` as a string next to a write call, 2 commands run with the working
directory inside the hooks directory (documented above), 1 `grep ~/.ssh/config_fleetops` (only `config` and
`known_hosts` are exempt), 1 test harness call with quoted dangerous strings. **B: 1 of 111** (`touch` of a file in the
hooks directory, a real write). Median 1.2 ms, p99 8 ms, max 173 ms per decision.

A second measurement with `measure.py` in the owner work directory: 270 real agent commands (`real_cmds.json`), 172
legitimate corpus commands (`corpus_legit.json`) and 2553 further real Bash commands from seven session transcripts.

**16 of 2995 denied (0.53 %)**, every one explained:

- 12 real commands that do access a held project by name (ssh and curl to OptinRouter VMs and hosts during the VM
  move). They are correct denials while the hold is active; that work needs the hold lifted or the hold narrowed.
- 2 memory-note writes whose file name contains a held word (`feedback-do-not-touch-yates.md`): a path naming a held
  project is denied by design; rename the note.
- 1 `git push --force-with-lease` in the legit corpus: force pushes are always denied by policy.
- 1 inline Python that edits a test file and holds `'{home}/.claude/hooks/...'` strings as data next to an
  `open(p, 'w')`: the inline-code heuristic can not tell data from a target.

Guard errors (not a policy decision) are therefore 3 of 2995 (0.10 %). The `fd.json` false-denial set: 1 of 63 denied
(`git remote set-url`, a policy denial).

Paths under `/home` and `/net` on macOS are only normalized, because the automounter costs about 30 ms per stat, and
each path is resolved once per decision: 40 `/home` operands decide in well under a second instead of hitting the 4 s
deadline.

## Residual (not chased)

These need deliberate intent; detection (integrity verify) covers the result where it touches a tracked file:

- a script file the agent wrote and then runs (`python3 /tmp/x.py`, `bash x.sh`, `./x.sh`), `make`, test runners;
- strings computed at run time (concatenation inside `-c` code, `echo cmd | sh`, variables from the environment,
  `PYTHONPATH=/tmp/evil python3 hook.py`, `importlib`, `exec(base64...)`);
- a planted pty, `script`, `expect`, `at`, `crontab`, `launchctl`, `osascript do shell script`;
- `git -c alias.x='!...'`, `core.sshCommand`, `core.fsmonitor`, `core.pager`, `tar --to-command`, `rsync -e`,
  `ssh -o ProxyCommand/LocalCommand`;
- ssh aliases or IP addresses for a held host that `holds.json` does not list, and `ssh localhost '...'`;
- `gh api` force operations and remote branch deletion (`git push --delete`);
- a symlink created in one command and written through in a later one;
- a malicious user or agent who edits the files **and** every mirror (dev2 file and GoodQA comments), or who changes a
  file and restores it between two verifies;
- session transcripts are not write-protected; a forged local transcript does not lift a hold on its own because the
  lift also needs the off-host backup copy, but a forged transcript that is then backed up is residual;
- `integrity.py record` run after tampering makes the newest record agree, and a forged GoodQA comment with a future
  `at` wins;
- `gh repo delete <held>`, a bare repo name given to `gh issue list`, WebFetch or WebSearch of a held host, and agent
  briefs are not matched.

Low-impact accidents, accepted:

- a new untracked file in the hooks directory is not detected (only listed names are hashed);
- if a record reached only one mirror and only the other is reachable later, `verify` compares with the older record and
  can raise a false CHANGED until the next run reaches both;
- `alert-state.json` has no lock: doctor and the deadman running together can emit one duplicate raise;
- `integrity.py record` from a sandbox copy of the hooks writes the real mirrors unless `--mirror-dir`, `--no-goodqa` and
  `--host-label` say otherwise;
- two tests need the checkout under `$HOME` (the ancestor logic is home-bound);
- a very long legitimate command approaches the 4 s deadline (60 KB of quoted words takes about 3 s);
- `RCLONE_CONFIG_PASS` is stripped, so an encrypted rclone config makes every lift "unreachable" (fail closed).
