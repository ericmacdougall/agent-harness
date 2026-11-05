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

## What is enforced

| Area | Denied | Allowed |
| --- | --- | --- |
| Holds | a path-like or URL-like operand, redirect or working directory naming a held project; every operand of a host verb (ssh, ping, docker, psql ...); file tools on a held path; GoodQA calls whose project, ticket or ref fields (or a `name#N` value) name a held project | the held name as plain text: a filter, an echo, a commit message, a `--note`/`--source`, a branch name, an agent brief |
| Credentials | reading verbs (cat, cp, base64, grep, python3 ...) and file tools on credential paths; recursive readers (grep -r, rg, tar, cp -r, find -exec) over the home directory or above | `ssh -i key`, public keys, `known_hosts`, `~/.ssh/config`, listing names (`ls`, `find` without -exec) |
| Protected harness files | any write (see below) to the installed hooks directory, `~/.claude/settings.json`, `~/.claude/settings.local.json`, any `.claude/settings.json` / `.claude/settings.local.json` (project level), or a destructive verb on a directory containing them (`~/.claude`, `~`, a `.claude` directory) | reading them in any way; running an installed hook script by path |
| Push safety | `git push` with `-f`/`--force*`/`--mirror`/`+refspec`; `git remote set-url/rename/remove`, `remote.*.url` / `url.*.insteadOf` writes, `git -c` overrides of those keys | plain pushes, `git remote add` |

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
- copy verbs (cp, rsync, scp, ditto, install) count only their destination, so copying a hook *out* is allowed.

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

## Tamper evidence

`integrity.py record` hashes (sha256) every installed hook file named in `hooks_manifest.json` (`integrity_files`,
equal to `install.HOOKS`, plus the manifest's hook scripts), `holds.json`, `holds.state.json` and the `hooks` object
of `settings.json` (`settings-hooks`). The record `{schema, host, at, digest, files}` goes to every mirror:

- **ssh mirrors** from `integrity_policy.json` (dev2; add T2 as another entry when it is a harness host): appended to
  `~/.agent-harness/integrity/<host>.jsonl` on the mirror, under flock, 0700 directory and 0600 file. The remote side
  is a small inline Python program run as `python3 -c <program> --local append|latest <dir> <host>` (the `--local`
  marker means a mirror never hops on), over `ssh -o BatchMode=yes -o ConnectTimeout=8` with a subprocess timeout;
- **GoodQA**: a comment on the registered ticket goodqa#14593 "Harness integrity mirror" (hashes and a timestamp only),
  posted and read with `~/.claude/goodqa-p0p1/gq.py`.

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
An alert that could not be delivered makes verify exit 3 on MATCH (CHANGED stays 1) and is retried on the next run.

Delivery is one function, `integrity.deliver()`: when `~/.claude/hooks/ops_watch.py` is installed it calls
`ops_watch.emit(event)` (the ops-watch ring `~/.agent-harness/state/alerts.jsonl`, goodqa#14591); until then it appends
the line to the deadman reserve file `~/.agent-harness/reserve/alerts-in.jsonl` (0700 directory, 0600 file). It never
writes the ring directly. `doctor.py check` runs `integrity.py verify --json` (skip with `--no-integrity`): CHANGED
fails the check (exit 1), UNVERIFIABLE warns.

### For ops-watch / G10

The deadman runs, every 3600 s with a 60 s timeout:

    python3 /Users/eric/.claude/hooks/integrity.py verify --alert

Exit 0 on MATCH and UNVERIFIABLE, 1 on CHANGED, 3 when an alert could not be delivered. This repository adds no timer.

## Measured false-deny rate

Measured with `measure.py` in the owner work directory against a sandbox copy of the hooks directory and a fake HOME
(payload strings only, nothing executed): 270 real agent commands (`real_cmds.json`), 172 legitimate corpus commands
(`corpus_legit.json`) and 2553 further real Bash commands from seven session transcripts of this project.

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
  lift also needs the off-host backup copy, but a forged transcript that is then backed up is residual.
