# Workspace janitor

`harness/hooks/workspace_janitor.py` keeps agent and runner checkouts from piling up (t2-dev reached 0 bytes free on
2026-11-21 with 117 GB of per-session copies, 50 GB of scratch in /dev/shm and ~895k OOM kills from uncapped test
containers). It is built on two modules:

- `hygiene_safety.py`: the one set of safety rules (recoverability, in-use, service references, removal, regenerable
  list, command splitter).
- `copy_hygiene.py` (PR #284): the single reuse API (`acquire`), the disk floor, the `/dev/shm` deny, the reaper, and
  the one config file and deletion switch.

## Deletion is off until the owner turns it on

Everything that removes files (`release`, `sweep --apply`, `session-end`, `copy_hygiene.py reap --apply`) checks one
switch: `"reaper_delete_enabled": true` (a literal JSON `true`) in `~/.agent-harness/state/copy-hygiene.json`.
`HARNESS_JANITOR=off` is a kill switch on top. The installer never sets it. Until then the hourly timer, `release` and
the SessionEnd hook only report, and `session-end` starts nothing.

## Reuse: one checkout per repository and PR/lane

```
python3 ~/.claude/hooks/copy_hygiene.py acquire --repo <checkout> --key pr-1408 [--ref <branch|tag|sha>]
python3 ~/.claude/hooks/copy_hygiene.py acquire --url <remote> --key pr-1408      # no checkout needed
```

One bare mirror per repository (`~/.agent-harness/mirrors/<host>/<name>-<id>.git`; the id hashes host and path, so
`a__b/c` and `a/b__c`, or one repo on two hosts, never collide) and one detached worktree per (repository, key) under
`~/.agent-harness/test-copies/<name>-<id>/<key>`. First clone goes to a temp folder and is renamed into place; a lock per
mirror and per key serialises runners; the free-space floor is checked before cloning and before `worktree add`. A branch
name resolves through `refs/remotes/origin/<ref>` after a fresh fetch (the clone's `refs/heads/*` copies are deleted, and
`origin/HEAD` is set with `remote set-head -a`, so a default branch of `master` works). The copy moves only when it is
clean and its HEAD commit is on a remote or still in your checkout; otherwise `acquire` exits nonzero (3 disk floor,
4 stale/refused, 1 other) and changes nothing. Use a PR number or lane as the key, never a per-round name.

## Cleanup

| Piece | What it does |
|---|---|
| `SessionEnd` hook (`session-end`) | When deletion is on, starts a detached `release --session <id> --apply --budget 600` and returns at once (the probes and per-repo `ls-remote` can take minutes). |
| `release --session ID / --path DIR [--apply] [--budget S]` | For `~/.agent-harness/work/<id>` or one folder inside `~/.agent-harness/{work,checkouts,test-copies}` (nothing else is accepted): removes each checkout that is verified recoverable. Removes the session folder when no file is left. Dry run without `--apply`. Call it at the end of every runner job. |
| `sweep --apply` (hourly timer) | `copy_hygiene.py reap`; `release` for every session folder idle (newest mtime or ctime) longer than `max_age_hours` (24) unless its Claude process is alive (session id on a command line, or a WAL newer than the TTL); user-owned `/dev/shm` entries idle longer than `shm_ttl_hours` (6) that nothing holds open or maps (`sem.*`, `PostgreSQL.*`, `libpod*` and browser segments are never touched; the process scan is taken inside the `/dev/shm` step and a failed scan keeps everything); reports the count and size of `~/.agent-harness/mirrors` and removes a mirror idle longer than `mirror_ttl_days` (14) only when it has no `worktrees/<k>` admin entry at all (even for a folder that is missing), a fresh `ls-remote` of its origin succeeds and every commit in it (all refs, so a branch that exists only in the mirror) is on what the origin advertises, nothing uses or references it and deletion is on (report-only otherwise); lists running docker/podman containers with no memory limit. Every removal re-reads idle time under the lock and repeats the process and service probes first. A failed probe keeps everything and exits 0. |
| `pretool` hook | Denies `docker\|podman run\|create` and `compose up\|run` without a memory cap, and Elasticsearch/OpenSearch without a heap cap (also via `--env-file`). Handles `sudo/env/timeout/nice/command`, `docker container run`, `$(...)`, pipes and `bash -c`; stops reading flags at the image name. Fails open. |

Testcontainers-style tests start containers through the Docker API and never reach the hook; the sweep lists them as
uncapped. Cap them in the test setup or run the daemon with a default cgroup-parent slice that has `MemoryMax`.

## What counts as safe to delete (`hygiene_safety.recoverable`)

Clean tree; no skip-worktree/assume-unchanged files; no stash, LFS or submodule; no rebase/merge in progress; no other
linked worktree of a standalone clone; **ignored files only when each is on the one regenerable list**
(`REGENERABLE_IGNORED`: `node_modules`, `.venv`, `target`, `dist`, `build`, `coverage`, `.cache`, ...), and an ignored
`build/`-style folder holding a nested repository is kept; every commit reachable from what each remote advertises right
now (`ls-remote`, not stale tracking refs). A kept path keeps every ancestor.

Never removed: anything a process uses (cwd, root, **exe, open files and `/proc/*/maps`**), anything a systemd unit
(system and user: `WorkingDirectory`, `ExecStart*`, `Environment*`, ... via `systemctl show -- <units>`, including
`list-units --all` for `systemd-run` units; template units are skipped), crontab, docker or podman container, or
launchd plist names (`~`, `$HOME`, `${HOME}`, `%h` expanded; symlinks in `~/bin`, `~/.local/bin` followed; compared by
`realpath`), anything with a mount inside (removal never crosses a mount), names in `protect_names`
(yates, optinrouter), matched against every checkout's path AND its remote URLs (release, reap and mirror removal alike),
ignored `test-results/` and `playwright-report/` folders (click-test evidence, not regenerable). Every probe fails closed:
an error or timeout keeps everything. Every removal (checkout, session folder, mirror) goes through one function that
re-reads the service units without the 60-second cache right before deleting; a session folder is removed bottom-up with
`rmdir` only, so a file written meanwhile survives. With deletion off, `release` and `sweep` report `would_remove` /
`would_free_bytes` (`mode: report-only`) and never `removed` / `freed`.

## Install the timer (Linux, opt-in)

```
python3 install.py --apply --janitor-timer
loginctl enable-linger "$USER"        # without linger a user timer runs only while you are logged in
```

The service has `TimeoutStartSec=1800` and `MemoryMax=1G`. By hand: copy `harness/systemd/agent-harness-janitor.*` to
`~/.config/systemd/user/` and `systemctl --user enable --now agent-harness-janitor.timer`. To let it delete, set
`"reaper_delete_enabled": true` in `copy-hygiene.json` after reading a report-only run (`sweep --json`).

Config: `~/.agent-harness/state/copy-hygiene.json` (`max_age_hours`, `shm_ttl_hours`, `mirror_ttl_days`, `roots`, `protect_names`,
`default_memory`, `reaper_delete_enabled`, plus the disk-floor keys). Roots outside `~/.agent-harness/{work,checkouts,
test-copies}` are ignored: one alert row per root per UTC day, across the janitor and the reaper (`janitor-root-ignored` from the janitor, `root-ignored` from the reaper, deduped through `state/alert-daily.json`, which is flock-protected). Without `/proc` (macOS) session liveness reads `ps -axo command=`; with no process list at all every session counts as alive. Audit and alert log: `~/.agent-harness/state/copy-hygiene-alerts.jsonl`.

Mirror safety checks are offline. Whether a mirror or a test copy holds commits the remote lacks is answered from a throwaway bare
repository that borrows the object directory (alternates) and has no promisor remote, so a missing id fails at once and nothing is
downloaded (git 2.43 has no `GIT_NO_LAZY_FETCH` and otherwise spins a failed lazy fetch per missing id). A `cat-file` or `rev-list`
failure or timeout always keeps the folder. The one exception is `recoverable`: when HEAD is not on what the remote advertises
and the copy lacks advertised commits (its own branch advanced upstream), it makes ONE time-limited fetch of the missing
`refs/heads/*` heads (only the copy's upstream branch when it has one; never `refs/pull/*`), using the filter a partial clone
has stored, and re-checks offline; a failed fetch keeps the copy. For mirrors, every ref except `refs/remotes/*` (branches, tags,
notes, `refs/backup/*`, anything) and HEAD count as local work, so a commit parked under a tag or a custom ref keeps the mirror;
a lightweight tag removed on the remote pins it only when its commit is on no advertised ref, and an annotated tag that no
remote ref carries is local-only and keeps it.
