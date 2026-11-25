# Session folders, saved work and the reaper

A worker host once filled its disk to 98% with about 10,650 git checkouts, their dependency trees, test fixtures and
containers. Nothing recorded who made them, so nothing could safely delete them. This page describes what the harness
does about it. No part of it blocks or delays a tool call, and none of it reads command text.

## The rule

1. **The path is the owner.** What a session makes lives in `~/.agent-harness/work/<session-id>/`. Whose a file is
   can be read from where it lies.
2. **Save, then delete.** Nothing with unsaved work is removed until that work is proven to exist somewhere else: a
   ref on a remote that `git ls-remote` shows with the exact commit id, or a bundle that passes `git bundle verify`.
3. **Unknown means keep.** A git error, a timeout, an unreadable directory or a process still using the folder: the
   folder stays and the reason is reported.

## What happens without anyone asking

| When | What | By |
|---|---|---|
| A session starts | The session folder is made. Shell commands get `AH_SESSION`, `AH_WORK` (the folder) and `TMPDIR` (`~/.agent-harness/tmp/<first 8 characters of the session id>`, so test fixtures land in a place the session owns). The agent is told in one line where its files belong. | `session_env.py` |
| A turn, a sub-agent or the session ends | Every git checkout in the session folder is saved: unpushed commits, tags, stashes, a detached HEAD and a snapshot of uncommitted and untracked files. An unchanged checkout costs no network call. | `autosave.py` |
| A session starts and its folder was last measured over the quota | One more line names the three largest directories. Nothing is refused. | `session_env.py` |

Nothing is deleted by these hooks. Deleting is `ah reap run --apply`, which you run or schedule yourself (below).

On Codex the same two hooks run at SessionStart and Stop. Codex has no env file, so `AH_WORK` and `TMPDIR` are not
set there; the folder, the line of context and the save work the same. Codex asks you to review new hooks in `/hooks`.

Limits worth knowing:

- The save hook is synchronous: the end of a turn waits for it, at most 20 seconds when many checkouts changed.
- It looks at 20 checkouts per run and only inside the session folder. A checkout made elsewhere (the home folder,
  another directory) is not saved by the hook; see `--path` and `--loose` below.
- The save at session end is best effort. The reaper saves again, freshly, before it deletes anything.
- The command guard still refuses a typed `rm` of a `*.jsonl` file under `~/.agent-harness/tmp`. Other files in the
  session's own temp directory are the session's to delete.

## Where saved work goes

Set these in `~/.agent-harness/local.json` ([local-config.md](local-config.md)):

- `rescue_remote`: the URL of a **private** repository you chose. Everything is saved there. Recommended.
- Without it, a checkout's own remote is used when `rescue_to_origin` allows it: `"private"` (the default: only when
  `gh` proves the repository is private), `"always"` or `"never"`.
- Otherwise a bundle is written to `~/.agent-harness/rescue/<host>/<session>/<name>-<8 hex>.bundle`, with a small
  `.json` file beside it.

On a remote the refs are `refs/rescue/<host>/<session>/<name>-<8 hex>/` followed by `heads/<branch>`, `tags/<tag>`,
`stash/<n>`, `detached` and `snapshot` (the working tree). `<name>` is the checkout's path inside the session folder
with `/` written as `-`; the 8 hex characters keep two checkouts of the same name apart.

Files that never go into a snapshot are copied to `~/.agent-harness/rescue/held/<host>/<session>/<name>-<8 hex>/`
(directories 0700, files 0600): secret-shaped names such as `.env`, `*.pem` and `*.key`, files over 20 MB, and ignored
files that are not rebuildable output. If they total more than 200 MB the checkout is kept, not deleted.

## Commands

`ah` below is `python3 ~/.claude/hooks/ah.py` (Codex: `python3 ~/.codex/agent-harness/ah.py`).

```sh
ah co OWNER/REPO [--ref REF] [--name NAME]   # a checkout in <session folder>/co/<name>, origin = the real URL
ah reap scan [--json] [--loose DIR ...] [--check-remote]   # read only: what is there, who owns it, what is unsaved
ah reap run                                  # dry run: prints the plan, changes nothing
ah reap run --apply                          # save, then delete what is eligible
ah reap run --apply --if-above 70            # only when the disk is at least 70% full; oldest first
ah reap run --apply --session ID             # one session folder
ah reap run --apply --path /home/me/old-clone   # one named directory outside the work root
```

`ah co` clones against a shared mirror in `~/.agent-harness/cache/git/` and then cuts the link, so the checkout
depends on no other checkout and "is this pushed?" always has an answer. Prefer it to cloning from a sibling checkout.

`ah reap scan` also lists docker containers and volumes. Label yours so they can be tied to the session:
`docker run --label ah.session=$AH_SESSION ...`. `--loose DIR` adds checkouts found directly under `DIR`, and
`--check-remote` also asks each remote what it already holds. A scan never deletes.

Exit codes of `ah reap`: 0 done or nothing to do, 1 something failed, 3 refused (bad arguments, unsafe platform).

## What `ah reap run --apply` removes, and when

A session folder is eligible when it has been idle for `reap_idle_hours` (default 48), or when it holds a `.done` file
and has been idle for 1 hour. With `--if-above PCT` nothing happens below that disk use; at or above it, folders idle
for 6 hours go, oldest first, until use is 5 points below `PCT`.

For an eligible folder, in this order:

1. Rebuildable directories go first, wherever they are: `node_modules`, `.venv`, `venv`, `__pycache__`,
   `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.next`, `.nuxt`, `.turbo`, `.parcel-cache`, `.gradle`, `.tox`,
   `target` beside a `Cargo.toml` or `pom.xml`, `dist` and `build` when git ignores them, and the session's temp
   directory. This also happens to folders that end up kept.
2. Every checkout is saved again (children first: a linked worktree before its repository). Only a proven save allows
   its removal. A checkout that a path outside the folder depends on is kept.
3. The folder is checked once more for use, then deleted, read-only trees included.
4. Docker containers and volumes labelled for that session are stopped and removed. Images are never pruned.

Every deletion, and every item kept with its reason, is one JSON line in `~/.agent-harness/logs/reap.jsonl`.

## What is never removed

- The folder of the session that runs the command, unless named with `--session`.
- A folder with a `.keep` file. Any `keep/` directory: put paid results and anything costly to recreate there.
- A folder a live process is using, a folder that is a symlink, and the harness's own protected paths.
- A checkout whose save could not be proven. Large loose files and unlabelled containers are reported only.
- Small files left in a reduced folder: those follow the older `python3 ~/.claude/hooks/workdir.py prune` retention.

## Getting a saved checkout back

From the remote (the URL and ref names are in `reap.jsonl`; `git ls-remote <url> 'refs/rescue/*'` lists them):

```sh
git clone <the project's own URL> back && cd back
git fetch <url> 'refs/rescue/<host>/<session>/*:refs/rescue/*'
git for-each-ref refs/rescue                       # what came back
git switch -c recovered refs/rescue/<name>-<8 hex>/heads/<branch>
git restore --source refs/rescue/<name>-<8 hex>/snapshot --worktree .   # the uncommitted and untracked files
```

From a bundle: `git clone ~/.agent-harness/rescue/<host>/<session>/<name>-<8 hex>.bundle back`. Everything is a
branch there: the snapshot is `origin/rescue/snapshot`, a stash `origin/rescue/stash/<n>`, a detached HEAD
`origin/rescue/detached`. The same `git restore --source origin/rescue/snapshot --worktree .` brings the files back.
Copy held files back by hand from `~/.agent-harness/rescue/held/<host>/<session>/<name>-<8 hex>/`.

## Running it on a timer (your choice)

The installer schedules nothing. Run `ah reap run --if-above 70` (no `--apply`) first and read the plan. Then, to
clean up whenever the disk passes 70%, add one of these yourself.

macOS, `~/Library/LaunchAgents/com.agent-harness.reap.plist`, then `launchctl load` that file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agent-harness.reap</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>exec python3 "$HOME/.claude/hooks/ah.py" reap run --apply --if-above 70</string>
  </array>
  <key>StartInterval</key><integer>1800</integer>
</dict></plist>
```

Linux, two files in `~/.config/systemd/user/`, then `systemctl --user enable --now ah-reap.timer`:

```ini
# ah-reap.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 %h/.claude/hooks/ah.py reap run --apply --if-above 70

# ah-reap.timer
[Timer]
OnBootSec=10min
OnUnitActiveSec=30min
[Install]
WantedBy=timers.target
```
