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
| A session starts | The session folder is made. Shell commands get `AH_SESSION`, `AH_WORK` (the folder) and `TMPDIR` (`~/.agent-harness/tmp/<key>`, so test fixtures land in a place the session owns). The key is the first 8 characters of the folder name when that is a lowercase UUID, else the first 8 hex characters of its SHA-256; `ah reap` uses the same key. The agent is told in one line where its files belong. | `session_env.py` |
| A turn, a sub-agent or the session ends | Every git checkout in the session folder is saved: unpushed commits, tags, stashes, a detached HEAD and a snapshot of uncommitted and untracked files. An unchanged checkout costs no network call. On Stop and SubagentStop it runs in the background (`"async": true`), so a turn never waits for it; SessionEnd waits for it. If the session's temp directory has gone, it is made again. | `autosave.py` |
| A session starts and its folder was last measured over the quota | One more line names the three largest directories. Nothing is refused. | `session_env.py` |
| A session starts after `ah reap` removed checkouts of its folder, or after a save that failed | One more line names them (and where `reap.jsonl` says they were saved), or the checkout and the reason. | `session_env.py` |

Nothing is deleted by these hooks. Deleting is `ah reap run --apply`, which you run or schedule yourself (below).

On Codex the same two hooks run at SessionStart and Stop. Codex has no env file, so `AH_SESSION`, `AH_WORK` and
`TMPDIR` are not set there (the line of context gives `ah co` with `AH_SESSION=<id>` in front); the folder, the line
and the save work the same. Codex asks you to review new hooks in `/hooks`.

The save hook looks at 20 checkouts per run, within 20 seconds, inside the session folder and its temp directory
(saved as `tmp/<path>`); a checkout made elsewhere (the home folder, another directory) is not saved by it (see `--path` and `--loose` below). The save at
session end is best effort: the reaper saves again, freshly, before it deletes anything.

## Where saved work goes

Set these in `~/.agent-harness/local.json` ([local-config.md](local-config.md)):

- `rescue_remote`: the URL of a **private** repository you chose. Everything is saved there. Recommended. A
  github.com URL that `gh` reports public gets a bundle instead.
- Without it, a checkout's own remote is used when `rescue_to_origin` allows it: `"private"` (the default: only when
  `gh` proves the repository is private), `"always"` or `"never"`.
- Otherwise a bundle is written to `~/.agent-harness/rescue/<host>/<session>/<name>-<8 hex>/<stamp>.bundle`, with
  a small `.json` file beside it that holds the command to restore it.
- Unpushed commits (stashes included) that add a file with a secret-shaped name or content go to the bundle, never
  to a remote; the `.json` names the file.

On a remote the refs are `refs/rescue/<host>/<session>/<name>-<8 hex>/<stamp>/` followed by `heads/<branch>`,
`tags/<tag>`, `stash/<n>`, `detached` and `snapshot` (the working tree). `<name>` is the checkout's path inside the
session folder with `/` written as `-` (`top` when the session folder is itself the checkout); the 8 hex characters
keep two checkouts of the same name apart. For a `--path` directory `<session>` is `loose` and `<name>` is the
directory's name. `<stamp>` (UTC time and 4 hex) names one life of a checkout: later saves of the same checkout update
its copy, but a checkout made again at the same path gets a new stamp, so nothing saved before is ever changed. A
checkout's first save writes a random life token to `ah-life` in its own git dir (`.git/`, `.git/worktrees/<name>/`
for a linked worktree, the repository itself for a bare one that is not inside another checkout) and records it in
the state file; a clone or a worktree made again at the same path has another token or none, so it is a new life,
even when it holds the earlier life's commits. A save goes on with a stamp only when the token is the one recorded
and the commits that stamp's copy named are still in the checkout. A copy that named no commit (only held files, such
as an ignored `.env`) proves nothing, so a held file that changed is copied under a new stamp and the earlier copy
stays as it was. A checkout that `ah reap` began to delete always gets a new stamp.

Files that never go into a snapshot are copied to `~/.agent-harness/rescue/held/<host>/<session>/<name>-<8 hex>/
<stamp>/` (directories 0700, files 0600; never through a symlink) and never pushed: secret-shaped names such as
`.env`, `*.pem`, `*.key`, `.pgpass` and `*kubeconfig*`, files up to 1 MB whose content has a secret shape (a token in
a `.log`, a key in `config.py`; binary files too, with the shapes of `redact.py`), files over 20 MB, and ignored
files that are not rebuildable output or tool output (a directory with `pyvenv.cfg`, `CACHEDIR.TAG` or a `.gitignore`
of `*`, as `htmlcov` has). A symlink goes into the snapshot as a link. A tracked file held back keeps its committed
version in the snapshot. The checkout is kept, not deleted, when held files total more than 200 MB, when an ignored
file is over 20 MB (it is named), when the repository uses git-lfs, or when its own git config names a filter
program (that program is never run).

## Commands

`ah` below is `python3 ~/.claude/hooks/ah.py` (Codex: `python3 ~/.codex/agent-harness/ah.py`).

```sh
ah co OWNER/REPO [--ref REF] [--name NAME]   # a checkout in <session folder>/co/<name>, origin = the real URL
ah reap scan [--json] [--loose DIR ...] [--check-remote]   # read only: what is there, who owns it, what is unsaved
ah reap run                                  # dry run: prints the plan, changes nothing
ah reap run --apply [--idle-hours N]         # save, then delete what is eligible
ah reap run --apply --if-above 85            # only when the disk is at least 85% full; oldest first
ah reap run --apply --session ID ...         # only these session folders (they must still be idle)
ah reap run --apply --path /home/me/old-clone   # one named directory outside the work root
```

`--session` also lifts the own-folder rule; idleness still applies, so cleaning your own live session needs
`--idle-hours 0`. `--path` names one real directory exactly (no wildcard); a symlink, the home folder or a folder
that holds it, and anything under `~/.agent-harness`, `~/.claude` or `~/.codex` is refused.

`ah co` clones against a shared mirror in `~/.agent-harness/cache/git/` and then cuts the link, so the checkout
depends on no other checkout and "is this pushed?" always has an answer. Prefer it to cloning from a sibling checkout.

`ah reap scan` also lists docker containers and volumes. Label yours so they can be tied to the session:
`docker run --label ah.session=$AH_SESSION ...`. `--loose DIR` adds checkouts at most two levels below `DIR`, and
`--check-remote` asks each remote what it holds (without it the remote-tracking refs answer, and a local-path origin
shows as unknown). A scan never deletes. On a work root of 200 GB it takes minutes. It also reports how many bundles
and held files `~/.agent-harness/rescue` holds, and their size.

`run` is cheap when nothing is eligible: with `--if-above` it reads the disk use first and stops at once below the
threshold, and it decides eligibility (own folder, `.keep`, idle time, in use) before it measures a folder or asks git
anything about it. A walk for the idle time stops at the first recent change.

Exit codes of `ah reap`: 0 done or nothing to do (a kept item is not a failure), 1 a deletion, a docker removal or
the log write failed, 3 refused (bad arguments, unsafe platform).

## What `ah reap run --apply` removes, and when

A session folder is eligible when it has been idle for `reap_idle_hours` (default 48), or when it holds a `.done` file
and has been idle for 1 hour. With `--if-above PCT` nothing happens below that disk use; at or above it, folders idle
for at least 24 hours (a larger `--idle-hours` raises that, a smaller one does not lower it) go, oldest first, until
use is 5 points below `PCT`. A live session that waits a night for its owner looks idle, so a shorter time would take
its checkouts.

For an eligible folder, in this order:

1. Rebuildable directories go first, wherever they are: `node_modules`, `.venv`, `venv`, `__pycache__`,
   `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.next`, `.nuxt`, `.turbo`, `.parcel-cache`, `.gradle`, `.tox`,
   `target` beside a `Cargo.toml` or `pom.xml`, `dist` and `build` when git ignores them, and the contents of the
   session's temp directory (the directory stays, mode 0700, so a session that comes back still has its `TMPDIR`).
   Inside a checkout such a directory goes only when git tracks nothing in it; a kept checkout loses it too. A
   directory that holds a `.git` entry anywhere (`pip install -e git+...` clones into `.venv/src/<name>`) is never
   removed this way: its checkouts are saved like any other.
2. Every checkout and every bare repository (a directory with `HEAD`, `objects` and `refs`, also one inside a
   checkout, such as in its ignored `node_modules/`) in the folder and in the session temp directory is saved again
   (children first: a linked worktree before its repository, a bare repository before the checkout it sits in, which
   is saved once more after it goes); one that cannot be saved is kept, and so is the checkout around it. Only a
   proven save allows its removal. A checkout that a path outside the folder depends on is kept.
3. The folder is checked once more for use. Then each saved checkout is marked (`.git/ah-reaping`: no save runs over
   it while the mark is there), checked to hold exactly what was proven (no network), and deleted, read-only trees
   included, and its state file in `~/.agent-harness/state/git-save` goes with it (in every mode, `--session` and
   `--path` too), so a checkout made again at that path starts afresh. A deletion that stops part way leaves the
   mark, and the checkout is kept and reported from then on, with the refs or the bundle of its proven copy.
   Removing the mark lets a fresh copy be made beside that one, which stays untouched (the state file remembers that
   a deletion was begun, so this holds even when the deletion took the mark itself).
   Loose files stay, and so does the folder itself unless it is itself a checkout.
4. The rest of the session temp directory goes, except a `keep/` and what holds a kept checkout.
5. Stopped docker containers and the volumes tied to that session (label `ah.session`, or a bind mount under the
   folder) are removed. A container that is running keeps the whole folder. Images are never pruned.

The whole folder is kept when it holds a mount point (nothing on another file system is ever removed), when a
container tied to it is not stopped, or while autosave is saving it (the reaper holds autosave's lock while it works).
Only one `ah reap run --apply` runs at a time.

A run over everything (no `--session`, no `--path`) also removes what the harness itself left behind: directories in
`~/.agent-harness/tmp` named like a temp key that belong to no folder of the work root, once idle for the same hours
and unused (one that holds a checkout or a bare repository stays); state files in `~/.agent-harness/state/git-save` whose checkout or session folder no longer exists; and
mirrors in `~/.agent-harness/cache/git` that `ah co` has not used for 30 days (a mirror something borrows from stays).

Every deletion is one JSON line in `~/.agent-harness/logs/reap.jsonl`, written before the deletion starts (no row,
no deletion). An item kept inside an eligible folder is logged with its reason; folders left alone (not idle, `.keep`,
in use) are printed, not logged. A folder with a kept checkout is tried again only after another idle period. Without
`rescue_remote`, a checkout with no remote off this host becomes a bundle under `~/.agent-harness/rescue`, on this disk.

## What is never removed

- The folder of the session that runs the command, unless named with `--session`.
- A folder with a `.keep` file. Any `keep/` directory (a checkout that holds one is kept whole): put paid results
  and anything costly to recreate there.
- A folder a live process is using, a folder that is a symlink, and the harness's own protected paths.
- A checkout whose save could not be proven. Large loose files and unlabelled containers are reported only.
- Bundles and held files under `~/.agent-harness/rescue`: they can be the only copy. Delete them yourself.
- Small files left in a reduced folder: those follow the older `python3 ~/.claude/hooks/workdir.py prune` retention.

## Getting a saved checkout back

From the remote (the URL and ref names are in `reap.jsonl`; `git ls-remote <url> 'refs/rescue/*'` lists them):

```sh
git clone <the project's own URL> back && cd back
git fetch <url> 'refs/rescue/<host>/<session>/*:refs/rescue/*'
git for-each-ref refs/rescue                       # what came back
git switch -c recovered refs/rescue/<name>-<8 hex>/<stamp>/heads/<branch>
git restore --source refs/rescue/<name>-<8 hex>/<stamp>/snapshot --worktree .   # uncommitted, untracked files
```

From a bundle, run the `restore` command in the `.json` beside it. A bundle that leaves out what the project's
remote already has needs that remote first: `git clone <the project's URL> back && git -C back fetch <bundle>
'refs/*:refs/rescued/*'`; the snapshot is then `refs/rescued/heads/rescue/snapshot`. A bundle with everything clones
on its own: `git clone <bundle> back`, and the snapshot is `origin/rescue/snapshot`, a stash `origin/rescue/stash/<n>`,
a detached HEAD `origin/rescue/detached`. `git restore --source <the snapshot> --worktree .` brings the files back.
Copy held files back by hand from `~/.agent-harness/rescue/held/<host>/<session>/<name>-<8 hex>/`.

## Limits

What this does not cover:

- A change made in the moment between the last check and the deletion is lost with the checkout.
- A commit reachable only from the HEAD reflog (a detached HEAD that was left), and the repository of a submodule
  that was deinitialised (`.git/modules/<name>`), are not saved.
- The content check reads files up to 1 MB as UTF-8 text: a secret in a larger file is not seen (its name rules
  still apply).
- Secrets in untracked files that are gzip-compressed, UTF-16 or base64 encoded are not detected, so such a file can
  go into a snapshot on a remote.
- Ignored tool output without a marker (`pyvenv.cfg`, `CACHEDIR.TAG` or a `.gitignore` of `*`) and outside the
  rebuildable names is copied into `~/.agent-harness/rescue/held`, and nothing cleans that folder.
- A repository that uses git-lfs is never removed.
- A checkout elsewhere on disk that borrows objects through alternates, outside the places searched (the work root,
  two levels below the home folder, beside each `--path`), breaks when its lender goes.
- Processes of other users are invisible to the in-use check.
- `reap.jsonl` stays on this machine unless you ship it with `ah log-push`.
- Codex sessions get no `TMPDIR` and no `AH_WORK`.
- A docker container is tied to a session only by the label `ah.session` or a bind mount under the session folder.
- The command guard still refuses a typed `rm` of a `*.jsonl` file under `~/.agent-harness/tmp`. Other files in the
  session's own temp directory are the session's to delete.
- A remote that never answers is given half the save's time budget; then the save falls back to a bundle.

## Running it on a timer (your choice)

The installer schedules nothing. Before you add a timer:

- Read a dry run first: `ah reap run --if-above 85` (`ah reap run` without `--apply` changes nothing) prints what
  would go.
- Set `rescue_remote` to a private repository before installing. Without it the save pushes `refs/rescue/*` to each
  project's own origin when `gh` reports that repository private, and otherwise writes bundles to the same disk the
  timer is trying to free.
- Saved copies (rescue refs, bundles, held files) are never removed automatically. Delete them yourself.

Then, to clean up whenever the disk passes 85%, add one of these yourself.

macOS, `~/Library/LaunchAgents/com.agent-harness.reap.plist`, then `launchctl load` that file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agent-harness.reap</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>exec python3 "$HOME/.claude/hooks/ah.py" reap run --apply --if-above 85</string>
  </array>
  <key>StartInterval</key><integer>1800</integer>
</dict></plist>
```

Linux, two files in `~/.config/systemd/user/`, then `systemctl --user enable --now ah-reap.timer`:

```ini
# ah-reap.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 %h/.claude/hooks/ah.py reap run --apply --if-above 85

# ah-reap.timer
[Timer]
OnBootSec=10min
OnUnitActiveSec=30min
[Install]
WantedBy=timers.target
```
