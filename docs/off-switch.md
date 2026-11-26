# Turning the harness off and on

## Three ways to run it

```
~/.agent-harness/bin/harness off --reason "trying without it"     # the shim install.py puts there
python3 ~/.claude/hooks/ah_switch.py off --reason "trying without it"
python3 ~/.claude/hooks/ah.py off --reason "trying without it"
```

`on` and `status` work the same way (`ah switch-status` for the status). Add `~/.agent-harness/bin` to `PATH` to type plain `harness off`. The shim answers `off`, `on`, `status` and `floor-check` and nothing else: any other word prints its usage and exits 2. It never hands a word to another `harness` program on `PATH`.

If `~/.agent-harness/bin/harness` is some other program, `install.py --apply` renames it to `harness.retired-<UTC stamp>` beside it (kept, never deleted), writes the shim, and prints both paths.

Nothing asks for a guard, an approval, a WAL note or a ticket. Each run adds one line to `~/.agent-harness/logs/switch.log`.

## What `off` does

1. It creates `~/.agent-harness/OFF`, a small JSON file that says who turned it off, when, and why.
2. Every harness hook is wired as `python3 ~/.claude/hooks/ah_hook.py <script> [args]` (Codex: `~/.codex/agent-harness/ah_hook.py`). While the flag exists, that launcher exits 0 at once and never starts the script, in sessions that are already running too. A running session reads its hook commands once at start, but it calls the launcher every time, and the launcher reads the flag on every call.
3. It moves the marked harness block out of `~/.claude/CLAUDE.md` (and the Codex block out of `~/.codex/AGENTS.md`) into `~/.agent-harness/off-stash/`. Sessions started while off get no harness rules. Your own text outside the markers is not touched.
4. It stops the harness background jobs that are loaded: the LaunchAgents `<prefix>log-backup`, `<prefix>backup-watch`, `<prefix>ops-watch` (`<prefix>` is local.json `launchd_label_prefix`), `com.agent-harness.mission-control` and an old `com.agent-harness.floor`; on Linux the systemd user units `log-backup.timer`, `backup-watch.timer`, `ops-watch.timer` and an old `agent-harness-floor.path`, when their unit file is in `~/.config/systemd/user/`. It records which ones it stopped. netwatch keeps running.

`harness off --keep-services` does steps 1 to 3 and leaves the background jobs running. `--services` is accepted and does nothing (it was the opt-in before release 1001).

## What `off` does not do

- It does not uninstall anything or edit `settings.json` or `hooks.json`. The wiring stays in place and only goes quiet.
- A running session still holds the instructions it read at start. Start a new session to drop them.
- A hook that some other tool wired straight to a script, not through `ah_hook.py`, still runs.

## `on`

`harness on` puts the stashed blocks back exactly where they were. If you edited the file while the harness was off, it appends the block at the end and keeps your edits. It then restarts only the services that `off` stopped, and removes the flag last. `on` and `off` are safe to run twice.

An install while the harness is off installs files and wiring but leaves the instruction block in the stash, refreshed to the new version. It does not touch the flag or the stash.

## Status

```
harness status            # harness: OFF since 2026-11-24T22:00:00Z by eric reason: ...; turn on: harness on
harness status --json     # flag, stashed blocks, stopped services, installed release, floor
```

## The release floor

Old checkouts and feature branches of this repo carry old installers. Those installers know nothing about the launcher or the flag. Running one puts old hook files and direct wiring back.

- `harness/RELEASE` holds one integer. Every successful install records that release and the source commit in `~/.agent-harness/install-state.json`. It snapshots the installed files, the managed hook groups and the instruction block to `~/.agent-harness/releases/<release>/` (the newest two are kept). It then writes the floor to `~/.agent-harness/floor.json`.
- `install.py` and `install_codex.py` refuse a checkout whose release is below the floor, with a one-line message.
- `harness floor-check` reports when an installer that predates the floor has run: the install state lacks a release or is lower, there is a new backup directory the floor does not know, hooks are wired differently from the snapshot or directly instead of through the launcher, or the instruction block is back while the harness is off. It only reports. The fix is `install.py --apply` from an up-to-date checkout. Files you edit by hand, with no old installer involved, are reported as a note and are not drift.

Nothing rewrites `settings.json` except an explicit `install.py --apply`. Release 1001 removed `harness floor-check --repair` (it now exits 2 and says so) and the floor watcher that ran it on every change. The first `install.py --apply` of release 1001 on the real home stops and deletes an old watcher (`com.agent-harness.floor`, or `agent-harness-floor.path` and `.service` on Linux).

### Downgrading on purpose

```
python3 install.py --apply --allow-downgrade
python3 install_codex.py --apply --allow-downgrade
```

A deliberate downgrade moves the floor down to the installed release.
