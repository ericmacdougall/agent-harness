# Turning the harness off and on

## Three ways to run it

```
~/.agent-harness/bin/harness off --reason "trying without it"     # the shim install.py puts there
python3 ~/.claude/hooks/ah_switch.py off --reason "trying without it"
python3 ~/.claude/hooks/ah.py off --reason "trying without it"
```

`on` and `status` work the same way (`ah switch-status` for the status). Add `~/.agent-harness/bin` to `PATH` to type plain `harness off`. The shim passes any other word (`harness tickets`, `harness version`) to a Go `harness` binary elsewhere on `PATH`.

Nothing asks for a guard, an approval, a WAL note or a ticket. Each run adds one line to `~/.agent-harness/logs/switch.log`.

## What `off` does

1. It creates `~/.agent-harness/OFF`, a small JSON file that says who turned it off, when, and why.
2. Every harness hook is wired as `python3 ~/.claude/hooks/ah_hook.py <script> [args]` (Codex: `~/.codex/agent-harness/ah_hook.py`, and the same for the git commit-msg backstop). While the flag exists, that launcher exits 0 at once and never starts the script. Guards, gates, reminders and injected context all go silent, in sessions that are already running too. A running session reads its hook commands once at start, but it calls the launcher every time, and the launcher reads the flag on every call.
3. It moves the marked harness block out of `~/.claude/CLAUDE.md` (and the Codex block out of `~/.codex/AGENTS.md`) into `~/.agent-harness/off-stash/`. Sessions started while off get no harness rules. Your own text outside the markers is not touched.
4. With `--services` it also stops the harness LaunchAgents that are loaded (`<prefix>ahd`, `log-backup`, `backup-watch`, `ops-watch`, where `<prefix>` is local.json `launchd_label_prefix`, `com.agent-harness.mission-control` and `com.agent-harness.floor`), or on Linux the systemd user units (`ahd.service`, `log-backup.timer`, `backup-watch.timer`, `ops-watch.timer`, `ahc-core`, `ahc-review`, `agent-harness-floor.path`). It records which ones it stopped. netwatch keeps running.

## What `off` does not do

- It does not uninstall anything or edit `settings.json` or `hooks.json`. The wiring stays in place and only goes quiet.
- A running session still holds the instructions it read at start. Start a new session to drop them.
- Without `--services`, background jobs keep running.
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

Old checkouts and feature branches of this repo carry old installers. Those installers know nothing about the launcher or the flag. Running one used to put old hook files and direct wiring back.

- `harness/RELEASE` holds one integer. Every successful install records that release and the source commit in `~/.agent-harness/install-state.json`. It snapshots the installed files, the managed hook groups and the instruction block to `~/.agent-harness/releases/<release>/` (the newest two are kept). It then writes the floor to `~/.agent-harness/floor.json`.
- `install.py` and `install_codex.py` refuse a checkout whose release is below the floor, with a one-line message. `ah install-files` refuses a `--from-ref` whose `harness/RELEASE` is below the remote host's floor. An installer old enough to have no `harness/RELEASE` cannot refuse, so the watcher catches it instead.
- `harness floor-check` reports when an installer that predates the floor has run: the install state lacks a release or is lower, there is a new backup directory the floor does not know, or hooks are wired directly instead of through the launcher. `harness floor-check --repair` puts the files, the wiring and the instruction block back from the snapshot, and writes one line to `~/.agent-harness/logs/floor.log`. While the harness is off, the repair keeps the instruction block in the stash and never removes the flag. A newer install raises the floor itself and is never undone. Files you edit by hand, with no old installer involved, are reported and left alone.
- On macOS, `install.py` loads the LaunchAgent `com.agent-harness.floor`. It runs `floor-check --repair` when `~/.claude/hooks`, `~/.claude/settings.json` or the install state changes (at most every 30 s). On Linux it uses the systemd user units `agent-harness-floor.path` and `agent-harness-floor.service`.

The watcher also puts the wiring back if you delete the hook entries from `settings.json` by hand. To silence the hooks, use `harness off`. To edit the wiring by hand, remove the watcher first.

### Downgrading on purpose

```
python3 install.py --apply --allow-downgrade
python3 install_codex.py --apply --allow-downgrade
python3 ~/.claude/hooks/ah.py install-files ... --allow-older
```

A deliberate downgrade moves the floor down to the installed release, so the watcher keeps it.

### Removing the floor watcher

```
python3 install.py --apply --no-floor-watch     # removes it and remembers the choice; --floor-watch brings it back
```

To stop it by hand, run `launchctl bootout gui/$(id -u)/com.agent-harness.floor` and delete `~/Library/LaunchAgents/com.agent-harness.floor.plist`. On Linux, run `systemctl --user disable --now agent-harness-floor.path` and delete both units from `~/.config/systemd/user/`. `harness off --services` stops it until `harness on`.
