# `ah doctor`: the host self-test

```
ah doctor [--json] [--role worker|reviewer|supervisor|all] [--strict] [--codex]
```

Exit codes:
- 0: nothing FAILED. UNPROVEN is a warning, unless `--strict` makes it count.
- 1: at least one row FAILED.
- 2: a config file exists but cannot be read (`local.json`, `settings.json`, `hooks.json`, `config.toml`, the managed
  drop-in or a generated sandbox file).

Doctor writes nothing except its own probe folder under `$TMPDIR`, which it removes. It never runs a hook script and
never reads command text. Short-lived probe files are removed at once: one in `~/.agent-harness/work` for the twin,
`$HOME/ah-doctor-outside-*` for the control, and any file a leaked denial created.

## Proven boundaries

Each probe has three parts:
- The control proves the target is real outside the sandbox: the file exists and this user can read one byte of it,
  or the folder is writable.
- The denial runs the same operation inside the role's sandbox, and must fail.
- The twin runs the nearest allowed operation in the same sandbox invocation, and must succeed.

| Outcome | When |
|---|---|
| PROVEN | control ok, denial refused, twin ok |
| FAILED | the denial went through, or the twin was refused (a boundary that blocks everything proves nothing) |
| UNPROVEN | the control could not be set up (target absent, mechanism missing) |

Reads go to `/dev/null` and only exit codes are kept, so no probe prints file content.

| Probe | Denial | Twin |
|---|---|---|
| `secrets` | read 1 byte of each `secret_paths` file (the first regular file under a folder) | read a file in the probe project |
| `records` | create a file under each existing `record_paths` folder, or open an existing record file for append without writing (a missing file such as `OFF` is never created) | write in `~/.agent-harness/work` (reviewer: read the project) |
| `write-scope` | write `$HOME/ah-doctor-outside-*` | write, `git init` and `git commit` in the probe project (reviewer: read it) |
| `read-only` (reviewer) | write in the probe project | read it |
| `approvals` (worker, supervisor) | worker: append to a stand-in `approvals.jsonl`; supervisor: append to a stand-in `roles.json` | worker: write the project; supervisor: append to the stand-in `approvals.jsonl` |
| `network` (`--codex`) | `curl https://example.com` | `curl https://github.com` (UNPROVEN while `features.network_proxy` is off) |

The probe sandbox is built from `ah_sandbox.role_lists`, which reads the same data as the generated settings:
- macOS: `/usr/bin/sandbox-exec -p` with an `(allow default)` profile that denies the secrets, denies every write,
  then allows the writable roots and denies the records again.
- Linux: `bwrap` with a read-only root, the writable roots bound read-write, the records bound read-only again, and
  the secrets hidden.

With `--codex` the probes also run under the real `codex sandbox -P ah-<role>`. Claude Code's own enforcement costs a
model call, so it is proven by `tests/e2e_combined.py` rather than by doctor.

## Checks

| id | Check | FAILED when |
|---|---|---|
| `local` | `local.json` parses | not JSON or not an object (exit 2) |
| `switch` | ON or OFF and since when; harness jobs loaded (`launchctl print` for `ah_switch.MAC_LABELS`, with both label prefixes; `systemctl --user is-active` for `LINUX_UNITS`) | a job runs while OFF |
| `files.<flavor>` | installed files against the newest release snapshot | any file differs or is missing |
| `wiring.<flavor>` | every harness handler goes through `ah_hook.py`, names an installed script, and no handler on PreToolUse, PostToolUse, PostToolUseFailure or PermissionDenied matches `Bash` (Claude Code's matcher rule); live wiring equals the snapshot's groups | any of those |
| `imports` | every installed `.py` imports under the `python3` on PATH with `-I` (one subprocess per flavor) | any import fails |
| `codex-trust` | each Codex harness handler's trust hash (sha256 of `{event_name, hooks:[{type, command, timeout, async}]}`) equals its `config.toml` entry | UNPROVEN: "review in /hooks" |
| `shim` | `harness` on PATH carries the switch-shim mark in its first 4 KiB | another program has the name |
| `python` | `python3` on PATH is 3.9 or newer | older or missing |
| `gh`, `mechanism` | gh installed and `gh auth status` ok; sandbox-exec or a working bwrap | gh missing or logged out (mechanism missing is UNPROVEN) |
| `backup` | age of `~/.agent-harness/logs/log-backup.last-ok` | older than 24 h, or installed with no valid marker (UNPROVEN when not installed) |
| `rescue-remote` | `rescue_remote` visibility (`gh repo view --json visibility`) | PUBLIC; unset says saves go to bundles |
| `disk` | used space of the home volume | above 70% (the reaper's timer threshold) |
| `managed` | the managed drop-in, when present, equals `ah sandbox show --flavor managed --role <sandbox_role>` | it differs |
| `sandbox-files` | `~/.agent-harness/sandbox/<role>.claude.json`, when present, equals `ah sandbox show` | out of date |

The first time doctor runs on a host it may report `switch` FAILED (old jobs still loaded while OFF), `shim` FAILED
(the Go `harness` binary has the name) and `disk` FAILED. These are the findings it exists to surface.
