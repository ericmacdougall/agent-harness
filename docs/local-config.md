# Local configuration (`~/.agent-harness/local.json`)

The harness names no host, project, person or backup remote in its code. Everything that differs between installs
lives in one optional file, `~/.agent-harness/local.json`, read by `harness/hooks/ah_local.py`. A missing or
malformed file is the same as an empty one: a fresh install works and has no remote hosts. Copy
`harness/local.json.example` to start. The file is read once per process; `AH_LOCAL_CONFIG=<path>` points at another
file (tests).

| Key | Shape | Used by | Default |
|---|---|---|---|
| `hosts` | `{name: {"role", "os": "linux"\|"macos"\|"windows", "limits": {...}}}` | `ah kill --host` (Windows hosts take the PowerShell route); every name is added to the sandbox network allow-list ([sandbox](sandbox.md)) | none |
| `heavy_job_host` | host name | Mission Control's remote WAL probe (off when unset) | none |
| `remote_worktree_hosts` | list of host names | `ah worktree-remove --host`; added to the sandbox network allow-list (kept for a later allow-list; workers' network is open) | none (only `local`) |
| `trusted_git_hosts` | list of host names | added to the sandbox network allow-list (kept for a later allow-list; workers' network is open) | `github.com` only |
| `backup_remotes` | `{rclone type: [remote names]}` | the log backup (`backup_remotes.b2`) | none |
| `launchd_label_prefix` | dotted prefix ending in `.` | the launchd labels of log-backup, backup-watch, ops-watch (`harness off` stops them) | `com.agent-harness.` |
| `protected_label_prefixes` | list of prefixes | `ah kill`: jobs with these labels need the owner's approval to stop (the label prefix above is always added) | none |
| `chat_prefix` | one line, at most 60 characters | `ah chat send`: the fixed prefix of every message | `Claude (bot). ` |
| `ticket_base_url` | https URL of a GoodQA API | `gq_browser` / `ah chat`: the one host a GoodQA token is sent to | `https://goodqa.app/v1` |
| `db_tool_patterns` | `[{"tool": "<tool name regex>", "fields": [...]}]` | prod-delete guard: extra MCP tools whose input fields are read as commands; `install.py` adds them to the hook matcher (re-run it after a change). A pattern that matches `Bash` is ignored | none |
| `review_forbidden_topics` | `[{"pattern": "<regex>", "label": "..."}]` | `kimi_review.py`: text that must never reach an external reviewer | none (Granola and interview material are built in) |
| `rescue_remote` | URL of a **private** git repository you chose | `git_save.py` (the save hook `autosave.py` and `ah reap`): every unsaved commit, stash and working-tree snapshot is pushed there under `refs/rescue/<host>/<session>/...` before anything is deleted; see [lifecycle.md](lifecycle.md) | none: see `rescue_to_origin` |
| `rescue_to_origin` | `"private"`, `"always"` or `"never"` | `git_save.py`, when `rescue_remote` is not set: may saved work go to the checkout's own remote? `"private"` needs `gh` to prove the repository is private. When the answer is no, the work goes into a verified bundle under `~/.agent-harness/rescue/` | `"private"` |
| `reap_idle_hours` | number of hours | `ah reap run`: how long a session folder must be idle before it may be removed (`--idle-hours` on the command line wins) | `48` |
| `session_tmpdir` | `true` or `false` | `session_env.py`: `false` stops it exporting `TMPDIR=~/.agent-harness/tmp/<key>` (the first 8 characters of a lowercase UUID session id, else 8 hex characters of its SHA-256) to the session's shell commands | `true` |
| `session_quota_gb` | number of GB | `session_env.py`: a session whose folder was last measured above this gets one extra line at session start naming its three largest directories; nothing is refused | `10` |
| `sandbox_allowed_domains`, `sandbox_extra_deny_read`, `sandbox_extra_write`, `sandbox_excluded_commands`, `sandbox_role` | lists of hosts or paths; a role name | `ah sandbox` and the sandbox files `install.py` writes: see [sandbox](sandbox.md) | none; `sandbox_role` is `worker` |

Keys the harness does not know are ignored. A key of the wrong type falls back to its default.

Changing an existing install: keep `launchd_label_prefix` at the prefix the jobs were installed with, or the
installers register a second job beside the old one. Remove the old LaunchAgent first if you change it.
