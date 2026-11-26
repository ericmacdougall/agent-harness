# Sandbox profiles per role (`ah sandbox`)

The boundary is the operating system's sandbox and the vendor's permission rules, not harness code. `ah sandbox`
only writes that boundary down, as native settings for Claude Code (2.1.332) and permission profiles for Codex
(0.171). No hook reads a command, and nothing here installs itself or switches anything on. `ah doctor`
([doctor.md](doctor.md)) proves on each host that the lists hold, and `tests/e2e_combined.py` proves it against the
real Claude Code and Codex.

## Roles

| Role | Writes | Reads | Notes |
|---|---|---|---|
| `worker` | the project (working directory), its session folder and temp, caches | everything except secrets | records are unwritable |
| `reviewer` | Bash: only `$TMPDIR` | everything except secrets | Edit, Write and NotebookEdit are removed; the checkout is write-denied by absolute path |
| `supervisor` | worker, plus append to `~/.agent-harness/approvals.jsonl` | everything except secrets | `harness` runs outside the sandbox so the owner's switch works |

The owner's own terminal has no role file and no sandbox (role `owner`). A session's role is the file it was launched
with: the generated settings carry `env.AH_ROLE` and `env.AH_ROLE_SOURCE` (`ah-sandbox:<role>`), and the Codex
launch arguments set `AH_ROLE` through `shell_environment_policy`. Because a worker's shell cannot write
`approvals.jsonl` or `roles.json`, a false `AH_ROLE` buys nothing.

## The data: `harness/hooks/sandbox_base.json`

Paths start with `~/`, so one file serves every user.

| List | Use |
|---|---|
| `secret_paths` | read-denied for every role (sandbox `denyRead`, `Read(...)` deny rules, Codex `deny`) |
| `record_paths` | write-denied for every role (sandbox `denyWrite`, `Edit(...)` deny rules, Codex `read`) |
| `worker_write` | extra writable roots for workers and supervisors (sandbox `allowWrite`, Codex `write`) |
| `supervisor_write_extra` | the supervisor's additions (`approvals.jsonl`), removed from its records |
| `network_allow`, `reviewer_network_allow` | the proxy allow-list (`sandbox.network.allowedDomains`, Codex `network.domains`) |
| `excluded_commands` | run outside Claude Code's sandbox (`sandbox.excludedCommands`, Bash-rule syntax) |

Records stay readable (workers run `ah approvals check` and `ah user-msg`). Exclusions: `ssh` and `scp` ignore the
proxy, `docker` breaks under Seatbelt, and `python3 ~/.claude/hooks/wal_note.py *` is excluded because Claude Code
keeps `~/.claude` write-protected even when `allowWrite` names `~/.claude/wals`. The vendor's docs say so in plain
words, so this is build plan decision 6.4-2. The known gap is that a session can append to, and so damage, its own
notes. Standing rules must spell the note command exactly that way for the exclusion to apply.

## `local.json` keys

| Key | Type | Effect |
|---|---|---|
| `sandbox_allowed_domains` | list of host names | appended to the worker and supervisor allow-list |
| `sandbox_extra_deny_read` | list of paths | appended to the secrets for every role |
| `sandbox_extra_write` | list of paths | appended to the worker and supervisor writable roots |
| `sandbox_role` | `worker`, `reviewer` or `supervisor` | the role a managed drop-in carries on this machine (default `worker`) |

Every name under `hosts`, `remote_worktree_hosts` and `trusted_git_hosts` also joins the allow-list. A key of the wrong
type falls back to its default (the `ah_local` rule); a name that is not a host name is dropped.

## Commands

```
ah sandbox show  --role R [--flavor F] [--json] [--project DIR]
ah sandbox write --role R [--flavor F] --out PATH            # atomic, mode 0600, never through a symlink
ah sandbox write --flavor managed --managed-dir DIR          # DIR/managed-settings.d/50-agent-harness.json
ah sandbox roles
```

Flavors:

- `claude`: the file for `claude --settings FILE`.
- `managed`: the same, plus `enableWeakerNestedSandbox: false` and `enableWeakerNetworkIsolation: false`, for
  `/Library/Application Support/ClaudeCode/managed-settings.d/` or `/etc/claude-code/managed-settings.d/`.
- `codex`: three `[permissions.ah-<role>]` tables, with no markers.
- `codex-launch`: `-c default_permissions="ah-<role>" -c shell_environment_policy.set.AH_ROLE="<role>"`.
- `codex-requirements`: an `/etc/codex/requirements.toml` body: `default_permissions`, `[allowed_permission_profiles]`
  listing the three names, and `[permissions.filesystem] deny_read` listing the secrets.

The output is plain JSON with sorted keys and a two-space indent, and is byte-identical on every run.

`--flavor managed` never writes the real directory. It writes under `--managed-dir` and prints the
`sudo install ...` line for the owner to run on a host once a shadow day is clean. The managed file never sets
`allowManagedHooksOnly`, which would silence the harness's own user hooks, or `allowManagedPermissionRulesOnly`,
which would drop a reviewer's `--settings` deny rules. Managed lists merge with `--settings` lists and locks take the
strictest value, so a reviewer file can narrow a worker host and nothing can widen it.

## Reviewer launches need the checkout

Claude Code does not read `.` or `./` in a `--settings` file as the working directory. The e2e run wrote into the
project with both spellings, and with the absolute path the write was refused. A reviewer is therefore launched with
the checkout named:

```
ah sandbox show --role reviewer --project /abs/checkout > /tmp/reviewer.json   # or pass the JSON itself to --settings
```

The generic `~/.agent-harness/sandbox/reviewer.claude.json` still removes the file-editing tools and denies secrets
and records. On its own, though, its Bash can write the working directory. `peer_review.py` therefore treats the
installed file as the switch and passes the per-review JSON, with its snapshot named, to `--settings`.

## What the e2e settled (Claude Code 2.1.332, macOS)

These were proven by `tests/e2e_combined.py`, with `--settings` alone and `--setting-sources project`:
- Sandboxed Bash ran without a prompt (`autoAllowBashIfSandboxed`).
- An unlisted host got HTTP 000 while github.com got 200 (`network.strictAllowlist` takes effect from `--settings`).
- A write outside the project was refused, and `~/.ssh` and a decoy path were unreadable to both Bash and the Read
  tool.
- `git commit` inside the project worked.
- The reviewer could not write or commit and could read.

Open items:
- `gh` cannot authenticate inside the worker sandbox, even with `gh *` in `excludedCommands` (one run each). Pushing
  from a worker needs a look in the shadow step.
- The Codex network rows need `features.network_proxy`, so Codex network stays open (decision 6.4-1).

## Codex

`codex sandbox -P ah-<role> -C DIR -- CMD` runs a command under a profile. Codex 0.171 has no `macos|linux` word.
Records are listed as `read`, so they stay read-only even when a workspace root holds them. Secrets are `deny`, and
`.git` is writable inside workspace roots so `git commit` works. Profiles and `sandbox_mode` do not combine, so a
session selects a profile with `codex_launch_args(role)`.
