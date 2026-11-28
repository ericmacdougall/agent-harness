# Sandbox profiles per role (`ah sandbox`)

The boundary is the operating system's sandbox and the vendor's permission rules, not harness code. `ah sandbox`
only writes that boundary down, as native settings for Claude Code (2.1.332) and permission profiles for Codex
(0.171). No hook reads a command, and nothing here installs itself or switches anything on. `ah doctor`
([doctor.md](doctor.md)) proves on each host that the lists hold, and `tests/e2e_combined.py` proves it against the
real Claude Code and Codex.

## Roles

| Role | Writes | Reads | Notes |
|---|---|---|---|
| `worker` | the project (working directory), `$TMPDIR`, caches, and all of `~/.agent-harness/work`, `tmp`, `scratch`, `state` and `codex-wals` | everything except secrets | records are unwritable; network open; bypass mode allowed |
| `reviewer` | Bash: only `$TMPDIR` | everything except secrets | Edit, Write and NotebookEdit are removed; the checkout is write-denied by absolute path; GitHub-only network; bypass refused |
| `supervisor` | worker, plus `~/.agent-harness/approvals.jsonl` and the answer inbox `~/.agent-harness/inbox` | everything except secrets | `harness` runs outside the sandbox so the owner's switch works |

The Writes column is the Bash sandbox. Claude Code's Edit and Write tools follow permission rules, not the sandbox:
in the owner's launch mode (`--dangerously-skip-permissions`, which the worker file allows) they can write anywhere
except the `Edit(...)` and `Read(...)` deny rules (records and secrets), which hold in bypass mode too. A worker
launched in default or acceptEdits mode is asked (and refused under `--permission-prompts none`) for a write outside
the project.

The write scope is wider than "the session folder": the file is generated once per role, not per session, so a
worker can write and delete every session's folder under `~/.agent-harness/work`, `scratch` and `tmp`, the `ah` store
under `~/.agent-harness/state` (ledger, audit and intent rows) and the Codex WALs. Per-session scoping needs a launcher
that writes `allowWrite` for one `$AH_WORK`; none exists yet. The records listed below (transcripts, the approvals log,
roles, the off switch, log backups, releases, the answer inbox) are the ones no worker can write.

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
| `network_allow`, `reviewer_network_allow` | the reviewer's proxy allow-list (`sandbox.network.allowedDomains`, Codex `network.domains`); the worker list is kept for a later allow-list measured in shadow |
| `excluded_commands` | run outside Claude Code's sandbox (`sandbox.excludedCommands`, Bash-rule syntax) |

Also in the file: `secret_globs` (project secret files by name, `**/.env` and friends, as `Read(...)` deny rules only:
the sandbox lists take paths, not globs), `open_network` (the roles whose network stays open), `mach_lookup`
(`com.apple.trustd.agent`, which Go programs such as `gh` need to verify TLS on macOS) and `harness_tools` (below).

Records stay readable (workers run `ah approvals check` and `ah user-msg`). The keychain (`~/Library/Keychains`) is
not read-denied: with it denied, `gh` and git over https could not authenticate in the sandbox, so no worker could push
or open a pull request (the e2e at d095790c). Keychain items stay behind securityd's own access rules. The trade-off,
stated: a worker can use the owner's gh token, so a determined agent could post `harness/review` itself through `gh
api` (docs/merge-rule.md). The keychain deny was the only thing in the way of that, and it also stopped all pushing.

Exclusions (`excluded_commands`, Bash-rule syntax): `ssh` and `scp` ignore the proxy, `docker`, `go` and jest break
under Seatbelt (the direction's known list), and headless Chrome cannot start in the sandbox at all (it needs a Mach
service registration the sandbox has no setting for, exit 21), so `npx playwright ...` runs outside it; a browser a
script starts itself does not, and the MCP browser tools run outside the sandbox anyway. `local.json`
`sandbox_excluded_commands` adds a project's own command lines.

`harness_tools` are the harness's own commands that must run outside the sandbox, each under three spellings (`~/`,
`$HOME/` and the absolute home; a real run proved each spelling is excluded and an unlisted one is not):

| Command | Why it cannot run sandboxed |
|---|---|
| `python3 ~/.claude/hooks/wal_note.py *` | `~/.claude` stays write-protected even where `allowWrite` names `~/.claude/wals` (build plan 6.4-2) |
| `python3 ~/.claude/hooks/peer_review.py *` | the reviewer's model login (keychain, `~/.codex/auth.json`) and transcripts |
| `python3 ~/.claude/hooks/ah.py secret *` | the clipboard (`pbpaste` exits 1 inside) and the gcloud store (`~/.config/gcloud` is a secret path) |
| `python3 ~/.claude/hooks/ah.py kill *`, `... worktree-remove *` | their audit rows in `~/.agent-harness/*-audit.jsonl`, written first, fail closed |
| `python3 ~/.claude/hooks/ah.py log-push *` | it deletes under `~/.claude/projects` and `~/.agent-harness/logs` after the push is verified |
| `python3 ~/.claude/hooks/ah.py chat *` | its GoodQA token under `~/.config/goodqa`, a secret path |

Each tool checks the real object itself (`ah secret rm` and `ah approve` check the launch role; `ah kill` checks
process ownership; `ah worktree-remove` refuses ignored files). `ah secret exec -- CMD` runs CMD outside the sandbox
too: that is what it is for. A compound command (`cd x && python3 ~/.claude/hooks/wal_note.py ...`, or one in a
pipeline) stays sandboxed, so the standing rules spell each one as its own command, and a refused note says so.

## `local.json` keys

| Key | Type | Effect |
|---|---|---|
| `sandbox_allowed_domains` | list of host names | appended to the worker and supervisor allow-list (kept for a later allow-list; the network is open now) |
| `sandbox_extra_deny_read` | list of paths | appended to the secrets for every role |
| `sandbox_extra_write` | list of paths | appended to the worker and supervisor writable roots |
| `sandbox_excluded_commands` | list of Bash-rule patterns | run outside the sandbox for workers and supervisors |
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
- A write outside the project was refused, and `~/.ssh` and a decoy path were unreadable to both Bash and the Read
  tool.
- `git commit` inside the project worked.
- The reviewer could not write or commit and could read; an unlisted host got HTTP 000 while github.com got 200.

The release 1001 fixes were proven with the real `claude -p` (2.1.332) in the owner's launch mode,
`--dangerously-skip-permissions` with the worker file (exit codes only):
- The Write tool inside the project works (before the fix, the file's `disableBypassPermissionsMode` turned bypass
  off and the write was denied).
- example.com, nodejs.org and api.anthropic.com answer: the network is open. github.com answers.
- A local port binds and a dev server on 127.0.0.1 answers (`allowLocalBinding`).
- `gh api user` and `git ls-remote` of a private repository work (no keychain deny, `trustd.agent` allowed).
- `~/.codex/auth.json`, `~/.config/fish-audio.env`, `~/.config/goodqa/user-token` and `~/.ssh` are unreadable; a write
  to `~` outside the project is refused.
- `go build` works inside the sandbox on this host; headless Chrome does not (exit 21, above).

Shadow step, counting refusals: Bash and the file tools are refused by different layers. A Bash `cat` of a denied file
is stopped by the sandbox ("Operation not permitted") and leaves no `permission_denials` entry; Read and Write tool
calls are stopped by the permission rules and do appear there. A shadow count must add the sandbox's refusals (failed
Bash results and proxy refusals) to `permission_denials`, or it misses every sandbox refusal.

Open items:
- The Codex network rows need `features.network_proxy`, so Codex network stays open (decision 6.4-1).
- `network.strictAllowlist` is used by the reviewer file only; whether it is read from `--settings` was not separated
  from `--permission-prompts none` (both refuse an unlisted host). A run that allows prompts would settle it.

## Codex

`codex sandbox -P ah-<role> -C DIR -- CMD` runs a command under a profile. Codex 0.171 has no `macos|linux` word.
Records are listed as `read`, so they stay read-only even when a workspace root holds them. Secrets are `deny`.
Inside workspace roots `.git` is writable so commit, merge, stash and gc work, but `.git/hooks`, `.git/config` and
`.git/config.worktree` are `read`, as Claude Code keeps them: a planted hook would run later, unsandboxed, in the
owner's own git. The more specific path wins; `codex sandbox` proved writing or renaming either is refused. Profiles
and `sandbox_mode` do not combine, so a session selects a profile with `codex_launch_args(role)`. Workers have no
`network.domains` table (open, as for Claude Code). With `~/.codex/auth.json` denied, a review runner started from a
sandboxed Codex worker cannot use the Codex login; Codex has no excluded commands.
