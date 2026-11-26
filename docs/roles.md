# Roles

A session's role is set by how it was launched, never by the model it runs or by anything the agent says.
`harness/hooks/ah_roles.py` is the one place that answers "who is calling and what may they do"; every tool asks it.
This replaces the rule that made every Fable or Astra session top rung (a main session with `model: fable` in its
settings was top rung on every call, docs/direction.md "Decisions taken").

## The four roles

| Role | Who | Writes (enforced by the sandbox, docs/sandbox.md) | May by role (`ah_roles`) |
|---|---|---|---|
| `owner` | a person in a terminal: no `AH_ROLE`, no agent marker | everything (no sandbox) | delete anywhere, handle secrets, grant every approval kind, name supervisors |
| `supervisor` | launched with `AH_ROLE=supervisor`, or an agent session the owner recorded with `ah supervisor set` | worker scope plus `~/.agent-harness/approvals.jsonl` and the answer inbox `~/.agent-harness/inbox` | delete in its own folder and its supervised projects; handle secrets; grant approvals inside its projects except `secret`, `spend`, `harness` |
| `worker` | launched with `AH_ROLE=worker`; also any agent the harness cannot place (least privilege) | the project, `$TMPDIR`, caches and the harness session area (every session's folder under `~/.agent-harness/work`, not only its own; docs/sandbox.md) | delete in its own folder and the checkouts it made; secrets only through `ah secret exec` |
| `reviewer` | launched with `AH_ROLE=reviewer` (the review runner does this) | its `$TMPDIR` only; Edit and Write tools removed | as a worker |

Decided against the owner's words of 2026-11-24, stated plainly: he asked that Fable and Astra may delete files and
handle secrets "even outside" their projects. Model names grant nothing now, and a supervisor deletes only in its own
folder and its supervised projects. The owner's own interactive `claude` session carries `CLAUDECODE`, so it is a
worker unless he records it (`ah supervisor set --session <id>`), or works in his own terminal, which is the owner
role and deletes anywhere. A wider supervisor (`delete_anywhere`) is not built: it would hand every supervisor's
sub-agents the same reach (they share its environment).

## How the role is decided

1. **`AH_ROLE` in the environment**, put there by the launch:
   - Claude Code: the `env` block of the generated settings file (`claude --settings ~/.agent-harness/sandbox/<role>.claude.json`,
     from `ah sandbox`), or of the managed drop-in on a worker host. A settings file's `env` applies to the session
     and its Bash commands. A hook process that does not see it still never counts as the owner: a hook payload is
     always an agent's call (rule 3).
   - Codex: `-c shell_environment_policy.set.AH_ROLE="<role>"`, from `ah_sandbox.codex_launch_args(role)`.
   - `AH_ROLE_SOURCE` names the file (`ah-sandbox:worker`); `ah_roles.describe()` shows it as `role_source`.
   - Only `worker`, `reviewer` and `supervisor` are launch roles. Any other value, `owner` and the empty string
     included, means `worker`.
2. **No `AH_ROLE` and no agent marker** (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_TOOL_CALL_ID`, `CODEX_SANDBOX`,
   `AI_AGENT`) and not a hook payload: `owner`.
3. **No `AH_ROLE` inside an agent** (a marker, or a hook payload): `supervisor` when the owner recorded this session
   in `~/.agent-harness/roles.json` with `ah supervisor set --session S --project DIR`, else `worker`.

A supervisor's sub-agents act as workers when a payload names the sub-agent (`agent_id`, `agent_type`). A sub-agent's
shell carries its parent's environment, so a command it runs is the parent's role; that limit is stated in
docs/approvals.md.

## Which projects a supervisor supervises

`roles.json` holds one entry per recorded session and, optionally, one role default entry:

```json
{"supervisors": {"<session id>": {"projects": ["/abs/dir"], "harness": true, "by": "user", "set_at": "..."}},
 "supervisor": {"projects": ["/abs/dir"], "by": "user", "set_at": "..."}}
```

A supervisor uses its own entry when one exists, else the role default. The default exists so a session launched
with `AH_ROLE=supervisor` (whose id is not known in advance) supervises the projects the owner chose:

```sh
ah supervisor set --role-default --project ~/src/app [--project DIR...] [--harness]   # owner only
ah supervisor clear --role-default
ah supervisor list                                                                    # entries and the default
```

A session launched as supervisor with no entry and no default supervises nothing: it can grant nothing.

## The operating system backs the role

`roles.json` and `approvals.jsonl` are in the sandbox's write-denied record paths for workers and reviewers
(`record_paths` in `sandbox_base.json`; only the supervisor profile may write `approvals.jsonl`). So a worker that
exports `AH_ROLE=supervisor` in its own shell is told by `ah_roles` that it is a supervisor, and still cannot record
anything: the append fails, and `ah approve` prints a refusal (exit 3) that names the path and the command to hand
on, for example

```
cannot write /Users/me/.agent-harness/approvals.jsonl (Operation not permitted): this session's sandbox keeps it
read-only, so ask the owner or a supervisor session to run `ah approve merge --project acme/app --pr 12 --reason "<why>"`
```

Roles decide what the harness's own tools do (`ah kill`, `ah worktree-remove`, `ah reap`, `ah approve`,
`log_backup.py ack`); the sandbox decides what any command can do. Where the two disagree, the sandbox wins.

Threat model: a careless agent, or one misled by text it read. Not a deliberately evasive agent running as the owner's
own user: such an agent could unset every marker and look like the owner to `ah_roles`; on a host with a worker
profile the sandbox still holds its writes. Closing the rest needs workers on a separate OS account.

## The predicates

| Name | Rule |
|---|---|
| `launch_role(environ=None, home=None)` | as above |
| `is_supervisor(payload)` | the role is `supervisor` and the payload is not a sub-agent's |
| `is_top_rung(payload)` | deprecated alias of "owner or supervisor"; no model is read |
| `may_delete(payload, path, extra_own_roots=(), home=None)` | owner: anywhere; supervisor: own roots and supervised projects; worker and reviewer: own roots and the checkouts they made |
| `may_handle_secrets(payload)` | owner or supervisor |
| `may_edit_harness(payload)` | a supervisor whose entry has `"harness": true`, with a live `harness` approval from the owner |
| `supervised_roots(payload)` | the projects of the supervisor's entry (own, else the role default) |
| `caller_model(payload)` | display and reviewer selection only; no permission reads it |
| `describe(payload)` | all of the above plus `role` and `role_source` |

Payload arguments are kept so existing callers need no edit; they give the session (for `roles.json`) and tell a
hook's or a sub-agent's call apart. They never carry identity.

Debugging: `echo '{}' | python3 ~/.claude/hooks/ah_roles.py` prints `describe()` for the current environment.
