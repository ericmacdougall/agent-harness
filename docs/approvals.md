# Approvals

One store holds everything the owner (or a supervisor) has already said yes to: `~/.agent-harness/approvals.jsonl`.
Before an agent asks the owner anything that needs permission, it looks here:

```sh
python3 ~/.claude/hooks/ah.py approvals                       # live approvals, one readable table
python3 ~/.claude/hooks/ah.py approvals check merge --repo owner/name --pr 12   # exit 0 = approved (prints it), 1 = ask
```

If `check` exits 0, the agent proceeds and cites the approval id. If it exits 1, the agent asks the owner and records
the answer with `ah approve` so nobody asks again.

## The model

An approval is one record:

| field | meaning |
|---|---|
| `id` | 8 hex characters |
| `kind` | `merge`, `delete`, `kill`, `top-rung`, `release`, `secret`, `spend`, `harness`, `other` |
| `scope` | any of: `project` (absolute dir or `owner/name`), `pr`, `path` (glob; relative to the project), `task`, `pids`, `host`, `what` (free text) |
| `granted_by` | `user` or `supervisor:<session>` |
| `reason` | free text, no syntax rules |
| `created`, `expires` | `expires` is optional; without it the approval is standing |
| `exact_head` | optional; absent by default, so an approval for a PR survives later commits |
| `revoked` | set by `ah approvals revoke <id>` (append-only: the revoke is a new line) |

Matching: the newest live record of the kind whose scope covers the facts wins. A scope field that is empty covers
every value; a field that is set needs the fact and a match. A record with no `pr`, `path` or `task` covers the whole
project for that kind. A project given as `owner/name` also matches a checkout whose `.git/config` names that GitHub
remote. For `harness`, `what` is matched (case-insensitive, globs allowed); for the other kinds it is description.

The store is mode 0600, written under a file lock, and read tolerantly: a corrupt line is skipped, and
`ah_approvals.allowed()` never raises (a broken store means "not approved").

## Who may grant

Who is calling is the launch role (docs/roles.md, `ah_roles.launch_role`), never the model.

- **The owner.** A command with no `AH_ROLE` and no agent marker (`CLAUDECODE`, `CODEX_THREAD_ID`,
  `CODEX_TOOL_CALL_ID`, `CODEX_SANDBOX`, `AI_AGENT`) in its environment is the owner. An agent may record the
  owner's answer with `--as-user --user-msg <id>`, citing the owner's own message by the id `ah user-msg --recent 3`
  prints; the cited words are stored with the record.
- **A supervisor session**, for the projects it supervises: a session launched with `AH_ROLE=supervisor`, or an agent
  session the owner recorded with `ah supervisor set --session S`. Its projects are its own `roles.json` entry, else
  the role default entry (`ah supervisor set --role-default --project DIR`). This includes `top-rung` for a named task
  in those projects. `secret`, `spend` and `harness` stay with the owner.
- **A worker or a reviewer** is refused (exit 3) with the `ah approve ...` command to hand to the owner or a supervisor
  session.

The operating system backs this. A worker's sandbox keeps `approvals.jsonl` and `roles.json` read-only, so a worker
that exports `AH_ROLE=supervisor` still cannot write a record: the append fails and `ah approve` exits 3 with
`cannot write <path> (<error>): this session's sandbox keeps it read-only, so ask the owner or a supervisor session to
run <command>`, never a traceback.

Limit: a sub-agent's shell carries its parent's environment, so a supervisor's sub-agents can grant inside the
supervisor's projects too.

## Commands

```sh
ah approve <kind> [--project P] [--pr N] [--path G] [--task T] [--pids N...] [--host H] [--what TEXT]
                  [--reason TEXT] [--expires 7d] [--exact-head SHA] [--as-user --user-msg ID]
ah approvals [--project P] [--kind K] [--all] [--json]
ah approvals revoke <id>
ah approvals check <kind> [--project P] [--repo R] [--pr N] [--path X] [--task T] [--pids N...] [--host H] [--head SHA] [--what TEXT]
ah supervisor set --session S --project DIR [--project DIR...] [--harness]     # owner only
ah supervisor set --role-default --project DIR [--project DIR...] [--harness]  # owner only: launched supervisors
ah supervisor clear --session S | --role-default                              # owner only
ah supervisor list                                                            # entries, the role default, harness flag
```

## Consumers

- The tools call `ah_approvals.allowed(kind="merge"|"delete"|"kill", ...)` through a guarded import (`ah kill`,
  `prod_delete_guard.py`, the owner override of `ah review-status`); the signature is documented at the top of
  `ah_approvals.py` and is kept stable.
- `ah approvals check top-rung --task T` is how an agent learns whether a Fable or Astra run for task `T` was approved.
  It is advice in the standing rules: no hook reads the model.

## Harness maintainer

A supervisor the owner marks with `ah supervisor set ... --harness` also maintains the harness: it may change guards
and rules, including weakening one that does not fit reality, with the owner's approval. The approval is the owner's
alone: `ah approve harness --what "<guard or rule>" --reason ...` for one change, or `ah approve harness` without
`--what` for a standing approval. Before the change the supervisor runs
`ah approvals check harness --what "<guard or rule>"`. The flag is stored as `"harness": true` in the supervisor's
`roles.json` entry (or the role default entry), where `ah_roles.may_edit_harness` reads it together with a live
`harness` approval.

## Migrating the old CLAUDE.md sections

Each standing approval sentence becomes one command, run once by the owner (or with `--as-user --user-msg <id>` citing
the sentence). Then delete the sentence from CLAUDE.md.

| Old section | Kind of sentence | Equivalent command |
|---|---|---|
| Supervisor standing authority | "session S supervises project P and may approve X there" | `ah supervisor set --session S --project P` (then the supervisor runs `ah approve <kind> --project P ...` itself) |
| Disposable test leftovers on a worker host | "agents may delete disposable test leftovers under DIR on host H" | `ah approve delete --host H --path 'DIR/*' --reason "disposable test leftovers"` |
| Harness stream: what the supervisor may approve | "the supervisor may merge harness PRs after review" | `ah approve merge --project owner/agent-harness --reason "after the required review"` (or a supervisor of that checkout runs it) |
| Harness stream: changes to guards | "the supervisor may change guard G" | `ah supervisor set --session S --project DIR --harness`, then `ah approve harness --what G` |
| Every supervised project: what the supervisor may approve | "in every project it supervises the supervisor may approve merges / releases / kills" | one `ah supervisor set` with every `--project`; the supervisor then records `ah approve merge|release|kill --project P` per project as it decides |
| Per-project standing approvals | "in project P, X is approved" (merge, release, a deploy step) | `ah approve <merge|release|other> --project P --what "<the step>" --reason "<the sentence>"` |
| Key-file exceptions for named key folders | "agents may read/handle the key files in folder K for purpose X" | `ah approve secret --path 'K/*' --what X --reason "<the sentence>"` (owner only) |
| A dated approval ("until Friday") | any of the above with an end | add `--expires 2026-12-01` (or `--expires 7d`) |
| An approval of one exact commit | "merge PR N at sha S" | only when the owner wants the pin: add `--exact-head S`; by default a PR approval survives later commits |
