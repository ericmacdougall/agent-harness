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

- **The owner.** A command not running inside an agent's tool call (no `CLAUDECODE`, `CODEX_THREAD_ID`,
  `CODEX_TOOL_CALL_ID`, `CODEX_SANDBOX` or `AI_AGENT` in its environment) is the owner. An agent may record the
  owner's answer with `--as-user --user-msg <id>`, citing the owner's own message by the id `ah user-msg --recent 3`
  prints; the cited words are stored with the record.
- **A supervisor session**, for the projects it supervises (`~/.agent-harness/roles.json`, set by the owner with
  `ah supervisor set`). This includes `top-rung` for a named task in those projects. `secret`, `spend` and `harness`
  stay with the owner.
- Anyone else is refused with the one command that proceeds.

Limit: a sub-agent's shell carries its parent's session id, so a supervisor's sub-agents can grant inside the
supervisor's projects too.

## Commands

```sh
ah approve <kind> [--project P] [--pr N] [--path G] [--task T] [--pids N...] [--host H] [--what TEXT]
                  [--reason TEXT] [--expires 7d] [--exact-head SHA] [--as-user --user-msg ID]
ah approvals [--project P] [--kind K] [--all] [--json]
ah approvals revoke <id>
ah approvals check <kind> [--project P] [--repo R] [--pr N] [--path X] [--task T] [--pids N...] [--host H] [--head SHA] [--what TEXT]
ah supervisor set --session S --project DIR [--project DIR...] [--harness]     # owner only
ah supervisor clear --session S                                               # owner only
ah supervisor list                                                            # projects, model, harness flag
ah limits show | ah limits set KEY VALUE --reason R                           # see "Limits" below
```

`ah approve-top` still verifies the owner's words for a top-rung task and records the ledger permission; it now also
writes a `top-rung` approval here, so `ah approvals` shows it.

## Consumers

- `tier_gate.py`: a live `top-rung` approval for the exact task (and, for a supervisor's, a spawn whose `cwd` is
  inside its project) counts as the task's permission, beside the ledger permission and a signed central decision.
  It applies to writers and to reviewers, so a supervisor can grant a top-rung reviewer.
- Sibling guards call `ah_approvals.allowed(kind="merge"|"delete"|"kill", ...)` through a guarded import; the signature
  is documented at the top of `ah_approvals.py` and is kept stable.
- `central_decisions.py` stays what it is: a signed, cross-host publication of one top-rung permission for the T2Scan
  worker host. It is not a second local store, so it was left in place.

## Harness maintainer

A supervisor the owner marks with `ah supervisor set ... --harness` also maintains the harness: it may change guards
and rules, including weakening one that does not fit reality, with the owner's approval. The approval is the owner's
alone: `ah approve harness --what "<guard or rule>" --reason ...` for one change, or `ah approve harness` without
`--what` for a standing approval. Before the change the supervisor runs
`ah approvals check harness --what "<guard or rule>"`. The flag is stored as `"harness": true` in the supervisor's
`roles.json` entry, where `ah_roles` reads it.

## Limits

Numbers the harness enforces have one home: `resource_budget.LIMITS`, with repo defaults in
`harness/hooks/resource_limits.json` and a local override in `~/.agent-harness/limits.local.json` (`ah limits set`).
Loosening is always honoured. Tightening is honoured only when it was set by the owner or a supervisor; a tighter value
anything else wrote is ignored with one line in `~/.agent-harness/logs/limits.log`. The owner cap is one number,
`max_live_owners` (default 16): helpers, reviewers and testers are never counted; at the cap the spawn hook prints a
short advisory unless `"enforce": true` is set.

## Migrating the old CLAUDE.md sections

Each standing approval sentence becomes one command, run once by the owner (or with `--as-user --user-msg <id>` citing
the sentence). Then delete the sentence from CLAUDE.md.

| Old section | Kind of sentence | Equivalent command |
|---|---|---|
| Supervisor standing authority | "session S supervises project P and may approve X there" | `ah supervisor set --session S --project P` (then the supervisor runs `ah approve <kind> --project P ...` itself) |
| Disposable test leftovers on t2-dev | "agents may delete disposable test leftovers under DIR on host H" | `ah approve delete --host H --path 'DIR/*' --reason "disposable test leftovers"` |
| Harness stream: what the supervisor may approve | "the supervisor may merge harness PRs after review" | `ah approve merge --project owner/agent-harness --reason "after the required review"` (or a supervisor of that checkout runs it) |
| Harness stream: changes to guards | "the supervisor may change guard G" | `ah supervisor set --session S --project DIR --harness`, then `ah approve harness --what G` |
| Every supervised project: what the supervisor may approve | "in every project it supervises the supervisor may approve merges / releases / kills" | one `ah supervisor set` with every `--project`; the supervisor then records `ah approve merge|release|kill --project P` per project as it decides |
| ParentProof standing approvals | "in project P, X is approved" (merge, release, a deploy step) | `ah approve <merge|release|other> --project P --what "<the step>" --reason "<the sentence>"` |
| Key-file exceptions for named key folders | "agents may read/handle the key files in folder K for purpose X" | `ah approve secret --path 'K/*' --what X --reason "<the sentence>"` (owner only) |
| A dated approval ("until Friday") | any of the above with an end | add `--expires 2026-12-01` (or `--expires 7d`) |
| An approval of one exact commit | "merge PR N at sha S" | only when the owner wants the pin: add `--exact-head S`; by default a PR approval survives later commits |
