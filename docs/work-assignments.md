# Work assignments ledger

`~/.agent-harness/work-assignments.json` (mode 0600) is the harness's own record of every human request, its owner
and its state. The model does not have to remember to keep it: hooks capture, check and re-inject on Claude Code and
Codex. Implementation: `harness/hooks/work_assignments.py`; policy: `work_assignments_policy.json` (installed user
level only; env, repo files and CLI cannot loosen it).

## What runs automatically

| Event | Claude Code | Codex (`--runtime codex`) | Effect |
| --- | --- | --- | --- |
| UserPromptSubmit | yes | yes | records the genuine human message as `untriaged` (excerpt of at most 15 words, redacted), binds it to uuid and transcript line, shows capture failures and violations |
| Stop | yes | yes | blocks while this session has untriaged messages or stale items, at most `max_stop_blocks` (3) per problem set, then records a violation shown at the next prompt |
| SessionStart / PostCompact | SessionStart (also fires after compaction) | both | injects a compact list of open items |
| PostToolUse AskUserQuestion | yes | yes | captures the answer as a message |
| PreToolUse | yes | yes | refuses direct Write/Edit/Bash changes to the store, backup, audit log, lock and policy |
| SubagentStart | yes | yes | tells the subagent how to update items it owns; subagents never create requests |

System reminders, task notifications, agent messages, compaction summaries and tool results are not captured
(`provenance.user_authorship` and `strip_blocks`, reused). Pasted-only messages are captured and flagged.
Codex hooks need the one-time `/hooks` trust. Until then, any harness hook on the same machine also discovers new
`~/.codex/sessions` rollouts (created after the ledger) and catches up their human turns.

## CLI

```
work_assignments.py status [--session S] [--json]       # always answer status questions from this
work_assignments.py split --msg M-0001 --item '...' [--owner agent:ID --ticket 'GoodQA p#n' --branch b --next '...']
work_assignments.py no-ask --msg M-0001 --reason '...'  # at least 10 characters, audited
work_assignments.py update WA-0001 [--state S] [--owner O] [--next N] [--evidence E] [--actor agent:ID]
work_assignments.py cancel WA-0001 --uuid U --file TRANSCRIPT --line N --quote 'words the user wrote'
work_assignments.py remove WA-0001 | prune [--apply]
work_assignments.py import LEDGER.jsonl | sync | failures [--ack] | recover | verify | show ID
```

Evidence is checked where it can be: a commit must exist in the repo (`--repo PATH`, default cwd), a `tested:` id must be a
REALLY_TESTED WAL note on this host; PR numbers and URLs cannot be checked offline and are stored as `attested`.
Cancel proof must also be a human message this ledger itself captured, from a transcript it tracks, not older than the
item, so a forged transcript file cannot cancel. `cancel`, `remove`, `prune`, `import` and `recover` are deliberately
not in the installed permission allow list; triage and status commands are.

States: open, assigned, in_progress, blocked, ready, done, cancelled. `done` needs evidence: commit sha, `PR#n`,
https URL or `tested:<WAL id>`. Tickets are referenced as `GoodQA <project>#<n>` strings only; this file never calls
GoodQA or copies ticket status (the GoodQA ledger stays the single source for tickets).

## Removal gate

`remove` and `prune` refuse unless the item has been `done` with evidence, or `cancelled` with proof, for more than
24 hours (clock: `state_since`). Cancel proof is a message uuid, transcript file (under the Claude projects or Codex
sessions directory) and line, plus a quote; the gate reads that line and confirms a genuine human turn containing the
quote, at cancel time and again at removal. An agent claim, tool result or summary is never proof.

## Durability

Atomic write with fsync, one flock for sessions and subagents, previous good copy in `work-assignments.json.bak`, a
hash-chained append-only `work-assignments.audit.jsonl` (`verify`). A corrupt file is preserved as
`work-assignments.corrupt-*.json` and every command fails loudly until `recover`; it is never replaced by an empty
ledger. A hook bug exits 0 (never blocks the user) and writes `work-assignments.failures.jsonl`, shown at the next
prompt until `failures --ack`. Hook budget: about 120 ms with 600 items (timeout 10 s, internal abort 6 s).

Known limits: the guard is best effort against shell tricks (it is a safety net for careless edits, not a sandbox);
a payload over 8 MB is rejected and recorded as a failure; the transcript sync window on first touch is the last
64 KB, so a message written long before the first hook of its session is bound by `cannot-bind` after 2 hours.

## dev2 sync (proposal, not built)

Each host keeps its own ledger. A later `export` could emit the audit log, and `import` merge by `source_id`;
items stay owned by the host that holds the session. Until then run `status` on each host.
