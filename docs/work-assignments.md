# Work assignments ledger (schema 2)

The harness keeps its own record of every human request, its owner and its state, so a request cannot be lost to
context compaction or a forgetful model. Implementation: `harness/hooks/work_assignments.py`; schema:
`harness/hooks/work_ledger.schema.json` (JSON Schema 2020-12, validated in the tests); policy:
`work_assignments_policy.json` (installed user level only; env, repo files and CLI cannot loosen it).

## Files (all under `~/.agent-harness/`, mode 0600)

| File | Role |
| --- | --- |
| `work-ledger.events.jsonl` | **source of truth**: one hash-chained event per mutation, identity `(hiveId, seq)` |
| `work-ledger.json` | snapshot = a fold of the events (`apply_event`), plus an `index` so hooks stay cheap |
| `work-ledger.archive.jsonl` | the full record of every removed ask (a tombstone points at its line and sha256) |
| `hive.json` | this installation's `hiveId`, `machineId`, `ledgerId` (minted once) |
| `work-ledger.spool.jsonl`, `work-ledger.failures.jsonl` | capture fallback and loud failure log |

`verify` replays the events and diffs them against the snapshot (session caches and the index excluded); `recover`
rebuilds the snapshot from the events. A corrupt snapshot is preserved as `work-ledger.corrupt-*.json` and every
command fails loudly until `recover`; it is never replaced by an empty ledger. A crash between the event append and the
snapshot write is repaired by the next transaction, which folds the events the snapshot lacks.

## What runs automatically

| Event | Claude Code | Codex (`--runtime codex`) | Effect |
| --- | --- | --- | --- |
| UserPromptSubmit | yes | yes | captures the genuine human message as `untriaged` (15-word redacted excerpt, sha256, counts; never the text), binds it to uuid and transcript line, shows capture failures and violations |
| Stop | yes | yes | blocks while this session has untriaged messages or stale asks, at most `max_stop_blocks` (3) per problem set (memory 6 h), then records a `stop_block_exhausted` violation shown at the next prompt |
| SessionStart / PostCompact | SessionStart (fires after compaction too) | both | injects a compact list of open asks |
| PostToolUse AskUserQuestion | yes | yes | captures the answer as a message |
| PreToolUse | yes | yes | refuses direct Write/Edit/Bash changes to ledger files and the policy |
| SubagentStart | yes | yes | tells the subagent how to update asks it owns; subagents never create requests |

Human detection reuses `provenance.user_authorship` and `strip_blocks` (Claude) and the `UserMessage` rollout item
(Codex); injected context (AGENTS.md, environment blocks, hook, subagent and task text, reminders, summaries) gives
`humanCheck.isHuman=false` and is never captured. Pasted-only messages are captured and flagged. A capture the store
cannot take (lock stall over 3 s, store error) is appended lock-free to the spool as a redacted text reference and
drained exactly once by the next transaction. Codex hooks need the one-time `/hooks` trust; until then any harness hook
on the machine also discovers new `~/.codex/sessions` rollouts and catches up their human turns.

## CLI

```
work_assignments.py status [--session S] [--json]       # answer every status question from this
work_assignments.py split --msg M-... --item '...' [--owner agent:ID --ticket 'GoodQA p#n' --branch b --next '...']
work_assignments.py no-ask --msg M-... --reason '...'   # at least 10 characters, audited
work_assignments.py update A-... [--state S] [--owner O] [--next N] [--evidence E] [--block-reason K --decision D-...]
                                 [--reopen-by M-...] [--repo PATH] [--actor agent:ID]
work_assignments.py cancel A-... --uuid U --file TRANSCRIPT --line N --quote 'words the user wrote' --binding B
work_assignments.py remove A-... | prune [--apply]
work_assignments.py relate A kind B | prereq A REF | decision ask|answer|assume ...
work_assignments.py import LEDGER.jsonl | migrate [v1-file] | sync | failures [--ack] | verify | recover | show ID
```

Asks and decisions follow the transition graph in the schema (`open -> assigned -> in_progress -> ready -> done`,
`blocked`, `cancelled`, `superseded`; reopening `done` needs a human-captured message). `ready` needs evidence;
`done` needs at least one **verified** evidence item: a commit that exists locally (`git-object`) or a `tested:<id>`
that is a REALLY_TESTED WAL note (`wal-really-tested`). PR numbers and URLs cannot be checked offline and stay
`attested`. Tickets are referenced as `externalRefs` strings only (`GoodQA <project>#<n>`); this file never calls
GoodQA or copies ticket status.

## Removal gate

`remove` and `prune` refuse unless the ask has been `done` with re-verifying verified evidence, or `cancelled` with a
user proof, for more than 24 hours (clock `stateSince`, cached as `removableAfter`), or `superseded` by a closed ask.
A cancel proof names `targets` and a `binding`: `same_message_retraction` (the ask's own message),
`explicit_reference` (the quote names the ask id or shares 3 or more words with its request),
`answer_to_decision` or `answer_to_cancel_question` (the human answer to a decision tied to the ask). It must also
be a human message this ledger captured from a transcript it tracks, not older than the ask, and the transcript
line is re-read at removal. Removal appends the full record to the archive and leaves a tombstone.

## Known limits

A verified commit proves the commit exists (and still resolves at removal), not that it fixes this ask; main's sign-off covers relevance. The event hash chain is unkeyed: it detects accidents and edits by anyone who does not also recompute it, and the guard covers agent edits. Pasted-only messages keep no excerpt. A superseded ask is removable only when its replacement, a different ask, is done with verified evidence.

The guard is best effort against shell tricks (a safety net for careless edits, not a sandbox); the event chain has
no external anchor; a payload over 8 MB is rejected and recorded as a failure; messages are not pruned (a triaged
message could be archived later); decisions have no removal path yet; session caches (sync offsets, stop-block
counters) are outside the fold by design. The first-touch sync window is the last 64 KB.

## dev2 sync (proposal, not built)

Each hive appends its own events; sync unions event files by `(hiveId, seq)` and re-folds (see the schema DESIGN notes:
scalar last-writer-wins by `(at, hiveId, seq)`, sets are unions, a transition conflict records `sync_conflict`).
Never copy `privateRef` or absolute log paths off the capturing machine.
