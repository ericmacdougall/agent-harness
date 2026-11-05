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

### Verified captures

Only a capture made from input the harness hands to a hook is a verified human turn. That means UserPromptSubmit,
AskUserQuestion PostToolUse, or a spool line one of those hooks wrote. Each one gets `humanCheck.attestation`: an
HMAC-SHA256 over the session, the text sha256, the pasted flag, the method, the provider item and a spool nonce. The
key is a 32-byte per-machine key in `$AGENT_HARNESS_HOME/work-ledger.key` (mode 0600, created atomically on first use,
outside `~/.agent-harness/work`). Turns caught up from a transcript or Codex rollout are still captured, so a missed
hook loses nothing, but with `verified: false`. They show in the digest as `[unverified: transcript only]`, and an ask
split from one has source kind `inferred`, not `user`. A cancel proof, a decision answer and `--reopen-by` all need a
verified message. A cancel proof also records the captured event id and its MAC, and both are re-checked against the
event log at removal. A transcript line alone never proves anything. A decision answer must be the first
hook-captured message (typed or an AskUserQuestion answer) in that session after the question was recorded, never an
agent's pick. A cancel through an answer needs the user's own words to retract the ask and name it (id or 3+ of its
words); the question text does not count, because the agent wrote it. An ask has at most one `superseded_by`
relation, to an ask split from the same human message. Superseding only marks the link for the digest: it never
makes an ask removable, because which asks a message holds is the agent's own split. The older ask leaves only
when the user cancels it. A request the user replaced is cancelled with their words as proof. The guard runs on Write, Edit, MultiEdit, NotebookEdit, Bash, Read, Grep, Glob and LS on Claude Code, and on every
tool on Codex. It looks at paths and shell commands, not file contents, and refuses a Grep rooted at the store or any folder
above it (such as the home directory) unless a plain `glob` (letters, digits and `._/*-` only, at most 32) or a `type` filter cannot match the key's name, because Claude
Code's Grep and Glob search hidden directories (checked headless on 2.1.318). Glob and LS list names only and are
refused only at the store itself; reading the key stays refused. Paths resolve against the session cwd, and a Glob
pattern against its path. It refuses a path or shell word that names the key or a glob that
could expand to it (a bare `*` does not count unless it is inside the store directory), recursive reads of the
store directory, in-process use (`import work_assignments`, `capture_key`, `hook_prompt(`) and agent calls of
`work_assignments.py hook`.

## CLI

```
work_assignments.py status [--session S] [--json]       # answer every status question from this
work_assignments.py split --msg M-... --item '...' [--owner agent:ID --ticket 'GoodQA p#n' --branch b --next '...']
work_assignments.py no-ask --msg M-... --reason '...'   # at least 10 characters, audited, listed in the digest
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

A no-ask can hide a real request, so the digest (`status`, SessionStart and PostCompact) counts every no-ask and
lists up to 8 of them with the reason and the actor who gave it. At capture the hook stores the names of request phrases
found in the typed text (`please`, `can you`, `i need`, `make sure`, an imperative such as `fix` at the start of a
sentence, and similar) as `text.requestCues`; the text itself is never stored. A no-ask on a message with any cue is
flagged `!request-phrase(...)` and listed first. Messages captured before cues existed are checked against their
redacted excerpt (`;excerpt`). To correct a no-ask, `split` the message: the split keeps the earlier no-ask as
`triage.reopenedFrom`. The flag is advisory: it never blocks Stop, and a correct no-ask on a message that happens to
contain a cue stays flagged until it is split.

## Removal gate

`remove` and `prune` refuse unless the ask has been `done` with re-verifying verified evidence, or `cancelled` with a
user proof, for more than 24 hours (clock `stateSince`, cached as `removableAfter`). A `superseded` ask is not removable; it can be cancelled with user proof.
A cancel proof names `targets` and a `binding`: `explicit_reference` (a later typed message) or
`answer_to_decision` / `answer_to_cancel_question` (the typed reply to a recorded decision about this ask). In every
case the user's whole message must be the command `cancel <ask-id>` (or `drop` / `withdraw`), optionally followed by
`: reason`; to cancel, the agent asks the user to send exactly that. A sentence that only sounds like a retraction,
a refusal, or a message naming another ask never counts, and an AskUserQuestion answer is a tool result, not a typed
turn, so it cannot be cancel proof. `same_message_retraction` is no longer accepted.

## Backup

The ledger can end up as the only surviving record of what the user asked for (GoodQA 1ae27b6b#14471: on 2026-11-04
it was the one record that survived). Each hive must keep a copy-only, versioned off-machine backup of
`work-ledger.json`, `work-ledger.events.jsonl`, `work-ledger.archive.jsonl`, `work-ledger.failures.jsonl`,
`work-ledger.spool.jsonl` and the v1 `work-assignments.json` in `$AGENT_HARNESS_HOME`. The lock file is not needed. These files sit
beside `~/.agent-harness/work`, not inside it, so a backup of the work directory alone misses them. On the Mac they are
in the source list of `~/.agent-harness/bin/log-backup.sh`, which runs every 15 minutes and copies them to Dropbox.
That job only copies: it never deletes the remote copy, and it keeps changed files under `versions/`. install.py
does not set up this job; a hive without it has no backup of the ledger. The event log is the source of truth, so
restoring `work-ledger.events.jsonl` and running `work_assignments.py recover` rebuilds the snapshot. The capture key
is deliberately not backed up (a copy in Dropbox would let anyone with the copy forge captures). Restoring onto a new
machine therefore mints a new key: earlier messages stop verifying, so asks cancelled but not yet removed fail their
removal check and need a fresh proof, and old messages cannot answer decisions. This fails safe: nothing is removed
early.

## Known limits

A verified commit proves the commit exists (and still resolves at removal), not that it fixes this ask; main's sign-off covers relevance. The event hash chain is unkeyed: it detects accidents and edits by anyone who does not also recompute it, and the guard covers agent edits. Pasted-only messages keep no excerpt and no request cues, and an excerpt whose first 15 words look secret-adjacent
(pass..., pw, key, token, secret, credential, login, ssh, auth..., PIN, OTP, common key prefixes) is withheld entirely.
That check is a keyword heuristic too: a secret with none of those words nearby can still reach the excerpt, the
event log and its backup. Request cues are English keyword heuristics: they miss requests phrased without them and flag some messages that are not requests. A superseded ask is never removed on the agent's word; it waits for a user cancel.

Agents run as the same Unix user as the hooks. A forged transcript line, a hand-written spool line and an invented or
altered attestation are refused. A hand-written event that copies a real attestation is accepted only for the same
session and text, so it can only duplicate a message the human really sent. The guard deters accidental reads and
casual forging only: an agent that writes a script file and runs it, or otherwise works around a pattern match, can
read the key or call the hook code with forged input. The attestation is not a cryptographic boundary; that needs a
separate Unix user or a key the OS holds. A capture spooled while a decision is open is ordered by when it is drained,
not when it was typed, so in that narrow window it can count as the decision's first answer. The guard is best effort against shell tricks (a safety net for careless edits, not a sandbox); the event chain has
no external anchor; a payload over 8 MB is rejected and recorded as a failure; `prune` archives a triaged message (with a tombstone that refuses re-capture) once its asks and decisions are gone and
24 hours have passed, or after 30 days for a no-ask; decisions have no removal path yet; session caches (sync offsets, stop-block
counters) are outside the fold by design. The first-touch sync window is the last 64 KB.

## dev2 sync (proposal, not built)

Each hive appends its own events; sync unions event files by `(hiveId, seq)` and re-folds (see the schema DESIGN notes:
scalar last-writer-wins by `(at, hiveId, seq)`, sets are unions, a transition conflict records `sync_conflict`).
Never copy `privateRef` or absolute log paths off the capturing machine.
