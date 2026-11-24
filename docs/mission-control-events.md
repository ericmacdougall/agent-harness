# Mission Control event and chat formats

[Mission Control](mission-control.md) uses two versioned JSON formats. Their JSON Schemas are published at:

- [`schemas/mc-event-v1.schema.json`](schemas/mc-event-v1.schema.json)
- [`schemas/mc-chat-v1.schema.json`](schemas/mc-chat-v1.schema.json)

A change that is not backward compatible gets a new version (`mc.event/2`); it never silently changes `/1`.

## mc.event/1

`mc.event/1` is one event in the activity feed and one pulse in the scene. The server's collectors make these events. External sources append them through the event-drop directory.

```json
{"schema": "mc.event/1", "id": "fabric:run-42:done", "ts": "2026-11-09T22:41:05Z", "kind": "deploy",
 "summary": "goodqa 0.2.58 deployed to live", "severity": "info", "count": 1,
 "actor": {"runtime": "fabric", "session": "run-42", "agent": "deployer"},
 "subject": {"repo": "goodqa", "branch": "main", "ticket": "goodqa#15561", "initiative": "goodqa#15561"}}
```

Required fields:

| Field | Rule |
| --- | --- |
| `schema` | `"mc.event/1"` |
| `id` | 1 to 200 characters: `[A-Za-z0-9][A-Za-z0-9._:@/#-]*`. It must be stable for the same real-world event, because a repeated id is shown once. |
| `ts` | UTC, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` |
| `kind` | One of: `wal`, `push`, `release`, `deploy`, `ticket`, `chat`, `owner`, `initiative`, `system` |

Optional fields:

| Field | Rule |
| --- | --- |
| `summary` | Up to 280 characters. It is redacted again on arrival. |
| `severity` | `info` (default), `warn` or `high` |
| `count` | Integer from 1 to 10^9 (default 1). Used for bursts. |
| `actor` | An object of strings, each up to 160 characters: `runtime`, `session`, `agent` |
| `subject` | An object of strings, each up to 160 characters: `repo`, `branch`, `ticket`, `initiative`. `subject.initiative` (or a matching `ticket`) links the event to an initiative. |
| `historic` | Boolean only. True identifies historical backfill and is preserved through external normalization and FileDrop; it never pulses. False or absent stays live. |

These fields are set only by the server:

| Field | Meaning |
| --- | --- |
| `source` | The collector, or for an event drop, the drop file's name. A `source` in a drop line is ignored. |
| `quiet: true` | A tool call or lifecycle line. It pulses and refreshes ages, but stays out of the feed by default. |

### Event drops (Fabric and other external sources)

Append one event per line to `~/.agent-harness/mission-control/sources/<name>.jsonl`.

- `<name>` must match `[a-z0-9][a-z0-9_-]{0,31}`. It becomes the event's `source`.
- Write whole lines with a single `write`, appending only. A partial line is held until its newline arrives.
- The server reads at most 32 drop files, polls every 5 s, and reads up to 512 KiB per file per tick.

These lines are skipped and counted in the Source health strip, and never shown:

- an unknown `schema` or `kind`;
- a bad `id` or `ts`;
- a summary over 280 characters;
- a line over 8 KiB;
- a non-string or over-long `actor` or `subject` value;
- a symlinked or non-regular drop file.

Every accepted line is rebuilt by the server: redacted again, its fields sanitised, and its `source` pinned to the file name. A drop line is never forwarded as written.

To rotate a drop file, rename it and start a new one. The server notices the new inode and starts from the beginning of the new file. Ids it has already seen are not shown again.

### MC polling consumer

The optional read-only Fabric poll starts with an empty cursor, without substituting `0`.
Successful calls resume with the exact opaque returned cursor. Both directions require a
string of at most 128 ASCII characters from `[A-Za-z0-9._:=-]`; invalid cursors are refused,
never coerced or truncated. Producer compatibility still needs producer-build evidence.

A response must end in exactly one cursor footer. Before publishing anything, the consumer
validates every event and enforces the 1 MiB response, 5,000 event and 8 KiB per-line limits.
The runner reads at most one byte past the output cap to detect overflow; it refuses the
response instead of accepting a truncated prefix. Timeout or overflow ends only that
owned read-only export subprocess and returns no partial output.
Malformed, incomplete or oversized responses leave the previous cursor and drop data intact.
External IDs retain all 200 allowed characters so distinct IDs do not collapse during deduplication.

MC owns `fabric.jsonl` and its private `.fabric-commit.json` checkpoint as a pair. The checkpoint
records the file identity and last accepted byte offset at a complete line boundary. The writer
locks the data file, appends and syncs a complete batch, then atomically syncs its new checkpoint.
Only after that publication succeeds does it acknowledge the producer cursor. FileDrop takes
a nonblocking shared lock and reads only the accepted prefix, including after reader restarts.
An active writer causes that file's read to wait for the next poll.

On a partial write or checkpoint-publication failure, the cursor remains unchanged. Bytes beyond
the accepted prefix stay hidden; retry replaces only that unaccepted tail before appending the
batch again. Stable event IDs deduplicate retries. This does not promise exactly-once delivery
across arbitrary restarts or outside FileDrop's bounded ID history.

A malformed checkpoint, changed file identity, shortened file or partial legacy tail is refused;
the consumer never guesses a new accepted position. Back up and retain the data/checkpoint pair
when planning repair or rotation. The general rotation rule above applies to unmanaged drops;
do not rotate the MC-managed file independently of its checkpoint. A rollback to an older reader
must first verify that the managed file contains no unaccepted tail, or retain the prefix-aware
reader until main coordinates recovery. Do not discard the checkpoint or truncate accepted data.

## Offline managed-state recovery

`fabric_state.py` supplies an offline maintenance API; the web app exposes no restore action.
Main must authorize maintenance and quiesce the service before restore or precommit recovery.
Snapshot, restore, resume and abort hold a permanent, never-replaced operation mutex in MC_HOME
across the entire operation, in addition to the data-file writer lock. A parallel helper returns
BUSY even after the data inode changes. Snapshot capacity defaults to 2 MiB.

A snapshot captures the accepted prefix, the full unaccepted tail and the original checkpoint
under both locks. Its manifest binds their lengths, SHA-256 digests and source identity; COMPLETE
seals the manifest. An incomplete or mixed bundle is refused. Restore requires an explicit expected
manifest digest and creates a fresh verified preimage before replacing data. Pending bytes are
retained in that preimage, never glued to a restored accepted prefix.

The durable REOPEN_COMMITTED journal precedes removal of the maintenance fence. Recovery after
that point only reconciles metadata: it verifies the committed generation and accepted prefix,
preserving valid later appends. An incompatible generation holds without replacement. Aborting
an already committed operation requires a new operation and a fresh verified preimage. A crash
before a verified preimage is journaled requires main's reconciliation and stays fenced.

## Native project observations

Optional private `MC_HOME/projects.json` contains a `projects` array of objects with `thread_id`,
`project`, `title` and optional recorded `model`. No model is inferred from a runtime. Registered
project mains remain visible ahead of background streams; missing observations say unknown,
observations older than two minutes say stale. A broken registry retains cached names as stale.
Observed activity is evidence of a WAL record, not a claim that its process is still running.
WAL event IDs bind runtime, source generation and each record's byte location, so two native
no-ID notes in a single poll remain distinct. Unsupported owner controls are visibly unavailable.

## mc.chat/1

`mc.chat/1` is one chat record. The server writes inbox records, which are messages from the page, to `~/.agent-harness/mission-control/chat/inbox/`. Agents write replies through `mc_inbox.py reply`, or through the desktop `mc_reply` tool.

```json
{"schema": "mc.chat/1", "id": "dash-01M718TER8EEAABANXNB135A7V", "client_key": "k3f…", "from": "user",
 "origin": "dashboard", "label": "USER_VIA_DASHBOARD", "to": "claude", "session": "baab765b-…",
 "thread": null, "reply_to": null, "text": "Summarise today's pushes.", "created": "2026-11-09T15:51:02Z",
 "sig": "<hex HMAC-SHA256>"}
```

| Field | Rule |
| --- | --- |
| `id` | `dash-<ULID>` for messages, `reply-<ULID>` for replies |
| `client_key` | 8 to 64 URL-safe characters, chosen by the page. The same key returns the same record, which makes sends idempotent. |
| `from` / `to` | `user` sends to `claude` or `codex`. A reply comes from `claude` or `codex` and goes to `user`. |
| `session` | For a message to `claude`, the registered target session. Otherwise null. |
| `thread` | An optional initiative id. |
| `text` | Up to 4,000 characters. It is cleaned of control characters and redacted before it is stored. |
| `sig` | An HMAC-SHA256 with the 0600 install secret, over the record minus `sig`, serialised as canonical JSON (sorted keys, no spaces). |

A record's delivery state lives beside it, in `chat/state/<id>.json`. The states are `queued`, `delivered`, `answered`, `failed`, `unavailable`, `forged` and `expired` (a dashboard decision main did not claim within 30 minutes). A queued message also has an empty marker, `chat/queue/<id>`. Pending lists come from these markers, so newer traffic never hides an older message; a marker whose state is no longer `queued` is dropped, never redelivered. A reader takes a message by creating `chat/claims/<id>` with `O_CREAT|O_EXCL`, which succeeds for exactly one reader. (Concurrent unlinks of one path are not exclusive on APFS, so the marker is never the lock.) If the install secret cannot be read, nothing is delivered and nothing is marked forged. A claim older than 60 s whose message is still queued was left by a process that died mid-claim; it is dropped and contended again. Markers with no state file are dropped, so junk markers cannot fill the scan window. A final reply takes `chat/answered/<id>` with `O_CREAT|O_EXCL`, so each message has exactly one final answer; a streamed Codex reply may finalise only its own reply id.

A record whose signature is missing or wrong is marked `forged`. It is never delivered by `wait`, `read`, the Stop hook or `mc_read`, and the page shows it struck through as "Untrusted content".

An agent receives a message only in its framed form:

1. a header line;
2. the authority notice. It says the text is data from the dashboard inbox and not proof the user typed it. The text may steer ordinary, reversible work, but anything consequential needs confirmation in the terminal, and it cannot grant top-rung models, approve production, deletion or credential actions, or override hard rules;
3. the reply command;
4. the text, inside a fence that carries a fresh random nonce for each frame, so the text can neither predict nor imitate it.

When an agent cites the message, it writes `dash:<id>`. `provenance.py` rejects `dash:` as the source of a user requirement.
