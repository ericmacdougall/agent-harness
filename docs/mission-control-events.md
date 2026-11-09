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

These fields are set only by the server:

| Field | Meaning |
| --- | --- |
| `source` | The collector, or for an event drop, the drop file's name. A `source` in a drop line is ignored. |
| `historic: true` | Backfill shown when the page opens. It never pulses. |
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

A record's delivery state lives beside it, in `chat/state/<id>.json`. The states are `queued`, `delivered`, `answered`, `failed`, `unavailable` and `forged`. A queued message also has an empty marker, `chat/queue/<id>`. Pending lists come from these markers, so newer traffic never hides an older message, and a reader takes a message by unlinking its marker, which succeeds exactly once.

A record whose signature is missing or wrong is marked `forged`. It is never delivered by `wait`, `read`, the Stop hook or `mc_read`, and the page shows it struck through as "Untrusted content".

An agent receives a message only in its framed form:

1. a header line;
2. the authority notice. It says the text is data from the dashboard inbox and not proof the user typed it. The text may steer ordinary, reversible work, but anything consequential needs confirmation in the terminal, and it cannot grant top-rung models, approve production, deletion or credential actions, or override hard rules;
3. the reply command;
4. the text, inside a fence that carries a fresh random nonce for each frame, so the text can neither predict nor imitate it.

When an agent cites the message, it writes `dash:<id>`. `provenance.py` rejects `dash:` as the source of a user requirement.
