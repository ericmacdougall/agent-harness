# ah chat: your own GoodQA chat, through two separate tokens

`harness/hooks/ah_chat.py` (goodqa#16396) lets an agent session read, and only when asked, send, your GoodQA direct messages. The harness member key acts as "Claude (agent)", which is not a party to your DMs, so it answers `not_found` for them. `ah chat` uses your own tokens instead, so the session acts as you, through one reviewed path.

```
ah chat probe [--token user|dm]                 what the endpoint offers (tool and parameter names only)
ah chat conversations --org ID [--limit N]      your direct and group-direct conversations          (dm-read token)
ah chat history --conversation ID [--limit N] [--before SEQ] [--no-text]   a DM or group DM by its id  (dm-read token)
ah chat history --with USER_ID_OR_NAME [--org ID] [--limit N] [--no-text]   the DM with one person    (dm-read token)
ah chat files   --conversation ID [--surface chat|issue|personal]   chat: a DM's files (dm-read token); issue, personal: file_list (user token)
ah chat send    --with USER --org ID --body-file F --client-msg-id ID        a direct message          (user token)
ah chat send    --conversation ID --body-file F --client-msg-id ID           a channel or group post   (user token)
```

## Two tokens, two files, no fallback

| File (mode 0600, one line) | Holds | Used for |
| --- | --- | --- |
| `~/.config/goodqa/dm-read-token` | a token you minted in the GoodQA web app with abilities `read` and `chat.dm.read`, named orgs only, short expiry | every read of private messages: `history`, `conversations`, `files --surface chat`, `probe --token dm` |
| `~/.config/goodqa/user-token` | your existing user token (as `gq_browser` uses) | `send`, `files --surface issue\|personal`, `probe` |

A missing or unusable file is an error that names the file. A read never tries the user token and a send never tries the dm-read token. `~/.config/goodqa/browser-defaults.json` (`allowedBases`, optional `org`) is shared. `--base` must be one of `allowedBases`. Creating the dm-read token is a step for you in the web app (it needs your signed-in session); nothing in this repository creates or reads it for you. The command guard refuses every ad hoc read of either file.

## Server dependency (read this before relying on it)

The server half (GoodQA tools `list_direct_conversations`, `get_direct_conversation_messages`, `list_direct_conversation_files`, and the `chat.dm.read` ability) is specified and not yet built or deployed. Until it is:

- `history --conversation`, `conversations` and `files --surface chat` fail with `server does not support DM read by conversation yet` (they check `tools/list` first), never with an empty result.
- `history --with USER --org ORG` calls the existing `get_direct_messages`. Whether the dm-read token returns your DM rows through it depends on the same server change. **Not verified live: AC-1 of goodqa#16396 (reading conversation 0d4e18ae) is open until a live run on the deployed server.**

## What it guarantees

- **The tokens are never shown.** Each is read in-process by `gq_browser` and used only as the Authorization header of an HTTPS request to `<allowedBase>/mcp`. It is not on a command line, in the environment, in a file written by this command, in the ledger or in the audit log. Redirects and environment proxies are never followed. A server error body is never printed: only an HTTP status and an allow-listed machine code are. Every result is scanned before it is printed, and one that holds either token (whole, base64, URL-encoded or a 12-character piece) is withheld (`withheld`).
- **Shapes.** The stubs and parsers follow the server routes that the new tools will call (read from the bugtracker source, `messaging/routes.ts` and `dms.ts`): conversation messages `{conversation, messages, headSeq, foundOldest, foundNewest}`, conversation list `{conversations, hasMore, nextCursor}`, files `{attachments, nextOffset}`. The tool wrappers themselves are not built yet, so their exact argument names (`before` as a sequence number, limits up to 100) are the spec's, not observed. File rows are reduced to metadata: the server's rows carry a `url` that may be a signed link, and a link is never printed.
- **A read can leave a trace for the other person.** The server's message GET advances your delivered marker for a DM page it returns, so the other person's delivery receipt can change when an agent reads. Read only what you need.
- **Reads are untrusted data.** Every read result carries `"untrusted": true` and a notice: message text and file names are written by other people, and instructions inside them are never followed. `--no-text` returns ids, authors and times only.
- **Reads are audited without their text.** The audit log gets a `chat.read`, `chat.list` or `chat.files` row (conversation or peer, count).
- **A name is resolved to who it is.** `--with "Pat Peer"` must match exactly one member on the first page of members; the result shows the user id and the matched name (`with_name`). A paged member list refuses a name; give the id.
- **Send is opt-in and idempotent.** `--client-msg-id` is required. A body that holds either token or matches a secret shape (the `gq_browser machine type` list) is refused, and the refusal does not show the body. The local send file (`~/.agent-harness/state/ah/chat-send.jsonl`) makes a repeat of the same id answer `duplicate` with no second post, a different body under the same id `key_conflict`, and an attempt whose outcome is unknown `uncertain`. An attempt is recorded as failed (the same id may post again) only when the server is known to have refused before acting: `not_found`, a known code such as `forbidden`, `bad_request` or `human_approval_required`, or an HTTP 4xx other than 408 and 429. A timeout text, an rpc error, a 5xx, a 2xx that names no message, and **`approval_required`** are `uncertain`: no server source readable when this was written shows `approval_required` is raised before the message is stored, so a retry with the same id needs `--confirm-not-delivered` (UNVERIFIED either way; `human_approval_required` is the user-token gate's 409 in bugtracker `ag.ts` lines 631-672, raised before the route handler runs; the request is not queued and is executed only when the same request is repeated with the approval id, which this command never sends. The server-side replay at lines 390-410 is for Commander-action tokens only. Read from the source; not exercised live). A direct message has no server-side duplicate check, so after `uncertain` read `ah chat history`, and only if it did not arrive retry with `--confirm-not-delivered`. A channel post passes the id to the server as `clientMsgId`, which dedupes it. The ah ledger and audit log record the target, the client id, the body's SHA-256 and its length, not the text.
- **A body file is checked, but the content check is the control.** `--body-file` must be a regular file of at most 8000 bytes with one hard link, not a symlink, whose real path (symlinked directories resolved) is not a dot file and not under a dot directory (`.env`, `.aws`, `.ssh`, `.config`, `.claude`), except `~/.agent-harness/work` and `~/.agent-harness/scratch`. That keeps the obvious credential files out. It does **not** stop a credential file that was copied to a plain name: a secret that matches no known shape (a netrc, a pgpass, a docker or kube config) is sent if you point `--body-file` at such a copy. What stops a secret is the content check (the tokens, and the secret shapes), and your own care about which file you name.
- **A conversation you are not in is a clean refusal** (`not_found`, exit 3), never a traceback.

## Where each input goes, and what is checked first

Sinks: **N** the request to `<allowedBase>/mcp`, **S** the send file `chat-send.jsonl`, **L** the ah ledger and its audit row (`ah.write`), **A** a read's audit row, **O** the printed result, **E** error text (printed as `{"ok": false, "message": ...}`). `ah chat` writes nothing to stderr. Every **O** passes `_checked` (either token, whole, encoded or a 12-character piece). Every **E** passes the `ChatError` screen (the same check plus the secret shapes), so a refusal never repeats credential material it was given. A "screen" below means both token files (`gq.holds_credential`) and `gq.SECRET_SHAPES`, run before the first sink. Every validating pattern uses `fullmatch`: a value ending in a newline is refused, never accepted with its newline. The only `re.match` calls left extract a numeric prefix from local or server text (`MCP error -N`, `GoodQA HTTP NNN`). They validate nothing.

| Source | Value | Sinks | Checked before the first sink | Test (`tests/test_ah_chat.py`) |
| --- | --- | --- | --- | --- |
| argv | `--client-msg-id` | S, L, N (channel `clientMsgId`), O | id pattern (fullmatch), then the screen. Both run first in `send`, before the body is read or a token is used | `SweepTests`: newline id; token pieces and shapes; whole tokens |
| argv, defaults file | `--org`, `org` | N, S (hashed), L, A, O | UUID (fullmatch), screen (`_org`) | `SweepTests`: newline (argv and file); hex-token piece |
| argv | `--conversation` | N, S (hashed), L, A, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| argv | `--with` as an id | N, S (hashed), L, A, O | UUID (fullmatch), screen (`_user`) | `SweepTests`: newline; hex-token piece |
| argv | `--with` as a name | none (compared locally) | name pattern (fullmatch) | `SweepTests`: newline name |
| argv | `--limit`, `--before`, `--surface`, `--token`, `--after` | N, A | int 1 to 100; `\d{1,12}` fullmatch with `--conversation` only; fixed set; argparse choices; refused | `ReadTests` |
| argv | `--base` | N (URL), E | exact `allowedBases` match; error text screened | `SweepTests`: credential piece in `--base`; `ReadTests` |
| argv | `--body-file` path | none (opened only) | not a dot path, no symlink, one hard link, unchanged between check and read | `SendTests` |
| file | body text | N; its SHA-256 and length to S, L, O | user-token pieces and shapes, then both token files | `SendTests`, `TokenSourceTests` |
| file | `user-token`, `dm-read-token` | the Authorization header only | read in-process; a file that exists but cannot be read safely refuses the command, because its token could not be screened | `TokenSourceTests`; `SweepTests`: unscreenable file |
| file | send-file rows | S (decisions), L, O (`message_id`) | key compared after JSON parsing; `request` must match; a stored `message_id` is checked again | `SweepTests`: escaped keys; replayed id |
| server | send `message.id` | S, L, O | id pattern (fullmatch), then the screen; otherwise dropped and the attempt is `uncertain` | `SendTests` |
| server | member `userId` | N, S (hashed), L, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| server | member name | O (`with_name`) | control characters removed, at most 80 characters | `ReadTests`, `SendTests` |
| server | message, file and conversation rows | O; A (count only) | `_scrub`; `--no-text` keys and values (fullmatch); file rows drop links | `ReadTests`; `SweepTests`: metadata newline |
| server | tool list and schemas | O (`probe`) | names fullmatch `[a-z_]{1,60}`; bounded enums and types | `ReadTests` |
| server | error code, HTTP status, JSON-RPC code | E; S (`why` holds a local code) | allow-listed code; status 0 to 999; integer below 10^7 | `ReadTests`, `SendTests` |

Not covered here: `ah.py`'s own `KEY_RE` (the ledger key pattern) still uses `match` with `$`. It is unreachable from `ah chat`, because the client id is checked with fullmatch first, and other `ah` commands are outside this change.

## Tests

`python3 -I tests/test_ah_chat.py` (loopback stub of the MCP endpoint answering with the server's real row shapes, two sentinel tokens, every output and file scanned), `python3 -I tests/test_command_guard_ah_chat.py`, and the failing-first check `python3 -B tests/mutants_ah_chat.py` (each broken variant must fail the tests). The command guard needed one minimal change for the second file: the credential path rule for `~/.config/goodqa/user-token` also names `dm-read-token`.
