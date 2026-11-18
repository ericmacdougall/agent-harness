# ah chat: read your own GoodQA chat, through two separate tokens

`harness/hooks/ah_chat.py` (goodqa#16396) lets an agent session read your GoodQA direct messages. The harness member key acts as "Claude (agent)", which is not a party to your DMs, so it answers `not_found` for them. `ah chat` uses your own tokens instead, so the session acts as you, through one reviewed path.

**This build is read only.** `ah chat send` answers `{"ok": false, "code": "not_available", ...}` with exit 2 and names goodqa#16399. `ah.py` returns that answer before it parses the arguments or imports `ah_chat`, so the refusal reads no token, opens no file and makes no request. Sending was taken out after review found two problems. Automatic DM retries rested on an unverified server delivery contract. The local send file could not make a DM idempotent on its own. goodqa#16399 holds those findings, what a send needs from the server first (an inspectable delivery contract and server-side DM dedupe), and the saved implementation.

```
ah chat probe [--token user|dm]                 what the endpoint offers (tool and parameter names only)
ah chat conversations --org ID [--limit N]      your direct and group-direct conversations          (dm-read token)
ah chat history --conversation ID [--limit N] [--before SEQ] [--no-text]   a DM or group DM by its id  (dm-read token)
ah chat history --with USER_ID_OR_NAME [--org ID] [--limit N] [--no-text]   the DM with one person    (dm-read token)
ah chat files   --conversation ID [--surface chat|issue|personal]   chat: a DM's files (dm-read token); issue, personal: file_list (user token)
```

## Two tokens, two files, no fallback

| File (mode 0600, one line) | Holds | Used for |
| --- | --- | --- |
| `~/.config/goodqa/dm-read-token` | a token you minted in the GoodQA web app with abilities `read` and `chat.dm.read`, named orgs only, short expiry | every read of private messages: `history`, `conversations`, `files --surface chat`, `probe --token dm` |
| `~/.config/goodqa/user-token` | your existing user token (as `gq_browser` uses) | `files --surface issue\|personal`, `probe` |

A missing or unusable file is an error that names the file. A private read never tries the user token. `~/.config/goodqa/browser-defaults.json` (`allowedBases`, optional `org`) is shared. `--base` must be one of `allowedBases`. Creating the dm-read token is a step for you in the web app (it needs your signed-in session); nothing in this repository creates or reads it for you. The command guard refuses every ad hoc read of either file.

## Server dependency (read this before relying on it)

The server half (GoodQA tools `list_direct_conversations`, `get_direct_conversation_messages`, `list_direct_conversation_files`, and the `chat.dm.read` ability) is specified and not yet built or deployed. Until it is:

- `history --conversation`, `conversations` and `files --surface chat` fail with `server does not support DM read by conversation yet` (they check `tools/list` first), never with an empty result.
- `history --with USER --org ORG` calls the existing `get_direct_messages`. Whether the dm-read token returns your DM rows through it depends on the same server change. **Not verified live: AC-1 of goodqa#16396 (reading conversation 0d4e18ae) is open until a live run on the deployed server.**

## What it guarantees

- **The tokens are never shown.** Each is read in-process by `gq_browser` and used only as the Authorization header of an HTTPS request to `<allowedBase>/mcp`. It is not on a command line, in the environment, in a file written by this command or in the audit log. Redirects and environment proxies are never followed. A server error body is never printed: only an HTTP status and an allow-listed machine code are. Every result is scanned before it is printed, and one that holds either token (whole, base64, URL-encoded or a 12-character piece) is withheld (`withheld`).
- **A token that cannot be screened refuses the command.** The output and id screens compare against both token files. A token file that exists but cannot be read safely (wrong mode, owner or type) would leave its token unscreened, so every command refuses, whichever token it uses.
- **Shapes.** The stubs and parsers follow the server routes that the new tools will call (read from the bugtracker source, `messaging/routes.ts` and `dms.ts`): conversation messages `{conversation, messages, headSeq, foundOldest, foundNewest}`, conversation list `{conversations, hasMore, nextCursor}`, files `{attachments, nextOffset}`. The tool wrappers themselves are not built yet, so their exact argument names (`before` as a sequence number, limits up to 100) are the spec's, not observed. File rows are reduced to metadata: the server's rows carry a `url` that may be a signed link, and a link is never printed.
- **Every output is an allow-list of fields.** A server row can carry a link (a signed download URL, an avatar URL, an invite) under any key, at any depth, and a link is a capability. So each output keeps only named fields, and only plain values under them (text, a number, true or false). A nested object is dropped unless a sub-list names its fields. A string shaped like a link (`scheme://`, `www.`, `data:`, `mailto:`, `javascript:`, `blob:`, or a path with a query) is dropped even under an allowed field.
  - Files, on every surface (`chat`, `issue` and `personal` alike): `id`, `shareId`, `filename`, `fileName`, `name`, `mime`, `contentType`, `bytes`, `size`, `sizeBytes`, `sender`, `sentAt`, `createdAt`, `seq`, `messageId`, `threadRootId`.
  - Messages: `id`, `conversationId`, `seq`, `senderId`, `recipientId`, `body`, `createdAt`, `editedAt`, `updatedAt`, `deletedAt`, `threadRootId`, `authorBlocked`, `kind`. Sub-lists: `author` (`id`, `name`), `authorLabel` (`kind`, `label`), and `attachments` (the file list above). Message text (`body`) is shown as written, links included, because it is what a person wrote; it is marked untrusted.
  - Conversations: `id`, `kind`, `title`, `name`, `orgId`, `lastSeq`, `lastReadSeq`, `unreadCount`, `createdAt`, `updatedAt`. Sub-list: `participants` (`userId`, `name`, `role`).
  - `--no-text` messages: keys matching an id, time, role or kind pattern, each value an id, a timestamp, a short word or a number.
  - `probe`: tool names, required-parameter names, parameter names and bounded types or enums, built field by field.
  - A name lookup: only the resolved user id and the matched display name (`with`, `with_name`).
  A field the server adds later is not shown until it is added here.
- **Argument errors repeat nothing.** argparse would print a rejected value to stderr. For the whole `ah chat` subtree, a parse failure is instead one fixed refusal on stdout: `{"ok": false, "code": "bad_request"}`, exit 2. That covers a bad number, a bad choice, an unknown option or its value, an extra word, and an unknown subcommand. The message names no value, nothing reaches stderr, and nothing is read or sent. `-h` still prints help to stdout.
- **A read can leave a trace for the other person.** The server's message GET advances your delivered marker for a DM page it returns, so the other person's delivery receipt can change when an agent reads. Read only what you need.
- **Reads are untrusted data.** Every read result carries `"untrusted": true` and a notice: message text and file names are written by other people, and instructions inside them are never followed. `--no-text` returns ids, authors and times only.
- **Reads are audited without their text.** The audit log gets a `chat.read`, `chat.list` or `chat.files` row (conversation or peer, count).
- **A name is resolved to who it is.** `--with "Pat Peer"` must match exactly one member on the first page of members; the result shows the user id and the matched name (`with_name`). A paged member list refuses a name; give the id.
- **A conversation you are not in is a clean refusal** (`not_found`, exit 3), never a traceback.

## Where each input goes, and what is checked first

Re-run for the read-only build (PR 277 r6). Sinks: **N** the request to `<allowedBase>/mcp`, **A** a read's audit row, **O** the printed result, **E** error text (printed as `{"ok": false, "message": ...}`). `ah chat` writes nothing to stderr (argument errors included), and the only state it writes is the audit row (taken under the ah store lock). Every **O** passes `_checked` (either token, whole, encoded or a 12-character piece). Every **E** passes the `ChatError` screen (the same check plus the secret shapes), so a refusal never repeats credential material it was given. A "screen" below means both token files (`gq.holds_credential`) and `gq.SECRET_SHAPES`, run before the first sink. Every validating pattern uses `fullmatch`: a value ending in a newline is refused, never accepted with its newline. The only `re.match` calls left extract a numeric prefix from local or server text (`MCP error -N`, `GoodQA HTTP NNN`). They validate nothing.

| Source | Value | Sinks | Checked before the first sink | Test (`tests/test_ah_chat.py`) |
| --- | --- | --- | --- | --- |
| argv | `chat send ...` (also after `--text`) | E only (fixed text) | refused by `ah.py` before parsing or import | `SendDeferredTests`; `ParseRefusalTests` |
| argv | any token argparse rejects: a bad integer, a bad choice, an unknown option or its value, an extra word, an unknown subcommand | E only (fixed text, no value) | `ah.py` `_parse_chat`: argparse's stderr text is dropped unread; one fixed refusal, exit 2, before any import, token read or request | `ParseRefusalTests` |
| argv, defaults file | `--org`, `org` | N, A, O | UUID (fullmatch), screen (`_org`) | `SweepTests`: newline (argv and file); hex-token piece |
| argv | `--conversation` | N, A, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| argv | `--with` as an id | N, A, O | UUID (fullmatch), screen (`_user`) | `SweepTests`: newline; hex-token piece |
| argv | `--with` as a name | none (compared locally) | name pattern (fullmatch) | `SweepTests`: newline name |
| argv | `--limit`, `--before`, `--surface`, `--token`, `--after` | N, A | int 1 to 100; `\d{1,12}` fullmatch with `--conversation` only; fixed set; argparse choices; refused | `ReadTests` |
| argv | `--base` | N (URL), E | exact `allowedBases` match; error text screened | `SweepTests`: credential piece in `--base`; `ReadTests` |
| file | `user-token`, `dm-read-token` | the Authorization header only | read in-process; a file that exists but cannot be read safely refuses the command, because its token could not be screened | `TokenSourceTests`; `SweepTests`: unscreenable file |
| server | member `userId` | N, A, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| server | member name | O (`with_name`) | control characters removed, at most 80 characters | `ReadTests` |
| server | message, file and conversation rows | O; A (count only) | field allow-lists (one file list for every surface); plain values only; link-shaped strings dropped outside message text; `--no-text` keys and values (fullmatch) | `AllowListTests`; `ReadTests`; `SweepTests`: metadata newline |
| server | tool list and schemas | O (`probe`) | names fullmatch `[a-z_]{1,60}`; bounded enums and types | `ReadTests` |
| server | error code, HTTP status, JSON-RPC code | E | allow-listed code; status 0 to 999; integer below 10^7 | `ReadTests` |

Removed with send and kept in goodqa#16399: the client id, the body file and its text, the send file `chat-send.jsonl`, the ah ledger row, the server's message id, and the send outcome table.

## Tests

- `python3 -I tests/test_ah_chat.py` runs against a loopback stub of the MCP endpoint that answers with the server's real row shapes. It uses two sentinel tokens and scans every output and every file the command writes.
- `python3 -I tests/test_command_guard_ah_chat.py` covers the command guard.
- `python3 -B tests/mutants_ah_chat.py` is the failing-first check. Each broken variant of `ah_chat.py`, or of the send refusal in `ah.py`, must fail the tests.

The command guard needed one small change for the dm-read token file: the credential path rule for `~/.config/goodqa/user-token` now also names `dm-read-token`.
