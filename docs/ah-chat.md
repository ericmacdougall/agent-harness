# ah chat: read your own GoodQA chat, through two separate tokens

`harness/hooks/ah_chat.py` (goodqa#16396) lets an agent session read your GoodQA direct messages. The harness member key acts as "Claude (agent)", which is not a party to your DMs, so it answers `not_found` for them. `ah chat` uses your own tokens instead, so the session acts as you, through one reviewed path.

**This build is read only.** `ah chat send` answers `{"ok": false, "code": "not_available", ...}` with exit 2 and names goodqa#16399. `ah.py` returns that answer before it parses the arguments or imports `ah_chat`, so the refusal reads no token, opens no file and makes no request. Sending was taken out after review found two problems. Automatic DM retries rested on an unverified server delivery contract. The local send file could not make a DM idempotent on its own. goodqa#16399 holds those findings, what a send needs from the server first (an inspectable delivery contract and server-side DM dedupe), and the saved implementation.

```
ah chat probe [--token dm|user]                 what the endpoint offers (tool and parameter names only); dm is the default
ah chat conversations [--org ID] [--limit N] [--cursor C]   your direct and group-direct conversations, one page  (dm-read token)
ah chat history --conversation ID [--limit N] [--before SEQ] [--no-text]   a DM or group DM by its id  (dm-read token)
ah chat history --with USER_ID_OR_NAME [--org ID] [--limit N] [--no-text]   the DM with one person    (dm-read token)
ah chat files   --conversation ID [--surface chat|issue|personal] [--offset N]   chat: a DM's files (dm-read token); issue, personal: file_list (user token)
```

## Two tokens, two files, no fallback

| File (mode 0600, one line) | Holds | Used for |
| --- | --- | --- |
| `~/.config/goodqa/dm-read-token` | a token you minted in the GoodQA web app with abilities `read` and `chat.dm.read`, named orgs only, short expiry | every read of private messages: `history`, `conversations`, `files --surface chat`, `probe --token dm` |
| `~/.config/goodqa/user-token` | your existing user token (as `gq_browser` uses) | only `files --surface issue\|personal` and an explicit `probe --token user`. A DM command (`history`, `conversations`, `files --surface chat`, `probe --token dm`) never opens this file, not even to screen output: a pasted user token is caught by its shape (`gqut_`). A bad mode on it does not block a DM read |

A missing or unusable file is an error that names the file. A private read never tries the user token. **The host is fixed: `https://goodqa.app/v1`.** `--base`, `base` and `allowedBases` in `~/.config/goodqa/browser-defaults.json` cannot move a token to another host (an agent can write that file); only `org` is read from it. The one exception is a loopback base with `GQ_BROWSER_TEST_LOOPBACK=1`, which is refused for a token under the real home's token path and for any token shaped like a real GoodQA user token (`gqut_`), so a hard link or copy of the real file into a test HOME is refused too (test tokens are `gqu_`). A refused base is rejected before any token file is read, and the refusal does not repeat it. A token file is opened with `O_NOFOLLOW` and `O_NONBLOCK` (a FIFO swapped in cannot hang the command; the descriptor's fstat then refuses it), and at most 4097 bytes of it are read. The dm-read token is created by the owner in the GoodQA web app, in their own signed-in session, with the abilities `chat.dm.read` and `read`, one or more named organizations and a short expiry (30 days at most); nothing in this repository creates or reads it for you, and no token value or fingerprint is recorded anywhere in it. The command guard refuses every ad hoc read of either file.

## Server dependency (read this before relying on it)

The server half is deployed and was exercised live (see "Verified live" below). The server tools are `list_direct_conversations`, `get_direct_conversation_messages` and `list_direct_conversation_files`, with the `chat.dm.read` ability, on goodqa.app build 2c3e16cba59d. The platform setting `userTokens.dmRead` is ON (it was OFF before the dedicated token existed). What the server offers to a token that is not a dedicated DM-read token is different, and the client checks for it:

- `history --conversation`, `conversations` and `files --surface chat` check `tools/list` first and fail with code `unsupported`, never with an empty result, when a tool is not offered. The message names both causes: the server lacks the feature, or this token is not a dedicated DM-read token (it needs the `chat.dm.read` ability, the `userTokens.dmRead` setting on, an org limit and an expiry within 30 days). Observed live: a user token without the DM ability is offered none of the three by-conversation tools.
- `history --with USER --org ORG` calls the existing `get_direct_messages`, but only after the same tools-offered check: the server answers that tool with an EMPTY successful list for a token the DM gate did not admit, which would read as "no messages". It cannot page (the tool takes no cursor; the output says so in `paging_note`). This path was run live (rows 16 to 20 below, at client commit a7cf3e8).
- AC-1 of goodqa#16396 (read a real DM conversation with a dedicated token) is verified live for the rows in the table below. Not covered live is listed at the end of "Verified live".

## What it guarantees

- **The tokens are never shown.** Each is read in-process by `gq_browser` and used only as the Authorization header of an HTTPS request to `https://goodqa.app/v1/mcp`. It is not on a command line, in the environment, in a file written by this command or in the audit log. Redirects and environment proxies are never followed. A server error body is never printed: only an HTTP status and an allow-listed machine code are. Every result is scanned before it is printed, and one that holds a screened token (whole, base64, URL-encoded or a 12-character piece) is withheld (`withheld`). The screened tokens are the dm-read token (read once per command, best effort, by every command) and the user token in the two commands that read it to send it.
- **Screening.** The output and id screens compare against the dm-read token when it is readable, and against the user token only in a command that already read it to send it. A DM command does not open the user-token file. What that gives up: a piece, or a base64 or URL-encoded copy, of the user token inside DM text is no longer recognised as that token; the whole token is still replaced by its shape. A read refuses only when the file it uses cannot be read safely (wrong mode, owner or type); the other token file is not a gate.
- **Secret shapes are withheld from text.** Every third-party string that reaches output goes through ONE screen (`ah_chat._screen`) first: message text, previews, author, participant and label names, file names, the resolved `with_name`, `--no-text` values and the probe's server strings (required and parameter names, enums, tool names). The screen is the union of `redact.py`'s shapes and `gq_browser.SECRET_SHAPES`, which adds the GoodQA user-token (`gqut_`, generally `gq[a-z]{1,4}_`), GoodQA key (`bt_k?_`) and DigitalOcean (`dop_v1_`) shapes `redact.py` lacks. A shape that matches only a prefix (`sk-ant-`, `sk-or-`) is extended over the rest of its token. A replaced span reads `[REDACTED:secret]` and the row (or, for `with_name` and `probe`, the result) carries `redacted: true`; a `--no-text` value that holds a shape is dropped. Names are screened before they are cut. The shapes are composed in `ah_chat`, not added to `redact.py`: `redact.py` is the WAL redactor and the `ahc_scan` finding floor for about twenty modules, and a `gq..._` shape there would flag the repository's own test sentinels. Names and every non-text value are cut at 200 characters, text at 20000. The untrusted notice names text, previews, participant and author names and file names.
- **Shapes.** The stubs and parsers follow the server routes that the new tools will call (read from the bugtracker source, `messaging/routes.ts` and `dms.ts`): conversation messages `{conversation, messages, headSeq, foundOldest, foundNewest}`, conversation list `{conversations, hasMore, nextCursor}`, files `{attachments, nextOffset}`. The client sends `orgId`, `limit` and `cursor` to `list_direct_conversations`, `conversationId`, `limit` and `before` (a sequence number) to `get_direct_conversation_messages`, and `conversationId` and `offset` to `list_direct_conversation_files`. The live probe (row 1 below) reported each tool's required fields and parameter types: `list_direct_conversations` requires `orgId` (string) and takes `limit` (integer), `cursor` (string) and `unreadOnly` (boolean); `get_direct_conversation_messages` requires `conversationId` (string) and takes `limit` and `before` (integers); `list_direct_conversation_files` requires `conversationId` and takes `q` (string) and `offset` (integer); `get_direct_messages` requires `orgId` and `userId` (strings) and takes `limit`. Declared by the schema is not the same as exercised live: only `orgId`, `limit`, `conversationId`, `before` (rows 2 to 5 below) and `userId` (rows 16 to 20) were sent to the live server; `cursor`, `offset`, `unreadOnly` and `q` were not, and limits up to 100 were exercised only at 5. The server tools were live; the stubs remain the unit tests' model of them. File rows are reduced to metadata: the server's rows carry a `url` that may be a signed link, and a link is never printed.
- **Every output is an allow-list of fields.** A server row can carry a link (a signed download URL, an avatar URL, an invite) under any key, at any depth, and a link is a capability. So each output keeps only named fields, and only plain values under them (text, a number, true or false). A nested object is dropped unless a sub-list names its fields. A string shaped like a link (`scheme://`, `www.`, `data:`, `mailto:`, `javascript:`, `blob:`, or a path with a query) is dropped even under an allowed field.
  - Files, on every surface (`chat`, `issue` and `personal` alike): `id`, `shareId`, `filename`, `fileName`, `name`, `mime`, `contentType`, `bytes`, `size`, `sizeBytes`, `sender`, `sentAt`, `createdAt`, `seq`, `messageId`, `threadRootId`.
  - Messages: `id`, `conversationId`, `seq`, `senderId`, `recipientId`, `body`, `createdAt`, `editedAt`, `updatedAt`, `deletedAt`, `threadRootId`, `authorBlocked`, `kind`. Sub-lists: `author` (`id`, `name`), `authorLabel` (`kind`, `display`), and `attachments` (the file list above). Message text (`body`) is shown as written, links included, because it is what a person wrote; it is marked untrusted.
  - Conversations: `id`, `kind`, `lastSeq`, `lastReadSeq`, `unreadCount`, `updatedAt`. Sub-lists: `participants` (`id`, `name`; the avatar link is dropped) and `lastMessage` (`id`, `seq`, `authorId`, `authorName`, `createdAt`, `deletedAt`, `authorBlocked`, `attachmentCount`, `preview`, and `authorLabel` as `kind`, `display`; the full `body` is not repeated). Attachment `url` values are dropped everywhere.
  - Paging, one page per invocation (nothing follows a next page for you): `conversations` adds `has_more` and `next_cursor` (pass it back as `--cursor`); `history --conversation` adds `found_oldest`, `found_newest` and `head_seq` (`found_oldest` false: read the next older page with `--before` set to the smallest `seq` shown); `history --with` adds `has_more`; `files --surface chat` adds `next_offset` (pass it back as `--offset`; the server pages files by offset, not by cursor). `--limit` stays 1 to 100.
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

## Verified live

Run on 2026-11-20 (UTC) from the PR clone at client commit `68366caf587ec37d767896b0f83a5b3b86db1028` (not installed), as `python3 -I harness/hooks/ah.py chat ...`, against goodqa.app server build `2c3e16cba59d` (deployment `selfhost-20261119T191901Z`), with `userTokens.dmRead` ON and a dedicated dm-read token (abilities `chat.dm.read`, `read`; one named organization; 30 days). Counts, codes and field names only: no message text, names, ids or token values are recorded.

| # | Command | Exit | Observed |
| --- | --- | --- | --- |
| 1 | `probe --token dm` | 0 | `ok`, `accepted`, 1 organization, `dm_read_by_conversation: true`; offered `list_direct_conversations`, `get_direct_conversation_messages`, `list_direct_conversation_files`, `get_direct_messages`, `list_orgs`, `list_org_members`; `missing: ["agent_chat_history"]` |
| 2 | `conversations --limit 5` | 0 | `ok`, 5 rows, `has_more: true` with a `next_cursor`; row keys id, kind, lastMessage, lastReadSeq, lastSeq, participants, unreadCount, updatedAt |
| 3 | `history --conversation <id> --limit 5 --no-text` | 0 | `ok`, 5 messages, seq 35 to 39, `head_seq: 39`, `found_newest: true`, `found_oldest: false`; keys authorId, conversationId, createdAt, id, kind, seq |
| 4 | `history --conversation <id> --limit 5 --before 35 --no-text` | 0 | `ok`, 5 messages, seq 30 to 34 (paging back, no overlap) |
| 5 | `files --conversation <id>` | 0 | `ok`, `count: 0` (that conversation has no files) |
| 6 | `history` on a well-formed conversation id the owner is not in | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 7 | `history --conversation <id> --base https://example.org/v1` | 2 | `ok: false`, `code: refused`, no request to that host |
| 8 | `probe --token user` (a token without the DM ability) | 0 | `accepted`, `dm_read_by_conversation: false`; the three by-conversation DM tools are in `missing` |
| 9 | `history --conversation <owner's DM in a second organization B> --limit 2 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 10 | `files --conversation <owner's DM in organization B>` | 3 | `ok: false`, `code: not_found`, no `files` key |
| 11 | `history --conversation <owner's DM in a third organization C> --limit 2 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 12 | `history --conversation <owner's DM in a fourth organization D> --limit 2 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 13 | `conversations --org <organization B> --limit 3` | 3 | `ok: false`, `code: not_found`, no `conversations` key |
| 14 | `conversations --org <the named organization A> --limit 3` (control) | 0 | `ok`, 3 rows |
| 15 | `history --conversation <owner's DM in organization A> --limit 2 --no-text` (control) | 0 | `ok`, 2 messages |

**What rows 9 to 15 show.** The token names one organization (A). The owner is also a member of other organizations and has direct conversations in three of them (B, C, D); those conversations were found in the owner's own signed-in web session (ids and kinds only, nothing read from them). Requested through the client with the A-only token, the owner's own direct conversations in B, C and D, and listing in B, answer `not_found` with no content, the same answer as for a conversation that does not exist; the same reads in A succeed. So a token that names one organization does not reach the owner's direct messages in the others. The server rule is in the GoodQA repository at the deployed build (`apps/api/src/lib/user-token-dm-read.ts`).

Rows 1 to 15 were run at client commit `68366caf587ec37d767896b0f83a5b3b86db1028`; rows 16 to 20 were run later, at client commit `a7cf3e86cd17f5517363d664a94899677ee115fd`, against the same server build and the same A-only token, for the by-person path (`get_direct_messages`, and `list_org_members` first for a name). User ids came from the participants of the owner's own conversations in the owner's signed-in web session; nothing was read from those conversations.

| # | Command | Exit | Observed |
| --- | --- | --- | --- |
| 16 | `history --with <id of the owner's DM partner in organization A> --org <A> --limit 3 --no-text` | 0 | `ok`, 3 messages; keys createdAt, id, recipientId, senderId |
| 17 | `history --with "<that member's exact name>" --org <A> --limit 3 --no-text` | 0 | `ok`, 3 messages |
| 18 | `history --with <id of the owner's DM partner in organization B> --org <B> --limit 3 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 19 | `history --with "<a member name>" --org <B> --limit 3 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |
| 20 | `history --with <id of the organization-B partner> --org <A> --limit 3 --no-text` | 3 | `ok: false`, `code: not_found`, no `messages` key |

**What rows 16 to 20 show.** The by-person path is held to the token's named organization too. In organization A it reads by user id and by member name. In organization B, where the owner does have a direct conversation with that user, it answers `not_found` with no content, by id and by name, and it does the same for a user who is outside the named organization when asked through it.
Not covered live: file metadata on a conversation that has files (the `files` result was empty, so file fields were not observed); the `cursor`, `offset`, `unreadOnly` and `q` arguments; a `--limit` above 5; behaviour with the platform setting OFF (a probe at commit 68366ca before the token existed was answered HTTP 401). A token whose organization list excludes a conversation or a user IS covered (rows 9 to 13 and 18 to 20), and `history --with` by id and by name IS covered (rows 16 to 20).

## Where each input goes, and what is checked first

Re-run for the read-only build (PR 277 r6). Sinks: **N** the request to `<allowedBase>/mcp`, **A** a read's audit row, **O** the printed result, **E** error text (printed as `{"ok": false, "message": ...}`). `ah chat` writes nothing to stderr (argument errors included), and the only state it writes is the audit row (taken under the ah store lock). Every **O** passes `_screen` field by field and `_checked` as a backstop (a screened token, whole, encoded or a 12-character piece). Every **E** passes the `ChatError` screen (the same token check plus every secret shape), so a refusal never repeats credential material it was given, including a path built from `HOME`. A "screen" below means the screened tokens (`_holds_token`) and the union of `redact.py` and `gq.SECRET_SHAPES` (`_secret_spans`), run before the first sink. Every validating pattern uses `fullmatch`: a value ending in a newline is refused, never accepted with its newline. The only `re.match` calls left extract a numeric prefix from local or server text (`MCP error -N`, `GoodQA HTTP NNN`). They validate nothing.

| Source | Value | Sinks | Checked before the first sink | Test (`tests/test_ah_chat.py`) |
| --- | --- | --- | --- | --- |
| argv | `chat send ...` (also after `--text`) | E only (fixed text) | refused by `ah.py` before parsing or import | `SendDeferredTests`; `ParseRefusalTests` |
| argv | any token argparse rejects: a bad integer, a bad choice, an unknown option or its value, an extra word, an unknown subcommand | E only (fixed text, no value) | `ah.py` `_parse_chat`: argparse's stderr text is dropped unread; one fixed refusal, exit 2, before any import, token read or request | `ParseRefusalTests` |
| argv, defaults file | `--org`, `org` | N, A, O | UUID (fullmatch), screen (`_org`) | `SweepTests`: newline (argv and file); hex-token piece |
| argv | `--conversation` | N, A, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| argv | `--with` as an id | N, A, O | UUID (fullmatch), screen (`_user`) | `SweepTests`: newline; hex-token piece |
| argv | `--with` as a name | none (compared locally) | name pattern (fullmatch), once, in `history` before the client (and so any token read) and before the first request | `SweepTests`: newline name |
| argv | `--limit`, `--before`, `--surface`, `--token`, `--after` | N, A | int 1 to 100; `\d{1,12}` fullmatch with `--conversation` only; fixed set; argparse choices; refused | `ReadTests` |
| argv | `--base` | N (URL), E | only `https://goodqa.app/v1` (loopback under the test switch, never with a `gqut_` token); refused before any token is read; the value is not repeated | `BasePinTests`; `TestModeTokenTests` |
| argv | `--cursor` | N | `CURSOR_RE` (fullmatch, at most 500), screen | `ContractTests`; `SweepTests`: secret-shaped cursor |
| env | `HOME` (in a token-file path) | E | the `ChatError` screen | `SweepTests`: secret-shaped HOME |
| file | `user-token`, `dm-read-token` | the Authorization header only | read in-process with `O_NOFOLLOW`, `O_NONBLOCK` and a 4097-byte bound; a file that cannot be read safely refuses a command that uses it; a DM command never opens `user-token` | `TokenSourceTests`; `TokenFileReadTests`; `UserTokenNotOpenedTests` |
| server | member `userId` | N, A, O | UUID (fullmatch), screen | `SweepTests`: newline; hex-token piece |
| server | member name | O (`with_name`) | control characters removed, screened, then cut at 80 characters | `ReadTests`; `ShapeScreenTests` |
| server | message, file and conversation rows | O; A (count only) | field allow-lists (one file list for every surface); plain values only; every string screened; link-shaped strings dropped outside message text; `--no-text` keys and values (fullmatch, then screened) | `AllowListTests`; `ReadTests`; `ShapeScreenTests`; `SweepTests`: metadata newline |
| server | tool list and schemas | O (`probe`) | names fullmatch `[a-z_]{1,60}`; bounded enums and types; every printed string screened | `ReadTests`; `ShapeScreenTests` |
| server | error code, HTTP status, JSON-RPC code | E | allow-listed code; status 0 to 999; integer below 10^7 | `ReadTests` |

Removed with send and kept in goodqa#16399: the client id, the body file and its text, the send file `chat-send.jsonl`, the ah ledger row, the server's message id, and the send outcome table.

## Tests

- `python3 -I tests/test_ah_chat.py` runs against a loopback stub of the MCP endpoint that answers with the server's real row shapes. It uses two sentinel tokens and scans every output and every file the command writes.
- `python3 -I tests/test_command_guard_ah_chat.py` covers the command guard.
- `python3 -B tests/mutants_ah_chat.py` is the failing-first check. Each broken variant of `ah_chat.py`, or of the send refusal in `ah.py`, must fail the tests.

The command guard needed one small change for the dm-read token file: the credential path rule for `~/.config/goodqa/user-token` now also names `dm-read-token`.
