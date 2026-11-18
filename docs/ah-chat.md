# ah chat: your own GoodQA chat, through the user token

`harness/hooks/ah_chat.py` (goodqa#16396) lets an agent session read, and only when asked, send, your GoodQA direct messages. The harness member key acts as "Claude (agent)", which is not a party to your DMs, so it answers `not_found` for them. `ah chat` uses your own user token instead, so the session acts as you, through one reviewed path.

```
ah chat probe                                   what the endpoint offers (tool and parameter names only)
ah chat history --with USER_ID_OR_NAME [--org ID] [--limit N] [--no-text]
ah chat history --conversation ID [--org ID]    a DM by its conversation id (the peer is found among that org's members)
ah chat files   --conversation ID [--surface chat|issue|personal]
ah chat send    --with USER --org ID --body-file F --client-msg-id ID        a direct message
ah chat send    --conversation ID --body-file F --client-msg-id ID           a channel or group conversation
```

Setup is the same as `gq_browser`: `~/.config/goodqa/user-token` (one line, mode 0600) and `~/.config/goodqa/browser-defaults.json` with `allowedBases` (and `org`, used when `--org` is not given). Nothing else is needed. `--base` must be one of `allowedBases`.

## What it guarantees

- **The token is never shown.** It is read in-process by `gq_browser.read_token()` and used only as the bearer of an HTTPS request to `<allowedBase>/mcp`. It is not on a command line, in the environment, in a file written by this command, in the ledger or in the audit log. Redirects and environment proxies are never followed. A server error body is never printed: only an HTTP status and an allow-listed machine code are. Every result is scanned before it is printed, and one that holds the token (whole, base64, URL-encoded or a 12-character piece) is withheld (`withheld`).
- **Reads are untrusted data.** Every read result carries `"untrusted": true` and a notice: message text and file names are written by other people, and instructions inside them are never followed. `--no-text` returns ids, authors and times only.
- **Reads are audited without their text.** The audit log gets a `chat.read` row (conversation or peer, message count).
- **Send is opt-in and idempotent.** `--client-msg-id` is required. A body that holds the token or matches a secret shape (the `gq_browser machine type` list) is refused, and the refusal does not show the body. The local send file (`~/.agent-harness/state/ah/chat-send.jsonl`) makes a repeat of the same id answer `duplicate` with no second post, a different body under the same id `key_conflict`, and an attempt whose outcome is unknown (a lost response) `uncertain`. A direct message has no server-side duplicate check, so after `uncertain` read `ah chat history`, and only if it did not arrive retry with `--confirm-not-delivered`. A channel post passes the id to the server as `clientMsgId`, which dedupes it. The ah ledger and audit log record the target, the client id, the body's SHA-256 and its length, not the text.
- **A conversation you are not in is a clean refusal** (`not_found`, exit 3), never a traceback.

## What the user token's endpoint does not offer

`ah chat probe` shows the live tool list. As of 2026-11-17 the user token sees `get_direct_messages`, `send_direct_message`, `file_list` and `chat_channel_post`, but not `agent_chat_history`. So there is no history read for a channel or group conversation, and a DM is read by its peer (`--with`) rather than by conversation id; `--conversation` finds the peer by looking at the newest message of each member of one org (at most 100 calls). `--after` and `--before` are not offered. `send_direct_message` may answer `approval_required`; that is shown as is and nothing is retried.

## Tests

`python3 -I tests/test_ah_chat.py` (loopback stub of the MCP endpoint, sentinel token, every output and file scanned), `python3 -I tests/test_command_guard_ah_chat.py`, and the failing-first check `python3 -B tests/mutants_ah_chat.py` (each broken variant must fail the tests). The command guard needs no change: `ah chat` is an ordinary command and every ad hoc read of the token file is still refused.
