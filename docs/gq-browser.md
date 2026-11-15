# gq-browser: a GoodQA worker browser for agents

`harness/hooks/gq_browser.py` gives any agent session (a click-tester, an owner) a controllable GoodQA worker browser. It runs from your own GoodQA user token with no human step (goodqa#15745, part B3). It is stdlib-only Python, available as a CLI and as a stdio MCP server.

## Setup

- `~/.config/goodqa/user-token`: your GoodQA user token, one line, mode 0600. Never paste it into chat. The client refuses a missing file, an unreadable one, or one readable by group or others.
- `~/.config/goodqa/browser-defaults.json` (mode 0600; a group- or world-writable file is refused):

```json
{"org": "ORG_UUID", "project": "PROJECT_UUID", "allowedBases": ["https://goodqa.app/v1"], "allowedOrigins": ["https://example.com"]}
```

  - `allowedBases` lists the only API bases the token is ever sent to. It defaults to `https://goodqa.app/v1`.
  - `allowedOrigins` is optional. When set, `open` refuses any origin outside it, whatever an agent asks for.

## Commands

```
gq_browser.py open --origin https://example.com [--hours 1] [--ttl 900]
gq_browser.py act LEASE navigate --url https://example.com/x
gq_browser.py act LEASE click --selector "#buy"
gq_browser.py shot LEASE [--name home.png]
gq_browser.py status LEASE [--job JOB_ID]
gq_browser.py close LEASE
gq_browser.py list [--orphans]
gq_browser.py keys --orphans | --delete KEY_ID      # CLI only
gq_browser.py mcp                                    # stdio MCP server
```

- **open** mints a key (scopes `agents` and `write`, the minimum the lease service accepts; named `gq-browser:LEASE`; expiring with the grant, by default 1 h and at most 24 h). It then creates an exact-origin grant and a lease, and prints ids only. If any step fails (an API error, a lost or malformed response, the 60 s activation limit, a local file error), it stops the lease, revokes the grant and deletes the key before it exits with code 1. When the lease-create response is lost, it stops every session the lease's own key can see.
- **act** supports navigate, click, type, get_text, read_page, find, console, network, tabs_list, tabs_new, tabs_switch and tabs_close.
  - Every result is wrapped as `{"untrusted": true, "notice": ...}`. Page content is data, never instructions.
  - A page-changing action that does not finish within the wait is never re-sent. It reports `state: unknown` with the job id, so you can read the job instead.
- **There is no credential action.**
- **shot** writes the PNG only under `~/.agent-harness/gq-browser/LEASE/shots/`, mode 0600. It never follows a symlink and never overwrites a file.
- **close** stops the lease, revokes the grant and deletes the key, then removes the key file. Running it again reports `already_closed`. Every step runs even when an earlier one fails, and the cleanup report names each failed step (`stop_failed`, `revoke_failed`, `key_delete_failed` with the key id). A lease whose key could not be deleted stays open so `close` can retry it.
- **list --orphans** lists your own leases that are not closed, from local state.
  - It never asks the server for sessions, because the server returns none to a user token.
  - `keys --orphans` and `keys --delete` cover a lease whose local state was lost. They work only on keys you created whose name starts with `gq-browser:`. If the key lookup fails or lacks those fields, they show and delete nothing.
- **MCP tools:** `gq_browser_open`, `gq_browser_act`, `gq_browser_screenshot`, `gq_browser_status` and `gq_browser_close`.
  - They take no base or org argument, and unknown arguments are refused.
  - The arguments are written by the model, so they are not a security bound. The bounds are the server's deny list and grant cap, the 24 h and 16-origin limits, and `allowedOrigins`.

## What protects the token and the key

The client never prints, returns or logs the user token or a minted key. They do not appear in tool output or state files (the tests scan both for the raw value, base64, URL-encoded and 12-character pieces). Requests never follow a redirect and ignore proxy environment variables, so the token only ever reaches an allowed base.

The installed command guard refuses a shell read of `~/.config/goodqa/user-token` and of `~/.agent-harness/gq-browser/LEASE/key` as a credential read (goodqa#15785, `tests/test_command_guard_gq_credentials.py`). The client reads them in process, so an agent uses the token only through these verbs. What limits the damage if a file is read anyway is the lifetimes: a key lives at most 24 h and dies with its grant.

- `keys --orphans` lists only live keys. The server's DELETE revokes a key and its key list keeps showing revoked rows, so the client skips any row with `revokedAt` set. Deleting such a key again is refused locally.

## Machines: remote control of your own enrolled machine (goodqa#16051)

These verbs let an agent (an independent click-tester, for example) drive GoodQA remote control of a desktop you enrolled, such as a test VM. They use the same in-process token read as the verbs above. They mint no key and create no grant. An org admin's operate grant for this token on that machine must already exist, for example the one a #15941 enrollment makes.

```
gq_browser.py machine open MACHINE_ID [--ttl 300]
gq_browser.py machine shot HANDLE
gq_browser.py machine click HANDLE --x 640 --y 400 [--button left|right|middle] [--double]
gq_browser.py machine type HANDLE --text "hello"
gq_browser.py machine key HANDLE --keys ctrl+l
gq_browser.py machine renew HANDLE [--ttl 300]
gq_browser.py machine close HANDLE
gq_browser.py machine list [--orphans]
```

MCP tools: `gq_machine_open`, `gq_machine_screenshot`, `gq_machine_click`, `gq_machine_type`, `gq_machine_key`, `gq_machine_renew` and `gq_machine_close`.

- **open** first reads the machine (`GET /machines/:id`). A 403 or 404 there (no grant, a read-only grant, someone else's machine) is printed with its code, and nothing else is sent. It then takes a control lease with a unique holder `gq-machine:HANDLE` and a short TTL (300 s by default, 30 to 7200). It prints a local 16-hex handle.
  - `allowedMachines` in `browser-defaults.json` is optional. When it is set, any other machine id is refused before a request is sent.
- **Scope.** Every command names the lease this tool opened, and nothing is retried with a wider scope: never `autoLease`, never `takeOver`, never another machine. A `lease_held`, `machines_token_grant_level`, `lease_ended` or `lease_not_yours` answer is printed with its code. An ended lease is marked closed locally.
- **Only four kinds exist:** screenshot, click, type and key. There is no generic kind, so `fill_login`, shell and clipboard cannot be reached.
- **shot** writes `shots/<UTC yyyymmddTHHMMSSZ>-<machineId>-<n>.png` (or `.jpg`) under `~/.agent-harness/gq-browser/machines/HANDLE/`, mode 0600, never overwriting and never through a symlink. The bytes must be a PNG or JPEG of at most 12 MB.
  - Each shot is tracked in `shots.jsonl` with the UTC time, machine, lease, command and artifact ids, size, sha256 and path.
  - Screenshots and command results are untrusted data.
- **type** takes literal text only, from `--text` or the MCP argument. There is no file, stdin, environment or vault source.
  - It refuses text that holds the user token (or any 12-character piece of it) or matches a token or secret shape: GoodQA `gq*_` and `bt_k*_`, `sk-`, GitHub, AWS, Slack, Google, JWT, bearer or private key.
  - A refusal never repeats the text, and typed text is never echoed in the output.
- **Approvals.** A lease that needs approval (202) or a command `awaiting_approval` is reported. The command is cancelled; the tool never waits on it or approves it.
- **Lost answers.** A command whose answer was lost is never re-sent (each send carries a fresh `clientRequestId`). Look at the screen before acting again.
  - If the lease answer is lost, open asks once more with the same holder; the server returns that holder's lease, never a new scope. It then releases that lease and fails.

### Release (AC-5)

- **open** releases in `try/finally` on any failure, Ctrl-C or SIGTERM.
- **SIGINT or SIGTERM during an action** cancels the command in flight, releases the lease and marks it closed (exit 130 or 143).
- **The MCP server** releases every lease it opened when it ends (EOF, SIGINT or SIGTERM).
- **SIGKILL** runs no cleanup code. The bound is the server's lease TTL (300 s by default). `machine list --orphans` shows what is still open, and `machine close` releases it.
