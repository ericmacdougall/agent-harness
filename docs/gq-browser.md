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

The client never prints, returns or logs the user token or a minted key. They do not appear in tool output or state files (the tests scan both for the raw value, base64, URL-encoded and 12-character pieces).

- **Fixed output schemas.** A server value reaches output or a state file only as a field of a fixed local shape: a strict uuid, an ISO-8601 UTC timestamp, a state from a local enum, or an allow-listed error code. Anything else is dropped or printed as `unrecognized_error` or `unrecognized`. The one exception is browser page content (`act` and `status --job` results), which is the data these verbs exist to return.
- **Backstop.** Every CLI line and MCP answer is checked before it is printed. Output that holds the user token or a lease key, whole, base64, URL-encoded or as any 12-character piece in any letter case, is withheld and replaced by a fixed message (exit 1, or an MCP error). A screenshot whose bytes hold the token is not saved.
- `tests/test_gq_machine.py` (class `HostileServer`) puts the lowercase token, a 12-character piece, a non-credential canary and nested mixes into every answer field of every machine verb, through the CLI and MCP, and asserts that none of them appears in any output or state file. Requests never follow a redirect and ignore proxy environment variables, so the token only ever reaches an allowed base.

The command guard that refused a shell read of these files is deleted (release 1001). In a sandboxed session `~/.config/goodqa` is a secret path no role's shell can read (docs/sandbox.md); the lease key under `~/.agent-harness/gq-browser` is not listed. The client (an MCP server, outside the sandbox) reads them in process, so an agent uses the token only through these verbs. What limits the damage if a file is read anyway is the lifetimes: a key lives at most 24 h and dies with its grant.

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
  - `allowedMachines` in `browser-defaults.json` is **required**: list each test machine id. A machine outside it, or a file without it, is refused before any request is sent. The token acts as the machine's owner, so without the list a grant over all of your machines would let an agent drive your own computer without approval.
  - The holder separates this tool's leases from yours, but the server checks a command's lease by principal (the user). Two agents sharing one token can therefore command under each other's lease, so give each tester its own machine.
- **Scope.** Every command names the lease this tool opened, and nothing is retried with a wider scope: never `autoLease`, never `takeOver`, never another machine. A `lease_held`, `machines_token_grant_level`, `lease_ended` or `lease_not_yours` answer is printed with its code. Only `lease_ended` marks the lease closed locally.
- **click, type and key** print the command id and `state: ok`. The server's command result is never copied into the output.
- **Only four kinds exist:** screenshot, click, type and key. There is no generic kind, so `fill_login`, shell and clipboard cannot be reached.
- **shot** writes `shots/<UTC yyyymmddTHHMMSSZ>-<machineId>-<n>.png` (or `.jpg`) under `~/.agent-harness/gq-browser/machines/HANDLE/`, mode 0600, never overwriting and never through a symlink. The bytes must be a PNG or JPEG of at most 12 MB.
  - Each shot is tracked in `shots.jsonl` with the UTC time, machine, lease, command and artifact ids, size, sha256 and path.
  - Screenshots and command results are untrusted data.
- **key** refuses the token and secret shapes like type does, since key arguments are stored on the server too.
- **type** takes literal text only, from `--text` or the MCP argument. There is no file, stdin, environment or vault source.
  - It refuses text that holds the user token (or any 12-character piece of it) or matches a token or secret shape: GoodQA `gq*_` and `bt_k*_`, `sk-`, GitHub, AWS, Slack, Google, JWT, bearer or private key.
  - A refusal never repeats the text, and typed text is never echoed in the output.
- **Approvals.** A lease that needs approval (202) or a command `awaiting_approval` is reported. The command is cancelled and the lease released; the tool never waits on it or approves it.
- **State files are checked.** The lease id, holder and ttl in `state.json` are validated before they reach a request.
- **Lost answers.** A command whose answer was lost is never re-sent (each send carries a fresh `clientRequestId`). Look at the screen before acting again.
  - If the lease answer is lost, open asks once more with the same holder; the server returns that holder's lease, never a new scope. It then releases that lease and fails. A 5xx, 3xx or 408 on create is handled the same way. Only a 202 approval ask with reason `access_mode` to that second ask proves there is no lease (the server asks only when you hold no live control lease). Any other answer (lost, 5xx, 429, 403, 404, `lease_held`, `lease_not_yours`) leaves the lease listed in `list --orphans`, and `close` retries. Until then, click, type, key, shot and renew refuse that handle locally, since no lease id is confirmed.
- **When a lease counts as ended.** A lease is marked closed only on a positive signal: a release answer (2xx) that names this lease with a UTC `releasedAt`, a 409 `lease_ended`, or a create that was never sent or was refused. Any other release answer (lost, 5xx, 429, 403, 404, 401, `lease_holder_mismatch`, any other 409, or a 2xx that does not name the lease as released) keeps the lease open and listed in `list --orphans`, the verb exits 1 with `lease kept open`, and `close` retries. A 404 is not proof, because the server answers 404 for a missing lease and also when the machines switch or your grant hides the machine. The server ends a lease at its TTL, but the local row stays until a `close` gets a positive answer.
- **Error codes.** A server error code is printed only if it is on the client's allow-list (`KNOWN_CODES`). Any other value prints as `unrecognized_error`, so a token echoed back as a code never reaches the output.

### Release (AC-5)

- **open** releases on any failure.
- **SIGINT, SIGTERM or SIGHUP during any machine verb** (open, shot, click, type, key, renew, close), at any point (before a request is sent, while it is in flight, after the server applied it but before the answer, while state is written), ends in one of two outcomes: the lease is released and confirmed, or it stays open and listed in `machine list --orphans`. The command in flight is cancelled when its id is known; otherwise the message says it may still run. One handler at the entrypoint does this, and its message (exit 130, 143 or 129) states the outcome; it never claims a release that did not happen.
  - The first signal starts the shutdown and later ones are ignored, so a second Ctrl-C cannot cut a release short. A signal that lands while a release is running is deferred to its end, not dropped.
  - An unexpected local error (for example a state file that cannot be written) releases nothing; the message says the lease is still open.
- **The MCP server** first ends the lease of the call in flight, then releases every lease it opened when it ends (EOF or a signal), and reports how many it could not release.
- **SIGKILL** runs no cleanup code. The bound is the server's lease TTL (300 s by default). `machine list --orphans` shows what is still open, and `machine close` releases it.
