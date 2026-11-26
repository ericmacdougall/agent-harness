# Mission Control

Mission Control is a local, realtime dashboard for the agent fleet (GoodQA #15585). It shows:

- every initiative: a progress bar, its state, the next step, and ETAs labelled with who estimated them;
- what each owner last did, and how long ago;
- a pulse whenever an agent writes its WAL, a branch is pushed, a project releases or deploys, or a ticket gets a checkpoint comment.

The same page has a chat. It can reach Claude main or Codex.

It runs on your Mac as a launchd user agent bound to `127.0.0.1`, and it is read-only toward repos, tickets and hosts.

The event and chat formats are in [mission-control-events.md](mission-control-events.md).

## The page

One scrolling page with six views (Overview, Requirements, Archive, Activity, Topology, Sources) and a docked chat. The Overview reads top to bottom:

1. **Mission**: five summary tiles (goals live and tested, live owners, asks waiting on you, blockers, live requirements), the goals from the ledger with their evidence one click down, and the initiatives behind a disclosure.
2. **Live owners and streams** and **Needs you**, side by side. The age beside each owner is its heartbeat (time since it last wrote). Needs you is part of the page, not a dialog; the top-bar button jumps to it.
3. **Recent deploys and live tests** and **Blockers**, side by side.

The top bar always shows the connection (Live, Reconnecting, Offline, Signed out) and the age of the last server message. The page opens one SSE stream and never polls `/api/state` on a timer; after a drop it resyncs once on reconnect. The 3D topology loads only when its tab is first opened (`#gl=off` still forces the static view). Every long text is clamped with a disclosure, and every list shows one page with "show more", so volume does not take over the page.

### Requirements, Archive and the archive rule

Asks and requirements are live or archived by one deterministic rule (`archive.py`). The first match wins, each row says which rule and why, nothing is deleted, and an item returns to live on the next read if its cause reverses.

| Rule | Archived when |
| --- | --- |
| M archived from the dashboard | someone archived it from the page (see below). The "who" is the dashboard session, never the user: any process that holds a launch link can make that click. A restore keeps it live whatever the other rules say |
| R1 terminal state | the record says resolved, closed, done, superseded, expired, declined or withdrawn; an ask has `resolved_at`; the sweeper cleared it as resolved or because its owner was reassigned |
| R2 done live | a deploy and a live test bound to the same ticket or commit, the newest of each by time, the test passing and not older than the deploy; or its ticket is closed (from the sweeper's cache). A local REALLY_TESTED pass, a lone deploy, an unbound pair, a FAIL or UNSTATED test, or a reopened ticket never archives |
| R3 superseded | a newer record of the same session (same owner for asks) has exactly the same full text, and that newer record is itself live. Near-duplicates stay live |
| R4 expired | a requirement is older than 30 days with no owner, ticket or evidence and is not sourced to you (`user:`, `uuid:`, `answer:` or `queue:`). The 30 days is an assumption, shown on the row ("moves to the archive in N d") before it applies |

An ask is never archived by age or by its `until`: an unanswered ask past its deadline stays in Needs you, answerable, with a stale mark. A requirement you stated yourself is never archived by age; if it has no owner it says so and waits for your own click. The Archive view lists archived asks and requirements with who registered them, their source, the resolution or reason, the evidence id and the rule. A missing who, when or source shows "unknown".

#### Archive and restore (the one write path of the cleanup)

Each requirement row has an Archive button (or Restore on an archived row). It opens a reason box (required, 1 to 300 characters) and a confirm button that stays disabled until there is a reason. `POST /api/requirements/archive` takes `req_id`, `action` (archive or restore), `reason`, the `digest` of the text the page showed and a `client_key`; it needs the session cookie, the exact Origin and the CSRF header like chat and approve. The server checks the requirement against its own ledger read and the digest, then appends one signed row to `~/.agent-harness/mission-control/requirements/actions.jsonl`:

| Field | Meaning |
| --- | --- |
| `at`, `session`, `req`, `action`, `reason` | when, whose main session, which requirement, what, why (redacted) |
| `rule` | always `manual` |
| `origin`, `source` | `dashboard` and `mc:<session>/<row id> "Dashboard click: ..."`. It is a dashboard click, never the user's own words (`user:`) |
| `digest`, `client_key`, `sig` | the text it was shown, the idempotency key, the HMAC with the install secret |

The manual archive's "who" is the dashboard session (`archived from dashboard session <short id>`), in the page, the activity line and the log row; Mission Control never writes "you" for it. A `user:`, `uuid:`, `answer:` or `queue:` sourced requirement archived this way keeps a distinct badge, and the Overview counts them with a one-click filter to review and restore them. The root cause (agents can obtain launch links, which also affects `/api/approve`) is goodqa#15926. The log only grows and is the audit trail. The latest verified row per requirement overrides the automatic rules, including on the next `ah requirements` read. A row with a bad signature, a wrong shape or a source that does not start with `mc:` is ignored. Nothing is written to the harness ledgers: the archive is a view you control.

### Ledger source

`ah goals --json`, `ah requirements --session S` and `ah status --session S --since 12h` are read through three allowlisted read-only runner shapes by the Ledger collector: once per cadence (60 s with a page attached, 300 s without, plus the attach refresh; never on a client request), at most 1 MiB each (4 MiB for requirements), 60 goals with 12 evidence records each, 1000 requirements, 30 rows per status list. A failing source keeps its last good rows marked stale and shows in Source health. The snapshot is published as the SSE event `ledger` (and in `/api/state`) only when its content changed.

**Status truth.** Every ledger part (goals, requirements, status) and every Source health row carries one `truth` value, computed once on the server (`collectors.read_truth`): `unknown` when the source has not been read successfully (an initial timeout, nonzero exit or invalid JSON, no main session yet, or a failed read for a session the rows on hand do not belong to), `stale` when a read failed after a good one (`at` is the last good read, `failed_at` the first failure since), `partial` when the last read succeeded but could not see everything (unread WALs, more goals than are kept, truncated requirements), and `current` otherwise. The page accepts only those four words (anything else, or a source it has not heard from, is `unknown`) and takes the worst over the sources a claim rests on (`CLAIM_SOURCES` in `web/js/adapt.js`; Blockers rest on status, asks, owners and initiatives). A zero or "none" (No blockers recorded, a 0 tile, Nothing needs you right now, Listening for signals…) is stated only when that is `current`. Otherwise the panel says what is known: `?` for an unknown count, `N+` for a partial one, and the last good read time (UTC) for a stale one, with one line per source that is not current. An initiatives file that is not configured is `off` but `current`: it has nothing to report, and an instance without OpenAI supervised owners reports that row the same way (a source that has never reported is `unknown`, never skipped).

**Truth across sessions, caps and the link.** A source is `current` only while its last attempted read succeeded, was whole, and was for the session main is in now. Requirements, status and asks are read for main's session: when it moves (to another session, or to none), the rows read for the old one are never shown, as `current` or as `stale`. They are `unknown` until a read for the new session succeeds. That is decided in one place per source (`Ledger.view()`; `Asks.health_truth()`), so what is pushed, what `/api/state` serves and the Source health row agree. The source is due at once, and a session watch (`App.follow_sessions`, twice a second and at each `/api/state`) tells the page even while that source's thread is still inside a slow read for the old session. `off` keeps no good-read time, so an error after it is `unknown`. A read that holds less than its source reports `partial`: over 100 asks or initiatives, over 60 owners, a goal, requirement, ask or owner row dropped for its shape, a WAL root or session directory that exists but cannot be listed, a WAL that exists but cannot be opened (retried until it reads, or it is removed), or the WAL file cap. A ledger payload that exits 0 but lacks one of its lists, or holds a status row that is not a row, is not read at all: it is an error, so `unknown` or `stale`, because a zero from it would be a guess. Status keeps 30 rows per list but carries each list's whole count; every count the page states from a status list uses that count, and the rows it does not hold are counted beside the list. Not marked: a non-regular `.jsonl` (a symlink or a FIFO) is refused by design and is not a WAL, and supervised-owner directories whose names break the supervisor's naming rule are not owners. The page also counts its own link: while it is not live (connecting, reconnecting, offline or signed out), every claim is at best `stale` as of the last data received (`unknown` if none came). After a drop, it is live again only once it has re-read `/api/state` from the server it reconnected to, so a restarted server's state replaces the old process's rows before anything is called current. A source whose reader stops (a hung or dead thread) is aged out: a row not checked within two of its slowest cadences plus its longest read turns `stale` (`unknown` if it never read) until its reader reports again. Bounded windows: up to 0.5 s between a session move and the watch pass that turns the session parts unknown; the previous session's asks stay listed (their truth already unknown) until the asks lock frees, which a click's read can hold up to its 60 s timeout; a `partial` asks read made by a click reaches Source health at the next asks run.

### Data with no UI today

Requirements of earlier sessions (only main's current session is read), the owner of a requirement (`ah requirements` leaves it empty, shown as no owner recorded), peer-review receipts, full ticket comment threads (only checkpoint comments arrive, as feed events) and release-kit deploy records outside the WALs have no read path in Mission Control. `web/coverage.json` maps every `/api/state` key, SSE event and ledger field to the page section that shows it; a test fails when a new key has no section.

## Run kit

| Task | Command |
| --- | --- |
| Open the dashboard | `mc` (installed to `~/.local/bin/mc`; it runs `python3 ~/.agent-harness/mission-control/app/server.py open`, which prints and opens a fresh one-time link). The installer never replaces an `mc` it did not write. |
| Install, or reinstall after a harness update | `python3 install.py --apply`. This copies the app to `~/.agent-harness/mission-control/app/` and registers the LaunchAgent. |
| Open it without the launcher | `python3 ~/.agent-harness/mission-control/app/server.py open`. This opens a single-use launch link, valid for 60 s. |
| Print a launch link instead | `python3 ~/.agent-harness/mission-control/app/server.py url` |
| Sign in a browser you cannot hand a link to (another host, a GoodQA agent browser) | Open the plain address; the page shows a sign-in code. On the host, run `server.py approve CODE` (same `MC_HOME` and `--port`). |
| Status (health and launchd state) | `python3 ~/.agent-harness/mission-control/app/server.py status` |
| Restart | `launchctl kickstart -k gui/$(id -u)/com.agent-harness.mission-control` |
| Stop until the next login or install | `launchctl bootout gui/$(id -u)/com.agent-harness.mission-control` |
| Turn it off for good | `python3 install.py --apply --no-mission-control`. The choice is remembered; files and chat data are kept. |
| Logs | `~/.agent-harness/mission-control/log/server.log` (rotated), plus `launchd.out.log` and `launchd.err.log` in the same folder |
| Invalidate every link, session and inbox signature | `python3 ~/.agent-harness/mission-control/app/server.py rotate-secret`, then restart |

The default port is 47615. To use another one, pass `--port P` to `serve`, `url`, `open`, `status` and `install-launchd`.

A disposable instance for testing does not touch your real chat data or launchd. In it, Codex is never run and the worker host is never contacted:

```sh
MC_HOME=$(mktemp -d) python3 harness/mission_control/server.py serve --port 47699 --no-remote --no-codex
MC_HOME=<same dir> python3 harness/mission_control/server.py url --port 47699
```

The server prints its own address, but no launch link. Use `url` with the same `MC_HOME` to get one.

## What it reads

Every source has a fixed interval. A failing source is never retried faster, and it shows as an error in the Source health strip at the bottom of the page.

| Source | What | Budget |
| --- | --- | --- |
| Claude + Codex WALs | `~/.claude/wals/<session>/*.jsonl` and `~/.agent-harness/codex-wals/`, tailed from the end. Symlinks are never followed. | A stat scan every 2 s; new files are found every 30 s. |
| Initiatives file | `initiatives.json` (see below) | Checked every 2 s, and read only when it changes. |
| Owners | `python3 ~/.claude/hooks/ah.py owners` | Every 60 s |
| GitHub | Your pushes and releases, from `gh api` events | One request every 60 s |
| GoodQA tickets | Checkpoint comments on tickets that initiatives reference | One ticket read every 10 s, round robin, at most 12 tickets |
| remote | One fixed WAL probe over ssh to local.json `heavy_job_host` (off when unset) | At most one ssh connection every 60 s |
| Event drops | `~/.agent-harness/mission-control/sources/*.jsonl`, written by external sources such as Fabric | Every 5 s |
| Ledger | `ah goals`, `ah requirements`, `ah status` (see Ledger source) | 60 s attached, 300 s idle |

Two kinds of WAL line are not work items:

- Tool calls, and lifecycle lines (subagent start and stop, prompts, gate notes such as `pending_stop`), are *quiet* events. They pulse the scene and refresh an owner's "last active" age, but they stay out of the feed unless you press **Show tool activity**.
- A WAL line written by a gate (it has a `by` field) is never treated as an owner's work item.

Two limits keep the server light:

- It holds at most 32 connections (an idle connection that has not signed in is evicted first) and 8 live streams, and keeps a replay ring of 500 redacted events.
- Events are limited to 20 per second, and quiet events get half of that budget.

The server stays under 100 MB RSS.

### What it costs

The two expensive sources are subprocesses: `provenance.py asks` (about 5 CPU seconds a run on a busy session) and `ah owners` (about 6). Neither is a blind poll any more.

- The asks ledger is read when a WAL line registers or resolves an ask (debounced by 5 s), when you click Approve or Deny, and at every sweep (5 minutes). It is not read every minute.
- `ah owners`, GitHub, the GoodQA ticket reader and the remote probe run at their normal interval while a page is attached, and at their idle interval (5 minutes; tickets 2 minutes) while none is. Attaching a page refreshes them at once.
- Scripts, styles and the three.js bundle are served gzipped with an ETag and `Cache-Control: no-cache, private`, so an unchanged file costs a 304. The page shell and every API response stay `no-store`.

### The read envelope and the gate

One rule holds from the producer to the sentence on the page: no layer turns an exception or a missing field into an
empty success. Three layers carry it.

| Layer | What carries the read | never read | failed | partial | stale |
|---|---|---|---|---|---|
| Producer (`ah requirements`, `ah status`, `ah owners`, `provenance asks`) | a `read` block, `harness.read/1` | no block: the collector refuses the output | `state: failed`, each unread source with its reason | `state: partial`: unread sources, skipped lines, `limited` | not its concern |
| Source (one Health row per collector) | the row: status, truth, `ok_at`, `checked`, `session` | no `ok_at`: unknown | error; unknown before a good read | ok with truth partial | error after a good read; a row not checked within its max age; a row read for another session is unknown |
| Dataset (`reads`, pushed before the rows) | `collectors.FEEDS` names its sources; `Truth` takes the worst | a source with no row | from its sources | from its sources | from its sources |
| Page | `adapt.CLAIMS` names a claim's datasets; `claim()` / `gate()` | no read from the server: unknown | from the read | from the read; rows the page could not show | from the read; the link not live |

To add to it:

- A new source: write its Health row through `Collector.run` (or `Health.ok` / `error` / `off`) and add its name to
  `FEEDS` for every dataset its data reaches. A source that is deliberately not configured reports `off` with
  `truth="current"`.
- A new producer: print a `read` block and parse the run with `collectors.producer_read`.
- A new claim: one line in `adapt.CLAIMS`, then state every count and every "none" through
  `gate(state, id).count(n)` and `.none(text, noun)`. A count of rows on hand ("Show 3 more") carries a
  `// held: <why>` comment instead.
- A new state key: one line in `adapt.STATE_DATASETS`.

Two tests compare what is declared with what is observed and fail on a difference:
`tests/test_mission_control_truth_chain.py` traces a run of the real server against `FEEDS`, and
`web/tests/truth-gate.test.mjs` renders each panel over a recording state against `CLAIMS` and scans the browser-only
modules for counts written outside the gate.

Limits of the two tests: the page derivation is per panel, so in a panel that makes several claims (the tiles, the inventory) one claim's declaration can excuse another's read; the browser-only modules are scanned as text, not rendered. Not marked: a single chat record that cannot be read is skipped by the chat store; `ah owners` reports the places it
could not list, not a WAL it could list but only partly parse; a status list keeps the newest 30 rows and says how many
more the ledger holds. If every server thread stops while the stream stays open, nothing ages the rows out.

## Needs you

"Needs you" lists the open asks of main's session. Each ask is shown whole (never clipped), with who registered it.

| You do | What happens |
| --- | --- |
| Approve or Deny | After a confirm step, the page sends `POST /api/approve` with the ask id, the digest of the text you were shown, and the decision. The server re-reads the asks ledger, refuses a closed or changed ask, and stores a signed record that main reads like a chat message. Main closes the ask with `wal_note.py --event ask_resolved --ref <ask> --decision approved|declined --source 'mc:<session>/<dash-id> "Dashboard decision: ..."'`. |
| Send reply | Your words go to main as a chat message tagged `[ask:<id>]`. |

The card states exactly how far a decision got: sending, sent and waiting, read by main (with the time), main replied, expired, or refused with the reason. A decision main has not read within 30 minutes expires and counts for nothing; the buttons come back.

What a dashboard decision is, and is not:

- It is bound to one session, one ask in main's WAL, and that ask's full text and reason. `wal_note` recomputes the digest from the WAL when the ask is closed and refuses a mismatch.
- It is its own provenance kind, `mc:`, with origin `dashboard`. It is never a `user:` source. Guards that ask for your own words (stopping another session's processes, production or deletion guards, credentials, top-rung models) refuse it, and main asks you in the terminal.
- Asks an owner registered, top-rung permission asks, and asks that cannot be shown whole cannot be decided here. The card says why and offers a reply.
- The install secret is a file your OS user can read, so a process running as you could forge a record. That is the same accidental-damage class as a queued message, and every trace says so.

### The sweeper

Every asks read is also a sweep (at least every 5 minutes, inside the dashboard server, which launchd keeps alive). It never resolves an ask and never writes a WAL or an answer. It only sorts what you see:

| Section | Rule |
| --- | --- |
| Cleared recently | The ask is settled: resolved in a session WAL, the ticket named by a `[ticket:ref]` tag that opens the ask closed (re-read every 30 minutes, so a reopen brings it back), its owner gone with a recorded reassignment, or the same words as an older ask of the same WAL that is still in plain view. Each row gives the reason and the evidence id. |
| Stale | Still open and answerable, but past its `until`, or 72 hours with no reply or decision. Never hidden. |
| Untraceable | Its source does not resolve through `provenance.py`. It is flagged, not shown as a valid ask, and has no controls. |

State lives in `~/.agent-harness/mission-control/needs/`: `<session>.json`, `audit.jsonl` (one row per transition: time, ask, action, reason, evidence) and `heartbeat.json`. Sweeps take a file lock, so two at once are safe. `ops_watch` raises `mc:needs-sweeper` when the heartbeat is older than 15 minutes.

### initiatives.json

The file is found in this order:

1. `MC_INITIATIVES`;
2. `"initiatives"` in `~/.agent-harness/mission-control/config.json`;
3. otherwise, the newest `~/.agent-harness/work/*/dashboard/initiatives.json`.

The file is a list of objects, or `{"initiatives": [...]}`. It is read up to 1 MiB, and the page shows at most 100 initiatives. Each object has these fields:

```
id, initiative, state, pct, milestones_done, milestones_total, milestones,
owner, ticket, next_step, next_eta, full_eta, estimate_by, note, updated
```

- Unknown fields are ignored.
- A missing `pct` is shown as "unknown", never as 0 %.
- ETAs always show their estimator (`estimate_by`, default `main`).
- A malformed file keeps the last good list on screen and marks it stale.

### Owners panel

The panel shows what `ah owners` reports and never rewrites a state.

**Default view: live owners by initiative.** Owners are grouped under the initiative whose ticket they name. Owners with no matching initiative go under "Not linked to an initiative".

Each group shows its live owners, with their working helpers nested under them. A parked owner that needs a decision also stays in view. Everything else folds under the group's fold button, which says how many rows it holds and how many of them need attention:
- parked owners (handoff, returned, done, DROPPED, finishing, waiting);
- finished helpers;
- helpers whose owner could not be found.

**Roles: live, parked and helper.** These are decided the way the owner cap counts them. The owner and helper type lists come from `caps.owner_types` and `caps.helper_types` in the policy tier_gate reads (`AGENT_HARNESS_TIER_POLICY`, else the hooks' `model_tiers.json`).
- That file is read only as a regular file of at most 1 MiB, never followed through a link. A FIFO, a directory, an oversized file or bad JSON falls back to the default lists.
- On a fallback the `owner-policy` Source health row errors. The owners claim is then not current, because the counts may differ from the cap's.

**Counts.**
- The headline and the summary line count live owners: holders of an 8-slot owner-cap slot, any runtime, as tier_gate counts them.
- Live Codex owners, parked or history rows, and helpers are separate figures beside it.
- Helpers never count toward any figure.
- Group headings sum to the headline.
- Every count goes through the owners claim: `?` while unknown, `N+` while partial, and "N (stale)" while stale.

**What a row may claim.** A row says "• live" only while the owners claim is current or partial. When the owners read is stale, or the row's own source is stale, the row shows its last known state, marked "(last known)". When the read is unknown, the row is marked "(not known now)".

**History window.** Owners finished over 6 h ago are not listed, and the summary line says so.

**Other views.** "All rows (flat)" lists every row in one list, sorted by severity and then recency, with no grouping and no folds. The Live, Dropped, Silent, Finishing, Codex, Returned and Done filters are flat lists of that state.

A DROPPED or SILENT owner is shown as *held* (amber, not red) when either:

- it has a recorded disposition that is still in force (`ah task dispose`); or
- its own last WAL note says it is waiting (for example "waiting on …" or "own background work").

The row says which of the two applies. Held owners do not count toward "need attention".

## Chat

The page sends chat to the local server. The server writes a signed record to `~/.agent-harness/mission-control/chat/`, and the agent reads it from there.

The chat follows these rules:

- Dashboard text is untrusted data. It is bounded to 4,000 characters, redacted, framed and fenced, and it is never executed.
- An agent cites it as `dash:<id>`, never as your own words.
- It may start or steer ordinary, reversible work. Anything consequential (pushing to a shared branch, merging, deploying, spending, deleting, contacting people) needs confirmation in the terminal, and it cannot grant top-rung models, approve production, deletion or credential actions, or override hard rules. The frame says so, because any process running as your OS user can write to the inbox: a message there is not proof that you typed it. Beside the composer, "About approvals" explains that chat never counts as an approval and that decisions are made in Needs you.
- A record without a valid server signature, or a signed record copied under another id, is marked FORGED and is never delivered.
- Each message is delivered once. Delivery is an atomic claim, so two waiters, or a waiter and a reader, never both take it. Reading an answered message again never reopens it.

Sending is idempotent:

- Each send carries a client key.
- If the response is lost, the page retries once with the same key, so a double-click or a retry never queues two messages.
- The server serializes each key and durably reserves its signed message before publishing the inbox and queue. A retry repairs interrupted publication with the original message ID, without reopening claimed or answered work.
- Reusing a key with different text, runtime, session or thread returns HTTP 409 (`key-conflict`). An unreadable reservation or invalid signature also fails closed; it never silently creates a second message. Older key indexes remain readable after signature and payload validation.
- The draft is cleared once the server accepts the message.

### Per runtime

| Runtime | How chat reaches it | Limits |
| --- | --- | --- |
| Claude Code CLI (main) | None since release 1001: `mc_inbox.py` (the waiter and its `reply` command) is on the kill list and deleted. The dashboard says so instead of offering to send. For an answer a Claude session must see, leave a note in the answer inbox, `~/.agent-harness/inbox/<session-id>/` (injected at its next prompt). | No dashboard reply from Claude main. |
| Codex CLI | The dashboard's Codex switch runs `codex exec --json` read-only on your ChatGPT subscription and streams the reply. The responder claims each message atomically, so it is answered once. | There is no Codex hook and no API-key fallback. When Codex is busy, rate-limited or not signed in, the page shows why and when it resets. Codex keys hook trust by position, so the installer adds no Codex hook. |
| Claude desktop | Ask the app to "check the dashboard". Its harness-tui plugin calls `mc_pending`, which attaches the app as the chat target `claude-desktop` and lists its unread ids (queued, or read but not yet answered) with their status. Pick `claude-desktop` in the dashboard's session picker to send to it. `mc_read` returns one verified, framed message and `mc_reply` answers it. | The desktop app has no Stop hook, so it never wakes on its own: a message waits until you ask the app to check. The tools never see messages for a terminal session. |
| ChatGPT / Codex desktop | There is no hook point and no supported MCP path from this harness. Use the dashboard's Codex switch, which runs the Codex CLI. | Messages are not delivered into the desktop app. |

## Security model

The trust boundary is one local OS user. The browser page, the server, Claude main and Codex all run as that user.

These are untrusted:

- every other web origin, including other `127.0.0.1` ports and DNS-rebound hosts;
- text inside WALs, ticket comments, GitHub events and event drops;
- chat text, as instructions.

The server defends against them as follows:

- **Bind**: `127.0.0.1` only. A taken port fails loudly in the log and is retried by launchd every 15 s. The server never falls back to another interface.
- **Access**: a launch code is an HMAC of the 0600 install secret; it is valid for 60 s and only once. It is exchanged for a fresh HttpOnly, SameSite=Strict session cookie, with a 303 redirect to a clean `/`. The access log never records query strings. Sessions survive a restart or reinstall: `~/.agent-harness/mission-control/sessions.json` (0600) holds only sha256 hashes of session ids with their times, bound to the install secret; the CSRF token is derived from the secret and the session id, so nothing in the file can be replayed. Demo mode keeps sessions in memory only.
- **Sign-in codes** (GoodQA #16047): for a browser that cannot be handed a launch link without putting a secret in it. On a loopback Host only, the signed-out page sets an HttpOnly, SameSite=Strict `mc_pending` cookie (a random id; the server keeps only its sha256) and shows a short code (8 characters from an alphabet without 0, O, 1, I or L). `server.py approve CODE` sends the code with a fresh single-use proof minted from the install secret under a domain of its own, in a POST body, to `/signin/approve`, which refuses any request carrying Origin, Sec-Fetch or Cookie headers. The next reload of that page, carrying that cookie, gets the session; the code alone grants nothing, so a screenshot of it is harmless. An entry, approved or not, is claimed once and lives at most 5 minutes; at most 8 are pending (oldest evicted); a look-alike code is refused, never mapped; rotating the secret voids every entry. The page has no script (it reloads itself every 3 s). The demo Funnel host, and any request carrying a proxy header, never gets a code. A retried approval after the session was claimed reports 409, not 404. Browsers share cookies across ports, so use a browser profile dedicated to Mission Control (one that visits no other loopback service): a hostile service on another loopback port could otherwise read or plant these cookies.
- **Requests**:
  - Every request has its Host checked against an exact allowlist, which defends against DNS rebinding.
  - Data reads and the event stream need `Sec-Fetch-Site: same-origin` or an exact Origin.
  - Writes need the exact Origin and the per-session CSRF header.
- **Responses**: no CORS. A strict CSP (`default-src 'self'`, `frame-ancestors 'none'`), plus `nosniff`, `no-referrer` and `no-store`. The page renders data only with `textContent`, and never loads a link or image that comes from data.
- **Secrets**: every event and chat text passes the harness redaction. Keychain, auth and credential files are never read.
- **Read-only**: nothing is written to repos, tickets or hosts. The ssh probe is one fixed read-only command.

Two parties are trusted, and this is stated rather than defended:

- Browser extensions with access to `127.0.0.1` can read the page and post chat.
- Same-user processes can read the install secret, so the inbox signature stops accidental or naive forgery but not a determined local attacker. The authority limit on `dash:` messages is what bounds the damage: the frame says a message is not proof the user typed it, and anything consequential needs the terminal.
- Inbox reads never block: a FIFO or device planted under a `.json` name is skipped, so no hook can hang on one.

## Demo mode

`serve --demo` runs the page on fixture data for click-tests and screenshots. Nothing real is read or run:

- The collectors get a canned runner, so `ah`, `gh`, ssh and `codex` never start. Real WALs are not read.
- Fixture initiatives, owners (including held amber owners) and WAL lines live in `MC_HOME/demo/`.
- A demo source pulses every few seconds. GitHub shows as failing, so the error notice can be checked.
- Chat lands only in the disposable `MC_HOME`. The targets `demo-main` and `claude-desktop` are fake, and each message gets a canned reply after 4 s. No agent ever sees it.

```
MC_HOME=<disposable dir> python3 ~/.agent-harness/mission-control/app/server.py serve --demo --port 47699
MC_HOME=<same dir> python3 ~/.agent-harness/mission-control/app/server.py url --port 47699   # another 60 s code
```

It refuses to start (exit 2) in these cases, before anything is written:
- `MC_HOME` is unset, or is the real `~/.agent-harness/mission-control` (or inside or above it);
- `MC_HOME` is a non-empty directory without the `.mc-demo-home` marker that demo mode writes into an empty home;
- any entry anywhere under it is a symlink (for example `sources`, `demo/wals` or `log/server.log`).

Fixture files are written without following symlinks. It prints a launch link to the terminal; codes are never written to a file. `url --demo-host` works only for an existing demo home that carries the marker; it never creates a secret and never uses the real install's, including from a backup copy of the real home.

To tie a test run to a commit, run the checkout's own `harness/mission_control/server.py` with `MC_HOOKS=<checkout>/harness/hooks`. The startup banner and `/healthz` then report `build`, which holds the commit, a digest of the served files, and `hooks: checkout` or `installed`. It contains no paths and no host name, because `/healthz` needs no session. In demo mode, `/api/state` shows the host as `demo`.

The page's `#gl=off` view flag forces the static (no-WebGL) view, so the fallback can be checked in any browser.

Three knobs exercise the slow-network and failure cases:

- `MC_DEMO_CHAT_DELAY_MS=3000` holds each chat send for 3 s before anything is stored, so the page's "Sending…" state and an edit made while pending can be seen.
- `MC_DEMO_DROP_FIRST=1` stores the first message and then drops its response, so the page's same-key retry can be checked.
- `MC_DEMO_REFUSE_FIRST=1` refuses the first send (409, which the page does not retry) without storing it, so the failed message, its Retry button and the kept text can be checked.

The demo feed also writes two tool-call records each pulse (seen with "Show tool activity"), and about once a minute a burst of 30 lines, which shows as a "more events in a burst" row.

`--demo-host NAME.ts.net` (only with `--demo`) also accepts that exact Tailscale Funnel host, with the Origin `https://NAME.ts.net`. The server still binds 127.0.0.1. Any other name is refused, and the LaunchAgent never passes `--demo`. On that host the session cookie is marked `Secure`. There is no launch-failure lockout: the 128-bit MAC cannot be guessed, and behind a Funnel all clients share 127.0.0.1, so a shared lockout would let one client block another's genuine code. Opening a Funnel exposes the page publicly, so only do it for a short, approved window, and close it afterwards.

## Rollback

- Stop the service: `launchctl bootout gui/$(id -u)/com.agent-harness.mission-control`. To keep it off across installs, run `python3 install.py --apply --no-mission-control`.
- Go back to the previous app: the installer keeps it at `~/.agent-harness/mission-control/app.prev/`. Swap it back into `app/` and restart. You can also reinstall from an earlier harness commit.
- Remove the hooks: release 1001 no longer installs `mc_inbox.py`; an upgrade moves an old copy into the install backup.

## Not yet

- **Remote access over Tailscale.** It would need a second listener on the tailnet address, with the same launch-code and cookie model plus an allowlist of tailnet identities. It is off until it has its own review.
- **Fabric events.** Fabric will write events through the event-drop directory, or through the remote probe once `fabric control export` ships. The format is fixed in [mission-control-events.md](mission-control-events.md).

### Named OpenAI owners

The dashboard reads supervised Codex owners independently from Claude owner discovery.
It polls `~/.agent-harness/codex-owners/<name>/status.json` every two seconds and displays
harness, recorded model, stream, ticket, state, last activity, and a redacted last reply.
An unavailable Claude source does not suppress those rows. The source health is shown as
**OpenAI supervised owners**; a failed scan retains the last good rows with **STALE SOURCE**.
A successful empty scan clears the rows. Missing or invalid state is a source error, never
reported as a healthy empty fleet.

The collector reads status files only, with no symlinks in the directory chain, at most
128 owner directories, and 64 KiB per status file. It does not read turn logs, credentials,
inboxes, or outboxes. Supervisor process checks use signal zero only. A running supervisor
is shown as live; an idle supervisor retains its waiting/blocked/error state when recorded;
a stopped supervisor and an unreachable supervisor are distinct. A reported DONE is shown
as idle and does not establish deployed-and-tested delivery. Models absent from the source
are explicitly unknown. Raw Codex WAL rows remain available for unmanaged sessions; a WAL
thread associated with a named supervisor is not duplicated.

This read-side integration does not enable direct messages to named owners. The existing
chat channels keep their existing routing until the generation-bound, durable inbox and
reply-correlation integration is installed and tested.

The chat store's named-recipient contract signs an OpenAI owner's name and immutable
generation, or a Claude owner's agent ID and exact registered main session. Client-key
retries cannot change that recipient. Named OpenAI messages are excluded from generic
pending, unread, read and reply paths; only the exact generation can claim them. Their
frame retains the dashboard authority limits and asks for an ordinary returned answer,
which a completed-turn bridge must correlate before publication. Claude frames identify
the owner and route via main, retaining the existing reply command. Until the supervisor
bridge is ready, HTTP requests carrying a named owner fail with `owner-route-unavailable`
rather than silently sending through a generic channel.

Queue and unread scans keep a durable read cursor per recipient route, operation and
logical consumer. Delivery workers pass stable consumer names; observers use a separate
default scope, so observation cannot advance a worker's traversal. Each poll examines
at most 2,000 markers and loads at most 500 candidate records, then resumes circularly on
the next poll. A backlog for one stopped owner therefore cannot permanently hide another
route's messages. Cursors do not authorize delivery or change message state; signatures,
exact recipient matching and atomic claims remain required. Results and unread counts
are bounded pages rather than an unbounded inventory; an empty page does not prove the
whole queue is empty. Polling workers retain their progress across restarts.
