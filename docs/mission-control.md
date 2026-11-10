# Mission Control

Mission Control is a local, realtime dashboard for the agent fleet (GoodQA #15585). It shows:

- every initiative: a progress bar, its state, the next step, and ETAs labelled with who estimated them;
- what each owner last did, and how long ago;
- a pulse whenever an agent writes its WAL, a branch is pushed, a project releases or deploys, or a ticket gets a checkpoint comment.

The same page has a chat. It can reach Claude main or Codex.

It runs on your Mac as a launchd user agent bound to `127.0.0.1`, and it is read-only toward repos, tickets and hosts.

The event and chat formats are in [mission-control-events.md](mission-control-events.md).

## Run kit

| Task | Command |
| --- | --- |
| Install, or reinstall after a harness update | `python3 install.py --apply`. This copies the app to `~/.agent-harness/mission-control/app/` and registers the LaunchAgent. |
| Open the dashboard | `python3 ~/.agent-harness/mission-control/app/server.py open`. This opens a single-use launch link, valid for 60 s. |
| Print a launch link instead | `python3 ~/.agent-harness/mission-control/app/server.py url` |
| Status (health and launchd state) | `python3 ~/.agent-harness/mission-control/app/server.py status` |
| Restart | `launchctl kickstart -k gui/$(id -u)/com.agent-harness.mission-control` |
| Stop until the next login or install | `launchctl bootout gui/$(id -u)/com.agent-harness.mission-control` |
| Turn it off for good | `python3 install.py --apply --no-mission-control`. The choice is remembered; files and chat data are kept. |
| Logs | `~/.agent-harness/mission-control/log/server.log` (rotated), plus `launchd.out.log` and `launchd.err.log` in the same folder |
| Invalidate every link, session and inbox signature | `python3 ~/.agent-harness/mission-control/app/server.py rotate-secret`, then restart |

The default port is 47615. To use another one, pass `--port P` to `serve`, `url`, `open`, `status` and `install-launchd`.

A disposable instance for testing does not touch your real chat data or launchd. In it, Codex is never run and t2-dev is never contacted:

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
| t2-dev | One fixed WAL probe over ssh | At most one ssh connection every 60 s |
| Event drops | `~/.agent-harness/mission-control/sources/*.jsonl`, written by external sources such as Fabric | Every 5 s |

Two kinds of WAL line are not work items:

- Tool calls, and lifecycle lines (subagent start and stop, prompts, gate notes such as `pending_stop`), are *quiet* events. They pulse the scene and refresh an owner's "last active" age, but they stay out of the feed unless you press **Show tool activity**.
- A WAL line written by a gate (it has a `by` field) is never treated as an owner's work item.

Two limits keep the server light:

- It holds at most 32 connections (an idle connection that has not signed in is evicted first) and 8 live streams, and keeps a replay ring of 500 redacted events.
- Events are limited to 20 per second, and quiet events get half of that budget.

The server stays under 100 MB RSS.

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

The panel shows what `ah owners` reports and never rewrites a state. By default it lists live, working, finishing and waiting owners, plus any that are DROPPED or SILENT; "All owners" shows the rest.

A DROPPED or SILENT owner is shown as *held* (amber, not red) when either:

- it has a recorded disposition that is still in force (`ah task dispose`); or
- its own last WAL note says it is waiting (for example "waiting on …" or "own background work").

The row says which of the two applies. Held owners do not count toward "need attention".

## Chat

The page sends chat to the local server. The server writes a signed record to `~/.agent-harness/mission-control/chat/`, and the agent reads it from there.

The chat follows these rules:

- Dashboard text is untrusted data. It is bounded to 4,000 characters, redacted, framed and fenced, and it is never executed.
- An agent cites it as `dash:<id>`, never as your own words.
- It may start or steer ordinary, reversible work. Anything consequential (pushing to a shared branch, merging, deploying, spending, deleting, contacting people) needs confirmation in the terminal, and it cannot grant top-rung models, approve production, deletion or credential actions, or override hard rules. The frame says so, because any process running as your OS user can write to the inbox: a message there is not proof that you typed it. The page says "Approvals need the terminal" beside the composer.
- A record without a valid server signature, or a signed record copied under another id, is marked FORGED and is never delivered.
- Each message is delivered once. Delivery is an atomic claim, so two waiters, or a waiter and a reader, never both take it. Reading an answered message again never reopens it.

Sending is idempotent:

- Each send carries a client key.
- If the response is lost, the page retries once with the same key, so a double-click or a retry never queues two messages.
- The draft is cleared once the server accepts the message.

### Per runtime

| Runtime | How chat reaches it | Limits |
| --- | --- | --- |
| Claude Code CLI (main) | Main runs `python3 ~/.claude/hooks/mc_inbox.py wait --session <session-id>` as a background task. It wakes when a message arrives, prints the framed message and exits; main answers with `mc_inbox.py reply <id>` (text on stdin) and re-arms the waiter. The installed `mc_inbox.py hook` on Stop and UserPromptSubmit points the registered session at a message it missed. | Only the session you pick in the dashboard receives a Claude message. The Stop hook blocks at most once per message (a message main ignored never hides a newer one), with a 120 s cooldown and at most 6 blocks an hour, and its text is a fixed pointer. The hook reads only its own session's target file, so an unregistered session pays one failed file open per prompt. Subagents never act on chat. With no registered session, the page says "no main attached" and does not accept Claude messages. |
| Codex CLI | The dashboard's Codex switch runs `codex exec --json` read-only on your ChatGPT subscription and streams the reply. The installer also ships `~/.codex/agent-harness/mc_inbox.py`, so a Codex session can list waiting Codex message ids (`pending --to codex`) by hand. The responder claims each message atomically, so it is answered once. | There is no Codex hook and no API-key fallback. When Codex is busy, rate-limited or not signed in, the page shows why and when it resets. Codex keys hook trust by position, so the installer adds no Codex hook. |
| Claude desktop | Ask the app to "check the dashboard". Its harness-tui plugin calls `mc_pending`, which attaches the app as the chat target `claude-desktop` and lists waiting ids. Pick `claude-desktop` in the dashboard's session picker to send to it. `mc_read` returns one verified, framed message and `mc_reply` answers it. | The desktop app has no Stop hook, so it never wakes on its own: a message waits until you ask the app to check. The tools never see messages for a terminal session. |
| ChatGPT / Codex desktop | There is no hook point and no supported MCP path from this harness. Use the dashboard's Codex switch, which runs the Codex CLI. | Messages are not delivered into the desktop app. |

## Security model

The trust boundary is one local OS user. The browser page, the server, Claude main and Codex all run as that user.

These are untrusted:

- every other web origin, including other `127.0.0.1` ports and DNS-rebound hosts;
- text inside WALs, ticket comments, GitHub events and event drops;
- chat text, as instructions.

The server defends against them as follows:

- **Bind**: `127.0.0.1` only. A taken port fails loudly in the log and is retried by launchd every 15 s. The server never falls back to another interface.
- **Access**: a launch code is an HMAC of the 0600 install secret; it is valid for 60 s and only once. It is exchanged for a fresh HttpOnly, SameSite=Strict session cookie, with a 303 redirect to a clean `/`. The access log never records query strings.
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

It refuses to start if `MC_HOME` is unset, or is the real `~/.agent-harness/mission-control` (or inside or above it). It prints a launch link to the terminal only; codes are never logged.

Two knobs exercise the slow-network cases:

- `MC_DEMO_CHAT_DELAY_MS=3000` holds each chat accept for 3 s.
- `MC_DEMO_DROP_FIRST=1` stores the first message and then drops its response, so the page's same-key retry can be checked.

`--demo-host NAME.ts.net` (only with `--demo`) also accepts that exact Tailscale Funnel host, with the Origin `https://NAME.ts.net`. The server still binds 127.0.0.1. Any other name is refused, and the LaunchAgent never passes `--demo`. Opening a Funnel exposes the page publicly, so only do it for a short, approved window, and close it afterwards.

## Rollback

- Stop the service: `launchctl bootout gui/$(id -u)/com.agent-harness.mission-control`. To keep it off across installs, run `python3 install.py --apply --no-mission-control`.
- Go back to the previous app: the installer keeps it at `~/.agent-harness/mission-control/app.prev/`. Swap it back into `app/` and restart. You can also reinstall from an earlier harness commit.
- Remove the hooks: reinstall a harness version without them. `mc_inbox.py hook` fails open and does nothing for a session that has not registered, so leaving it in place is harmless.

## Not yet

- **Remote access over Tailscale.** It would need a second listener on the tailnet address, with the same launch-code and cookie model plus an allowlist of tailnet identities. It is off until it has its own review.
- **Fabric events.** Fabric will write events through the event-drop directory, or through the t2-dev probe once `fabric control export` ships. The format is fixed in [mission-control-events.md](mission-control-events.md).
