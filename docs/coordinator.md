# coordd: the coordinator service on the build host

`coordd` (GoodQA goodqa#16043) is a small service that takes tasks, routes them to a worker lane by a fixed table, and reports each result to the task's ticket. It runs under systemd on the build host, so it keeps working when the laptop is off. It is the stand-in for the intake, routing and chat parts of the coordinator until the `ahc` daemon (goodqa#16034) takes them over; it holds no review-receipt or merge authority.

State: runs from a feature branch, not yet reviewed or merged.

## Run kit

All commands run on the build host. `C` is `python3 ~/coordinator-v2/agent-harness/harness/coordinator/coordd.py`.

| Task | Command |
| --- | --- |
| Status | `C status` |
| List tasks | `C tasks` |
| One task | `C show t-<id>` |
| Submit a task | `C submit --kind agent --text "..." [--ticket goodqa#N] [--needs run-commands] [--key K] [--wait 300]` |
| Chat | `C chat status`, `C chat unreviewed`, `C chat run <task> ticket:goodqa#N`, `C chat help` |
| Queue a PR review | `C review --repo owner/name --pr N --packet FILE --ticket goodqa#N --owner <agent id>` (repo must be in `COORD_REVIEW_REPOS` in `~/.config/coordd.env`) |
| Approve a browser sign-in | `C logins`, then `C approve ABCD-EFGH` (shows the requester and asks; `--yes` skips the question for scripted use after reading `logins`) |
| Remove every browser session | `C logout-all` |
| Service state | `systemctl --user status coordd.service mission-control.service` |
| Restart | `systemctl --user restart coordd.service` |
| Stop | `systemctl --user stop coordd.service` (add `disable` to keep it off after a reboot) |
| Logs | `journalctl --user -u coordd.service -n 100` |
| Ledger | `~/.agent-harness/coordinator/ledger.sqlite` (tasks, effects, events, logins, sessions) |
| Tests | `python3 -m unittest tests.test_coordd` |

Install on a Linux host with linger on: clone the repo, write `COORD_APP=<checkout>` to `~/.config/coordd.env`, copy `harness/coordinator/systemd/*.service` to `~/.config/systemd/user/`, then `systemctl --user daemon-reload && systemctl --user enable --now coordd.service mission-control.service`.

## Connecting from another machine

Both services listen on loopback only (coordinator page 47625, Mission Control 47615).

- Over SSH: `ssh -L 47625:127.0.0.1:47625 -L 47615:127.0.0.1:47615 <build host>`, then open `http://127.0.0.1:47625/`. For Mission Control, print a launch link on the host with `MC_HOOKS=<checkout>/harness/hooks python3 <checkout>/harness/mission_control/server.py url --port 47615` and open it through the forward.
- The coordinator page signs a browser in by device approval. The page shows a code; approve that exact code on the host. Check the client line that `C logins` prints before approving: approve only a code you (or your tester) just started. Codes last 5 minutes and work once, for the browser that started them. Sessions last 12 hours.
- Publishing the page inside a private network (never publicly) is a host operation and is recorded on the ticket, not in this file.

## What it does and does not do

| Kind | Lane | Notes |
| --- | --- | --- |
| `status` | built in | Host facts, no model. |
| `agent` | `codex-pool-build` | A read-only worker through the budget-capped Codex pool. It can answer; it cannot run commands on this host today, so a task with `--needs run-commands` is `blocked` instead of dispatched. |
| `review` | `review-receipt` | Runs `peer_review.py pr` at the PR's exact head in a service-owned clone and writes PASS or BLOCK with findings to the ticket. The receipt is unbound: it never authorizes a merge. An unchanged head and packet is not re-run. Needs a reviewer CLI signed in on the host; a packet that fails lint is `blocked` with the lint lines. |
| `chat` | command table | `status`, `tasks`, `unreviewed`, `show`, `run`, `help`. Free-form text needs an agent CLI signed in with a subscription on the host; API keys are never used for chat. |

Task states: `queued`, `running`, `done`, `failed` (tried and went wrong), `blocked` (could not be attempted or verified), `outcome-unknown` (interrupted where a rerun is not known to be safe).

Rules the code keeps:

- A worker's exit code is not a result. Its last line must be `COORD_RESULT: ok`; anything else is `blocked` or `failed`.
- The ticket report is written once per task (an upsert keyed by the task id), with an intent row before the call and the outcome after it. A failed report is retried.
- After a restart, a running task is requeued only on a replay-safe lane and within its attempt budget of 2.
- A transient provider failure (quota, rate limit, overload, timeout) is retried once.
- Chat runs on its own loop, so a long worker never blocks it.
- A browser session can use `status`, `tasks`, `unreviewed`, `show` and `help` only. It cannot queue worker or review tasks, name a ticket, reach any model, or approve or list sign-ins; those are host-CLI actions.
- Every 10 minutes the service lists open PR heads in the allowlisted repos that have no receipt and records each once (`unsubmitted`). A failed listing is recorded as `scan-failed`, never as nothing to do.
