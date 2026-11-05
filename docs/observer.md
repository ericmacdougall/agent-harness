# Resource observer contract (schema version 1)

This is the contract between the Python harness (hooks, `ah-run`, `deadman.py`) and the Go observer in netwatch (GoodQA goodqa#14547). Both sides vendor `docs/observer-sample.json` and pin its sha256; a conformance test on each side parses the golden sample and checks the rules below. The contract lands before any implementation so that neither owner blocks the other.

## Attribution the harness provides

`ah-run` starts every agent command in its own process group (macOS) or a `systemd-run --user --scope` unit (Linux) and exports exactly these variables into the child tree:

| Variable | Meaning |
|---|---|
| `AGENT_HARNESS_TASK` | task key (`[task:KEY]` from the spawn, or a generated `auto-<hash>`) |
| `AGENT_ID` | agent id from the hook input, or `main` |
| `AGENT_HARNESS_TICKET` | GoodQA reference, or `none` |
| `AGENT_HARNESS_SESSION` | Claude Code or Codex session id |
| `AGENT_HARNESS_RUN_ID` | ledger row id (32 hex) |

The ledger lives at `~/.agent-harness/reserve/ledger/<run_id>.json` (0600). A row holds the attribution, `pid`, `pgid` or `unit`, the process start token (`proc:<starttime>` on Linux, `ps:<lstart under TZ=UTC>` on macOS), a command digest (never the command), cwd digest, host, and at the end the exit code, wall time, rusage, max rss and a masked pid tree. Rows never contain raw commands or environments.

## What the observer samples

For every process of the current user the observer emits one sample per interval with:

| Field | Type | Rule |
|---|---|---|
| `schema` | int | always `1` |
| `host` | string | hostname |
| `at` | string | RFC 3339 UTC; writers emit their native form (`Z` from Go, `+00:00` from Python) and every reader accepts both |
| `pid`, `ppid` | int | from the kernel |
| `pgid` | int or null | process group; null when unknown |
| `cgroup` | string or null | Linux cgroup path when available |
| `uid` | int | owner |
| `start_token` | string | same scheme as the ledger: `proc:<starttime>` (Linux), `ps:<lstart under TZ=UTC>` (macOS, 1 s resolution), `win:<creation FILETIME decimal>` (Windows); pid reuse within the same second and under the same ppid is an accepted residual, so consumers needing stronger identity compare pid, token and ppid together |
| `rss_bytes` | int64 | resident set size |
| `cpu_seconds` | float64 | cumulative |
| `disk_write_bytes`, `disk_read_bytes` | int64 or null | cumulative; null when the platform has no per-process counter |
| `net_tx_bytes`, `net_rx_bytes` | int64 or null | cumulative; null when unavailable |

`pid`, `ppid`, `pgid`, `uid` and every `*_bytes` field are integers (int64); `schema` is an int; `cpu_seconds` is the only float. A platform that cannot fill a nullable field emits null, never an invented value. Windows: environment reading is unsupported, so attribution there is `unattributed` unless ancestry reaches a ledger row; ah-run does not ship on Windows in this phase.
| `argv_masked` | string | argv joined, passed through the harness secret mask (`usage_guard.SECRET`), at most 512 characters |
| `attribution` | object | see below |

### Attribution rules

- The observer reads only the five variables above from a process environment (`ps -E` / `ps eww` on macOS, `/proc/PID/environ` on Linux) and the ledger ancestry (walk `ppid` to a pid whose start token matches a ledger row). It never persists any other environment variable and never infers a task from cwd or command text.
- `attribution` is one of:
  - `{"state": "attributed", "task": ..., "agent": ..., "ticket": ..., "session": ..., "run_id": ..., "via": "env" | "ancestry" | "both"}`
  - `{"state": "unattributed"}` when neither env nor ancestry gives an answer.
  - `{"state": "conflict", "env": {...}, "ancestry": {...}}` when they disagree; the observer never picks one.
  - `{"state": "hook-ssh", ...}` when the row says the run came over an ssh line built by the hook: it carries the attribution the line claimed (`task`, `agent`, `ticket`, `session`, `run_id`, `via`); when ancestry disagrees the state stays `hook-ssh` and an `ancestry` object is added beside the claimed fields; a hook-ssh row never produces `conflict`, consumers never raise a conflict alert from it, and it counts as unverified wherever verification matters.
- A sample for a process whose environment holds a secret (for example `SECRET_X=...`) must not contain that value anywhere.

## Aggregates the deadman consumes

`netwatch report --json` keeps every key it emits today and adds one top-level key `observer` holding exactly this schema-1 document (`schema`, `host`, `at`, `volumes`, `top_writers`, `samples`); `deadman.py` reads `report["observer"]`. The document returns, besides the samples, per-volume disk use keyed by filesystem id (not mount name) with free bytes, a growth rate over the last hour, the top five growing directories under the watched roots, and the top five writers by `disk_write_bytes` delta with their attribution. `deadman.py` names them in alerts; when the observer is absent the deadman reports directory growth only and marks process attribution `unavailable`.

## Conformance

- Python: `python3 -m unittest tests.test_observer_contract` parses `docs/observer-sample.json`, checks every rule above, and checks the pinned sha256.
- Go: the netwatch repository vendors the same sample and sha and runs the equivalent test.
- Changing the sample or the schema needs a version bump here and in both tests.
