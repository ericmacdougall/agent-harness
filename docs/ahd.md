# ahd: the harness daemon

`harness/hooks/ahd.py` (GoodQA goodqa#14601) is a monitor and scheduler. It runs once per host on a 60 s loop. Design authority: `ahd-design/DESIGN.md` sections 2, 5, 7 and 10.

**ahd writes no harness state.** Every write is a subprocess call to the `ah` CLI, the single writer. Each call carries a deterministic idempotency key derived from what ahd observed: the host, the source, the alert key, the severity, and the ring `seq` of that key's latest event. So when ahd restarts or is killed mid-tick, it re-issues the same keys, and `ah` applies each one once. ahd has no socket and no state file. Its only own files are:

- the lock `~/.agent-harness/run/ahd.lock`, an empty flock file. A second instance exits 0 with "already running", so launchd and systemd never crash-loop.
- its log, `~/.agent-harness/logs/ahd.log`, at 5 x 8 MiB.

## Tick

The tick has a wall-time budget of 45 s. Each `ah` call gets the remaining budget as its timeout. Steps that run past the budget are skipped and logged, and a tick with skipped reads never clears alerts.

| Step | What | Write via |
|---|---|---|
| heartbeat | the deadman input | `ah heartbeat beat --service ahd` |
| checks | `ops_watch.checks.run_all`, once ops-watch exposes it; until then the ops-watch timer runs (never both) | `ah alert raise\|clear` |
| owners | `ah owners --session S` for each session whose main WAL moved in the last 48 h; the liveness rule lives in `liveness.py` (ah) | — (read) |
| asks | the v1 ledger `~/.agent-harness/work-assignments.json` (JSON, read-only), and `ask` WAL entries with no `ask_resolved`. The #14465 ledger replaces v1 via `work_assignments.py status --json` once installed | — (read) |
| alerts | diff the desired ahd alerts against this host's active `source=ahd` entries in the ring (read-only); raise new or escalated alerts, clear resolved ones. More than 10 transitions go in one `ah apply --batch -` | `ah alert raise\|clear` |
| spool | drain queued writes (GoodQA) | `ah spool drain` |

Alert keys:

- `liveness:<session8>/agent-<id>`: warning for SILENT; high for SILENT-HIGH and DROPPED.
- `ask:<id>:unowned`: warning; high when the request is under 24 h old and has been unowned for 2 h.
- `ask:<id>:stale` and `ask:<id>:no-evidence`: warning.
- `wal:unsafe:<session8>`: high; see Unsafe WALs below.

An active alert whose text no longer matches, or whose severity has fallen, is raised again with `detail.updated`. Changed words and lower severity wait at least 5 minutes since the last write; number-only changes wait an hour. Rises are immediate. ahd keeps no state, so every raise carries hashes of its raw text (`detail.text_sha`, `detail.text_shape`) and the rule in `liveness.ring_text_stale` compares those, because the ring's own text may be redacted or cut. A slot that overflowed has lost them and refreshes at most hourly, even when its text never changes: up to 24 rows a day for that key. The marks add about 62 bytes to each row, so a 300-character message with roughly 46 or more non-ASCII characters overflows its slot and loses its `detail`. A severity that flaps every tick costs up to 20 rows an hour, where ops-watch, which holds a downgrade for two runs, writes about none. A refresh posts no ticket comment. Only rows that `ah owners` marks as owners raise anything, so helpers never alert.

If ahd cannot read a session's owners, it does not clear that session's liveness alerts. A missing `ah` verb is skipped for 10 min and logged once.

**Clock.** Each tick compares the wall-clock delta with the monotonic delta. If they differ by more than 5 min, ahd logs `clock:jump` and holds liveness transitions for 1 tick. Clears still go through.

**Memory.** All daemon reads go through `safe_read`, which uses `O_NOFOLLOW` and `O_NONBLOCK`, accepts regular files only and caps the size. `run_cmd` caps each child's output at 32 MiB and then kills its process group. The systemd unit sets `MemoryMax=1G` and `MemorySwapMax=0`. launchd has no equivalent, so on the Mac the daemon runs `memory_guard`, which exits with code 70 once peak RSS passes `memory_cap_bytes`. It polls every 2 s, so it is a backstop and not a hard limit, and it does not cover `ah` children. ops-watch's footprint alert is the second backstop.

**Unsafe WALs.** `ah owners` reads a session's main and task WALs. A session with a WAL over `owners_wal_max_bytes` (256 MiB), or one that isn't a regular file, is not passed to `ah`. Its liveness alerts are held, and `wal:unsafe:<session8>` raises at high, so that session is visibly unmonitored. Every owner in that session loses liveness until the WAL shrinks; a per-WAL exclusion is planned.

**Testing rule.** Run known-bad code and resource-abuse fixtures (`/dev/zero`, floods, FIFOs) only on dev2 or its successor, under `systemd-run --user --scope -p MemoryMax=2G -p MemorySwapMax=0` and `timeout`. Never run them on the Mac. A 2026 test run on the Mac without a limit reached a 75.9 GB footprint.

**Full disk.** `ah` refuses a durable write (exit 3), and ahd logs it and carries on. A failing log write never escapes a step (`logging.raiseExceptions = False`), and no step failure stops the loop.

## Peek

`harness/hooks/ahd_peek.py` is the backend for `ah peek`. It is read-only.

- **`list`** stats Claude sessions (`~/.claude/projects/*/<session>.jsonl`), subagents (`.../subagents/agent-*.jsonl` and `.meta.json`) and Codex rollouts. It never opens a transcript to do this.
- **`tail <id> [-n N] [-f]`** reads at most `peek_tail_max_bytes` (4 MiB) from the end of the file:
  - It skips malformed lines, over-long lines (over 1 MiB) and a half-written last line, and counts each.
  - It renders tool calls (name plus a summary of the input), results and messages, all through `redact.py`. Without `redact.py` it prints no free text.
  - Follow mode restarts at offset 0 when the inode changes or the file shrinks.

**Interview material is never read, shown or stored.** The `exclude` table in `ahd_policy.json` sets the rule:

- Token prefixes `solve` and `interview`, plus the Interview Pilot paths and the VM 108 host names. These are matched against the path, the resolved path, the project dir, the agent description, any record's `cwd`, and the host.
- Such an instance is listed as `excluded` with its id and age only, and tail refuses it.
- Any rendered item naming such material is blanked.
- Classification fails closed: a missing policy, a relative path, a path outside the transcript roots, or a symlink out of them counts as excluded.
- The per-host `~/.agent-harness/ahd.json` may add exclusions but never remove one.

## Run, test, stop

```
python3 ~/.claude/hooks/ahd.py --once            # one tick in the foreground, JSON summary
python3 ~/.claude/hooks/ahd.py report            # one tick, then the dropped / silent / unowned / waiting-on-user lists
python3 ~/.claude/hooks/ahd_peek.py list [--all] [--json]
python3 ~/.claude/hooks/ahd_peek.py tail c:<agent-id> -n 30 [-f]
python3 ~/.claude/hooks/ahd.py install [--apply]  # launchd com.ericmacdougall.ahd / systemd --user ahd.service
tail -f ~/.agent-harness/logs/ahd.log
launchctl bootout gui/$(id -u)/com.ericmacdougall.ahd     # stop (macOS)
systemctl --user disable --now ahd.service                # stop (Linux)
python3 -m unittest tests.test_ahd tests.test_ahd_peek
```
