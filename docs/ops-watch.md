# ops-watch

`harness/hooks/ops_watch.py` is a small, read-only watcher (GoodQA goodqa#14591). It runs every 10 minutes on each host: launchd `com.ericmacdougall.ops-watch` on the Mac, and the systemd user units `ops-watch.timer` and `ops-watch.service` on Linux. It is a stopgap: the G10 resource observer (goodqa#14548) and netwatch I4 will take over its checks, and they will keep writing to the same alert file.

It never deletes, kills, reclaims or writes Codex trust. It writes only its own state, the alert ring and a heartbeat. The one process it ends is its own `du` child, when that child runs past its timeout.

## Checks

| Check | Key(s) | Severity | Fires when |
|---|---|---|---|
| disk | `disk:volume:<path>` | warning / high / critical | 85 / 92 / 97 % used, or less than `free_floor_gib` (10) free ; on macOS the Data volume `/System/Volumes/Data` is read first, since `/` is the sealed system volume |
| disk | `disk:growth` | high | a measured dir, or the volume itself, grows by 10 GiB/h or more; names the top three growers |
| disk | `disk:unmeasured` | warning | a dir keeps timing out under `du` and cannot be split further |
| units (Linux) | `units:failed` | high | failed user units (transient `run-*.scope` excluded) |
| units (Linux) | `reclaim:<unit>` | high | a watched reclaim job's last run failed, its timer is inactive, or its last invocation logged `failed` lines |
| crashes (macOS) | `crashes` | warning; high for python SIGKILL or sandbox SIGKILL | `.ips` reports newer than the last run, kept for 6 h; only process name, pid, parent and time are reported |
| processes | `procs:orphans`, `procs:runaway`, `procs:chrome-helpers`, `procs:shells` | warning / high | `netwatch orphans --json` (pid/name/age/rss/cpu only, never cmd), and Chrome and shell counts over their limits |
| processes | `procs:agent-spawned` | warning | shells over 100 or ssh clients over 60 whose ancestry reaches a `claude` or `codex` process (one `ps` snapshot) |
| processes | `mem:swap`, `mem:pressure` | warning; high at macOS pressure level 4 | swap over 70 % (macOS `vm.swapusage`, Linux `/proc/meminfo`); macOS `kern.memorystatus_vm_pressure_level` 2 or 4 |
| processes | `procs:heavy-suite` | warning | on a no-heavy-jobs host (the Mac by default): `unittest discover`, `pytest` or `gradle test` processes; only the pid and suite kind are reported |
| delivery | `delivery:<path>` | high | a configured delivery checkout is missing, not on `main`, or dirty (`GIT_OPTIONAL_LOCKS=0`) |
| drift | `drift:claude-md`, `drift:hooks` | warning | the CLAUDE.md managed block differs from `HARNESS.md` at `origin/main`, or an installed hook's git blob hash differs from main |
| codex | `codex:trust` | high | a `~/.codex/hooks.json` handler has no `[hooks.state]` trust entry or a stale `trusted_hash`: "Codex is skipping harness hooks" |
| liveness | `liveness:<session8>/<task>` | From the shared rule for owners; warning or high for task WALs | Fires as "owner silent: ...", "owner dropped: ..." or "owner ticket quiet: ...".<br>**Sub-agent owners** use `ah.owners` and `liveness.py`, the same rule as `ah owners`. Silent at 30 min is a warning and at 60 min is high. A stop with no handoff, result or named wait becomes DROPPED (high) only after a 30-minute grace (`FINISH_GRACE_S`). Any WAL or transcript activity after a stop cancels the stop. Types other than `task-owner` count only when registered or named by main, so a helper that returns its result is not a drop. Alerts carry ids and tickets, never task text.<br>**Task WALs** (`<session>/<task>.jsonl`) warn after 60 min of silence. They retire, with no alert, on any `handoff`, `result`, `done` or `delivered` event, a `WORKDIR_DONE:` or `DELIVERED:` status, a blocker naming its wait, or a closed ticket. Silence alone stops warning after 6 h. That limit applies only to named task WALs: an open quiet ticket still raises high until the WAL has been idle for 24 h, and sub-agent owners never retire this way.<br>**Ticket quiet:** an open GoodQA ticket with no comment for 3 h is high, or a warning when its owner is still running. The Mac checks this through `gq.py`, at most 10 lookups and 90 s per run, cached for 30 min.<br>**History:** a session idle for 24 h is ignored, or for 7 days when it still has an active alert. A clear means the owner moved, ended or retired, not that anyone resumed the work.<br>**Display:** the prompt context folds all liveness alerts into one entry per host. |
| ops-watch | `ops-watch:sink:<name>`, `ops-watch:check-error:<check>`, `ops-watch:internal-error` | warning / high | a sink cannot deliver (cleared when it recovers), a check raised an exception (its existing alerts are kept), or the run crashed |
| peers | `peer:<host>:unreachable`, `peer:<host>:stale` | warning | a configured peer's `active.json` cannot be read, or that peer's watcher has not run for 30 min |

Disk sizes come from `du -skx`, run round-robin with the least recently tried dir first, inside a 90 s budget per run and with 60 s per dir. A dir that times out is split into its children on later runs, up to depth 2 and at most 200 children. A dir that cannot be split is reported as unmeasured. Growth is computed from two measurements of the same dir taken between 10 min and 6 h apart.

The Codex trust hash is the sha256 of the sorted-key, compact JSON of `{"event_name": <snake_case event>, "hooks": [handler with async defaulting to false, and only type, command, timeout, async and statusMessage kept], "matcher"?}`. That follows the sidekick crate's mirror of codex-rs hook discovery, and it was checked against live trusted entries on the Mac and dev2 (the dev2 entry carries extra, unhashed fields). Groups with a `matcher` have not been checked against a live entry.

### Per-process memory (`footprint` check)

- `mem:footprint:<pid>`: warning at 8 GiB, critical at 20 GiB, and warning when a process of at least 2 GiB grows 20 GiB/h or faster between runs. macOS reads the MEM column of `top` (physical footprint), because RSS read 4.9 MB for a 76 GB orphan. Linux reads RSS from `ps`. The alert names the pid, the cwd and the owner: the user, the task taken from the cwd, and whether the process is an orphan.
- `mem:jetsam`: JetsamEvent reports in `/Library/Logs/DiagnosticReports` in the last hour: warning at 1, high at 3. Only file names and times are read.
- This check only reports. To stop a process, use `netwatch orphans --kill --pid <pid>`, or the process's owner. With a 10-minute cadence, a fast runaway can do damage between runs.

### Comment rate and uninstall

Each host posts at most one digest comment per 30 minutes (`sinks.comment_min_interval_s`). A digest holds the latest transition per key. Stop and remove the timer with `ops_watch.py uninstall --apply`; unit files move to `~/.agent-harness/state/ops-watch/uninstalled/`, and the ring and state stay.

An active alert's ring entry follows its condition. When the words change, ops-watch rewrites the entry at most every 5 minutes; when only numbers change, at most hourly. A rewrite is a `raise` with `detail.updated`, and it adds nothing to digests or deadman mail. `liveness.alert_text_stale` is the rule, shared with ahd.

Alert text is redacted when written to the ring and again when injected. The context line neutralizes instruction words, and a peer's alerts appear there as severity, host and key only.

## Alert path (canonical)

`~/.agent-harness/state/alerts.jsonl` is a preallocated ring of 1024 slots of 1024 bytes each. Every slot is one JSON object padded with spaces, followed by `\n`. Empty slots read `{"empty":true}`.

- **Writing:** producers call `ops_watch.emit(event)`, or run `ops_watch.py emit --json '<event>'`.
- **Locking:** under `flock` on `alerts.lock`, `seq` is set to the highest seq in the ring plus 1, and the event goes into slot `seq % 1024`, overwriting the oldest. The write is an in-place `pwrite` followed by `fsync`, so the file never grows and the write works on a full disk.
- **Fields:** `schema` (1), `seq`, `at` (RFC 3339 UTC), `host`, `source`, `event` (`raise` or `clear`), `severity` (`info`, `warning`, `high` or `critical`), `key`, `message` and `detail`. The required ones are host, source, event, severity, key and message. When an event is too big for a slot, `detail` is dropped, and if it still doesn't fit, `message` is truncated.
- **Semantics:** the ring holds transitions only. A producer raises once per (host, source, key), raises again when the severity changes or to refresh the text (`detail.updated`), and clears once. ops-watch applies a downgrade only after it holds for two runs, so a value hovering at a threshold does not flap, and the downgrade then replaces the stale message. If ops-watch loses its state, it treats its own active raises in the ring as already raised, so they still clear.
- **Active alerts:** an alert is active when the latest event for its key is a `raise`.
- **Reassertion:** a producer whose raise has been overwritten by the ring wrapping must re-emit it with `detail.reasserted=true`. ops-watch does this every run.

`wal.py` adds `ops_watch.injection_text()` to the SessionStart, UserPromptSubmit and SubagentStart context. It reads only regular files, without blocking and with a size cap. It never raises, and it is empty when nothing is active. Alert text is reduced to a safe character set and labelled as data, not instructions. On the Mac it also includes the peers' active alerts, read from each peer's `~/.agent-harness/state/ops-watch/active.json` over ssh.

## Delivery of transitions

1. The ring, as described above.
2. One GoodQA comment per run on goodqa#14592. `sinks.comment` may be a list that is tried in order, so t2-dev can relay through `ssh <mac> python3 ~/.claude/hooks/ops_watch.py relay-comment` until its own goodqa CLI is installed. That relay only ever posts to #14592.
   - The Mac uses `gq.py comment_on_issue` with an idempotent `operationId`.
   - Linux uses the `goodqa ticket comment` CLI.
3. The deadman alert script, for critical raises only. Each command in `sinks.deadman` is tried in order until one succeeds.

Each run saves its transitions to the ring and to state before calling any slow sink. Comments are posted in chunks of about 7000 characters. The chunk in flight is pinned in state and re-sent byte for byte until it succeeds, so a lost response retries the same uuid5 `operationId` and never posts a duplicate. When no deadman command is configured, nothing is queued for it. On Linux, give the goodqa CLI as `~/.local/bin/goodqa`; ops-watch expands the program path, because systemd's user PATH does not include `~/.local/bin`. A run makes at most 3 deadman attempts and sends at most one deadman mail per key every 6 h, and every sink is bounded by a 420 s deadline per run. When a sink fails, its transitions stay queued and are retried on the next run. The run raises `ops-watch:sink:<name>`, writes the failure to stderr and exits 2. On a fully successful run, ops-watch touches `~/.agent-harness/logs/ops-watch.last-ok`. The deadman config watches that file as the markers `t2-ops-watch` and `mac-ops-watch`, so a dead watcher still sends an email.

State lives in `~/.agent-harness/state/ops-watch/state.json`, which has two fixed 512 KiB slots written alternately in place.

## Configure, install, run

Per-host settings go in `~/.agent-harness/ops-watch.json`. Every key is optional and is merged over the defaults; `python3 ops_watch.py config` prints the effective config.

```json
{"delivery": ["~/repos/bugtracker-delivery2"],
 "drift": {"repo": "~/repos/agent-harness"},
 "peers": ["dev2", "t2-dev"],
 "remote_units": [{"host": "t2-dev", "unit": "t2-blog-drip", "user": true, "max_age_h": 26}],
 "sinks": {"comment": {"mode": "gq"},
           "deadman": [["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "t2-dev",
                        "~/.agent-harness/bin/deadman-alert.sh '{SUBJECT}'"]]}}
```

```
python3 ~/.claude/hooks/ops_watch.py install           # dry run
python3 ~/.claude/hooks/ops_watch.py install --apply   # launchd or systemd --user, every 10 min, nice 19, idle IO
                                                       # (units point at this file: run it from the installed copy)
python3 ~/.claude/hooks/ops_watch.py run               # one run now
python3 ~/.claude/hooks/ops_watch.py status            # active alerts, peers, queued deliveries
tail ~/.agent-harness/logs/ops-watch.err               # macOS; Linux: journalctl --user -u ops-watch
launchctl bootout gui/$(id -u)/com.ericmacdougall.ops-watch   # stop (macOS)
systemctl --user disable --now ops-watch.timer                # stop (Linux)
```

`remote_units` (goodqa#15070) watches a oneshot timer job on another host. The check makes one read-only, bounded call per entry: `ssh -o BatchMode=yes -o ConnectTimeout=5 HOST systemctl [--user] show UNIT.service UNIT.timer`, with 20 s in total. It never starts, stops or resets anything there. It raises these alerts:

- `:failed` (high): the last run failed. `Result=success` is trusted, so a `SuccessExitStatus` exit code is not a failure.
- `:stale` (high): there has been no success within `max_age_h`. With no stored success, the age is counted from when the timer started only if the service has never started; otherwise the check waits until it sees a success.
- `:missing` (high): the service is not installed.
- `:timer` (high): the timer is not active.
- `:unreachable` (warning): the host cannot be read for 30 min. While a read fails, the alerts from the last good read are kept, so they are neither cleared nor raised again.

Host and unit names must be plain words, and `max_age_h` must be a finite positive number; any other entry is refused as `:config` and never reaches ssh.

`proxmox_pools` (goodqa#15771) watches the capacity of a dir-type Proxmox storage pool whose thin guest disks can fill it. It is empty by default; enable it per host in `ops-watch.json`:

```json
{"proxmox_pools": [{"host": "root@t2-proxmox", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}]}
```

Each run makes one read-only call: `ssh -o BatchMode=yes -o ConnectTimeout=5 -- HOST SCRIPT` with 25 s in total. The script is fixed text, each command under a remote `timeout` (3 to 8 s): `pvesm status --storage STORAGE`, `qm list` and `qm config` for every VM (config files only, needed for the overcommit total), and `du -sk` of the watched VMs image directories only. ssh runs with `-n`, `StrictHostKeyChecking=yes` and no ControlMaster, so the host key must already be in known_hosts. The host may carry a login (`root@t2-proxmox`: the hypervisor admits root only); alerts show the host without it. Host, storage and mount are checked against plain-word patterns and VM ids must be integers, so a bad entry is refused as `disk:config:...` before ssh. Nothing changes on the hypervisor. Alerts (key suffix `HOST:MOUNT`):

- `disk:volume:` warning at 85% used, high at 92%, critical at 97% or under 20 GiB free. The overcommit ratio is reported in this alert and not alerted on its own: it is a standing condition, decided by the disk options in goodqa#15771. The detail holds `overcommit_ratio` (disk sizes on this storage over pool total), `provisioned_gib`, and for each watched VM `allocated_gib`, `actual_gib` (du of its image dir) and `growth_gib_day`.
- `disk:growth:` more than 10 GiB/day, measured against the stored sample 6 to 48 h old that is closest to 24 h (samples every 30 min, kept 48 h, from good reads only). High when the pool would fill within 3 days at that rate, else warning.
- `disk:vmunknown:` (warning) a watched VM has no config or disk usage in the probe, so a partial read cannot pass silently even below every threshold.
- `disk:unknown:` UNKNOWN: the host cannot be reached or the output is unusable (missing marker, inactive storage, non-numeric or inconsistent numbers). Warning at first, high after 30 min without a good read. The last good alerts stay active meanwhile, so an outage is never green. Alert text never carries remote output or addresses, only the configured host name.

Tests: `python3 -m unittest tests.test_ops_watch_proxmox`.

Tests: `python3 -m unittest tests.test_ops_watch`.
