# Workspace janitor

`harness/hooks/workspace_janitor.py` keeps agent and runner checkouts from piling up (t2-dev reached 0 bytes free on
2026-11-21 with 117 GB of per-session copies, 50 GB of scratch in /dev/shm and ~895k OOM kills from uncapped test
containers). It complements `test_copies.py` (one test copy per PR, disk floor, report-only reaper).

| Piece | What it does |
|---|---|
| `checkout --url U --key K [--ref R]` | One bare partial mirror per repo under `~/.agent-harness/mirrors/`, one linked worktree per (repo, key) under `~/.agent-harness/checkouts/`. Reused on the next call; moved to R only when clean. Use a PR number or lane as the key. |
| `SessionEnd` hook (`session-end`) | Releases `~/.agent-harness/work/<session_id>`: removes each checkout that is clean, has no untracked files, no stash, every commit on a remote ref, no other linked worktrees, nothing open, and no service reference. The folder goes when only rebuildable folders remain. Never blocks. |
| `release --session ID / --path DIR [--apply]` | The same for a runner job's folder; call it at the end of every job. Dry run without `--apply`. |
| `sweep --apply` (hourly timer) | `release` for every work folder and checkout idle longer than `ttl_hours` (24); removes the user's own `/dev/shm` entries idle longer than `shm_ttl_hours` (6) that nothing holds open; lists running containers with no memory limit. |
| `pretool` hook | Refuses `docker run/create` without `--memory`/`-m`, and Elasticsearch/OpenSearch without `ES_JAVA_OPTS`/`OPENSEARCH_JAVA_OPTS`. Fails open. |

Protected always: anything a process has open or works in; paths named by systemd units (system and user), crontabs,
docker mounts/compose dirs and launchd plists (earlier cleanups removed folders that live services ran from); names in
`protect_names` (yates, optinrouter). `HARNESS_JANITOR=off` turns every removal into a report.

Install the timer on Linux hosts:

```
mkdir -p ~/.config/systemd/user
cp harness/systemd/agent-harness-janitor.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now agent-harness-janitor.timer
```

Config: `~/.agent-harness/state/workspace-janitor.json` (`ttl_hours`, `shm_ttl_hours`, `work_roots`, `protect_names`,
`default_memory`). Audit log: `~/.agent-harness/state/workspace-janitor.jsonl`.
