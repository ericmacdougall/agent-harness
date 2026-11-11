# Changelog

Newest first. Flaws and their fixes are described plainly here and in
[docs/FINDINGS.md](docs/FINDINGS.md). This project has no tagged releases yet; entries
group by pull request.

## Unreleased

### Fixed
- kill_guard false positive (goodqa#15365): a path glob in argument position of an ssh remote command (`ssh host 'ls tools/x/*'`) is no longer read as the command name `*` and refused as `[broad-kill]`. A glob in command position, and every real kill through ssh, still block. Tests: `python3 -m unittest tests.test_kill_guard_ssh_glob`.
- merge gate false positives (goodqa#15122): `git push gh <sha>:refs/heads/<feature>` (a remote named gh) is no longer read as a gh call; read-only gh calls whose words come from a literal variable in the same command pass; the subagent exception-record block allows only known free-text forms (notes through the harness helpers, commit messages, ticket bodies, print and search commands) and keeps the old text rule for every other program; any builtin that can assign (`printf -v`, `declare -n`, `trap`, `read`) makes literal variables unknown; pushes to `heads/main`, through `xargs`, or with alias or push config on the command line block. New: a `git push` to main or master, `--all`, `--mirror` or a destination built at run time blocks.
- command_guard false positive (goodqa#15122): removing or overwriting a command's own `mktemp` file, also with TMPDIR relocated under the harness and from a script file, is no longer refused as a protected harness directory; WAL and transcript deletes through a variable, a reassigned temp variable, a symlink or a TMPDIR pointing at protected logs stay blocked.
- log-backup bulk lane yields to tier 1 (goodqa#15147): the lane no longer splits the write budget. While a tier-1 run holds the run lock it makes no copy requests; a copy in flight stops within one poll plus the stop grace and its 300-file chunk is sent again whole, the cursor unchanged. Tier 1 always copies at the full rate. The plist ships the lane off until three tier-1 runs in a row finish inside the budget.
- log-backup bulk lane: on the Mac the bulk tier now runs as its own detached run beside tier 1, on a split of the
  same 2/s write budget, instead of in the few minutes tier 1 left (about 400 files an hour). Bulk chunks are 1000
  files. A pass is listed again when the exclude lists change, and five verified `.lanes` copies (about 230k files)
  are excluded with a pinned tag and a backed-up manifest (goodqa#15062).
- log-backup bulk lane review (PR #124): runs that share their 13 minutes keep 100-file chunks and every chunk fits
  the time left; the rate is split whenever a lane is live; an unsplittable limit turns the lane off instead of
  stopping every backup; the lane starts only when due and is confirmed; SIGTERM stops a run's own copy; opting out
  stops the lane; status shows it; the lane has its own log; exclude edits stop a pass at the next chunk.
- log-backup bulk tier: a pass now resumes from a checkpoint instead of starting over every run. With the 620k-file
  work tree, each run re-checked the same first files and the pass never finished. Files verified by an earlier pass
  are not checked again, and only new or changed files are sent (goodqa#15062).

### Added
- Codex owner supervisor (GoodQA #15565): `harness/bin/codex_owner.py`, installed by `install_codex.py --apply` as `~/.codex/agent-harness/codex_owner.py`, runs long-lived Codex owners on the ChatGPT subscription (`start`, `send`, `status [--json]`, `log`, `stop`, `restart`, `vet`). Owners run in yolo mode by default (the user: "codex owners should run with yolo mode but still obey the harness"): `--dangerously-bypass-approvals-and-sandbox` plus `--dangerously-bypass-hook-trust`, both added only after the per-turn hook vet passes; a failed vet starts no child and leaves the owner BLOCKED. `codex exec resume` rejects `-s` and `--add-dir`, so resumes never pass them (turn 2 used to fail with rc 2); `--no-yolo` sandboxes the first turn with `-s workspace-write` and the owner's own WAL and work dirs plus allowlisted `--add-dir` entries. The vet: every `hooks.json` command runs a python file in the harness dir (full match), `python3` on the child's fixed PATH is not writable by others, the Codex home, `hooks.json`, the harness dir and the hook files are user-owned, single-linked and not group- or world-writable, `config.toml` holds no hook tables, plugins carry no command hooks, and the owner's project has no `.codex` hooks. The strict vet (the default when the new `~/.codex/agent-harness/install-manifest.json` exists; `--no-strict-vet` warns every turn) checks every installed file's sha256 and refuses unlisted `.py` files. After every turn the supervisor fingerprints the harness files again; a change blocks the owner with an ALERT until `restart`. Authoritative config lives in a supervisor-owned control dir read only at start (`status.json` is output only); inbox messages are HMAC-signed with nonce replay protection and forged files never reset the auto-turn bound; STOP is latched; the lock inode is re-checked; the child env is an allowlist (`--env`, `--allow-secret-env`); signals terminate the running child. `install_codex.py --apply` ends with a `codex:trust` report (ops_watch's algorithm; never writes `trusted_hash`; never crashes the install). Residual: a yolo owner can rewrite hooks mid-turn; the guards still run per command and the supervisor detects it after the turn only. Tests: `python3 -m unittest tests.test_codex_owner`, `python3.13 -m unittest tests.test_install_codex`.
- ops_watch `remote_units`: a read-only ssh check of a timer job on another host (for example t2-blog-drip on
  t2-dev). It alerts when the last run failed, when there has been no success within `max_age_h` (26 h), or when
  the unit is missing or its timer is stopped (goodqa#15070).
- command_guard `approve-delete --archive/--archive-sha256/--archive-listing`: approve a delete from one verified remote tar
  archive (.tar, .tar.gz or .tar.zst) when a file-by-file mirror is too slow; the guard streams and checks the archive
  itself (goodqa#15068).
- Heavy work off the Mac (goodqa#14817, P12). `heavy_job_guard.py` has a `copy` rule: cp, rsync, tar, ditto,
  `git clone`, `gh repo clone` and `git worktree add` are sized (bounded walk, `ssh du`, GitHub repo size) and
  refused at 1 GiB (`HARNESS_COPY_GIB`), unknown size counting as heavy. `HARNESS_LOCAL_OK` is limited to one use
  per owner per hour (`HARNESS_HATCH_PER_HOUR`), audited to the WAL and the alert ring (source `heavy-guard`), and
  never applies to a large copy above 85% disk. `ops_watch.py` gives each `work/<session>/<sub>` owner a 5 GiB disk
  budget (kit `disk_budget_gib` up to 20), alerts `disk:owner:<agent>` by name and writes
  `state/disk-budget/<agent>.json`; an over-budget owner cannot start a heavy copy. Nothing is killed or deleted.
  `install_codex.py` installs the guard for Codex (trust it in Codex `/hooks`).
- Heavy families off the Mac (goodqa#14817). `heavy_job_guard.py` now denies package installs (pnpm/npm/yarn/bun),
  replay/synthetic/stress/soak scripts and `k6 run`, docker/podman run, pull and compose up (remote engines are
  allowed), and backgrounded or looped `claude -p` (unquoted `&` only; the cap plus `HARNESS_LOCAL_OK` is the
  escape). `xargs -P` and `parallel` fan-out is enforced too. Each denial prints a runnable route: copy the
  checkout, then `ssh HOST bash -lc '<whole command>'`. Default host `t2-dev` (`HARNESS_ROUTE_HOST`); headless
  claude goes to `dev2` (`HARNESS_CLAUDE_ROUTE_HOST`) because claude is not logged in on t2-dev. Not covered:
  pip/uv/bundle installs, `codex exec`, `claude -p` in nested shells. `exempt_hosts` in `heavy_job_guard.json`
  switches the guard off on a heavy-work host such as the Mac mini.
- Dropbox upload lane (goodqa#14817). `heavy_job_guard.py` rule `dropbox-lane` (enforce) refuses an agent
  `rclone copy|copyto|sync|move|moveto|bisync` to a Dropbox remote (type from `rclone listremotes --long`, never the
  config file) without `--tpslimit` of at most 4, with more than 4 `--transfers`, or while another agent upload to
  Dropbox runs. The launchd log backup is never the lane holder. Dry runs, downloads and listings are allowed;
  `HARNESS_LOCAL_OK` applies. Two parallel unthrottled uploads stalled the log backup for 6 h on 2026-11-07.
- `command_guard.py`: `rm` of a top-level git clone needs no Dropbox backup when git proves it clean, with nothing
  untracked, and every local commit reachable from a remote-tracking ref that matches the live remote
  (`reproducible_clone` policy). Any doubt keeps the existing approve-delete rule.
- `scripts/leak_scan.py`: scans tracked files (or history with `--history [--range]`) for
  tokens, private keys, real home-directory names, private and shared-address-space (RFC 6598) addresses,
  tailnet names and a local denylist. It never prints a matched value, and exits 2 if
  nothing was scanned. Fixture paths with deliberately fake tokens go in `.leakscan-allow`.
- `commit_policy.local.json` overlay: personal values (org, repos, key location) are
  read from an untracked file beside `commit_policy.json`; `.example` shipped.
- `CHANGELOG.md` and `docs/FINDINGS.md`.

### Changed
- `commit_policy.json` is generic: no org id, secret name, project or owner-specific repo
  pattern. **Behaviour change:** with no local profile, ticket checks and the commit-msg
  backstop apply to no repository. Existing installs must add their local profile.
- `spec_policy.local.json` overlay (same rules): GoodQA project routing and `enforced_projects` moved out of
  the tracked `spec_policy.json`. **Behaviour change:** with no local spec profile, spec project routing is empty.
  `install.py` now reports a missing profile. `AGENT_HARNESS_POLICY_LOCAL` only works for files under `tests/data`.
- Test fixtures and docs no longer contain a real private address, username, or home path.

### Fixed
- heavy_job_guard: the per-owner disk-budget block now judges the owner dir a copy writes into (its destination,
  or the cwd after `cd`), not the session cwd, and its message keeps the copy rule's reason. The Mac mini
  (`ah-mac-mini`) is in the default measured fleet, so a small download from it is sized instead of counted as
  heavy (goodqa#15067).
- Removed a real Tailscale-range address and hostname from a test in HEAD (F-008). Git
  history still contains it; it was not rewritten.

### Known gaps (not fixed in this entry)
- Windows install and hooks are untested and `wal.py` imports `fcntl` (breaks on Windows).
- Command guard, kill guard and merge gate are not yet part of the shipped installer.
