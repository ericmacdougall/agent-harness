# Changelog

Newest first. Flaws and their fixes are described plainly here and in
[docs/FINDINGS.md](docs/FINDINGS.md). This project has no tagged releases yet; entries
group by pull request.

## Unreleased

### Added
- `ah chat probe|conversations|history|files` (goodqa#16396), read only: an agent session reads your own GoodQA chat through one reviewed path (`harness/hooks/ah_chat.py`) and two separate credentials with no fallback between them. Reads of private messages use a dedicated `~/.config/goodqa/dm-read-token` (abilities `read` + `chat.dm.read`, minted by you); `probe` and a non-DM `files` surface use the user token. Tokens are read in-process only (`O_NOFOLLOW`, `O_NONBLOCK`, at most 4097 bytes); a DM command never opens the user-token file, not even to screen output, go only to `https://goodqa.app/v1/mcp` (the base is fixed: `--base` and `browser-defaults.json` cannot move it, except a loopback test base under `GQ_BROWSER_TEST_LOOPBACK=1` that never takes a token from the real token path or one shaped like a real user token; no redirects, no proxies), and are never printed, logged or put on a command line. Server error bodies are never shown, and error text holding a screened token or a secret shape is withheld. Every third-party string that is printed (message text, previews, names, file names, `with_name`, `--no-text` values, the probe's server strings) goes through one screen, the union of `redact.py`'s shapes and `gq_browser.SECRET_SHAPES` (GoodQA user tokens and keys and DigitalOcean tokens included), before it is printed (the row carries `redacted: true`). Ids from argv, the defaults file or the server are fullmatched and screened before any request or audit row. Reads are wrapped `untrusted: true` and audited without text. Every read output is an allow-list of fields, with one file-metadata list for every surface (`chat`, `issue`, `personal`); nested objects it does not name and link-shaped values are dropped. An `ah chat` argument that argparse rejects is answered with one fixed refusal on stdout (exit 2) that repeats no value and writes nothing to stderr; `-h` still works. `history` (both forms), `conversations` and `files --surface chat` need the three GoodQA tools, which are deployed on goodqa.app (2c3e16cba59d) but offered only to a dedicated DM-read token with the `userTokens.dmRead` setting on (off by default), and fail with `unsupported` until then; `history --with` makes the same check, because its server tool answers a ungated token with an empty list (never an empty result); the message names both causes, a server without the feature or a token that is not a dedicated DM-read token (`chat.dm.read`, `userTokens.dmRead` on, an org limit, expiry within 30 days). Output follows the server shapes: participants `id`+`name`, author label `kind`+`display`, a bounded `lastMessage` preview on conversation rows, and one page per call with the envelope surfaced (`has_more`/`next_cursor` with `conversations --cursor`, `next_offset` with `files --offset`, `found_oldest`/`found_newest`/`head_seq` with `history --before`); live reading was verified on goodqa.app build 2c3e16cba59d with a dedicated DM-read token for `probe`, `conversations`, `history --conversation` (with paging back) and an empty `files` result, plus a `not_found`, a refused base and a token without the DM ability; file metadata, `history --with` and the setting-off case were not covered (see "Verified live" in docs/ah-chat.md). `ah chat send` is not in this build: it answers `not_available` (exit 2) before anything is parsed, imported, read or sent, and sending is deferred to goodqa#16399 (it needs a server delivery contract and server-side DM dedupe). `command_guard`: the credential path rule for `user-token` now also names `dm-read-token` (one regex and one sample). See [docs/ah-chat.md](docs/ah-chat.md). Tests: `python3 -I tests/test_ah_chat.py`, `python3 -I tests/test_command_guard_ah_chat.py`, failing-first `python3 -B tests/mutants_ah_chat.py`.
- gq_browser machine verbs (goodqa#16051): `gq_browser.py machine open|shot|click|type|key|renew|close|list` and the `gq_machine_*` MCP tools drive GoodQA remote control of your own enrolled machine. They use the user token through the same in-process read, against only the routes the #15941 enrollment grant opens; they mint no key and create no grant. Commands always name the tool's own lease (never autoLease or takeOver), and a 403 or 404 is surfaced, never widened. Screenshots are saved with a UTC timestamp and machine id and tracked in `shots.jsonl`. `type` refuses the token and secret shapes. SIGINT and SIGTERM cancel and release; SIGKILL is bounded by the 300 s lease TTL. A lease is marked closed only on a positive end signal (a release naming it released, or `lease_ended`); any other answer keeps it in `machine list --orphans` for `close` to retry. Server values reach output only through fixed local schemas, and every CLI and MCP output is withheld if it holds the token or a key. See [docs/gq-browser.md](docs/gq-browser.md). `allowedMachines` is required (fail closed). Tests: `python3 -I tests/test_gq_machine.py`.
- ops-watch `proxmox_pools` check (goodqa#15771): read-only capacity alert (85/92/97 percent, 20 GiB floor, growth, overcommit, VM 102/103 growth) for a Proxmox pool; UNKNOWN when it cannot be read. Tests: `python3 -m unittest tests.test_ops_watch_proxmox`.
- Mission Control (goodqa#15585): a local, read-only, realtime dashboard of the agent fleet, with initiative progress, each owner's last work item, pulses for WAL writes, pushes, releases, deploys and ticket checkpoints, and chat with Claude main or Codex. It is bound to 127.0.0.1 behind a single-use launch link, and it runs as the LaunchAgent `com.agent-harness.mission-control`, installed by `install.py --apply` (`--no-mission-control` opts out). See [docs/mission-control.md](docs/mission-control.md). Tests: `python3 -m unittest tests.test_mission_control tests.test_mission_control_install tests.test_mc_inbox`.

### Fixed
- peer_review isolation false refusal (goodqa#16271): `peer_review.py pr` on a large clean checkout (bugtracker, 62k entries) no longer fails `ISOLATION_FAILED` "refused a special or unstable entry" when the host is loaded. The cause was the source-side metadata scan's fixed 5 s deadline (12 concurrent scans on the Mac: 11 of 12 refused at 5.00 s), reported with the same message as a special file. It was not the tracked symlink. The scan budget is now 5 s plus 0.5 ms per tracked index entry, still capped at 250000 entries (worst case 130 s), and the three refusals are distinct. `exceeded limits` (time, entry or depth budget, or a Git listing budget) is the new code `WORKTREE_SCAN_LIMIT`. A FIFO, socket, device or snapshot symlink is `WORKTREE_SPECIAL_ENTRY`. An entry that changed or could not be read keeps `ISOLATION_FAILED`, now with its errno. A partial clone is now refused as `SNAPSHOT_PARTIAL_CLONE` before the source inspection. The snapshot also pins `core.symlinks=false` in its own config, so a reviewer's Git without the helper's environment (`checkout`, `reset`, `stash`) can no longer turn a committed symlink into a real one. Tests: `python3 -B -m unittest tests.test_review_diagnostics.WorktreeScanTests`.
- kill_guard false positive (goodqa#16124): a kill word only inside the test path of an exact test-runner line is no longer refused as `[script-kill]`, for example the QAC run kit's `python3 lanes/pgpool.py run --job N --lane qac-b1 --ttl 1500 --mode server -- ~/qacp-work/fable-b1/dbtest-any.sh WT LOG test/qac-kill-switch-ceiling.test.ts [-t NAME]`. The exemption is an allowlist (PR 265 rescue: two reviews found runner scripts escaping heuristic versions). The whole interpreter command must be `python3 [-I|-u|-B] lanes/pgpool.py run [--job|--lane|--ttl|--mode|--template|--database V]... -- INNER` (INNER is `[/abs/|~/]dbtest-any.sh WT LOG TEST [-t NAME]`, `npx [-y] vitest run TEST...` or `pnpm --filter PKG exec vitest run TEST...`), `python3 [-I|-u|-B] -m pytest TEST...` or `node --test TEST...`. TEST must be a plain relative path word with no empty, `.` or `..` component, under a `test/`, `tests/` or `__tests__/` directory, with a test-shaped file name (`.test.`, `.spec.`, `test_`, `test-`), so `tests/../tools/kill-all.js` blocks. Only TEST words are exempt. Any other word, option, wrapper, runner or subcommand anywhere in the command keeps the full scan, so `-- env -C /srv tools/kill-all.py`, `-- npx tsx --tsconfig tsconfig.json tools/kill-all.ts` and `npx vitest run tools/kill-all.ts` block. Two forms are scanned in full again: generic script operands (`python3 tools/lint.py src/kill-switch.go`), and wrappers inside the pgpool line (`-- env CI=1 npx vitest run ...`). There is no per-repo or per-file allowlist. Tests: `python3 -m unittest tests.test_kill_guard_path_operands`.
- gq_browser `keys --orphans` (goodqa#16051, found by a click-tester): a deleted key is no longer listed. The server's DELETE revokes a key and its list keeps the revoked row, so a re-delete answered 404. Rows with `revokedAt` are skipped. Tests: `python3 -I tests/test_gq_browser.py -k deleted_key`.
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
