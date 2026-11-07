# Changelog

Newest first. Flaws and their fixes are described plainly here and in
[docs/FINDINGS.md](docs/FINDINGS.md). This project has no tagged releases yet; entries
group by pull request.

## Unreleased

### Added
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
- `prod_delete_guard.py` (Kimi PR-C review, goodqa#14993): nested `/* */` comments, single-quoted `DO`
  bodies, `--fi''le`, `$(cat 'f')`, `/bin/cat`, a multiline mysql `source`, files read on an ssh host or in a
  container, psql `\cd`, `ssh -B`/`-P`, unknown ssh options, ProxyCommand/ProxyJump (command line or config) and
  quoted config `Include` paths no longer get past it. `SELECT 'DELETE FROM x'` and a commented-out include are no
  longer denied. Quadratic ssh and UPDATE paths are linear, and a 5 s decision budget fails closed for database
  commands. `kill_guard.py` accepts bundled `ssh -qT` and `-o 'BatchMode yes'` for a recorded remote kill.
- Removed a real Tailscale-range address and hostname from a test in HEAD (F-008). Git
  history still contains it; it was not rewritten.

### Known gaps (not fixed in this entry)
- Windows install and hooks are untested and `wal.py` imports `fcntl` (breaks on Windows).
- Command guard, kill guard and merge gate are not yet part of the shipped installer.
