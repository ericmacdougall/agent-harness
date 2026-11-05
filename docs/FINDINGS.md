# Findings and incidents

A plain record of flaws found in this harness (or in how we ran it): what was broken, the
impact, how it was found, and what fixed it. Entries are not softened. If a fix is not yet
merged, the entry says so. If a detail could not be verified, it says that instead of
guessing. Dates are UTC, 2026. Ticket numbers are in the maintainers' private tracker;
commit SHAs are the durable reference, and entries marked "SHA to be added" are updated as
the fixes merge.

## F-001 Command guard was never wired on any host (2026-11-04)

- **Broken:** the harness promised a guard against destructive shell commands, but no
  PreToolUse hook for it was registered on the Mac or on dev2, and the guard was not yet in
  this repository. The instructions forbade such commands; nothing enforced it.
- **Impact:** a builder agent's recursive delete ran on dev2. P0 #14471 (F-006) is the same
  class of failure. A later probe on dev2 confirmed that no live hook blocked a recursive
  delete of the agent transcript directory.
- **Found by:** the incident review and a probe by the rules owner.
- **Fix:** command guard (`feat/command-guard`), kill guard (`feat/kill-guard-14506`) and
  merge gate (`feat/merge-gate-14502`) were unmerged when this was written; `harness doctor`
  is to prove the guard is wired. SHA to be added.
- **Status:** open until those merge and doctor passes on a fresh install.
- **Lesson:** a documented rule is not an enforced rule. Docs must say which hook enforces
  each rule, and doctor must check wiring, not just files.

## F-002 A dead review run locked the provider pool for about 1.5 hours

- **Broken:** a review run died without releasing its provider-pool lock; later reviews
  waited on a lock no live process held.
- **Impact:** reviews blocked for roughly 1.5 hours.
- **Fix:** tracked in the harness-reliability tickets (#14525-#14533). SHA to be added; not
  verified at the time of writing.

## F-003 Zero-launch attempts burned the retry budget

- **Broken:** review attempts that never launched a model counted as failures against the
  retry and escalation budget.
- **Impact:** work could escalate to a costlier model after infrastructure failures that
  were not genuine review failures.
- **Fix:** only machine-receipted genuine failures count; infrastructure and zero-launch
  attempts do not. SHA to be added.

## F-004 One shared lock let a bulk backup block transcript backups for hours

- **Broken:** the log-backup job used one lock for both the small, important transcript pass
  and the slow bulk pass.
- **Impact:** a long bulk upload stopped transcript backups for hours.
- **Fix:** two locks, so a slow bulk pass cannot block transcripts. The script is copy-only
  and moves changed files to a versions folder instead of overwriting. SHA to be added.

## F-005 The spec done gate was bypassable through the GoodQA helper script

- **Broken:** the done gate in `spec_flow.py` was enforced by a hook on the GoodQA MCP
  tools, but the maintainers' own helper script called the same API directly, so a status
  change through it never met the gate.
- **Impact:** a ticket could be closed without the gate's evidence checks.
- **Fix:** tracked on the rules-deterministic work. SHA to be added.

## F-006 P0 #14471: Mac agent transcripts and WALs deleted (2026-11-04)

- **Happened:** a test script's heredoc ended early and the real shell ran the remainder,
  which deleted the agent transcript and WAL directories under `~/.claude` and printed
  credentials for the backup remote.
- **Impact:** every Mac Claude transcript and WAL from before about 23:22Z on 2026-11-04 was
  lost. The remote-backup credentials appeared in output and were treated as exposed. Work
  state was rebuilt from the records that remained.
- **Why possible:** no guard wired (F-001) and no verified off-machine copy of the logs.
- **Response:** continuous copy-only log backup (F-004); rules that agents never put
  deletion strings or config dumps in a live shell, heredoc, or test corpus fed to a shell
  (corpora are data files); the guards in F-001.

## F-007 Safety-rule slips after the rules were issued (2026-11-04)

Recorded because the rules did not enforce themselves. None of these was blocked, because
no guard was installed.

1. A guard owner wrote probe rows and docstrings containing deletion text through Bash
   heredocs. Nothing ran; the protected directories were verified intact afterwards.
2. An owner put a delete of the null device in a launch command on dev2. Harmless
   (unprivileged).
3. A click-tester wrote harmless fixtures with heredocs. No hostile text.
4. A background-job owner ran a name-pattern process kill on the Mac (newest `sleep 300`
   process, output discarded). The exact target is unknown; no other owner's run was found
   affected.
5. Before the rules existed, an owner ran a broad pattern kill of test runners on dev2 and
   removed its own scratch directories.

Sources: the harness-coverage owner's WAL entries and the PR bodies in the tickets.
Common cause: guards not installed (F-001).

## F-008 Real private-network address in public history (found 2026-11-04)

- **Broken:** two tests contained `ssh` example strings with a real Tailscale-range address
  (shared address space, RFC 6598), a maintainer username and a host name, committed to this
  public repository: `deee8b5` in `tests/test_commit_policy.py` (in HEAD until PR1) and
  `00885c4` in `tests/test_heavy_job_guard.py` (no longer in HEAD).
- **Impact:** low. A Tailscale address is reachable only from inside the authenticated
  tailnet and the host is being retired, but it discloses internal topology.
- **Found by:** the new `scripts/leak_scan.py`. **My first manual scan missed it** because
  its output was cut off by a `head` filter. Scan output is never piped through a
  truncating filter, and the script prints a findings count so truncation is detectable.
- **Fix:** removed from HEAD in PR1 (#14538). `leak_scan.py` fails on any RFC 6598
  address or tailnet domain name. `scripts/leak_gate.py` runs it locally before push (no CI).
- **History was not rewritten** (it would need a force-push, which is forbidden). Old
  commits therefore still contain that address, plus these non-secret identifiers: the
  maintainer's GitHub login, a GoodQA org name, a GCP project id and Secret Manager secret
  name (in `commit_policy.json` and docs), `/Users/<name>` paths in a few docs and a review
  JSON, and `<name>@<hostname>` author emails on some commits. No credential values were
  found in history; the `sk-ant-`, `ghp_` and `AKIA` strings the scanner matches there are
  test fixtures labelled fake. Author identity is left unchanged because `deliver.py`
  checks it.
- **Limits:** the history scan is regex-based; gitleaks (pinned by SHA-256 in
  `leak_gate.py`) is the second opinion.

## F-009 Personal identifiers shipped in the tracked policy (fixed in PR1)

- **Broken:** `harness/hooks/commit_policy.json` hard-coded one maintainer's GoodQA org id,
  secret name, GCP project and repo patterns, so a stranger's install would have carried
  another person's settings.
- **Fix:** the tracked policy is generic. Personal values live in an untracked
  `commit_policy.local.json` beside it, merged over the shipped file
  (`commit_policy.local.json.example` is the template). A profile that exists but cannot be
  read fails closed.
- **Consequence:** a host without its local profile has ticket enforcement off (no
  repository matches). `harness doctor` should report that state.

## F-010 Pre-install snapshot filled the Mac disk (2026-11-04)

- **Broken:** the pre-install snapshot for #53 copied all of `~/.codex` (5.9 GB) into the
  work directory. The disk hit ENOSPC, every agent's shell died, and no agent could free
  space because the deletion rules forbid deletes outside a reviewed list.
- **Recovery:** main removed the copy by explicit path after verifying every file still
  had its original.
- **Fix so far:** the snapshot rule is now hooks, agents, tools, `settings.json` and
  `CLAUDE.md` only, never `~/.codex`. Deterministic guards (placement, disk floor,
  self-recovery) are in progress under a separate task; SHA to be added.
- **Side effect on this work:** test runs during the outage gave misleading errors, so
  they were re-run on dev2 (all passed).

## F-011 Heavy jobs ran on the Mac because the guard was not installed

- **Broken:** `heavy_job_guard` was merged but not installed, so heavy test suites and
  browser jobs ran on the Mac instead of dev2.
- **Fix:** installed on the Mac and dev2 as of 84688d7.
- **Common cause with F-001:** a merged guard that is not installed protects nothing.

## F-012 Failing tests on dev2 that are not caused by PR1 (found 2026-11-04)

- **Observed:** on dev2 (Python 3.9) a clean copy of the PR1 base commit already fails
  `test_report_finalization.test_review_cleanup_races` (5 sub-cases) and two `test_rescue`
  tests (`test_fallback_when_astra_executable_unavailable_is_blind_and_handed_off`,
  `test_forged_commit_graph_parent_does_not_accept_sibling`). With PR1 applied the full
  suite is 1104 tests, 8 skipped, and only those 7 fail.
- **Cause:** not investigated. They are out of scope for PR1 and are left unchanged.
- **Follow-up:** needs its own ticket; SHA to be added when fixed.

## F-013 Personal GoodQA project ids in `spec_policy.json`, found by the first real denylist scan

- **Broken:** the tracked `harness/hooks/spec_policy.json` carried the maintainer's GoodQA
  project and org ids. The earlier scrub missed them because the scanner had no personal
  denylist loaded (`denylist_rules=0`): generic rules cannot recognise your own identifiers.
- **Fix:** the tracked file now has `"projects": {}`. Personal values live in an untracked
  `spec_policy.local.json` that may set only `projects` and `enforced_projects`; an unreadable
  profile fails closed. `install.py` prints whether both profiles are present.
- **Scanner change that caught it:** `leak_gate.py` now refuses to run without a non-empty
  denylist (exit 2) unless `--no-denylist` is passed, and an explicitly named denylist that is
  missing is exit 2. Found by code-inspection review finding F1 (vacuous pass).
- **Also fixed from that review:** allowlisted fixture paths skip token rules only (network
  rules always apply); the history scan reads merge commits and added lines that begin `++`;
  symlink targets and file paths are scanned; skipped files are counted; git errors are exit 2;
  the gate needs `--range` and a clean tree; the pinned gitleaks copy is what runs; the
  `AGENT_HARNESS_POLICY_LOCAL` test variable is honoured only for files under `tests/data`.
- **History:** the old ids remain in git history (not rewritten), like the other identifiers
  in F-008.
