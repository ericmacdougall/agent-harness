# Direction: the harness, unified

Date: 2026-11-25. Status: decided direction, partly built (the session-folder, save and reaper part is in `docs/lifecycle.md`). This is the one product distilled from three sources: this harness (and redesign PR #364), the outside agent Neo, and the stalled Go project agent-fabric. It replaces the open questions in PR #364 with decisions.

Evidence: twenty source maps written the same day (every guard, gate, daemon and tool in this repo; all 175 issues and 204 pull requests of Neo; Fabric's code and state; what Claude Code 2.1.332 and Codex 0.171 provide natively; 21 days of this fleet's own transcripts and audit logs), plus a worker host's disk report.

## The product in one paragraph

The harness stops judging what agents type and instead sets real boundaries in a few places. The operating system limits where a session can write and which secrets it can read. GitHub refuses a merge without a passing independent review. A handful of small tools handle the actions that matter outside the machine (secrets, deleting records, removing checkouts, production data) by checking the real object and proving the result. Each session works in its own folder, and what it leaves behind is saved and then removed. Everything else is advice given once, or is deleted. The target is about a tenth of today's code, no hook on ordinary shell commands, and standing rules a person can read in two minutes. It still runs on Claude Code and Codex subscriptions; it does not replace their agent loop.

## What the evidence says

| Finding | Number |
|---|---|
| Hook refusals in 21 days | 16,723 (2.8 per 100 shell calls) |
| Of a random sample of 76 refusals: prevented real harm / blocked legitimate work | 1 / 68 |
| Refusals caused by a guard's own timeout or crash | 2,103 |
| The five catches the owner listed "for balance" that came from a hook | 0 (all from review, agent judgment or a self-report) |
| Direct spellings of a protected action blocked / indirect routes blocked | 26 of 26 / 0 of 22 |
| Merges that passed the old merge gate on an agent-issued waiver | 510 of 665 |
| Independent PR reviews in 24 days: blocked / passed / no result | 1,713: 759 / 399 / 555 |
| Times the worktree-removal check protected unpublished or dirty work | 141 |
| Question cards sent to the owner | 18 a day |
| Standing rules in force; context injections per human prompt | 8,242 words; 16 |
| Hook processes started by one Bash call (still 14 launcher starts when "off") | about 15 |
| Codex sessions on the Mac that ran with any sandbox | 203 of 1,163 |
| Open pull requests on this repo; of those, ones that conflict with the redesign | 69; 50 |

Two outside results match. Neo built a command classifier with permission modes, took four defect reports against it in one day, and deleted it seven weeks later; its 40-line replacement is already growing back into a parser. Fabric tried the opposite, proving everything before allowing anything, and has never run a real task.

## Five rules

1. **Boundaries are enforced by the operating system or the server, never by reading command text.** If a rule cannot be enforced that way, it is advice, and it is labelled as advice.
2. **Actions with consequences outside the machine go through small tools that check the real object and prove the result.** Verify, then delete. Record intent, act once, read back.
3. **Independent review before merge is the one gate.** It is the only control with evidence behind it.
4. **The path is the owner.** Every session works in its own folder. What it leaves is saved, then removed, without anyone having to judge it.
5. **Unsure means allow, and say so once. Off means off.** A new control runs in shadow first and stays only if it records a true catch.

## The parts

| Part | What it does | Comes from | State |
|---|---|---|---|
| Sandbox profiles per role | Workers write only to their session folder and project; nobody's shell can read key files or delete transcripts, notes and audit logs; reviewers are read-only | Native: Claude Code sandbox and deny rules in managed settings; Codex permission profiles and `/etc/codex/requirements.toml`. Neo's stance, with the sandbox Neo never shipped | To roll out, in shadow first |
| Host self-test | Proves on each host that the profile really denies what it claims, with a positive twin for each denial | Fabric's negative controls, as `ah doctor` checks | To build (small) |
| Merge rule on GitHub | Pull request required, no force-push, no branch deletion, and a passing `harness/review` status on the head commit | Rulesets, already active on one of the owner's private repos | To roll out: configuration |
| Review runner | A reviewer one rung above the author, another vendor when available, a structured verdict, at most two repair rounds, then the owner's queue | `peer_review.py`, trimmed | Exists |
| Tools for consequential actions | `ah secret` (clipboard to store, use without printing), `ah log-push` (push, verify, delete), `ah kill` (stop only what you started), `ah worktree-remove`, `ah reap` | The harness; Fabric's "record intent, act once, read back" | Exist; `ah reap` built now |
| Roles and approvals | One roles file and one approvals log. A role is the sandbox profile a session is launched with, so it cannot be claimed | `ah_roles.py`, `ah_approvals.py`, with identity moved from self-report to the launch profile | Exists; identity change to build |
| Session folder, saved work, reaper | Each session gets a folder and a temp directory; unpushed work is saved at every turn end; dead sessions' checkouts, dependency trees, fixtures and containers are saved and removed | The worker host's disk report; `workdir.py`; Neo's "capability, not checking" | Built now (below) |
| Records and visibility | Native transcripts as the mechanical record; a short per-session note log for intent, decisions, asks and handoffs; a file inbox for answers; status computed on demand | The four small things the fleet already runs on | Exists; trim the rest |
| One switch, one installer, one config | `harness off` stops hooks and background jobs; one versioned release directory and a pointer; `local.json` for the machine, one policy file for defaults | Redesign PR #364; Neo's first-file-wins and loud errors for removed keys | Partly exists |
| Standing rules | At most 600 words, with a size test in the suite | Neo's byte budgets | To write |

## What we took, and what we left

**From the harness.** Kept: independent review before merge, the off switch, verify-then-delete, checks on the real object (worktree removal, process ownership), the secret tool, the session note log, the file inbox, the delivery states "ready" and "finished". Left: the command guard (10,712 lines) and its eleven sibling command readers, the kill, heavy-job and copy guards, the merge gate and its analyser, commit-form checks, provenance, spec flow, the model-ladder state machine, mission coverage, both daemons (`ahc`, `ahd`), the Go port and ticket ledger, the console, the patched Codex build.

**From Neo.** Taken: no policy on the tool path, a role defined by the tools and profile it holds, refusals that say how to proceed, one output budget, quiet one-line receipts, a size budget on standing text enforced by a test, a written list of non-goals, a doctor command, removed settings that fail loudly. Left: Neo itself as a runtime (it bills Claude models by API key, keeps no durable record, is single-process and has one maintainer), and its missing sandbox.

**From Fabric.** Taken: a boundary must be proven on the host before it is trusted, recorded intent with readback for outward actions, "done" bound to the deployed commit, approval that expires, rolling a control out as shadow then enforce. Left: PostgreSQL, the multi-tenant roadmap, per-tool-call human review, pinned client binaries, fail-closed everywhere. The Fabric repo is frozen.

## The "never" list

| Never | Mechanism | Not covered |
|---|---|---|
| The only copy of something is destroyed | Record folders are not writable by a session's shell; `ah reap` and `ah worktree-remove` delete only after a remote ref is confirmed with `ls-remote` or a bundle verifies; work is saved at every turn end | A session that deletes inside its own folder before the turn ends |
| A secret reaches a transcript, a log or the wrong host | Key files are unreadable in the worker profile; secrets enter through `ah secret` and are used through a child's environment; logs are redacted when they leave the machine | Claude Code's file tools follow permission rules, not the sandbox; a secret the owner pastes into chat |
| A change reaches a protected branch without a passing independent review | GitHub ruleset with a required review status | Until the reviewer's token is held where workers cannot read it, a determined agent could post the status itself |
| Production data is changed without a grant | Workers do not hold production credentials; the existing check on named database tools stays until credentials are scoped | Any production credential left readable on a host |
| Disk or memory runs away | Reaper on a timer that acts at 70% disk; per-session folder size reported back to the session; memory limits on Linux workers | Memory on the Mac |
| An outward action happens twice or is lost | The tools record intent, act once and read back | Raw `git push` and `gh` from a session |
| Work is silently dropped | A turn-end nudge to write a handoff, once; saved work survives a dead session; status shows silent owners on demand | Nobody reads the status |
| The control layer stops all work or cannot be switched off | No hook on ordinary shell commands; every hook exits 0 on its own errors; `harness off` stops hooks and jobs | A vendor change to hook behaviour |
| Untrusted text steers an agent into damage | The same boundaries: limited write scope, unreadable secrets, a server-side merge rule | Exfiltration over the network: outbound network stays open, because ssh to the worker hosts is everyday work |

Threat model: this holds against a careless agent and against one misled by text it read. It does not claim to hold against a deliberately evasive agent running as the owner's own user with the owner's tokens. Closing that needs workers on a separate OS account, which is practical on the Linux hosts and not planned for the Mac.

## Decisions taken

- **Supervisors may grant the top rung.** Recorded in the approvals log, visible in `ah approvals`, revocable by the owner.
- **The merge condition does not read CI.** GitHub does: the ruleset requires the review status, and any checks a repo defines.
- **A passing review settles lineage records with no owner card.**
- **The Fabric collector leaves the dashboard.** It never carried an event.
- **The nine disguised delete forms stop mattering** once record folders are protected by the sandbox and permissions.
- **Reviews bind to the commit; owner approvals bind to the pull request.** A fix after review triggers an automatic re-review, never a new card. This replaces the 150-line allowance.
- **Roles come from the launch profile, not from the model name.** Today `model: fable` in the settings makes every main session top rung.
- **Log backup goes to the B2 remote already configured (`backup_remotes.b2` in `local.json`), using PR #312's local checkpoint.** Dropbox lists one folder per request, which is the root cause of twelve days of failed runs. `ah log-push` to the private transcripts repository stays for "push this log, then delete it". The duplicate fix on this branch (commit 4f1a112b) is reverted.
- **Outbound network stays open in the first version.** File boundaries first; an allow-list later, measured in shadow.
- **The dashboard stays as a read-only view.** Nothing in the core depends on it.

## Junk: prevent it and clean it up (built on this branch)

A worker host's disk report found 10,648 checkouts, 13.6 GB of fixtures in `/tmp`, 93 GB of session folders and containers nobody stopped, all because nothing recorded who made a thing or when it could go. The harness already had a session-folder pruner, but it skipped any folder holding unpushed work, never rescued that work, ignored uncommitted changes, and was never scheduled.

- **Prevent.** At session start a hook creates the session's folder and temp directory and exports `AH_WORK` and `TMPDIR`, and tells the agent in one line to put clones, scratch and fixtures there. `ah co <repo>` makes a checkout there with the real GitHub URL as origin. The sandbox write scope will make this a fact, not a request.
- **Save.** At every turn end a hook saves each checkout in the session folder: unpushed commits, stashes, and a snapshot of uncommitted and untracked files, to rescue refs on a private remote, confirmed with `ls-remote`, or to a verified bundle. Secret-shaped files are held back locally and never pushed. It never blocks the turn.
- **Clean.** `ah reap scan` reports every session folder, its owner, whether it is live, what is unsaved, and loose checkouts elsewhere. `ah reap run --apply` removes dependency trees and build output, then saves and removes checkouts (children before parents), then stops the session's containers. It keeps anything it is unsure about and logs every deletion. `--if-above 70` makes it safe to run on a timer.

See `docs/lifecycle.md`.

## Order of work

Each step leaves the fleet working and is undone by `harness off` or by reverting one configuration change.

1. **Stop the bleeding.** Make `harness off` stop background jobs by default; remove the watcher that rewrites `settings.json`; fix the `harness` name collision; rebase and land PR #312 against B2; run `ah reap` in dry run on each host, then apply, then put it on a timer. Exit check: no harness process running while off; backup marker fresh; disk below 70%.
2. **Move the gate to the server.** Apply the existing ruleset pattern (pull request required, no force-push, no deletion) to every active repo with a required `harness/review` status; make the review runner post it; unregister the merge gate and commit-policy hooks. Exit check: a merge without a passing review is refused by GitHub, not by a hook.
3. **Turn on the boundary, in shadow.** Enable the native sandbox profiles on one project with denials logged and nothing refused; adjust write scope, read denials and excluded commands until a normal day shows almost none; then enforce for workers. Exit check: fewer than five denials a day, each one correct.
4. **Delete.** Unregister and remove the guards, gates and daemons on the kill list with their tests; close the superseded pull requests; cut the standing rules to 600 words. Exit check: no hook fires on a Bash call.
5. **Measure weekly** from the transcripts: refusals, owner cards per day, injected bytes, time from "reviewed" to "merged", disk use. A control with no true catch is removed.

## The open pull requests

Close as superseded: the classifier patches (22 PRs), the self-serve stack (7), WAL segment rotation (7), guards that protect authority files from the same user (4), delivery allow-list grammars, and project-specific changes. Keep the ideas from about eight: #312 (backup checkpoint), #316 (redact and split logs on push), #352 (bounded monitoring), #353 and #317 (review runner facts), #322 and #336 (one parity check and one updater), #355 (retire an ended session's owners), #359 (verifier facts for removing clones, now covered by `ah reap`).

## Before and after

| | Today | Target |
|---|---|---|
| Hook registrations | 48 | about 6, none on Bash |
| Processes started by one Bash call | about 15 | 0 |
| Standing rules | 8,242 words | 600 or fewer |
| Hook code | 97,169 lines | about 10,000 |
| Config and policy files | 61 | 2 |
| Background jobs | 7 | 2 timers (log shipping, reaper), plus the optional dashboard |
| Owner cards per day | 18 | fewer than 3 |

## Risks and how each is settled

- **The sandbox blocks ordinary work**, as it did when Codex full access was restored on 2026-10-30. Settled by the shadow step: nothing is enforced until a normal day is clean. Known today: Claude Code's sandbox breaks docker, jest and Go tools on macOS and proxies only TCP, so those commands and ssh are excluded from it.
- **Claude Code's sandbox covers only its Bash tool.** File tools are held by deny rules in managed settings, which a determined local user can edit. Stated, not hidden.
- **The review status can be forged with the owner's own token.** Settled when the reviewer posts through an identity workers cannot read.
- **Rescue refs may be refused by a remote.** The save falls back to branches, then to a bundle; it never reports success without proof.
- **The Linux hosts were not inspected.** `ah doctor` and `ah reap scan` on each host come first.
