# Field notes: a five-project supervised run (2026-11-23 to 2026-11-24)

One coordinator session supervised five project sessions, each fanning out its own agents, for about a day. This file
records what the harness got wrong or made slow, what was fixed and merged, and what is still open. It is a snapshot,
not a status page: GoodQA tickets are the status of record, and each open item names its ticket where one exists.

Everything here is the coordinator's own observation. The measured numbers come from that session's log and its
review receipts, which are not in this repository; treat them as reported, not independently verified. Open security
defects are described by type only; their details live in the tickets and fix branches.

## Fixed and merged during the run

| PR | Commit | What it fixed |
|---|---|---|
| 313 | 98d20350 | Fixes in `deliver.py` and `integrate_local.py` (delivery of verified work to the original checkout) |
| 333 | 1ff0b090 | A refused `git worktree remove` now names the route that works (`ah.py worktree-remove`) instead of a dead end |
| 334 | 39f0735e | One shared shell-word scanner for merge_gate and copy_hygiene; quoted punctuation no longer costs a review its stamp; an ssh is exempt from the copy floor only when provably plain and remote; the review stamp is bound to main's running tool call and lives at most 120 s |
| 337 | b8d7670c | `ah chat send` and `ah chat allow`: main can message an allow-listed person in GoodQA, proved by the user's own words and the recipient's member name at every send |

All four are installed on the Mac and t2-dev. PR 334's background-launch stamp rule was confirmed live by two review
launches from two different main sessions after the install.

## Open defects

Severity uses three labels: CRITICAL (security, an auth or tenant boundary, data loss, privacy, money, a broken release or rollback), USER_EXPERIENCE (a real user hits it in normal use) and ticket (everything else). The first two block a merge.

| Id | Severity | Defect | Ticket / owner |
|---|---|---|---|
| H24 | CRITICAL | Session WALs, including a main WAL, are not write-protected against agents. Details are in the ticket. | goodqa#17008 |
| launcher | CRITICAL | The installed delete guard does not analyse some launcher wrappers. The shapes are in the fix branch, not here. | fix branch `fix/launcher-command-analysis` |
| H26 | CRITICAL (boundary) | The guard analyses the command it is given, not the body of a script that command runs on another host. Seen twice; both were an agent's own scratch clone and were stopped. The guard should read such a script or refuse it. | backlog (H26) |
| H23 | USER_EXPERIENCE | The command analyser's budget is wall-clock seconds. With the Mac at load 80 to 110 it expired on ordinary commands and refused them as `log_delete/unanalysable`; it blocked a staging deploy, an `ah kill` and several read-only inspections. Measure it in the analyser's CPU time with a larger wall-clock backstop. | backlog |
| H22 | USER_EXPERIENCE | peer_review's per-provider deadline is a hard 720 s. A reviewer at max effort cannot finish a real diff in that time: five consecutive timeouts on one project's release-tooling PR. Each timeout still spends one of eight launches and the rung's budget. Deadline should come from review_policy.json by rung and effort. | goodqa#16947 |
| H25 | ticket | `ah worktree-remove` refuses a worktree whose HEAD is on a pushed branch but not at its tip. It should accept any commit reachable from a live remote ref. | backlog |
| H16 | ticket | `ah worktree-remove` refuses nested worktrees (`repo/.claude/worktrees`), which is where most agent worktrees live. | backlog |
| H5 | ticket | The spawn hook warns at 8 owners where the user's parallel-build norm allows 16. | backlog |
| remote kill | ticket | Every `ah kill --host` needs `--foreign`, so an agent cannot stop a process its own session started on t2-dev without a user approval. The user has now given a standing approval for the five supervised projects; the tool should recognise a pid tied to the caller's own WAL row. | backlog |
| chat send error | USER_EXPERIENCE | `ah chat send` reported a definite server refusal as `uncertain` with no reason, because the client drops the server's error code. | fix in progress |
| GoodQA DM | product gap, P0 | A user token can open a new DM but can never reply in an existing one (`assertAiPrivateConversation`), so chat send cannot reach an existing conversation. Needs an owner-granted `chat.dm.write` ability; an auth change that needs the owner's decision and a security review. | goodqa#17013 |
| guard false positives | ticket | The guard refuses commands whose text merely names a protected thing: a heredoc containing the installer module's name or the word `git`; a `curl -r` range flag read as a credential file; a redirect that overwrites a file the agent itself wrote in its work dir; a read-only transcript search. | backlog (H17 to H19) |
| checkout registry | in spec | Agents cannot be allowed to delete "their own" checkouts until ownership is provable. A spec review's probe found that path, device and inode are reused on ext4 (40 of 40 trials); identity must include birth time. | goodqa#16947 (the umbrella ticket for this run's harness work; the registry has no ticket of its own yet) |
| supervisor power | BLOCK | PR 326 lets a qualifying agent request merge and delete power from the user. Review found that a hand-edited request file is shown to the user as the session's own, that revocation fails open, and that harness logs were not excluded. In repair. | PR 326 |

## What made the run slow, with numbers

1. **Agent processes, not jobs, load the Mac.** Tests, builds and browsers already ran on t2-dev. With more than forty
   agent processes on a ten-core Mac the load sat at 80 to 110, because every tool call (including an ssh to t2-dev)
   passes through several hooks on the Mac. Cutting to the critical path brought the load to about 7. t2-dev has 48
   cores and no `claude` CLI installed; running sub-sessions there is the durable fix.
2. **A review is minutes; getting one launched was often half an hour.** Measured reviewer run times were 67 s to 523 s.
   One review needed four launches: a wrong repository name, a ticket with no comment naming the new commit, a reply the
   helper rejected as badly formatted, then the verdict. Other launches failed packet lint for a missing literal command
   and exit status. A single preflight (`commit_policy check-range --verify-tickets`, packet lint, PR binding) before
   every launch removed the repeat launches. peer_review should run that preflight itself and report every problem at
   once rather than one per launch.
3. **A compound launch line produces a review with no receipt.** `W=...; shasum ...; python3 peer_review.py ...` ran a
   full review and then failed the publication check with "no current signoff". The helper should refuse a launch it
   cannot stamp before spending the review, not after.
4. **Reviewer verdicts on the same head can differ.** One head got PASS in text (no receipt) and then BLOCK on wording.
   Triage by main is what kept this moving; the receipt of record was the BLOCK, fully triaged.
5. **Fan-out exhausted the weekly allowance.** Sessions running 10 to 16 owners each stopped every project at once. The
   owner cap is per session; nothing bounds the total across sessions that share one subscription.
6. **Serial gates in front of cheap work.** An experiment whose runs cost about ten cents each was queued behind hours of
   checker repair and document review. Runs that keep complete logs can be audited afterwards; only work that cannot be
   repeated cheaply needs every gate first.

## Operating rules that held up

- A command the guard refuses does not go into a script, a kit or an ssh payload. The refusal goes to the session lead.
  The guard's own stated alternatives (a script file for an over-long analysis, the smallest direct command) are
  allowed; a third shape is not.
- A sub-session must not publish to a public place, or message a person, on its own judgement. Both need the user's own
  words, cited. One session approved a public push itself and withdrew it before anything was pushed.
- Trace a number before treating it as the user's. Stage caps and a per-run limit had been reported as the user's; a
  trace showed his words fixed only the overall ceiling and the design.
- When a merged change replaces review tooling, install it between reviews, not during one, and treat the next review
  launch as the live test with the previous pin as the rollback.
- Terminal results the user runs can reach the coordinator an hour late. Check the current state before acting on one.
