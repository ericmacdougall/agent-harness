# ahc slice 1 (b): spec deviations, ASSUMPTIONs and limitations

Ticket goodqa#16049. Spec r9 is `slice1b-spec-r9.md`, at core e488a8cb. The branch is feat/ahc-slice1b-build, on base 4d45fe40.

Every entry here was ruled by an agent. A ruling attributed to "the owner" (coordinator owner agent af4233df3d4a6054b) or to "main" is an agent message and an ASSUMPTION. None of it is the user's words, and none of it is user approval. Status of record: goodqa#16049.

## For the adversarial review (MATERIAL)

**A-1. AC-8 option A replaces r9's R3 row.** This is an owner ruling, ASSUMPTION; WAL `wcdb47764f4e`.

*What r9 says.* The unit runs the bound `peer_review pr` argv: the GitHub repo and PR, no main stamp, the expected head H and the base B_r. The settle path is a FINAL on core's socket from the unit's uid.

*Why that cannot work as written.* peer_review requires `--repo`, `--packet` and `--output`. It writes a report file, never a FINAL. A synchronous `systemd-run --pipe` under a 60 s launch timeout cannot hold a multi-minute review.

*What was built instead* (harness/hooks/ahc_review.py):
- **Detached launch.** The unit runs detached, with no `--pipe`, `RemainAfterExit=yes` and `RuntimeMaxSec=3600`.
- **Bound command line.** It is the completion wrapper (`ahc_review_final.py --socket --row --intent --report`), then `peer_review pr --repo <core's clone at H> --packet <core's R2 packet> --output <root/reports/{row}-{intent}/report.md>` and the r9 flags. The whole line is in the intent digest, and the launch is byte-equal to it (AC-13).
- **Conditions 1 and 2: the FINAL is a completion signal only.** It carries the row, the intent, the InvocationID and the report sha256. Core never takes a verdict from it (`completion` drops every other key). Core then checks, in order:
  - the report, read no-follow and bounded (`ahc_core.read_regular_resolved`);
  - the sha256;
  - `Reviewed HEAD` = H;
  - `Reviewed packet SHA-256` = the row's R2 packet;
  - the verdict, taken from the header-block position only (r1 F4).

  Any mismatch is unverified-producer and settles nothing.
- **Condition 3: one writable path.** The unit may write exactly one path: a fresh 0700 per-attempt directory, `ReadWritePaths=<that directory>`, bound in the digest. peer_review refuses an existing `--output` (`require_fresh`), so core makes the directory rather than the report file; the owner accepted this.
  - The unit's DynamicUser uid is known only after it starts, so `runner.grant_output(dir, uid)` runs after the uid is read.
  - The production grant is not built (PRT-r3-grant, goodqa#16275). There is deliberately no world-writable fallback, because a writable report lets anyone plant a PASS.
- **Condition 4: completion.** Completion is read through the allowed `systemctl show` forms. A unit that ends with no FINAL, or outlives REVIEW_MAX plus 300 s, goes to outcome-unknown, never PASS.
- **Condition 5: no runner injection in production.** The wrapper stub and the runner are injectable only through `Launcher.for_test`.
- **Likely gap, not settled (PRT-peercred).** Core's socket is `<root>/sock/review.sock`, and the daemon creates the root 0700 (`~/.agent-harness/ahc`). A DynamicUser unit is neither owner nor group, so it likely cannot reach the socket to send its FINAL. Every launch would then end in outcome-unknown, which fails closed. The AC-12 kit's preflight settles this on t2-dev, and the fix belongs with goodqa#16274/#16275.
- **Condition 6: the wrapper is not shipped.** It is PRT-r3-wrapper, goodqa#16274, an AC-12 live-gate item. Until it ships, the production Launcher has no runner and every R3 launch goes to infra-wait.

*Admission.* W1 binds the item and its rows to core's R2 packet sha256. The owner's packet sha is listed inside the fenced owner section, and the shadow queue holds only that sha. A packet that cannot be built leaves the request held (fail closed).

*Variants.* "AC-8 option A: …" kills these mutations:
- core takes the wrapper's verdict field;
- the tick drops the scheduler call;
- no sha check;
- no InvocationID check;
- no packet check;
- no head check;
- the verdict counts anywhere in the report;
- the report is read following links;
- an ended unit is waited on;
- no grant;
- the report directory is made world-writable (`os.makedirs` + `chmod 0777` instead of `ahc_fs.make_fresh_dir`). The variant is named "the report directory is made world-writable (makedirs + chmod 0777), not fresh".

**A-2. R5 corpus-scan exemptions added on this branch** (`tests/data/ahc_scan_corpus_exempt.json`, 3 entries; ASSUMPTION). tests/test_ahc_scan.py CleanCorpusTests requires every listed file to yield exactly its listed per-rule counts, and every unlisted file to yield none. A pinned entry also covers only the bytes whose sha256 it names.

| File | Tier | Why it is safe | Pinned |
|---|---|---|---|
| `tests/data/review_diagnostics_hostile.json` | exposure (`pem`, `anthropic`, `high-entropy`, plus redact rules) | synthetic hostile fixture of the peer-review diagnostics tests; see below | yes, sha256 `be3b1311…85c6` |
| `tests/data/merge_gate_corpus.json` | prefix only (3 prefix-tier findings: one auth-scheme word, two public token prefixes; exact counts in the exemption file) | pre-existing merge-gate command corpus (55ce595). Bare public token prefixes and an auth-scheme word in command text; no value follows a prefix | yes, sha256 `7075418f…8893` (addendum) |
| `tests/data/ahc_scan_corpus_exempt.json` | prefix only (73 prefix-tier findings across two rule kinds; exact counts in its own entry) | the exemption list names scanner rule kinds in its own keys and reasons; it holds no values | no, ASSUMPTION: a file cannot hold its own sha256 (fixed point). It is bound by its exact per-rule counts, so any new shape or any exposure-tier finding in it fails the scan |

Details for the hostile fixture follow. It has exposure-tier findings (a key-block shape and a token tail).
- *How it was confirmed synthetic, without printing values.* The fixture predates this slice: commits f119894 and 117e8af, peer-review stream. Its own `_comment` says it holds hostile values interpolated into printed diagnostics, read only by tests/test_review_diagnostics.py. Its fields are named `private_key_block` and `fake_token_tail`. tests/test_review_diagnostics.py loads it to test redaction.
- *Owner condition.* The entry pins the file's sha256, so any edit drops the exemption and the scan fires (tests/test_ahc_scan.py, CleanCorpusTests). The addendum also pins the merge-gate corpus; `test_a_pinned_exemption_drops_on_any_edit` covers it.
- *Follow-up for that stream.* Build the values at run time.

**A-3. The tick schedules R3.** This is an owner ruling. One slot per tick, oldest offerable row first. Live shadow stays inert until a GoodQA reader exists (goodqa#16262, ruling g); after that the path is complete, apart from A-1's two PENDING_REAL_TEST items.

## PR 272 review round 1 (code inspection at 084a610b, three material findings, all fixed)

**F1, availability.** Before the fix, every core tick opened `Ledger(migrate=True)`, and the v5 gate waited on both role locks. The running review daemon holds its lock for life, so core refused after 60 s with schema exit 3, which does not restart.
- *Fix.* `Ledger._v5_current` reads the version under the shared maint lock. A current, unfenced v5 ledger takes no migration lock.
- *Upgrade path.* An upgrade or a fence still takes both role locks and the exclusive maint lock, and reads the version again under them. A migration with another role running still refuses (NEG-27, `test_neg27_a_migration_with_another_role_running_still_refuses`).
- *Reconciliation.* `startup_reconcile` takes the role, and only core (or an all-in-one run) reconciles. The review role opens no ledger at start.
- *Tests.*
  - `MigrationV5Tests.test_f1_a_current_v5_ledger_opens_while_the_review_role_runs`, multiprocess;
  - `test_f1_both_roles_start_together_on_a_v5_ledger`, two processes;
  - `StartupReconcileTests.test_f1_only_core_reconciles_and_migrates_at_start`.

**F2, fail-closed reconciliation.** Before the fix, a list-units failure blocked only rows with an open or started intent, so a freshly queued row could still launch.
- *Fix.* A durable gate in `contract_meta` (`r3_reconcile`): `running` at the start of a reconciliation, then `ok` or `failed`.
  - `launch_intent` refuses unless the gate is `ok`.
  - `Launcher.launch` retries the reconciliation before a launch while the gate is closed.
- *Tests.*
  - `ReviewTickTests.test_neg36_a_failed_unit_listing_closes_every_launch_until_a_reconciliation_succeeds`: zero start calls, then the retry lifts the gate;
  - `RuntimeTests.test_neg36_launch_intent_refuses_until_a_reconciliation_succeeds`.
- *ASSUMPTION: a ledger never reconciled is open.* The daemon reconciles before its first tick (pinned by `test_ac8_the_daemon_reconciles_before_its_first_tick`), and a host without review isolation starts no unit.
- *ASSUMPTION: the retry runs inside the tick.* It opens the guard's recovery-stop window (`policy.reconciling`) for that reconciliation only. No launch runs concurrently in the process.

**F3, AC-9 acceptance flow.** Before the fix, `settle_final` built every receipt with `finding_ids: []`.
- *Fix.* For a non-PASS verdict, core extracts the ids from the report it read itself (`report_finding_ids`). The receipt goes through `ahc_shadow.findings_receipt`, which applies the id rule and the 64 cap and keeps `finding_ids_dropped`.
- *ASSUMPTION: the id rule.* It copies peer_review's `finding_ids` heading rule (`F<n>`/`R<n>`, optionally suffixed, at the start of a line). The daemon does not import peer_review.
- *Test.* `ReviewTickTests.test_ac9_a_block_reports_finding_ids_reach_w3_and_main_accepts_them` follows a BLOCK report with F1 and F2 through settlement, W3 escalation naming both, and main's W16 acceptance into a named ticket, after which W3 no longer applies.

**Variants.** Each fix has an entry; all are PROVEN:
- "PR 272 F1 …": 2 of 2 mutations killed;
- "PR 272 F2 …": 3 of 3;
- "PR 272 F3 …": 2 of 2.

**Owner ruling (agent message, ASSUMPTION; owner WAL wbf5d92d5ea4).** The DynamicUser socket-reachability gap routes to goodqa#16274 and #16275 and does not block the merge.

## PR 272 review round 2 (code inspection at bbaff656, four findings, all fixed)

One invariant was meant to hold across F4 to F6: a launch intent leaves `open` or `started` only once its unit is confirmed inactive, failed or gone. (It did not hold for a settled FINAL; see the PR 272 rescue section below.) Reconciliation and the sweep walk the ledger's intents, not only the units systemd lists.

**F4, crash windows (high).**
- *Fix (a).* After the listed-unit pass, `Reconciler.run` visits every open or started intent whose unit systemd does not list (`reconcile_absent`). An open one is orphaned with its charge kept (NEG-22), so the row launches again.
- *Fix (b).* `start_attempt(..., intent=)` binds the row to running and moves its intent open to started in one transaction, so no crash can leave a running row on an open intent.
- *Recovery of an earlier ledger.* A ledger written before this fix may hold a running row on an open intent. Reconciliation moves that intent to started (`recover_bound`) instead of orphaning it; the sweep then settles the row through R7.
- *Named crash points.* `r3.intent_committed` and `r3.attempt_bound` are new. `check_r3_launch` now also requires a running row's intent to be started, and no row to be queued behind a live intent.
- *Tests.*
  - `RuntimeTests.test_f4_a_crash_before_the_unit_starts_is_orphaned_and_the_row_launches_again`;
  - `test_f4_b_a_crash_right_after_start_attempt_leaves_a_started_intent_that_the_sweep_settles`;
  - `test_f4_reconciliation_recovers_a_running_row_whose_intent_is_still_open` (unit listed, and unit gone);
  - `NamedPointTests` over the two new points.

**F5, cleanup without a confirmed stop (high).**
- *Fix.* `stop_confirmed` sends the stop, then requires `ActiveState` inactive or failed within the reconciliation bound (`STOP_BOUND`, 60 s, at most 61 polls). The stop's return value is never the confirmation.
- *Unconfirmed.* `Launcher.abandon` keeps the intent open, so `launch_intent` starts no second unit, blocks the row and records an incident. Each tick the sweep retries the stop; on confirmation it closes the intent and lifts the block.
- *Reconciliation.* `reconcile_owned` treats an active unit of a closed or orphaned intent as inconsistent. It records an incident and stops the unit through the guard's startup recovery rule (`slice_ok` when the unit is in the review slice).
- *The sweep's R7 branch had the same unconfirmed stop.* A unit that outlived its bound now keeps its intent started until a stop is confirmed.
- *Tests.*
  - `RuntimeTests.test_f5_an_unconfirmed_cleanup_stop_keeps_the_intent_and_no_replacement_unit_starts` (stop returns False, and stop returns True while the unit stays active);
  - `test_f5_reconciliation_stops_an_active_unit_whose_intent_is_closed_or_orphaned`, with every show and stop passed through the real guard.

**F6, cancellation never completed (medium).**
- *Fix.* The sweep handles a cancelling row: it stops the unit, confirms the stop, applies R15 (cancelling to superseded) and closes the intent. A failed stop keeps the row cancelling and the intent started; a later tick, also after a restart, finishes the job. A cancelling row with no live intent (an outcome-unknown row cancelled after its unit was confirmed stopped) goes straight to R15.
- *Tests.*
  - `ReviewTickTests.test_f6_w20_owner_cancel_stops_the_unit_and_settles_the_row_superseded`: a failed stop, then a restart;
  - `test_f6_w4_head_supersede_stops_the_unit_and_settles_the_row_superseded`, through the tick;
  - `RuntimeTests.test_f6_a_cancelled_outcome_unknown_row_settles_superseded`.

**F7, the scheduler bypassed the policy's B33 (medium).**
- *Fix.* `launch_intent` takes the budget from `Contracts.launch_budget`. That is the policy record of the latest stored observation for the item's (repo, pr), the record W15 evaluates. A caller's `budget_obs` can only lower it.
- `launch_intent` also refuses a row of an exhausted item until main's W16 disposition.
- `offerable_rows` skips rows of exhausted items and rows whose lineage has spent its B33, so a refused row cannot hold the slot.
- *Tests.*
  - `RuntimeTests.test_f7_launch_intent_takes_b33_from_the_items_recorded_policy`;
  - `test_f7_launch_intent_refuses_a_row_of_an_exhausted_item`;
  - `test_f7_offerable_rows_skip_exhausted_items_and_spent_lineages`;
  - `ReviewTickTests.test_f7_a_policy_b33_of_one_stops_every_launch_and_charge_after_the_first`: b33=1 and two queued rows of one lineage give one start and one charge over three ticks.

**ASSUMPTIONs added in round 2 (builder, unconfirmed).**
- *Policy budget with no stored observation.* The default B33 (8, D-8) applies. The production tick observes every live item before it schedules, so an item normally has one.
- *Observation scope.* The policy record is read from the latest observation for the item's (repo, pr), so a W4 successor at the same PR uses the policy its predecessor was observed with until it is observed itself.
- *A digest mismatch fails closed.* An observation whose fields fail their digest makes the launch refuse, and the row is not offered.
- *A failed or refused show is not an end.* Before this change, the sweep read `show` returning nothing as "the unit ended". It now treats that as unknown and retries; only the bound (R7 "outlived its bound") gives the row up.
- *The sweep can wait up to the stop bound per unconfirmed unit in one tick.* Production uses the same 60 s bound as reconciliation; tests poll with no sleep.
- *Recovery of an earlier ledger's open intent under a running row promotes it to started.* The other option was to stop the unit and give the row up through R7. Promotion keeps an attempt that may still deliver its result.

**Variants.** Each finding has an entry, and every mutation is killed by a test that isolates its half of a defence in series:
- "PR 272 F4 …": 4 mutations;
- "PR 272 F5 …": 4;
- "PR 272 F6 …": 3;
- "PR 272 F7 …": 5, including the integrated tick with every gate removed.
- Five older anchors moved onto the round-2 code with the same mutation intent: NEG-25 finished items, NEG-22 the unit is not stopped, NEG-22 the charge is refunded, NEG-49 the unbounded stop, and option A's ended unit.

## PR 272 rescue (main's exact-head receipt at f532d495: BLOCK, F1-F4)

The round-2 invariant above did not hold on every path: `settle_final` closed a started intent and then called `stop()` without confirming it. The sweep selected only open and started intents, so a failed stop after a valid FINAL was never retried. The rescue (agent ac329364439760e40) replaces per-call-site cleanup with one state machine.

**F1, the unit lifecycle (high), fixed.**
- *States.* `launch_intents.state` gains `stopping`, with `retire_to` (closed or orphaned). The flow is open → started → stopping → closed, or open → stopping → closed or orphaned. A terminal intent found with an active unit (a ledger an earlier build wrote) goes back to stopping with the same `retire_to`, and an incident is raised.
- *One chokepoint.*
  - `Contracts.intent_move` has no edge to a terminal state (`INTENT_EDGES`).
  - `Contracts.intent_retire` is the only writer of closed or orphaned. It takes the ActiveState the caller observed after its stop and refuses anything but inactive or failed.
  - In one transaction it ends the intent, applies R15 to a row that is cancelling on this unit, and lifts the block this unit holds (the old `unblock_row` was not unit-scoped; that is now fixed too).
  - `ahc_review.retire` (stop, then show until inactive or failed, within `STOP_BOUND`) is its only caller. A stop's return value never confirms.
- *Durable before the stop.* Every way an attempt ends only moves the intent to stopping, and does so before any stop: a verified FINAL and R7's outcome-unknown move it in the row's own transaction (`settle_attempt`); an abandoned launch, a cancelling row and a startup orphan move it with `intent_move`. A crash after that commit leaves the cleanup in the ledger. New named point `r3.settled`. `check_r3_launch` now fails on any terminal intent with a live unit.
- *Retried everywhere.* `LIVE_INTENT` = open, started, stopping drives:
  - the second-unit check in `launch_intent`;
  - `live_intent_units`, which keeps a stopping unit in the guard's committed-intent form after a restart;
  - `offerable_rows`, so a row with a live intent never takes the slot;
  - the sweep and both reconciliation passes.
- *RemainAfterExit.* `ReviewStage.ended` counts ActiveState active with SubState exited as ended, so R7 fires at once instead of after REVIEW_MAX. It is never a confirmed stop: only inactive or failed after a stop retires an intent. This closes the round-2 disclosure on `ended()`; real systemd behaviour is still the AC-12 gate.
  - Field observation (the coordinator owner, on t2-dev, relayed by main; an agent report, not reproduced by the rescue): an exited RemainAfterExit unit reads `ActiveState=active`, `SubState=exited`, `Result=success`. That confirms neither ActiveState nor `Result=success` is a stop confirmation, and that `ended()` must read SubState. A test pins exactly that triple.
- *Tests* (`tests.test_ahc_contracts.RuntimeTests`):
  - `test_rescue_f1_a_valid_final_never_retires_the_intent_before_its_unit_is_confirmed_stopped`: stop returns False, returns True while the unit stays active, or is refused;
  - `test_rescue_f1_a_crash_between_settlement_and_the_stop_leaves_cleanup_that_is_finished`: the next sweep, and a restart through the real guard;
  - `test_rescue_f1_remain_after_exit_an_exited_unit_is_given_up_and_still_stopped_before_it_retires`;
  - `test_rescue_f1_the_observed_t2_dev_triple_active_exited_success_is_ended_but_never_a_stop`: the injected runner returns exactly active/exited/success;
  - `test_rescue_f1_only_intent_retire_writes_a_terminal_state_and_only_on_a_confirmed_stop`, including a source scan;
  - `test_rescue_f1_a_stopping_intent_after_a_restart_is_retried_through_the_guards_intent_form`;
  - `tests.test_ahc_crash.NamedPointTests` with `r3.settled`.
- *Changed expectations.* Round 2's `test_f5_an_unconfirmed_cleanup…` and `test_f6_w20…` asserted that the barrier intent stayed `open` or `started`. It is now `stopping`. The barrier itself (no second unit, nothing terminal until confirmed) is asserted unchanged.

**F2, the snapshot base (high), fixed.** peer_review takes its snapshot base only from `--snapshot-base`; `--base` is the commit-policy range. The R3 row (docs/spec/ahc-m1-state-machine.md, R3) binds "`--expected-head H` with snapshot base B_r, `--base B_r`". `r3_command` now passes `--snapshot-base B_r --base B_r`, both inside the launch digest.
- *Tests.*
  - `RuntimeTests.test_rescue_f2_the_r3_command_line_names_b_r_as_the_snapshot_base_inside_the_digest`.
  - `R3SnapshotBaseTests.test_rescue_f2_the_real_helper_reviews_b_r_to_h_when_b_r_is_not_h_first_parent` runs the committed peer_review.py with the bound argv on a fixture where B_r is not H^1, with fake reviewer CLIs, and asserts the snapshot base and the reviewer's `git diff B_r HEAD`. At f532d495 the report showed H^1.
- *Stated test deviation.* The `--github-repo/--pr` pair is removed from that run. The harness's merge-gate hook forbids a subagent from running a GitHub-bound PR review, and the binding is a GitHub read that does not touch the snapshot.

**F3, the production AC-8 path.**
- (a) A `--user` policy without `sandbox_repo` refuses. This conforms to spec r9 line 116: "R-c is allowed only for the repo the policy record names as the sandbox".
- (b) and (c), the wrapper and the output grant, are deferred to goodqa#16274 and goodqa#16275. This is main's ruling (ASSUMPTION, an agent message, relayed by the coordinator owner), recorded as part of A-1. Line 116 requires production to fail closed to infra-wait "where isolation is unavailable", which it does. AC-12 (line 120) cannot pass without them, so they are forced before live.
- New pin: `RuntimeTests.test_rescue_a1_every_production_r3_launch_goes_to_infra_wait_while_the_wrapper_is_absent`. It goes through `LiveDeps.review_stage` with `SystemdRunner.available` forced true, and asserts no intent, no charge and no start. A positive control (a wrapper file present) builds the production runner.

**F4, the Linux live legs.** Out of scope for this merge, per main's ruling quoting spec r9 line 101 ("Out: Running live, and real systemd units. AC-12 is the gate before live.") and line 120 (AC-12 is "required before the coordinator runs live and not before the integration merge"). The run kit stays shipped. The focused unit suites, MigrationV5Tests included, also ran on t2-dev at the rescue head (see the packet). That is unit-level Linux evidence, not the AC-12 live gate.

**ASSUMPTIONs added by the rescue (unconfirmed).**
- *A pre-release v5 ledger is refused.* `launch_intents` is new in v5, and `CREATE TABLE IF NOT EXISTS` never alters an existing table. A v5 ledger written by a pre-rescue build therefore has a CHECK that refuses `stopping`, and `Ledger._check_intent_lifecycle` refuses to open it. No such ledger is expected outside test fixtures, because slice 1 (b) was never installed.
- *An unlisted unit is still stopped once.* A non-terminal intent whose unit systemd does not list is retired through the same stop-then-show path. A stop of an unloaded unit is harmless, and its show reports inactive.
- *An admitted B_r that is not an ancestor of H now fails closed.* peer_review refuses such a `--snapshot-base`, so the unit ends without a FINAL and the row goes outcome-unknown. Before F2 the reviewer silently diffed H^1..H. Admission does not check that B_r is an ancestor of H; that is a follow-up, not fixed here.

**Variants.**
- Eighteen anchors moved onto the rescue code with the same mutation intent. They cover NEG-22 (2), NEG-25, NEG-36 (2), NEG-49, option A's two R7 mutations, test_r03's `--author-harness`, F4 (3), F5 (4) and F6 (2).
- Three new entries:
  - "PR 272 rescue F1 …" (8 mutations, including "Result=success counts as a confirmed stop");
  - "PR 272 rescue F2 …" (2);
  - "PR 272 rescue A-1 …" (1).

## Owner rulings carried in this build (agent messages, ASSUMPTION)

- **(a)** The Mac only.
- **(b)** The shadow list is agent-harness only. This is main's ASSUMPTION.
- **(c)** The maint lock is named `ledger.sqlite3.maint` (D-1), citing goodqa#16049 comment 1cfb71d8.
- **(d)** The AC-13 tests live in tests.test_ahc_guard (D-12).
- **(e)** The helper sha is bound to ahc_release.json `helpers`. Done in b5b8b64, which replaces D-13.
- **(f)** The Linux-only legs are PENDING_REAL_TEST on t2-dev, and the PR is held until t2-dev clears.
- **(g)** GoodQA reader option A: `shadow_parts` stays fail-closed (no reader), so live shadow admits nothing. Follow-up goodqa#16262.
- **(h)** The canary is never sent in shadow.

## Builder ASSUMPTIONs added in build 2

- **AC-7.** Live W21 is inert: LiveDeps passes `w21=None` until goodqa#16262.
- **AC-7 successor at H'.** A resolved send's H' is reviewed with core's own R2 packet against B_r = the tip the send merged.
  - That tip must equal `H'^2` in core's clone, or the move waits (fail closed). The successor's code rows are queued in the move's transaction, at round 1, so no B7 round is charged. B33 is charged at its R3 intent.
  - When no send resolved, the owner's held request is still required (W4 waits).
- **AC-8 R3.**
  - The DynamicUser uid is read as the owner of the unit's main process (/proc, Linux).
  - The provider launch flags stay inside the bound peer_review helper.
  - `--collect` together with `RemainAfterExit` keeps the unit readable until core stops it. This is a Linux leg.
- **AC-8 R2.** A git read over 4 MiB fails the build. The packet text must also fit peer_review's packet budget, which is checked by peer_review itself.
- **AC-8 R-c.** A `--user` scope launch is allowed only for `ReviewStage(sandbox_repo=…)`; production names none.
- **AC-11 under AC-13.**
  - The open-file probe runs through the active policy's lsof/fuser form: resolved executable, minimal env, cwd at the root, and checked before launch.
  - `Ledger._migrate_guarded` opens `policy.migrating` for the migration only. Before this change, a daemon migration under the installed guard was refused (cwd `/`, gate closed).
- **AC-12.** The run kit is scripts/ahc_ac12_live_gate.py. It is not run. It needs a Linux host main names (t2-dev).
  - Its probe unit carries the R3 template's properties: `RuntimeMaxSec` (300 s for the probe; the daemon uses 3600), `ReadWritePaths` (one fresh 0700 directory), DynamicUser, RemainAfterExit, NoNewPrivileges, PrivateTmp and `--collect`.
  - Its socket sits under the daemon root's `sock/` (default `~/.agent-harness/ahc/sock/ac12-<id>.sock`), as core's `review.sock` does in production.
  - Before any unit starts, the kit reports any directory above the socket that denies search to other uids (exit 3, "path: … not traversable by other uids"). The production root is created 0700, so on a default layout this check is expected to fire, and that result *is* the PRT-peercred socket-reachability finding.
  - A unit that never connects is reported as "kit: no connection within 60s" with its ActiveState/Result (exit 4). Both results are kept apart from the four legs, so a kit or path failure is never read as a daemon peer-uid fault. Tests: test_ahc_guard.Ac12KitTests.

## Spec Verify-by → test path

| AC | r9 Verify-by | Where the tests are |
|---|---|---|
| AC-1 | tests.test_ahc_observe | tests/test_ahc_observe.py ProducerTests (NEG-33/34 variants proven in 221fc5b) |
| AC-2 | tests.test_ahc_observe | tests/test_ahc_observe.py ChecksEvidenceTests |
| AC-3 | tests.test_ahc_runner | ShadowBoundaryTests, ShadowIntegratedTests, and ReviewTickTests (zero mutating gh with R3 in the tick) |
| AC-4 | tests.test_ahc_runner tests.test_ahc_crash | ShadowTickTests; test_ahc_crash NamedPointTests (tick.observed, w21.before_send, w21.after_send, r3.unit_started) |
| AC-5 | tests.test_ahc_runner.StateMachineTests | as named |
| AC-6 | StateMachineTests | as named (W16 tests) |
| AC-7 | tests.test_ahc_runner | W21Tests; ShadowTickTests.test_ac7_w21_successor_at_h_prime_gets_core_r2_packet_with_b_r_parent2 |
| AC-8 | tests.test_ahc_contracts tests.test_ahc_runner | RuntimeTests (test_r02 x2, test_r03 x3, test_r04 x4, test_r05, test_r07, NEG-22, NEG-36); ReviewTickTests; StartupReconcileTests; PENDING_RUNTIME = () |
| AC-9 | StateMachineTests | the test_b_* tests |
| AC-10 | tests.test_ahc_clock | ClockTests, BootIdTests (Linux leg PENDING_REAL_TEST) |
| AC-11 | tests.test_ahc_runner MigrationV5Tests | MigrationV5Tests; test_ahc_guard.MigrateProbeTests (Linux leg PRT-mig-v5) |
| AC-12 | run kit checklist on goodqa#16049 | scripts/ahc_ac12_live_gate.py (not run) |
| AC-13 | tests.test_ahc_runner (NoModelInDaemonTests) | **tests/test_ahc_guard.py** (D-12): NoModelInDaemonTests, LegacyProductionPathTests, OrphanRecoveryTests (NEG-49), MigrateProbeTests |
| AC-14 | tests.test_ahc_runner EgressTests | as named |
| AC-15 | tests/variants/ahc_slice1b_variants.py | run outputs in the PR packet |
| AC-16 | tests.test_ahc_runner | MigrationV5Tests / review identity tests |

## PENDING_REAL_TEST (t2-dev unless named)

| Id | What is pending |
|---|---|
| PRT-r3-wrapper | goodqa#16274; AC-12 gate |
| PRT-r3-grant | goodqa#16275; AC-12 gate |
| PRT-peercred | SO_PEERCRED and real systemd units, including RemainAfterExit/--collect and socket reachability for the dynamic uid |
| PRT-bootid | /proc boot_id (AC-10 Linux leg) |
| PRT-mig-v5 | MigrationV5Tests on Linux (AC-11 Linux leg) |
| PRT-ac1-trunc | the AC-1 live truncation probe (D-20) |
| PRT-obs-pages | live API page delimiting (D-21) |
| AC-12 | the run kit on the host main names; REALLY_TESTED there |

## Earlier entries (build 1, deduplicated from the builders' WALs and CP64-CP68)

The earlier entries are listed below. Each was ruled by an agent, unless a main ruling (itself an agent message) is cited.

**Schema and migration**
- D-1: the maint lock is `ledger.sqlite3.maint`, not `ledger.maint`. It is CONTRA and covered by ruling (c).
- D-2: NEG-43's stray-ledger test uses a raw connect at the publish seam.
- D-3: pre-v5 rows get no timer rows, so they are treated as unknown elapsed.

**Clock**
- D-4: the Gate 1 lease, D20 and pruning stay on the wall clock (#16245).
- D-5: the macOS boot id. Resolved at 518af18.

**Notices**
- D-6: E12's comment is a ticket-kind outbox row, never delivered.
- D-7: inert rows are announced as one digest notice per finishing move.

**Bounds**
- D-8: B33_RUNS is 8 unless the policy sets `b33`.
- D-9: W12's independence lists come from the GoodQA reader.

**W16**
- D-10: the W16 proof id is derived from the argv digest, the boot id and the boot clock.

**File names**
- D-11: the authority log and digest names sit inside `ledger.sqlite3.*`.

**AC-13 launch guard**
- D-12: the AC-13 tests are in tests.test_ahc_guard. CONTRA; ruling (d).
- D-13: replaced by ruling (e) (b5b8b64).
- D-14: the helper env takes a key allowlist with values snapshotted at start.
- D-15: the trusted directory list.
- D-16: no GH_TOKEN in production.
- D-17: resolved in da2098c. The tick raises guard incidents.
- D-18: the four SAFE `core.*` pairs. Per main.
- D-19: the posix_spawn audit note.

**Producer**
- D-20: the AC-1 live truncation probe is pending.
- D-21: API pages are delimited on fixtures only.
- D-22: a check run plus a status counts as a duplicate.
- D-23: every rerun attempt must pass.
- D-24: the observation row cap is 200,000.
- D-25: no fetch credentials (T12, #16240).

**Process**
- D-26: the variant harness mutates in place. Never run it beside another suite in the same checkout. Build 2 runs variants in a separate copy.
- D-27: the suites run on the Mac; t2-dev is held for disk.
- D-28: build order.
- D-29: ticket triage. Filed: #16234-#16245. Folded in: T1/R8-1, T11, R9-3 and L-r4-1.

## Invariants kept

- Zero mutating GitHub calls on every path except W21 with its flag on. W21 is live-inert.
- No E2 dispatch.
- A daemon PASS is never a merge authorization.
- ahc never calls the main stamp or waiver helpers.
- Truncated, stale or unknown inputs fail closed.
- The daemon makes no model call. R3 runs peer_review in its own unit, under B33.
