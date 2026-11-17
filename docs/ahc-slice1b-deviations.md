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
- no fresh directory.

**A-2. The R5 exemption covers `tests/data/review_diagnostics_hostile.json`.** This file has exposure-tier findings (a key-block shape and a token tail).
- *How it was confirmed synthetic, without printing values.* The fixture predates this slice: commits f119894 and 117e8af, peer-review stream. Its own `_comment` says it holds hostile values interpolated into printed diagnostics, read only by tests/test_review_diagnostics.py. Its fields are named `private_key_block` and `fake_token_tail`. tests/test_review_diagnostics.py loads it to test redaction.
- *Owner condition.* The entry pins the file's sha256, so any edit drops the exemption and the scan fires (tests/test_ahc_scan.py, CleanCorpusTests).
- *Follow-up for that stream.* Build the values at run time.

**A-3. The tick schedules R3.** This is an owner ruling. One slot per tick, oldest offerable row first. Live shadow stays inert until a GoodQA reader exists (goodqa#16262, ruling g); after that the path is complete, apart from A-1's two PENDING_REAL_TEST items.

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
