# ahc root ownership: test and variant evidence (goodqa#16049, PR 258)

Reproducible counts for PR 258 and its v1 BLOCK repair. The logs are kept outside the repository, in the owner's
work directory, so only their SHA-256 values are recorded here. Run on a Mac with Python 3.9.6.

## Commands

Run each from the repo root.

- Failing first: the repair's tests against the hooks at cbe43e6d (the head that was blocked), in a scratch tree:
  ```
  git archive cbe43e6d harness/hooks | tar -x -C <scratch>
  cp tests/test_ahc_core.py tests/test_ahc_clone.py <scratch>/tests/
  touch <scratch>/tests/__init__.py
  cd <scratch>
  python3 -B -m unittest tests.test_ahc_core.RootOwnershipTests tests.test_ahc_clone.CloneLinkTests
  ```
  Result: `Ran 31 tests`, `FAILED (failures=62, errors=13)`, exit 1.
  Log `ff258.log`, sha256 ff50de48d929a208b660639a482391d6a1366dcd661176b398f62d793e71e156.
- Variants: `python3 -B tests/variants/ahc_root_variants.py <out>`
  Result: `SUMMARY: 20 variants, 0 did not fail: []`, exit 0.
  Log `variants_root4.out`, sha256 9d99e0ae8eee733e7b8e6885cc7d0c767a3dc6e1a2f999a19a4a7969501a9b57.
  (The 19-variant run before the shared-dir test was added: `variants_root3.out`, sha256
  c262021ed6872889960854d29a2471e3b90fa4abd1fa37b8979ce65e39d9dd7f.)
- Focused suites:
  `python3 -B -m unittest tests.test_ahc_contracts tests.test_ahc_runner tests.test_ahc_core tests.test_ahc_scan tests.test_redaction tests.test_redact_shapes tests.test_ahc_crash tests.test_ahc_clone tests.test_ahc_packet`
  Result: `Ran 417 tests`, `OK (skipped=1)`, exit 0.
  Log `ev20.log`, sha256 6a3e78b8f281d9d7bdebd70ae87fa68ad91a3535195609e04f6c3b13f4c364c5.

## PR 258 v3 BLOCK repair (heads 675be534 and 8d3b4ae2)

Run on a Linux worker host (Python 3.12.3, git 2.43.0) by `~/wt/ahc-pr258v3.sh <head> <old head>`. The script makes a fresh
blob-filtered clone under `~/wt`, refuses to start with less than 30 GiB free, and keeps logs in the run directory.

- Focused suites at 8d3b4ae20f826fe96b0520891b6baec8ec4bd4ef: the nine above plus `tests.test_ahc_fs` and
  `tests.test_install_ships_modules`. Result: `Ran 461 tests`, `OK (skipped=1)`, exit 0.
  Log `suites.log`, sha256 c20d7ce5e4c6f0ab37706b6faee2da55115a0e26a074ed121f9decd475af29ec.
- Failing first: the hooks at 367c6c14 (the head the v3 receipt blocked) with the new tests. The tests are
  `test_ahc_fs.PathWriteScanTests`, `test_ahc_clone.CloneReuseHardeningTests` and `CloneLinkTests`,
  `test_ahc_core.RootOwnershipTests`, the runner report-directory test and `FileTransportOptInTests`.
  Result: `Ran 61 tests`, `FAILED (failures=53, errors=12)`, exit 1.
  Log `failing_first.log`, sha256 7ae062b80a3cf366d920e9ad4c80779d57bba663a979158508fa7a06d3b20b5c.
  - Defects at 367c6c14:
    - `ForeignRoot` not raised (32): loose root and dir modes, a foreign uid, loose ancestors;
    - the clone not quarantined (11), and git breaking on planted packed-refs, shallow and refs;
    - a hard-linked report and a report with an extra entry routed as PASS;
    - the file transport opt-in not honoured or not refused;
    - path-based writes found by the scan.
  - From APIs that did not exist at that head:
    - 5 `_append_private` signature TypeErrors, from the shared-dir regression guard;
    - 1 missing `canonical_config_text`;
    - 1 old report path layout.
- Variants: `SUMMARY: 44 variants, 0 did not fail: []`, exit 0.
  Log `variants.out`, sha256 b76aad9d2861416cac14732218efd0c5b391ae3f44288c70822eeea6bc8b1174.
  - The first run at 675be534 (39 variants) left 3 alive, and 8d3b4ae2 fixed all three:
    - "symlinked root followed" and "a link inside .git is accepted" each had a second layer, so the variants now
      drop both;
    - the git-env test was vacuous, because the fixture env already isolated git, so it now passes a hostile env.
  - That first run's log is `variants.out` at 675be534, sha256
    6e1f5b2200fe27a3d434341d17c53de45d12e0695e0bd0399025090c18f971a8.
- Mac, Python 3.9.6, at 8d3b4ae2: `tests.test_ahc_crash`, `CloneReuseHardeningTests`, `FileTransportOptInTests`,
  `IngestValidationTests` and `tests.test_ahc_fs`. Result: `Ran 60 tests`, `OK (skipped=1)`.

v3 variants:
- F1: path-based writes in claim_root and in the clone config;
- F2: no owner or mode check of the root or its dirs, and no ancestor rule;
- clone (D4): the allowlist, the bounds, quarantine, the hardened env, the umask, the private clone dir and the
  transports;
- report: the inode compare, the only-entry check, the single link, the size cap and quarantine of a failed
  attempt;
- the file transport opt-in honoured for the production root.

## PR 258 v4 BLOCK repair: F1, a streamed restore (heads 0dc0ca99 and 2049e625)

Run on a Linux worker host (Python 3.12.3, git 2.43.0) by `~/wt/ahc-pr258v4.sh <head> <old head>`, in a fresh blob-filtered
clone. The script refuses to start under 30 GiB free.

- Focused suites at 2049e6254c300cf57b7491e3097ee770f3799ca5, the eleven above plus
  `tests.test_install_ahc_modules` (PR 263, now on this branch): `Ran 471 tests`, `OK (skipped=1)`, exit 0.
  Log `suites.log`, sha256 10ca214a10879f61a478c9d5f5f0d66ad005b71b27dc10565126f4e7617f94e6.
- Failing first: `tests.test_ahc_runner.SchemaTests` and `tests.test_ahc_fs.RootFsTests` against the hooks at
  ec1ff5d6, the head the v4 receipt blocked plus PR 263. Result: `Ran 33 tests`,
  `FAILED (failures=3, errors=5, skipped=1)`, exit 1.
  Log `failing_first.log`, sha256 5d02188f304c0ddcee42b152cd8d5316e0d4e1a62066b2331219a90a2079b398.
  - Defects at ec1ff5d6:
    - the restore held 17,098,290 bytes for an 8,388,608-byte backup, against a 4 MiB budget;
    - a lost backup raised `Unreadable` from `read_regular` after the live database had already been moved aside;
    - an over-cap ledger was migrated;
    - a partial temp copy was left behind.
  - From new APIs: `copy_to_temp`, `remove_temps` and `TooLarge` (4 errors).
- Variants: `SUMMARY: 51 variants, 0 did not fail: []`, exit 0, and no variant timed out.
  Log `variants.out`, sha256 0c5142214e5b339a950008d122834d9de525bea2c291d50d8dafe8a63b1943de.
  - The run at 0dc0ca99 stopped on a 900 s TimeoutExpired. The "no cap" variant met a test whose mocked read never
    ended. 2049e625 bounds that mock and records any hang as `rc=timeout`.
- Mac, Python 3.9.6, at 0dc0ca99 before the fast-forward: `tests.test_ahc_crash`, `tests.test_ahc_fs` and
  `tests.test_ahc_runner.SchemaTests`. Result: `Ran 48 tests`, `OK (skipped=1)`.

v4 variants:
- the copy reads the whole backup at once;
- the live database is moved aside before the copy;
- the intent is kept after a copy failure;
- there is no size check before the migration;
- the partial temp is not removed;
- copy_to_temp enforces no cap;
- remove_temps matches any name.

## PR 258 v5 BLOCK repair: F1, a restore resumed from its files; F2, honest variant counts

The receipt `harness-pr258-v5` (reviewed head e4fc5ce4) blocked on two findings:
- F1 (High): `_resume_restore` refused when the intent's backup was not a file, before the safe abandon could
  run. A crash right after the intent was written, with the backup then gone, stranded an intact live ledger:
  every later start refused.
- F2 (Medium): the variants runner skipped a timed-out variant without counting it, and always exited 0.

The counts, logs and their SHA-256 values for this repair are in the PR 258 v5 delta packet and the ticket, not
here, so this file does not move the validated head. Commands, from the repo root:

- The recovery table: `python3 -B -m unittest tests.test_ahc_crash.RestoreRecoveryTableTests`. Seven real crash
  points of a restore (before the intent, after it, mid-copy, after the fsync, after the move, after the publish,
  after the intent is dropped) x the backup present, missing or partial x the live ledger present or absent: 42
  rows. Each crash state comes from a real crash child and is checked for its expected file shape first, so a
  code version without that crash point fails as "another state", never as a wrong outcome.
- The whole crash matrix, which also crashes inside the resume itself (six `resume-*` scenarios):
  `python3 -B -m unittest tests.test_ahc_crash`.
- Failing first: the tests against the hooks at e4fc5ce4, in a scratch tree:
  ```
  git archive e4fc5ce4 harness/hooks | tar -x -C <scratch>
  mkdir <scratch>/tests && cp tests/*.py <scratch>/tests/
  cd <scratch>
  python3 -B -m unittest tests.test_ahc_crash tests.test_ahc_runner.SchemaTests tests.test_ahc_fs.RootFsTests
  ```
  Most table rows fail there on their shape check (e4fc5ce4 has no mid-copy, publish or intent-removal seam). The
  rows that fail on behavior are the receipt's exact sequence (it refuses "names no backup beside the ledger"), a
  partial backup published over the intact ledger (it no longer opens), and a staged copy left behind. The v4
  residual (a found publish moved aside over the failed database) and the foreign-file refusal fail first in
  `SchemaTests`, not in the table.
- The variants runner's own tests: `python3 -B -m unittest tests.test_ahc_root_variants`. Failing first: seven
  controlled broken runners, e4fc5ce4's exit-0 and skipped-timeout behavior among them, each run against these
  tests.
- Variants: `python3 -B tests/variants/ahc_root_variants.py <out>`. It exits 0 only when every variant was caught.

Decisions in this repair:
- The intent records the proven backup's SHA-256 (`Ledger.backup` streams it after the integrity and row-count
  proof). A copy is published only if its bytes hash to it, so a partial or changed backup is never published.
- A failed copy with the live ledger never moved abandons the restore: the intent is dropped, a warning is logged,
  and the start goes on with that ledger; its migration is retried with a fresh verified backup. `restore()`
  itself still raises (`RestoreAbandoned`, a `SchemaError`).
- An intent from an ahc before v5 has no `sha256`; its backup is never published (see docs/ahc.md).
- Every move-aside target is checked before the copy and before the first rename. That replaces v4's separate
  "the file at the ledger's name is not the verified backup" refusal, which the same check covers.
- A backup name in the intent must be `[A-Za-z0-9._-]+` and the suffix `.failed-` plus ASCII digits.
- The runner reports four outcomes: caught, survived, timed out and broken (no tests ran, an import failed, or
  another exit status). Only "caught" passes. A timeout kills the test command's process group, and a `.vs.bak`
  left by an interrupted run stops the run instead of being overwritten.
- Two crash-matrix checks changed. `committed_events` skips a copy SQLite cannot read (a backup cut short holds
  no committed rows). The restart may write the before-migration row itself (phase "resume") only when no such row
  had committed at the crash.

v5 variants:
- the backup's availability checked before the files decide (the receipt's defect);
- a failed copy abandons even with no live ledger;
- no digest asked for, or `copy_to_temp` ignoring it, or the backup's digest not recorded;
- a found publish not recognised, and the whole v4 residual (also renaming over a taken target);
- a taken move target renamed over, or targets checked only as each is renamed;
- a `-journal` left beside the restored copy;
- an abandoned resume that stops the start;
- a control character in the backup name, or non-ASCII suffix digits, accepted;
- an undigested record that trusts the backup's current bytes, or strands a never-moved live ledger.

## What the variants break

Each variant is a unique text swap applied to one source file, and the source is restored after the run.

Ownership checks (PR 258 v1):
- `ensure` only makes directories;
- the root is back at `~/.agent-harness/coordinator`;
- an unmarked non-empty root is claimed;
- there is no foreign-entry check in a marked root;
- the marker's content is not verified;
- a symlinked root is followed;
- a symlinked marker is accepted, because both layers are dropped: the marker is opened following links and is
  also exempt from the type check;
- an interrupted claim's temp marker is refused;
- the marker is written in place;
- `main()` does not claim the root.

v1 BLOCK repair:
- names are checked without lstat;
- the entry check follows links;
- state directories are not walked;
- there is no strict tree;
- shared directories are walked strictly;
- a clone's `.git` is not checked;
- the ledger is opened by plain `sqlite3.connect`;
- there is no device and inode comparison after the open;
- clone `prepare` follows a linked clone directory.

Shared directories (spec owner's condition 1 on PR 258 v2):
- a linked report name is not refused at its operation.

`IngestValidationTests.test_links_in_every_shared_dir_are_refused_at_their_operation_while_ahc_keeps_serving`
plants a link in each shared directory at once. It fails under this variant and under "shared directories walked
strictly". At cbe43e6d it is a regression guard, not a failing-first test, because the per-operation checks
already existed there.

## One variant changed meaning during the repair

The variant "marker opened following symlinks" survived its first run on the repair. The new lstat type check of
every top-level entry also refuses a symlinked `.ahc-root`, so the marker's `O_NOFOLLOW` is now a second layer at
start. It still guards against a swap between the check and the open. The variant now drops both layers.
