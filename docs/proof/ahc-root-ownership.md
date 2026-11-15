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
  Result: `SUMMARY: 19 variants, 0 did not fail: []`, exit 0.
  Log `variants_root3.out`, sha256 c262021ed6872889960854d29a2471e3b90fa4abd1fa37b8979ce65e39d9dd7f.
- Focused suites:
  `python3 -B -m unittest tests.test_ahc_contracts tests.test_ahc_runner tests.test_ahc_core tests.test_ahc_scan tests.test_redaction tests.test_redact_shapes tests.test_ahc_crash tests.test_ahc_clone tests.test_ahc_packet`
  Result: `Ran 416 tests`, `OK (skipped=1)`, exit 0.
  Log `ev19.log`, sha256 f828413030bb1d97dd4624756067dabe9b3081487b2ca5793b9c2e9e1a613355.

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

## One variant changed meaning during the repair

The variant "marker opened following symlinks" survived its first run on the repair. The new lstat type check of
every top-level entry also refuses a symlinked `.ahc-root`, so the marker's `O_NOFOLLOW` is now a second layer at
start. It still guards against a swap between the check and the open. The variant now drops both layers.
