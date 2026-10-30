# Concurrent WAL creation proof

The [macOS latest-Python CI job](https://github.com/ericmacdougall/agent-harness/actions/runs/41012381601/job/123920922322) failed one of eight concurrent WAL writers with `FileNotFoundError` on an `O_CREAT` open of `main.jsonl`. That run used Python 3.14.9. The original writer at `e47ab48e909c55fa652b1a37ed70dc9a04762af9` failed a deterministic injected one-time `ENOENT` test (exit **1**, one error): [baseline transcript](wal-enoent-before.txt).

Reproduce the first failure from a checkout containing the new tests:

```sh
BASELINE_DIR=$(mktemp -d)
git archive e47ab48e909c55fa652b1a37ed70dc9a04762af9 | tar -x -C "$BASELINE_DIR"
cp tests/test_wal.py "$BASELINE_DIR/tests/"
(cd "$BASELINE_DIR" && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_wal.WalTests.test_transient_missing_file_during_create_retries_without_losing_record -v)
```

Sol found that the first bounded retry at `1c775d7c90e42823443f9aa09f5fd986c0c7addd` could still write to a moved directory if it changed during the short backoff or after open. Five deterministic directory and file replacement tests failed against that commit (exit **1**, five failures): [intermediate transcript](wal-races-before.txt). Reproduce them from a checkout containing the new tests:

```sh
INTERMEDIATE_DIR=$(mktemp -d)
git archive 1c775d7c90e42823443f9aa09f5fd986c0c7addd | tar -x -C "$INTERMEDIATE_DIR"
cp tests/test_wal.py "$INTERMEDIATE_DIR/tests/"
(cd "$INTERMEDIATE_DIR" && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_wal.WalTests.test_retry_refuses_directory_moved_during_backoff \
  tests.test_wal.WalTests.test_open_refuses_directory_moved_before_write \
  tests.test_wal.WalTests.test_write_refuses_directory_moved_before_success \
  tests.test_wal.WalTests.test_open_refuses_log_file_replacement_before_write \
  tests.test_wal.WalTests.test_write_refuses_log_file_replacement_before_success -v)
```

The repaired writer retries only while the named session directory matches its pinned descriptor. It checks the directory and log file identity before writing and after `fsync`. A replacement during a write can leave a record in the moved file, but the hook returns an error rather than claiming that the advertised WAL contains it. External mutation after the final check remains possible.

Sol's next review found that checking the session path alone follows symlinks in its `.claude` and `wals` ancestors. Three new tests replace either ancestor with a symlink during backoff, after open, or during `fsync`; all three failed against `f528b371443a6e826497a429e0076401c38416b5` (exit **1**): [ancestor failure transcript](wal-ancestors-before.txt). The writer now retains directory descriptors for `.claude`, `wals`, and the session, and checks each component through its pinned parent descriptor without following links. Reproduce the failure-first cases from a checkout with the new tests:

```sh
ANCESTOR_DIR=$(mktemp -d)
git archive f528b371443a6e826497a429e0076401c38416b5 | tar -x -C "$ANCESTOR_DIR"
cp tests/test_wal.py "$ANCESTOR_DIR/tests/"
(cd "$ANCESTOR_DIR" && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_wal.WalTests.test_retry_refuses_wals_ancestor_symlink_during_backoff \
  tests.test_wal.WalTests.test_open_refuses_claude_ancestor_symlink_before_write \
  tests.test_wal.WalTests.test_write_refuses_wals_ancestor_symlink_before_success -v)
```

The focused WAL suite passed **26/26**. Thirty separate process-level trials of the original concurrency scenario each launched eight writers and verified 200 parseable, unique records: **6,000 records** total, exit **0**. The stress command from the repaired checkout was:

```sh
python3 - <<'PY'
import subprocess
import sys
command = [sys.executable, '-W', 'error::ResourceWarning', '-m', 'unittest',
           'tests.test_wal.WalTests.test_concurrent_writers_leave_parseable_complete_records']
for trial in range(30):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'trial {trial + 1} failed: {result.stderr}')
print('30/30 trials passed; 6,000 records verified')
PY
```

The full suite passed **144/144** on macOS Python 3.15.0 in **102.189 seconds** and Python 3.9.6 in **88.761 seconds**, both with resource warnings treated as errors: [Python 3.15 transcript](wal-python315.txt), [Python 3.9 transcript](wal-python39.txt). Commands:

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3 -W error::ResourceWarning -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -X pycache_prefix=/tmp/agent-harness-wal-pycache -m compileall -q install.py harness tests
git diff --check
```

Python 3.9 is a supplemental compatibility check; supported versions begin at 3.10. Passing stress trials do not prove the OS cannot return `ENOENT` again. The deterministic tests verify the retry behavior and fail-closed path checks.
