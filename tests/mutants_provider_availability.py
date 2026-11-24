"""goodqa#17108 failing-first evidence: tests.test_provider_availability must fail against origin/main and against each
controlled broken variant below (one behaviour removed per mutant).

Run: python3 -B tests/mutants_provider_availability.py [name-substring ...]
(copies the hooks and the tests into a temporary tree per mutant; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests.test_provider_availability'
FAST = ['StoreTests', 'ResetParsing', 'RecordOnQuota', 'LoopSkip', 'AttemptLines', 'BusyPool', 'HolderStatusStore']
CLI = ['CommandLine']

# name: (file, old, new, test classes that must fail)
MUTANTS = {
    'a recorded provider is not skipped': (
        'peer_review.py', 'skipped = availability_skip(availability, provider, pool)\n', 'skipped = None\n', FAST),
    'a quota refusal records nothing': (
        'peer_review.py', "        if outcome.get('reason') == 'QUOTA':\n            value = availability.record(",
        "        if False:\n            value = availability.record(", FAST),
    'a local refusal (no launch) records': (
        'peer_review.py', 'if availability is None or launched <= 0:', 'if availability is None:', FAST),
    'an auth failure records as quota': (
        'peer_review.py', "        if outcome.get('reason') == 'QUOTA':\n            value = availability.record(",
        "        if outcome.get('reason') in ('QUOTA', 'AUTH'):\n            value = availability.record(", FAST),
    'a verdict does not clear the record': (
        'peer_review.py', '            availability.clear(provider, pool)\n', '            pass\n', FAST),
    'a skipped fallback is still tried': (
        'peer_review.py', "            if len(order) == 1 or provider != primary:\n                raise ReviewFailure(outcome, source)\n            failure = ('Primary reviewer skipped",
        "            if False:\n                raise ReviewFailure(outcome, source)\n            failure = ('Primary reviewer skipped", FAST),
    'a structured quota still writes the ack-forever pool cooldown': (
        'peer_review.py', "account_cooldown=outcome['account_cooldown'] and not (recorded and outcome['reason'] == 'QUOTA'),",
        "account_cooldown=outcome['account_cooldown'],", FAST),
    'every-provider-skipped preflight removed': (
        'peer_review.py', 'if all(record is not None for _, _, record in skips):', 'if False:', CLI),
    'only the last attempt is printed on failure': (
        'peer_review.py', "        print_attempt_lines(options, always=True)\n        diagnosis = diagnostics.final_diagnostic(",
        "        diagnosis = diagnostics.final_diagnostic(", CLI),
    'an expired record still skips': (
        'usage_guard.py', "if not self._valid(value, provider, pool, now) or now >= value['until']:",
        'if not self._valid(value, provider, pool, now):', FAST),
    'no cap when a record is read': (
        'usage_guard.py', "and until - recorded <= AVAILABILITY_MAX_SKIP_SECONDS + 1)", ')', ['StoreTests']),
    'no cap when a record is written': (
        'usage_guard.py', 'if candidate > now + AVAILABILITY_MAX_SKIP_SECONDS:', 'if False:', ['StoreTests', 'ResetParsing']),
    'a record from the future is trusted': (
        'usage_guard.py', 'return (recorded <= now + AVAILABILITY_CLOCK_SKEW_SECONDS and recorded < until',
        'return (recorded < until', ['StoreTests']),
    'a record for another provider or pool is trusted': (
        'usage_guard.py', "or value['provider'] != provider or value['pool'] != pool ", '', ['StoreTests']),
    'a corrupt record raises instead of reading as none': (
        'usage_guard.py', "        except (GuardError, OSError, ValueError, TypeError, UnicodeError, RecursionError):\n            return None",
        "        except ZeroDivisionError:\n            return None", ['StoreTests']),
    'an ISO time without a zone is trusted': (
        'usage_guard.py', 'return value.timestamp() if value.tzinfo is not None else None', 'return value.timestamp()',
        ['ResetParsing']),
    'a relative time anywhere in the text is trusted': (
        'usage_guard.py', 'match = _RESET_RELATIVE.match(text)', 'match = _RESET_RELATIVE.search(text)', ['ResetParsing']),
    'a busy last pool is not waited for': (
        'peer_review.py', 'may_wait=provider != primary or not later_open,', 'may_wait=False,', ['BusyPool']),
    'a dead holder is waited for': (
        'peer_review.py', "            if status is None or not status.get('busy'):\n                raise",
        "            if status is None:\n                raise", ['BusyPool']),
    'the wait ignores the run budget': (
        'peer_review.py', 'limit = max(0.0, min(POOL_WAIT_SECONDS, wait_limit))', 'limit = POOL_WAIT_SECONDS', ['BusyPool']),
    'a pool that stays busy ends TRANSIENT_INFRA': (
        'peer_review.py', "super().__init__('POOL_BUSY', message)", "super().__init__('TRANSIENT_INFRA', message)", ['BusyPool']),
    'a live holder gets reconcile advice': (
        'peer_review.py', "                busy = getattr(error, 'busy_status', None)\n", "                busy = None\n", ['BusyPool']),
    'a past-deadline holder counts as busy': (
        'usage_guard.py', "busy = (not finished and liveness['state'] != 'DEAD' and not liveness['past_deadline']",
        "busy = (not finished and liveness['state'] != 'DEAD'", ['HolderStatusStore']),
    'a busy run spends a repeat': (
        'usage_guard.py', "ZERO_LAUNCH_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH', 'POOL_BUSY'}",
        "ZERO_LAUNCH_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH'}", ['BusyPool']),
}


def run(tmp, label, classes):
    names = [TEST + '.' + name for name in classes]
    done = subprocess.run([sys.executable, '-B', '-m', 'unittest', *names], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print('%-64s %s' % (label, 'FAILS (good)' if killed else 'PASSES (test is vacuous)'), flush=True)
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix='mutant-availability-'))
    shutil.copytree(ROOT / 'harness' / 'hooks', tmp / 'harness' / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(ROOT / 'tests', tmp / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
    return tmp


def main(selected):
    bad = 0
    if not selected or 'origin/main' in selected:
        tmp = tree()
        try:
            for name in ('peer_review.py', 'usage_guard.py', 'review_diagnostics.py', 'escalation.py'):
                base = subprocess.run(['git', '-C', str(ROOT), 'show', 'origin/main:harness/hooks/' + name],
                                      capture_output=True, check=True).stdout
                (tmp / 'harness' / 'hooks' / name).write_bytes(base)
            bad += 0 if run(tmp, 'origin/main (no change)', FAST + CLI) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    for name, (module, old, new, classes) in MUTANTS.items():
        if selected and not any(part in name for part in selected):
            continue
        tmp = tree()
        try:
            path = tmp / 'harness' / 'hooks' / module
            text = path.read_text()
            if text.count(old) != 1:
                print('MUTANT NOT APPLIED (%d matches): %s' % (text.count(old), name))
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name, classes) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print('mutants: %d listed, %s' % (len(MUTANTS), 'all killed' if not bad else '%d NOT killed or not applied' % bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
