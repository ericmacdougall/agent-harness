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
FAST = ['StoreTests', 'ResetParsing', 'RecordOnQuota', 'LoopSkip', 'AttemptLines', 'BusyPool', 'HolderStatusStore',
        'AhcDaemonClasses']
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
        'usage_guard.py', [(r"(?:Z|[+-]\d{2}:?\d{2}))'", r"(?:Z|[+-]\d{2}:?\d{2})?)'"),
                           ('return value.timestamp() if value.tzinfo is not None else None', 'return value.timestamp()')],
        None, ['ResetParsing']),
    'a finished holder counts as busy': (
        'usage_guard.py', "busy = (not finished and liveness['state'] != 'DEAD'", "busy = (liveness['state'] != 'DEAD'",
        ['HolderStatusStore']),
    'a relative time anywhere in the text is trusted': (
        'usage_guard.py', 'match = _RESET_RELATIVE.match(text)', 'match = _RESET_RELATIVE.search(text)', ['ResetParsing']),
    'a busy last pool is not waited for': (
        'peer_review.py', 'may_wait=provider != primary or not later_open,', 'may_wait=False,', ['BusyPool']),
    'a dead holder is waited for': (
        'peer_review.py', "            if kind != 'busy':\n                raise",
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
    'a holder without a parseable deadline counts as busy': (
        'usage_guard.py', "and not liveness['past_deadline']\n                and 'deadline' in liveness)",
        "and not liveness['past_deadline'])", ['HolderStatusStore']),
    'no clamp to now + cap when a record is read': (
        'usage_guard.py', "return {**value, 'until': min(value['until'], now + AVAILABILITY_MAX_SKIP_SECONDS)}",
        'return value', ['StoreTests']),
    'a limit recorded during the wait is launched into': (
        'peer_review.py', '                    late = availability_skip(availability, provider, pool)\n',
        '                    late = None\n', ['BusyPool']),
    'a limit recorded before an unwaited acquire is launched into': (
        'peer_review.py', '                    late = availability_skip(availability, provider, pool)\n',
        '                    late = availability_skip(availability, provider, pool) if waited else None\n',
        ['BusyPool']),
    'a live holder past its deadline gets reconcile advice': (
        'peer_review.py', "    if status.get('finished') is True or status.get('state') == 'DEAD':",
        "    if status.get('finished') is True or status.get('state') == 'DEAD' or status.get('past_deadline') is True:",
        ['BusyPool']),
    'the unknown line names no inspect command': (
        'peer_review.py', "if isinstance(reference, str) and START_REFERENCE.fullmatch(reference)", 'if False',
        ['BusyPool']),
    'holder_status gives no START reference': (
        'usage_guard.py', "'start_reference': '%s:start:%s' % (run_id, start_sha)}", "'start_reference': None}",
        ['HolderStatusStore']),
    'the preflight checks Claude under the Codex pool': (
        'peer_review.py', "'claude': options.get('fallback_pool', 'default'),", "'claude': options.get('pool', 'default'),",
        CLI),
    'a pool wait spends no aggregate time': (
        'usage_guard.py', "                    spent += elapsed\n                    if zero_launch_attempt(record):",
        "                    if not zero_launch_attempt(record):\n                        spent += elapsed\n"
        "                    if zero_launch_attempt(record):", ['HolderStatusStore']),
    'ahc stops on a recorded skip': (
        'ahc_runner.py', 'if code in ("PROVIDER_USAGE_LIMIT", "PROVIDER_SKIPPED"):', 'if code == "PROVIDER_USAGE_LIMIT":',
        ['AhcDaemonClasses']),
    'ahc stops on a busy pool': (
        'ahc_runner.py', 'if code == "POOL_BUSY":', 'if False:', ['AhcDaemonClasses']),
    'the skip line has no reset time ahc can read': (
        'peer_review.py', "skipped until it resets at %s (%s)'", "skipped until %s (%s)'", ['AhcDaemonClasses']),
    'a holder of unknown state gets reconcile advice': (
        'peer_review.py', "        return 'stale'\n    return 'unknown'", "        return 'stale'\n    return 'stale'",
        ['BusyPool']),
    'an unreadable holder status keeps the old reconcile advice': (
        'peer_review.py', "    except Exception as error:  # noqa: BLE001\n        status = {'run_id': run_id, 'busy': False, 'unreadable': True,",
        "    except Exception as error:  # noqa: BLE001\n        return None\n        status = {'run_id': run_id, 'busy': False, 'unreadable': True,",
        ['BusyPool']),
    'a holder of unknown state is waited on': (
        'peer_review.py', "        return 'stale'\n    return 'unknown'", "        return 'stale'\n    return 'busy'",
        ['BusyPool']),
    'a busy run spends a repeat': (
        'usage_guard.py', "ZERO_LAUNCH_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH', 'POOL_BUSY'}",
        "ZERO_LAUNCH_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH'}", ['BusyPool']),
}


def run(tmp, label, classes, *, control=False):
    """True when the selected classes fail by an assertion or error inside a test (a killed mutant), or, for the
    control, when they pass. A tree that fails to import or run counts as neither, so it can never look killed."""
    names = [TEST + '.' + name for name in classes]
    done = subprocess.run([sys.executable, '-B', '-m', 'unittest', *names], cwd=str(tmp), capture_output=True, text=True)
    tail = done.stderr.strip().splitlines()[-3:]
    ran = any(line.startswith('Ran ') and not line.startswith('Ran 0 ') for line in done.stderr.splitlines())
    if control:
        good = done.returncode == 0 and ran
        print('%-64s %s' % (label, 'PASSES (control ok)' if good else 'CONTROL FAILED: ' + ' | '.join(tail)), flush=True)
        return good
    killed = done.returncode != 0 and ran and 'Failed to import' not in done.stderr
    print('%-64s %s' % (label, 'FAILS (good)' if killed else 'NOT KILLED: ' + ' | '.join(tail)), flush=True)
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix='mutant-availability-'))
    shutil.copytree(ROOT / 'harness' / 'hooks', tmp / 'harness' / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(ROOT / 'tests', tmp / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
    return tmp


def main(selected):
    bad = 0
    tmp = tree()
    try:  # the unchanged tree must pass, or no mutant result means anything (red-team F6)
        if not run(tmp, 'control (this tree, unchanged)', FAST + CLI, control=True):
            print('mutants: control failed; nothing below is evidence')
            return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not selected or 'origin/main' in selected:
        tmp = tree()
        try:
            for name in ('peer_review.py', 'usage_guard.py', 'review_diagnostics.py', 'ahc_runner.py'):
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
            pairs = old if isinstance(old, list) else [(old, new)]
            missing = [a for a, _ in pairs if text.count(a) != 1]
            if missing:
                print('MUTANT NOT APPLIED: %s' % name)
                bad += 1
                continue
            for a, b in pairs:
                text = text.replace(a, b, 1)
            path.write_text(text)
            bad += 0 if run(tmp, name, classes) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print('mutants: %d listed, %s' % (len(MUTANTS), 'all killed' if not bad else '%d NOT killed or not applied' % bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
