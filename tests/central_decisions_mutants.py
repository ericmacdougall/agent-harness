#!/usr/bin/env python3
"""Controlled broken variants of the central-decision code (goodqa#16651). Each variant edits one rule in a COPY of
the repository's harness/hooks, install.py and tests (the checkout is never modified), runs the named test modules
against the copy, and must make them FAIL. Exit 0 only when every variant is killed.

  /usr/bin/python3 tests/central_decisions_mutants.py [--only NAME ...]

Not collected by unittest discovery (no test_ prefix). Earlier rounds' variants are kept so a regression of an
older control is caught too."""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CD, GATE, PH, PROV = ('harness/hooks/central_decisions.py', 'harness/hooks/tier_gate.py',
                      'harness/hooks/provenance_hooks.py', 'harness/hooks/provenance.py')
INSTALL = 'install.py'
TESTS = ('tests.test_central_decisions',)

# (name, file, old, new): `old` must occur exactly once.
VARIANTS = [
    # earlier rounds
    ('skip-signature', CD, "        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, signed_message(issue_id, payload_raw))", "        pass"),
    ('skip-revocation', CD, "        if any(covers(r, p) for r in revokes):\n            reasons.append('revoked'); continue", "        pass"),
    ('loose-task', CD, "        if p['task'] != task:\n            continue", "        if not task.startswith(p['task'][:2]):\n            continue"),
    ('skip-later-scan-at-publish', CD, "        if later_mentions(session, turn, home):", "        if False:"),
    ('skip-time', CD, "            if not _time_ok(p, now):", "            if False:"),
    ('skip-family', CD, "        if family not in p['families']:", "        if False:"),
    ('no-archived-revokes', CD, "            match = REVOKE.fullmatch(body.strip())\n            if match:", "            match = REVOKE.fullmatch(body.strip())\n            if match and not item.get('archived'):"),
    ('no-tombstones', CD, "    revokes = revocations + local_tombstones(store)\n    per_turn", "    revokes = revocations\n    per_turn"),
    ('no-issue-binding', CD, "    return DOMAIN + issue_id.encode('ascii') + b'\\x00' + payload", "    return DOMAIN + payload"),
    ('prior-tier-gate', GATE, "        if 'value' not in central:", "        return False\n        if 'value' not in central:"),
    ('no-turn-cap', CD, "    if task not in tasks and len(tasks) >= PER_TURN_CAP:", "    if False:"),
    ('verify-ignores-caller-cap', CD, "            if max_age_seconds is not None and now - parse_time(p['assent_at']) > max_age_seconds:", "            if False:"),
    ('no-do-not-opener', CD, r"""BARE_WITHDRAWAL = re.compile(r"\s*(?:stop|cancel|revoke|withdraw|no|do\s+not|don'?t)\b", re.I)""", r"""BARE_WITHDRAWAL = re.compile(r"\s*(?:stop|cancel|revoke|withdraw|no|don'?t)\b", re.I)"""),
    # this round (PR 14 round-2 class A: every withdrawal channel reaches the ledger)
    ('answer-hook-ignores-text', CD, "    return on_hook_event(session, text=text, unreadable=text is None, claude_home=claude_home, store=store,", "    return on_hook_event(session, text=None, unreadable=False, sweep=False, claude_home=claude_home, store=store,"),
    ('unreadable-answer-allowed', CD, "        if unreadable:\n            targets = dict.fromkeys(live, 'unreadable-answer')", "        if False:\n            targets = {}"),
    ('no-transcript-sweep', CD, "        elif sweep:\n            for turn in sorted(set(live.values())):", "        elif False:\n            for turn in sorted(set(live.values())):"),
    ('sweep-fails-open', CD, "                    late, why = True, 'transcript-unreadable'", "                    late, why = False, 'transcript-unreadable'"),
    ('withdraw-queues-only-denied', CD, "    except Exception as error:  # noqa: BLE001  any failure to post (the GoodQA client raises its own types): queue it", "    except Denied as error:"),
    ('withdraw-twice', CD, "                    and row['decision_id'] not in done):", "                    ):"),
    ('predicate-ignores-retract', CD, "        if candidate and (esc.TOP_TERMS.search(candidate) or esc.TOP_RETRACT.search(candidate)", "        if candidate and (esc.TOP_TERMS.search(candidate)"),
    ('stop-lint-no-sweep', PH, '    central_note(session, payload, "stop")  # goodqa#16651 transcript sweep (queued messages); never raises\n', ''),
    ('answer-verb-not-dispatched', PH, '        handler = {"ask-gate": cmd_ask_gate, "stop-lint": cmd_stop_lint, "prompt": cmd_prompt,\n                   "answer": cmd_answer}[command]', '        handler = {"ask-gate": cmd_ask_gate, "stop-lint": cmd_stop_lint, "prompt": cmd_prompt}.get(command, lambda _: {})'),
    ('answer-hook-not-registered', INSTALL, '        "PostToolUse": [{"matcher": "AskUserQuestion", "hooks": [hook("answer")]}],\n', ''),
    ('extractor-reads-rendered-string', PROV, '    answers = result.get("answers") if isinstance(result, dict) else None', '    answers = {"q": result} if isinstance(result, str) else (result.get("answers") if isinstance(result, dict) else None)'),
]
TRUST = 'scripts/trust-central-decisions.sh'
INSTALLER_TESTS = ('tests.test_trust_central_installer',)
INSTALLER_VARIANTS = [
    ('installer-no-match-head', TRUST, ' --merge --match-head-commit "$head" >&2', ' --merge >&2'),
    ('installer-no-head-check', TRUST, 'if fields.get("Reviewed HEAD") != head:', 'if False:'),
    ('installer-no-verdict-check', TRUST, 'if not verdict or verdict.group(1) == "BLOCK":', 'if False:'),
    ('installer-no-parent-check', TRUST, '[[ $parent == "$head" ]] || die', 'true || die'),
    ('installer-publish-before-install', TRUST, '"$REPAIR" --ref "$H_MERGE" --host "$HOST" --check || die "repair-harness preview failed"', 'die "repair-harness preview failed"'),
]


def run(name, rel, old, new, python, tests=TESTS):
    with tempfile.TemporaryDirectory(prefix='cd-mutant-') as temp:
        copy = Path(temp) / 'repo'
        for part in ('harness/hooks', 'tests', 'harness/agents', 'scripts'):
            if (REPO / part).exists():
                shutil.copytree(REPO / part, copy / part, symlinks=True)
        shutil.copy2(REPO / INSTALL, copy / INSTALL)
        target = copy / rel
        src = target.read_text()
        if src.count(old) != 1:
            return name, 'STALE', 'pattern occurs %d times' % src.count(old)
        target.write_text(src.replace(old, new))
        result = subprocess.run([python, '-m', 'unittest', *tests], cwd=copy, capture_output=True, text=True,
                                timeout=300)
        last = (result.stderr.strip().splitlines() or ['?'])[-1]
        failed = [line for line in result.stderr.splitlines() if line.startswith(('FAIL:', 'ERROR:'))]
        return name, 'KILLED' if result.returncode != 0 else 'SURVIVED', last + (' | ' + failed[0] if failed else '')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*')
    parser.add_argument('--python', default=sys.executable)
    args = parser.parse_args()
    ok = True
    plan = [(v, TESTS) for v in VARIANTS] + [(v, INSTALLER_TESTS) for v in INSTALLER_VARIANTS]
    for (name, rel, old, new), tests in plan:
        if args.only and name not in args.only:
            continue
        name, verdict, detail = run(name, rel, old, new, args.python, tests)
        ok &= verdict == 'KILLED'
        print('%-34s %-8s %s' % (name, verdict, detail), flush=True)
    print('ALL VARIANTS KILLED' if ok else 'SOME VARIANTS SURVIVED OR WENT STALE')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
