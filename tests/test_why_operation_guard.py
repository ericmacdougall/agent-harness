"""Non-executing regressions for pinned why set-note analysis.

The synthetic script is deliberately not the pinned first-party source. Patching
its digest exercises the recognition contract without publishing private tooling.
"""
import hashlib
import subprocess
from unittest import mock

from test_command_guard import Fixture, cg


SCRIPT = '''#!/usr/bin/env bash
mode=set
case "$mode" in
  show) echo show;;
  clear)
    rm -f "$HOME/.claude/history.jsonl"
    exit 0;;
esac
f=$(note_of "$d")
printf '%s' subject > "$f.tmp"
mv "$f.tmp" "$f"
'''


class WhyOperationTests(Fixture):
    def decide(self, command, cwd='@WT@', **kwargs):
        return super().decide(command, cwd=cwd, **kwargs)

    def setUp(self):
        self.repo = self.home / '.agent-harness/work/S/T/wt'
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.script = self.repo / 'bin/why'
        self.script.parent.mkdir(exist_ok=True)
        self.script.write_text(SCRIPT)
        self.script.chmod(0o700)
        self.pin = mock.patch.object(cg, 'WHY_SET_SCRIPT_SHA256', hashlib.sha256(SCRIPT.encode()).hexdigest(), create=True)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_literal_set_note_is_allowed(self):
        for args in ('-l lane subject', '--lane lane -m 20 -p src/file subject body',
                     '-l lane subject -p src/file -m 0'):
            with self.subTest(args=args):
                self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why ' + args)[0], 'allow')

    def test_non_set_and_uncertain_arguments_keep_analysis(self):
        for args in ('-l lane --clear', '--clear -l lane subject', '-l lane subject --clear',
                     '-l lane --clear --show subject', '--show -l lane subject',
                     '-l lane -h subject', '-l lane --shared subject', '-l', '-l lane -m',
                     '-l lane -m nope subject', '-l lane --unknown subject', '-l ../lane subject',
                     '-l lane "$UNKNOWN"', '-l lane "$(printf subject)"', '-l lane {subject,other}',
                     'subject', '-l lane'):
            with self.subTest(args=args):
                self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why ' + args)[0], 'block')

    def test_untrusted_script_and_invocation_keep_analysis(self):
        for prefix in ('', 'WHY_GIT_DIRS=../.claude ', 'WHY_GIT_DIRS="$UNKNOWN" '):
            self.assertEqual(self.decide(prefix + 'bin/why -l lane subject')[0], 'block')
        for invocation in ('bash bin/why', 'source bin/why', 'sh bin/why'):
            self.assertEqual(self.decide('WHY_GIT_DIRS=.git ' + invocation + ' -l lane subject')[0], 'block')
        self.script.write_text(SCRIPT + '\necho changed\n')
        self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')

    def test_adjacent_operations_remain_protected(self):
        base = 'WHY_GIT_DIRS=.git bin/why -l lane subject'
        for suffix in (' > @HOME@/.claude/history.jsonl', '; rm @HOME@/.claude/history.jsonl',
                       ' "$(rm @HOME@/.claude/history.jsonl)"'):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.decide(base + suffix)[0], 'block')

    def test_symlink_script_and_note_targets_keep_analysis(self):
        real = self.script.with_name('original')
        self.script.rename(real)
        self.script.symlink_to(real)
        self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')
        self.script.unlink()
        real.rename(self.script)
        notes = self.repo / '.git/autocommit.why.d'
        notes.mkdir(exist_ok=True)
        for name in ('lane', 'lane.tmp'):
            target = notes / name
            target.symlink_to(self.home / '.claude/history.jsonl')
            try:
                self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')
            finally:
                target.unlink()

    def test_same_command_script_replacement_keeps_analysis(self):
        self.assertEqual(self.decide('printf "rm @HOME@/.claude/history.jsonl\\n" > bin/why; '
                                     'WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')

    def test_existing_temp_and_hardlinked_final_are_not_trusted(self):
        notes = self.repo / '.git/autocommit.why.d'
        notes.mkdir(exist_ok=True)
        tmp = notes / 'lane.tmp'
        tmp.write_text('existing data')
        try:
            self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')
        finally:
            tmp.unlink()
        final = notes / 'lane'
        final.hardlink_to(self.home / '.claude/history.jsonl')
        try:
            self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'block')
        finally:
            final.unlink()

    def test_temporary_publish_permission_does_not_escape_script(self):
        base = 'WHY_GIT_DIRS=.git bin/why -l lane subject'
        self.assertEqual(self.decide(base + '; mv .git/autocommit.why.d/lane.tmp .git/autocommit.why.d/lane')[0], 'block')

    def test_existing_regular_note_can_be_updated(self):
        notes = self.repo / '.git/autocommit.why.d'
        notes.mkdir(exist_ok=True)
        final = notes / 'lane'
        final.write_text('old note')
        try:
            self.assertEqual(self.decide('WHY_GIT_DIRS=.git bin/why -l lane subject')[0], 'allow')
        finally:
            final.unlink()

    def test_git_identity_environment_and_ancestry_fail_closed(self):
        base = 'WHY_GIT_DIRS=.git bin/why -l lane subject'
        with mock.patch.object(cg, '_git_out', side_effect=ValueError('not a git directory')):
            self.assertEqual(self.decide(base)[0], 'block')
        for assignment in ('PATH=/untrusted;', 'BASH_ENV=startup;', 'ENV=startup;'):
            self.assertEqual(self.decide(assignment + base)[0], 'block')
        for mode in (0o777,):
            old = self.script.parent.stat().st_mode
            self.script.parent.chmod(mode)
            try:
                self.assertEqual(self.decide(base)[0], 'block')
            finally:
                self.script.parent.chmod(old)
