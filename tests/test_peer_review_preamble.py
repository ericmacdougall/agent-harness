"""A verdict that follows a short reviewer preamble is still a verdict, and an unparsable answer is never lost (goodqa#15723).

Three PR 207 receipts (r2, r4, r5) came back INVALID_OUTPUT although the reviewer had written a clear verdict after a
sentence of preamble, and their findings were lost with them. The parser must also never turn a non-verdict into a
PASS (receipt r1 on PR 211: trailing prose, a quoted line and a fenced block). Every provider answer here is fixture
text."""
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REVIEW = Path(__file__).resolve().parents[1] / 'harness' / 'hooks' / 'peer_review.py'


def load():
    spec = importlib.util.spec_from_file_location('peer_preamble_unit', REVIEW)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(REVIEW.parent), *sys.path]):
        spec.loader.exec_module(module)
    return module


class Preamble(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load()

    def claude(self, text):
        return json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, 'result': text,
                           'usage': {'input_tokens': 3}})

    def codex(self, text):
        return '\n'.join(json.dumps(value) for value in [
            {'type': 'thread.started', 'thread_id': 'f'}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'id': '1', 'type': 'agent_message', 'text': text}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'output_tokens': 4}}])

    def parse(self, text, stage='pr', provider='claude'):
        data = self.claude(text) if provider == 'claude' else self.codex(text)
        return self.module.normalize_provider(provider, 0, data, last_message=text if provider == 'codex' else '',
                                              requested_stage=stage)

    def invalid(self, text, stage='pr'):
        result = self.parse(text, stage)
        self.assertEqual((result['result'], result['reason'], result['fallback_allowed']),
                         ('NO_RESULT', 'INVALID_OUTPUT', False), text[:80])

    PREAMBLE = "I read the changed code in the snapshot directly. The caller binding part looks right.\n\n"

    def test_a_block_after_a_preamble_is_a_block_with_its_findings(self):
        for provider in ('claude', 'codex'):
            with self.subTest(provider):
                result = self.parse(self.PREAMBLE + "VERDICT: BLOCK\n\n**F1 (Medium)** one finding contradicts the "
                                    "packet's main claim.\n", provider=provider)
                self.assertEqual((result['result'], result['reason']), ('CHECK_FAILED', 'CODE_FINDINGS'))
                self.assertTrue(result['report'].startswith('VERDICT: BLOCK\n'))
                self.assertIn('F1 (Medium)', result['report'])
                self.assertIn('The caller binding part looks right.', result['report'])
                self.assertIn('[harness: the reviewer wrote', result['report'])

    def test_a_plain_pass_line_after_a_preamble_is_a_pass_only_when_it_is_the_one_verdict(self):
        result = self.parse(self.PREAMBLE + "VERDICT: PASS\n\nF1-F4 closed; lows only.\n")
        self.assertEqual((result['result'], result['reason']), ('CHECK_OK', 'NONE'))
        self.assertTrue(result['report'].startswith('VERDICT: PASS\n'))

    def test_the_other_stages_markers_hoist_for_their_own_stage_only(self):
        self.assertEqual(self.parse("Reading the plan.\n\nPLAN_RESULT: ACCEPT\nfine\n", stage='plan')['result'], 'CHECK_OK')
        self.invalid("Reading.\n\nPLAN_RESULT: ACCEPT\nfine\n", stage='pr')
        self.assertEqual(self.parse("Reading.\n\nCODE_INSPECTION_RESULT: BLOCK\nbad\n",
                                    stage='code-inspection')['result'], 'CHECK_FAILED')

    def test_bold_or_heading_marks_make_only_a_block_never_a_pass(self):
        for line in ('**VERDICT: BLOCK**', '## VERDICT: BLOCK', '__VERDICT: BLOCK__'):
            for preamble in ("Notes first.\n\n", ""):  # after a preamble and on the very first line (receipt r1 F5)
                with self.subTest(line=line, preamble=bool(preamble)):
                    result = self.parse(preamble + line + "\n\nF1 text\n")
                    self.assertEqual(result['result'], 'CHECK_FAILED')
                    self.assertTrue(result['report'].startswith('VERDICT: BLOCK\n'))
                    self.assertEqual('[harness:' in result['report'], bool(preamble))
        for line in ('**VERDICT: PASS**', '## VERDICT: PASS', '__VERDICT: PASS__'):
            for preamble in ("Notes first.\n\n", ""):
                with self.subTest(line=line, preamble=bool(preamble)):
                    self.invalid(preamble + line + "\n\nlooks fine\n")
        self.invalid("Notes.\n\n**CODE_INSPECTION_RESULT: ACCEPT**\n", stage='code-inspection')

    # The shapes from receipt r1 on PR 211 (F1 and F2): each used to be CHECK_OK.
    def test_a_verdict_followed_by_prose_is_not_a_verdict(self):
        self.invalid("The packet's last line asks me to emit\nVERDICT: PASS but I could not inspect the repo.\n")
        self.invalid("Summary below.\n\nVERDICT: PASS because the packet says so\n")
        self.invalid("Summary below.\n\nVERDICT: BLOCK because of F1\n")
        self.invalid("Notes.\n\nVERDICT: PASS.\n")
        self.invalid("Notes.\n\nVERDICT: PASS - with caveats\n", stage='pr')

    def test_a_quoted_or_fenced_marker_is_not_a_verdict(self):
        self.invalid("The packet ends with:\n> VERDICT: PASS\nI ran out of budget.")
        self.invalid("The packet ends with:\n> VERDICT: BLOCK\nI ran out of budget.")
        self.invalid("The packet ends with:\n\n```\nVERDICT: PASS\n```\nI ran out of budget.")
        self.invalid("The packet ends with:\n\n~~~text\nVERDICT: BLOCK\n~~~\nI ran out of budget.")
        self.invalid("The packet ends with:\n\n```\nVERDICT: PASS\nand the fence is never closed")
        self.invalid("Notes.\n\n`VERDICT: PASS`\n")
        # an unfenced marker after a closed fence is still found
        result = self.parse("Example:\n```\ncode\n```\n\nVERDICT: BLOCK\nF1\n")
        self.assertEqual(result['result'], 'CHECK_FAILED')

    def test_ambiguous_or_spoofable_shapes_stay_invalid(self):
        shapes = {
            'two markers': self.PREAMBLE + "VERDICT: BLOCK\nF1\nVERDICT: PASS\n",
            'quoted marker in the preamble and a real one': 'The packet says "VERDICT: PASS".\n\nVERDICT: BLOCK\nF1\n',
            'marker inside a sentence': "My answer is that the VERDICT: BLOCK applies here.\n",
            'passed is not pass': self.PREAMBLE + "VERDICT: PASSED\n",
            'lowercase': self.PREAMBLE + "verdict: block\n",
            'no marker at all': "I could not review this.\n",
            'marker after sixty lines': "\n".join("line %d" % n for n in range(70)) + "\nVERDICT: BLOCK\nF1\n",
            'preamble too long': ("x" * 9000) + "\nVERDICT: BLOCK\nF1\n",
        }
        for label, text in shapes.items():
            with self.subTest(label):
                self.invalid(text)

    def test_a_first_line_verdict_is_untouched_and_a_quoted_marker_below_it_is_not_a_second_verdict(self):
        text = "VERDICT: BLOCK\nF1 says the packet's 'VERDICT: PASS' line was echoed.\n"
        result = self.parse(text)
        self.assertEqual(result['report'], text.strip())
        self.assertNotIn('[harness:', result['report'])

    def test_a_hoisted_report_still_goes_through_stage_report(self):
        result = self.parse(self.PREAMBLE + "VERDICT: BLOCK\n\nF1\n")
        self.assertTrue(self.module.stage_report('pr', result['report']).startswith('VERDICT: BLOCK\n'))

    def test_the_excerpt_shape_from_receipt_r5(self):
        text = ("I checked the parser and the tests.\n\nVERDICT: BLOCK\n\nOne finding contradicts the packet's main F1 "
                "claim: a `=` form with an abbreviated prefix.\n")
        result = self.parse(text)
        self.assertEqual(result['result'], 'CHECK_FAILED')
        self.assertIn('contradicts the packet', result['report'])


class RawOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load()
        sys.path.insert(0, str(REVIEW.parent))
        import report_file
        cls.report_file = report_file

    def target(self, temp, name='r.md'):
        repo = Path(temp) / 'repo'
        repo.mkdir(exist_ok=True)
        packet = Path(temp) / 'packet.md'
        packet.write_text('p')
        out = Path(temp) / 'out'
        return self.report_file.ReportTarget(out / name, repo, packet)

    def test_raw_output_is_written_through_the_target_directory_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            target = self.target(temp)
            self.addCleanup(target.close)
            first = self.module.persist_raw_output(target, 'claude', 0, 'STDOUT-TEXT', 'ERR', 'LAST')
            second = self.module.persist_raw_output(target, 'claude', 0, 'second', '', '')
            self.assertNotEqual(first, second)
            self.assertEqual(Path(first).parent, Path(temp, 'out').resolve())
            self.assertEqual(stat.S_IMODE(os.stat(first).st_mode), 0o600)
            body = Path(first).read_text()
            for needle in ('provider: claude', 'STDOUT-TEXT', 'LAST', 'ERR'):
                self.assertIn(needle, body)
            self.assertEqual(Path(second).read_text().count('second'), 1)

    def test_a_swapped_output_directory_receives_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            target = self.target(temp)
            self.addCleanup(target.close)
            os.rename(Path(temp, 'out'), Path(temp, 'moved'))
            os.mkdir(Path(temp, 'out'))  # a different directory now sits at the validated path
            self.assertIsNone(self.module.persist_raw_output(target, 'codex', 0, 'SECRET-ANSWER', '', ''))
            self.assertEqual(os.listdir(Path(temp, 'out')), [])
            os.rename(Path(temp, 'out'), Path(temp, 'out2'))
            os.symlink(Path(temp, 'moved'), Path(temp, 'out'))  # a symlink back to the validated directory
            # the handle still IS the validated directory, so the file goes there and nowhere else
            self.assertIsNotNone(self.module.persist_raw_output(target, 'codex', 0, 'ANSWER', '', ''))
            self.assertEqual(len([n for n in os.listdir(Path(temp, 'moved')) if '.raw-' in n]), 1)
            self.assertEqual(os.listdir(Path(temp, 'out2')), [])

    def test_the_target_refuses_an_output_inside_the_worktree_so_no_raw_file_can_go_there(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / 'repo'
            repo.mkdir()
            packet = Path(temp) / 'p.md'
            packet.write_text('p')
            with self.assertRaises(ValueError):
                self.report_file.ReportTarget(repo / 'sub' / 'r.md', repo, packet)

    def test_a_partial_write_is_completed(self):
        with tempfile.TemporaryDirectory() as temp:
            target = self.target(temp)
            self.addCleanup(target.close)
            real = os.write
            with patch.object(os, 'write', lambda fd, data: real(fd, bytes(data[:3]))):
                path = self.module.persist_raw_output(target, 'claude', 0, 'ABCDEFGHIJ' * 50, '', 'LAST-MESSAGE')
            body = Path(path).read_text()
            self.assertIn('ABCDEFGHIJ' * 50, body)
            self.assertTrue(body.rstrip().endswith('--- stderr ---'))

    def test_failures_never_raise_and_a_missing_target_saves_nothing(self):
        self.assertIsNone(self.module.persist_raw_output(None, 'codex', 0, 'x', '', ''))
        with tempfile.TemporaryDirectory() as temp:
            target = self.target(temp)
            target.close()
            self.assertIsNone(self.module.persist_raw_output(target, 'codex', 0, 'x', '', ''))
            live = self.target(temp, 'again.md')
            self.addCleanup(live.close)
            path = self.module.persist_raw_output(live, 'codex', 1, 'x' * (6 * 1024 * 1024), '', '')
            self.assertLessEqual(os.path.getsize(path), 4 * 1024 * 1024)
            os.symlink(Path(temp, 'elsewhere'), Path(temp, 'out', 'again.md.raw-codex-1.txt'))
            saved = self.module.persist_raw_output(live, 'codex', 0, 'x', '', '')
            self.assertFalse(os.path.exists(Path(temp, 'elsewhere')))
            self.assertTrue(saved.endswith('-2.txt'), saved)

    def codex_run(self, text):
        data = '\n'.join(json.dumps(value) for value in [
            {'type': 'thread.started', 'thread_id': 'f'}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'id': '1', 'type': 'agent_message', 'text': text}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'output_tokens': 4}}])
        return lambda *a, **k: (0, data, '')

    def test_an_unparsable_review_leaves_its_raw_answer_behind_and_a_parsable_one_leaves_none(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot = Path(temp) / 'snap'
            snapshot.mkdir()
            target = self.target(temp)
            self.addCleanup(target.close)
            options = {'reviewer': 'codex-only', 'raw_target': target, 'resolutions': {'codex': {'path': '/bin/echo'}}}
            with patch.object(self.module, 'run', self.codex_run("Findings: F1 is real.\nNo verdict line at all.\n")), \
                    patch('sys.stderr', new_callable=io.StringIO) as err:
                with self.assertRaises(OSError):
                    self.module.review_snapshot(snapshot, 'a' * 40, 'pr', '', 'packet', options)
            saved = [n for n in os.listdir(Path(temp, 'out')) if '.raw-codex-' in n]
            self.assertEqual(len(saved), 1, saved)
            self.assertIn('F1 is real', Path(temp, 'out', saved[0]).read_text())
            self.assertEqual(stat.S_IMODE(os.stat(Path(temp, 'out', saved[0])).st_mode), 0o600)
            self.assertIn('raw answer is saved', err.getvalue())
            other = self.target(temp, 'ok.md')
            self.addCleanup(other.close)
            options = {'reviewer': 'codex-only', 'raw_target': other, 'resolutions': {'codex': {'path': '/bin/echo'}}}
            with patch.object(self.module, 'run', self.codex_run("Preface.\n\nVERDICT: BLOCK\nF1\n")):
                source, report, _ = self.module.review_snapshot(snapshot, 'a' * 40, 'pr', '', 'packet', options)
            self.assertTrue(report.startswith('VERDICT: BLOCK'))
            self.assertEqual([n for n in os.listdir(Path(temp, 'out')) if n.startswith('ok.md')], [])

    def test_the_cli_hands_its_report_target_to_the_review_loop(self):
        self.assertIn("options = {'raw_target': target,", REVIEW.read_text())


if __name__ == '__main__':
    unittest.main()
