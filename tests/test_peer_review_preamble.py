"""A verdict that follows a short reviewer preamble is still a verdict, and an unparsable answer is never lost (goodqa#15723).

Three PR 207 receipts (r2, r4, r5) came back INVALID_OUTPUT although the reviewer had written a clear verdict after a
sentence of preamble, and their findings were lost with them. Every provider answer here is fixture text."""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REVIEW = Path(__file__).resolve().parents[1] / 'harness' / 'hooks' / 'peer_review.py'


class Preamble(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('peer_preamble_unit', REVIEW)
        cls.module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(REVIEW.parent), *sys.path]):
            spec.loader.exec_module(cls.module)

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

    PREAMBLE = ("I read the changed code in the snapshot directly. The caller binding part looks right.\n\n")

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

    def test_a_pass_after_a_preamble_is_a_pass_only_when_it_is_the_one_verdict_in_the_text(self):
        result = self.parse(self.PREAMBLE + "VERDICT: PASS\n\nF1-F4 closed; lows only.\n")
        self.assertEqual((result['result'], result['reason']), ('CHECK_OK', 'NONE'))
        self.assertTrue(result['report'].startswith('VERDICT: PASS\n'))

    def test_the_other_stages_markers_hoist_for_their_own_stage_only(self):
        plan = self.parse("Reading the plan.\n\nPLAN_RESULT: ACCEPT\nfine\n", stage='plan')
        self.assertEqual(plan['result'], 'CHECK_OK')
        self.assertEqual(self.parse("Reading.\n\nPLAN_RESULT: ACCEPT\nfine\n", stage='pr')['reason'], 'INVALID_OUTPUT')
        inspect = self.parse("Reading.\n\nCODE_INSPECTION_RESULT: BLOCK\nbad\n", stage='code-inspection')
        self.assertEqual(inspect['result'], 'CHECK_FAILED')

    def test_markdown_decoration_around_the_marker_line_is_ignored(self):
        for line in ('**VERDICT: BLOCK**', '## VERDICT: BLOCK', '> VERDICT: BLOCK', '__VERDICT: BLOCK__'):
            with self.subTest(line):
                result = self.parse("Notes first.\n\n" + line + "\n\nF1 text\n")
                self.assertEqual(result['result'], 'CHECK_FAILED', line)
                self.assertTrue(result['report'].startswith('VERDICT: BLOCK\n'))

    def test_ambiguous_or_spoofable_shapes_stay_invalid(self):
        shapes = {
            'two markers': self.PREAMBLE + "VERDICT: BLOCK\nF1\nVERDICT: PASS\n",
            'quoted marker in the preamble and a real one': 'The packet says "VERDICT: PASS".\n\nVERDICT: BLOCK\nF1\n',
            'marker inside a sentence': "My answer is that the VERDICT: BLOCK applies here.\n",
            'marker only in a code span': "Result.\n\n`VERDICT: PASS`\n",
            'passed is not pass': self.PREAMBLE + "VERDICT: PASSED\n",
            'lowercase': self.PREAMBLE + "verdict: block\n",
            'no marker at all': "I could not review this.\n",
            'marker after sixty lines': "\n".join("line %d" % n for n in range(70)) + "\nVERDICT: BLOCK\nF1\n",
            'preamble too long': ("x" * 9000) + "\nVERDICT: BLOCK\nF1\n",
            'marker with trailing text on its line': self.PREAMBLE + "VERDICT: BLOCK because of F1\n",
        }
        for label, text in shapes.items():
            with self.subTest(label):
                result = self.parse(text)
                if label == 'marker with trailing text on its line':
                    self.assertEqual(result['result'], 'CHECK_FAILED')  # a first-class verdict line, hoisted
                    continue
                self.assertEqual(result['reason'], 'INVALID_OUTPUT', label)
                self.assertEqual(result['result'], 'NO_RESULT')
                self.assertFalse(result['fallback_allowed'])

    def test_a_first_line_verdict_is_untouched_and_a_quoted_marker_below_it_is_not_a_second_verdict(self):
        text = "VERDICT: BLOCK\nF1 says the packet's 'VERDICT: PASS' line was echoed.\n"
        result = self.parse(text)
        self.assertEqual(result['report'], text.strip())
        self.assertNotIn('[harness:', result['report'])

    def test_a_hoisted_report_still_goes_through_stage_report(self):
        result = self.parse(self.PREAMBLE + "VERDICT: BLOCK\n\nF1\n")
        rendered = self.module.stage_report('pr', result['report'])
        self.assertTrue(rendered.startswith('VERDICT: BLOCK\n'))

    def test_the_excerpt_shape_from_receipt_r5(self):
        text = ("I checked the parser and the tests.\n\nVERDICT: BLOCK\n\nOne finding contradicts the packet's main F1 "
                "claim: a `=` form with an abbreviated prefix.\n")
        result = self.parse(text)
        self.assertEqual(result['result'], 'CHECK_FAILED')
        self.assertIn('contradicts the packet', result['report'])


class RawOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Preamble.setUpClass.__func__(cls)

    def test_raw_output_is_saved_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = os.path.join(temp, 'r4-pr207.md')
            first = self.module.persist_raw_output(prefix, 'claude', 0, 'STDOUT-TEXT', 'ERR', 'LAST')
            second = self.module.persist_raw_output(prefix, 'claude', 0, 'second', '', '')
            self.assertNotEqual(first, second)
            self.assertEqual(stat.S_IMODE(os.stat(first).st_mode), 0o600)
            body = Path(first).read_text()
            for needle in ('provider: claude', 'STDOUT-TEXT', 'LAST', 'ERR'):
                self.assertIn(needle, body)
            self.assertEqual(Path(second).read_text().count('second'), 1)

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
            options = {'reviewer': 'codex-only', 'raw_prefix': os.path.join(temp, 'r.md'),
                       'resolutions': {'codex': {'path': '/bin/echo'}}}
            with patch.object(self.module, 'run', self.codex_run("Findings: F1 is real.\nNo verdict line at all.\n")), \
                    patch('sys.stderr', new_callable=__import__('io').StringIO) as err:
                with self.assertRaises(OSError):
                    self.module.review_snapshot(snapshot, 'a' * 40, 'pr', '', 'packet', options)
            saved = [name for name in os.listdir(temp) if '.raw-codex-' in name]
            self.assertEqual(len(saved), 1, saved)
            self.assertIn('F1 is real', Path(temp, saved[0]).read_text())
            self.assertEqual(stat.S_IMODE(os.stat(Path(temp, saved[0])).st_mode), 0o600)
            self.assertIn('raw answer is saved', err.getvalue())
            options = {'reviewer': 'codex-only', 'raw_prefix': os.path.join(temp, 'ok.md'),
                       'resolutions': {'codex': {'path': '/bin/echo'}}}
            with patch.object(self.module, 'run', self.codex_run("Preface.\n\nVERDICT: BLOCK\nF1\n")):
                source, report, _ = self.module.review_snapshot(snapshot, 'a' * 40, 'pr', '', 'packet', options)
            self.assertTrue(report.startswith('VERDICT: BLOCK'))
            self.assertEqual([n for n in os.listdir(temp) if n.startswith('ok.md')], [])

    def test_the_cli_hands_its_output_path_to_the_review_loop_as_the_raw_prefix(self):
        # main() builds the options dict the loop reads; the raw file sits beside the --output report
        source = REVIEW.read_text()
        self.assertIn("options = {'raw_prefix': str(output_arg),", source)

    def test_raw_output_is_bounded_and_failures_never_raise(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.module.persist_raw_output(os.path.join(temp, 'r'), 'codex', 1, 'x' * (6 * 1024 * 1024), '', '')
            self.assertLessEqual(os.path.getsize(path), 4 * 1024 * 1024)
            self.assertIsNone(self.module.persist_raw_output(os.path.join(temp, 'missing', 'dir', 'r'), 'codex', 0, 'x', '', ''))
            self.assertIsNone(self.module.persist_raw_output('', 'codex', 0, 'x', '', ''))
            self.assertIsNone(self.module.persist_raw_output(None, 'codex', 0, 'x', '', ''))
            link = os.path.join(temp, 'l')
            os.symlink(os.path.join(temp, 'elsewhere'), link + '.raw-codex-0.txt')
            saved = self.module.persist_raw_output(link, 'codex', 0, 'x', '', '')
            self.assertFalse(os.path.exists(os.path.join(temp, 'elsewhere')))
            self.assertTrue(saved is None or saved.endswith('-1.txt'))


if __name__ == '__main__':
    unittest.main()
