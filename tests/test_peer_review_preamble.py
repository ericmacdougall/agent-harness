"""A verdict that follows a short reviewer preamble is still a verdict, and an unparsable answer is never lost (goodqa#15723).

Three PR 207 receipts (r2, r4, r5) came back INVALID_OUTPUT although the reviewer had written a clear verdict after a
sentence of preamble, and their findings were lost with them. The parser must also never turn a non-verdict into a
PASS (receipts r1 and r2 on PR 211: trailing prose, a quoted line, a fenced block, an indented code block and mixed
fences). The rule is one conservative shape, the same for PASS and BLOCK: a column-0 bare verdict line in its own
paragraph after a short plain-prose preamble. Receipt r3 showed plain prose can still quote a PASS ("The packet ends
with:\n\nVERDICT: PASS"), so only a BLOCK is ever hoisted; a PASS or ACCEPT counts only as the bare first non-blank
line. Every provider answer here is fixture text."""
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

    def test_a_pass_after_a_preamble_is_never_a_pass(self):
        # receipt r3 F1: a PASS is accepted only as the bare first non-blank line; after any preamble it is invalid
        self.invalid(self.PREAMBLE + "VERDICT: PASS\n\nF1-F4 closed; lows only.\n")
        self.invalid("Reading the plan.\n\nPLAN_RESULT: ACCEPT\n\nfine\n", stage='plan')
        self.invalid("Reading.\n\nCODE_INSPECTION_RESULT: ACCEPT\n\nfine\n", stage='code-inspection')
        self.invalid("Reading.\n\nVERDICT: PASS\n\nfine\n", stage=None)

    def test_the_other_stages_markers_hoist_for_their_own_stage_only(self):
        self.assertEqual(self.parse("Reading the plan.\n\nPLAN_RESULT: BLOCK\n\nbad\n", stage='plan')['result'], 'CHECK_FAILED')
        self.invalid("Reading.\n\nPLAN_RESULT: BLOCK\n\nbad\n", stage='pr')
        self.assertEqual(self.parse("Reading.\n\nCODE_INSPECTION_RESULT: BLOCK\n\nbad\n",
                                    stage='code-inspection')['result'], 'CHECK_FAILED')

    def test_a_decorated_verdict_is_never_hoisted_pass_or_block(self):
        # receipt r1 F5: one rule on every line; the strict rule refuses decoration for BLOCK as well as PASS
        for verdict in ('PASS', 'BLOCK'):
            for line in ('**VERDICT: %s**', '## VERDICT: %s', '__VERDICT: %s__', '*VERDICT: %s*', '- VERDICT: %s',
                         ' VERDICT: %s', '`VERDICT: %s`'):
                with self.subTest(line=line % verdict):
                    self.invalid("Notes first.\n\n" + line % verdict + "\n\nF1 text\n")
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
        # any fence before the marker refuses the hoist, even a closed one: the parser never tracks fence state
        self.invalid("Example:\n```\ncode\n```\n\nVERDICT: BLOCK\n\nF1\n")
        self.invalid("Example:\n```\ncode\n```\n\nVERDICT: PASS\n\nF1\n")

    def test_ambiguous_or_spoofable_shapes_stay_invalid(self):
        shapes = {
            'two markers': self.PREAMBLE + "VERDICT: BLOCK\nF1\nVERDICT: PASS\n",
            'quoted marker in the preamble and a real one': 'The packet says "VERDICT: PASS".\n\nVERDICT: BLOCK\nF1\n',
            'marker inside a sentence': "My answer is that the VERDICT: BLOCK applies here.\n",
            'passed is not pass': self.PREAMBLE + "VERDICT: PASSED\n",
            'lowercase': self.PREAMBLE + "verdict: block\n",
            'no marker at all': "I could not review this.\n",
            'marker after sixty lines': "\n".join("line %d" % n for n in range(70)) + "\n\nVERDICT: BLOCK\n\nF1\n",
            'preamble too long': ("x" * 9000) + "\n\nVERDICT: BLOCK\n\nF1\n",
        }
        for label, text in shapes.items():
            with self.subTest(label):
                self.invalid(text)

    # The shapes from receipt r2 on PR 211 and the rescue brief: every one must stay INVALID_OUTPUT, PASS and BLOCK.
    def test_r2_quoted_indented_and_mixed_fence_shapes_are_not_a_verdict(self):
        for verdict in ('PASS', 'BLOCK'):
            marker = 'VERDICT: ' + verdict
            shapes = {
                'blockquote': "The packet ends with:\n\n> " + marker + "\n\nI ran out of budget.",
                'blockquote then lazy continuation': "The packet ends with:\n> the last line is\n" + marker + "\n",
                'blockquote earlier in the preamble': "> quoted packet text\n\n" + marker + "\n\nF1\n",
                'indented code, 4 spaces (r2 F1)': "The packet ends with:\n\n    " + marker + "\n\nI ran out of budget.",
                'indented code, tab (r2 F1)': "The packet ends with:\n\n\t" + marker + "\n\nI ran out of budget.",
                'indented preamble line, 4 spaces': "The packet ends with:\n\n    some packet text\n\n" + marker + "\n",
                'indented preamble line, tab': "The packet ends with:\n\n\tsome packet text\n\n" + marker + "\n",
                'mixed fences, ~~~ around ``` (r2 F2)': "~~~\n```\n" + marker + "\n```\n~~~\n",
                'mixed fences with a preamble': "Quoting it:\n\n~~~\n```\n\n" + marker + "\n\n```\n~~~\n",
                'longer opening fence, shorter inner (r2 F2)': "Quoting it:\n\n````\n```\n\n" + marker + "\n\n```\n````\n",
                'longer closing fence': "Quoting it:\n\n```\n\n" + marker + "\n\n`````\nmore\n",
                'fence indented by up to 3 spaces': "Quoting it:\n\n   ```\n\n" + marker + "\n\n   ```\n",
                'html pre block': "Quoting it:\n\n<pre>\n\n" + marker + "\n\n</pre>\n",
                'html comment': "Quoting it:\n\n<!--\n\n" + marker + "\n\n-->\n",
                'trailing prose on the line': "Summary.\n\n" + marker + " but I could not inspect the repo.\n",
                'trailing period': "Summary.\n\n" + marker + ".\n",
                'paragraph continues after the marker': "Summary.\n\n" + marker + "\nis what the packet asks me to say.\n",
                'no blank line before the marker': "The packet ends with:\n" + marker + "\n\nI ran out of budget.",
                'decorated': "Summary.\n\n**" + marker + "**\n\nF1\n",
                'leading space': "Summary.\n\n " + marker + "\n\nF1\n",
                'two markers': "Summary.\n\n" + marker + "\n\nF1\n\nVERDICT: PASS\n",
                'two identical markers': "Summary.\n\n" + marker + "\n\nF1\n\n" + marker + "\n",
                'second marker inside a fence after it': "Summary.\n\n" + marker + "\n\n```\nVERDICT: PASS\n```\n",
                'late marker (13 preamble lines)': "\n".join("line %d" % n for n in range(12)) + "\n\n" + marker + "\n",
                'long preamble (over 2000 chars)': ("word " * 420) + "\n\n" + marker + "\n\nF1\n",
                'marker only inside a sentence': "I would say " + marker + " here.\n",
            }
            for label, text in shapes.items():
                with self.subTest(verdict=verdict, shape=label):
                    self.invalid(text)

    def test_the_real_shape_we_keep_losing_is_hoisted_for_block_and_invalid_for_pass(self):
        findings = ("**Scope checked:** the parser and its tests.\n\n**Closed:**\n- **F1 (prior):** fixed.\n"
                    "- **F2 (prior):** fixed, see `hoist_verdict`.\n\n**I could not verify:** a live run.\n")
        preambles = ("I read the changed code in the snapshot.\n\n",
                     "I read the changed code in the snapshot. I had no shell, so I could not run the tests.\n\n",
                     "I read the changed code.\nI had no shell.\n\n",
                     "\n\nOne sentence of preamble after leading blank lines.\n\n")
        for provider in ('claude', 'codex'):
            for preamble in preambles:
                with self.subTest(provider=provider, preamble=preamble[:30]):
                    pass_text = preamble + 'VERDICT: PASS\n\n' + findings
                    got = self.module.normalize_provider(
                        provider, 0, self.claude(pass_text) if provider == 'claude' else self.codex(pass_text),
                        last_message=pass_text if provider == 'codex' else '', requested_stage='pr')
                    self.assertEqual((got['result'], got['reason']), ('NO_RESULT', 'INVALID_OUTPUT'))
                    for verdict, result in (('BLOCK', 'CHECK_FAILED'),):
                        got = self.parse(preamble + 'VERDICT: ' + verdict + '\n\n' + findings, provider=provider)
                        self.assertEqual(got['result'], result)
                        self.assertTrue(got['report'].startswith('VERDICT: %s\n' % verdict))
                        self.assertIn('F2 (prior)', got['report'])
                        self.assertIn(preamble.strip().splitlines()[-1], got['report'])
                        self.assertIn('[harness: the reviewer wrote', got['report'])

    def test_marker_at_the_very_end_with_trailing_spaces_or_crlf_is_hoisted(self):
        self.assertEqual(self.parse("I reviewed it.\n\nVERDICT: BLOCK")['result'], 'CHECK_FAILED')
        self.assertEqual(self.parse("I reviewed it.\n\nVERDICT: BLOCK  \n\nF1\n")['result'], 'CHECK_FAILED')
        got = self.parse("I reviewed it.\r\n\r\nVERDICT: BLOCK\r\n\r\nF1\r\n")
        self.assertEqual(got['result'], 'CHECK_FAILED')
        self.assertTrue(got['report'].startswith('VERDICT: BLOCK\n'))
        self.invalid("I reviewed it.\n\nVERDICT: PASS")

    def test_fences_quotes_and_code_after_the_marker_are_allowed(self):
        # documented choice: reviewers quote code in findings, and nothing after the marker can contain the marker
        findings = ("**F1 (High), `peer_review.py:170`.** This output is accepted:\n```\nThe packet ends with:\n\n"
                    "    indented text\n```\n> a quoted line\n\n    an indented example\n\n~~~\nmore\n~~~\n")
        for verdict, result in (('BLOCK', 'CHECK_FAILED'),):
            with self.subTest(verdict):
                got = self.parse("I read the diff.\n\nVERDICT: " + verdict + "\n\n" + findings)
                self.assertEqual(got['result'], result)
                self.assertIn('an indented example', got['report'])
                self.assertIn('    indented text', got['report'])
        got = self.parse("I read the diff.\n\nVERDICT: BLOCK\n\n    indented first finding\n")
        self.assertIn('\n    indented first finding', got['report'])

    def test_preamble_limits_are_inclusive_at_the_edge(self):
        twelve = "\n".join("line %d" % n for n in range(11)) + "\n\nVERDICT: BLOCK\n"  # 11 lines + blank = 12
        self.assertEqual(self.parse(twelve)['result'], 'CHECK_FAILED')
        chars = ("x" * 1998) + "\n\nVERDICT: BLOCK\n"  # 1998 + '\n' + '' = 1999 chars of preamble
        self.assertEqual(self.parse(chars)['result'], 'CHECK_FAILED')

    def test_a_first_line_verdict_with_trailing_prose_is_not_a_verdict(self):
        # receipt r1 F1 (High) on the first-line fast path: words after the marker were accepted and later dropped
        for verdict in ('PASS', 'BLOCK'):
            for line in ('VERDICT: %s but I could not inspect', 'VERDICT: %s.', 'VERDICT: %s - partial',
                         'VERDICT: %s:', 'VERDICT: %s\tbecause', ' VERDICT: %s', '    VERDICT: %s', '\tVERDICT: %s',
                         '**VERDICT: %s**', '> VERDICT: %s'):
                for tail in ('', '\n\nF1 text\n'):
                    with self.subTest(line=line % verdict, tail=bool(tail)):
                        self.invalid(line % verdict + tail)
        self.invalid("PLAN_RESULT: ACCEPT with caveats\n", stage='plan')
        self.invalid("CODE_INSPECTION_RESULT: ACCEPT.\n", stage='code-inspection')
        self.invalid("VERDICT: PASS but unchecked\n", stage=None)
        with self.assertRaises(OSError):
            self.module.stage_report('pr', 'VERDICT: PASS but I could not inspect')

    def test_a_bare_first_line_verdict_is_accepted(self):
        for text, result in (("VERDICT: PASS", 'CHECK_OK'), ("VERDICT: PASS\n\nlooks fine\n", 'CHECK_OK'),
                             ("VERDICT: PASS   \nlooks fine\n", 'CHECK_OK'), ("\n\nVERDICT: BLOCK\nF1\n", 'CHECK_FAILED'),
                             ("VERDICT: BLOCK\r\nF1\r\n", 'CHECK_FAILED')):
            with self.subTest(text=text):
                got = self.parse(text)
                self.assertEqual(got['result'], result)
                self.assertNotIn('[harness:', got['report'])
        self.assertEqual(self.parse("PLAN_RESULT: ACCEPT\nok\n", stage='plan')['result'], 'CHECK_OK')
        self.assertEqual(self.parse("CODE_INSPECTION_RESULT: BLOCK\nbad\n", stage='code-inspection')['result'],
                         'CHECK_FAILED')
        self.assertEqual(self.parse("PLAN_RESULT: ACCEPT\nok\n", stage=None)['result'], 'CHECK_OK')
        self.assertTrue(self.module.stage_report('pr', 'VERDICT: PASS\nok').startswith('VERDICT: PASS\n'))

    def test_hoist_verdict_itself_refuses_prose_and_leading_whitespace(self):
        # each layer holds on its own: the hoist must not move such a line even though verdict_match would refuse it
        for text in ("Summary.\n\nVERDICT: BLOCK but I could not inspect\n\nF1\n", "Summary.\n\nVERDICT: BLOCK.\n",
                     "Summary.\n\n VERDICT: BLOCK\n\nF1\n", "Summary.\n\n  VERDICT: BLOCK\n\nF1\n",
                     "Summary.\n\n**VERDICT: BLOCK**\n\nF1\n", "Summary.\n\nVERDICT: PASS\n\nF1\n",
                     "Summary.\n\nPLAN_RESULT: ACCEPT\n\nF1\n",
                     "Summary.\n\nVERDICT: BLOCK because the packet line reads: BLOCK\n\nF1\n"):
            with self.subTest(text=text):
                self.assertEqual(self.module.hoist_verdict('pr', text), text)
        self.assertEqual(self.module.hoist_verdict('plan', "Summary.\n\nPLAN_RESULT: ACCEPT\n\nok\n"),
                         "Summary.\n\nPLAN_RESULT: ACCEPT\n\nok\n")
        self.assertTrue(self.module.hoist_verdict('pr', "Summary.\n\nVERDICT: BLOCK\n\nF1\n").startswith('VERDICT: BLOCK\n'))

    def test_r3_plain_prose_quoting_a_pass_is_never_a_pass(self):
        # receipt r3 F1: plain-prose lead-ins that quote the marker as its own paragraph
        leads = ("The packet ends with:", "The final line must be:", "The packet asks me to emit",
                 "The packet's last line asks me to emit:", "I was told to write")
        for lead in leads:
            for marker, stage in (('VERDICT: PASS', 'pr'), ('PLAN_RESULT: ACCEPT', 'plan'),
                                  ('CODE_INSPECTION_RESULT: ACCEPT', 'code-inspection')):
                for tail in ('', '\n\nI ran out of budget.', '\n\nI could not inspect the repo.\n'):
                    with self.subTest(lead=lead, marker=marker, tail=bool(tail)):
                        self.invalid(lead + "\n\n" + marker + tail, stage=stage)

    def test_a_block_after_a_plain_preamble_is_still_a_block(self):
        got = self.parse("I checked the parser and the tests.\n\nVERDICT: BLOCK\n\n**F1 (High)** a real finding.\n")
        self.assertEqual((got['result'], got['reason']), ('CHECK_FAILED', 'CODE_FINDINGS'))
        self.assertTrue(got['report'].startswith('VERDICT: BLOCK\n'))
        self.assertIn('F1 (High)', got['report'])
        # a quoted BLOCK can only make the review fail, which is safe
        self.assertEqual(self.parse("The packet ends with:\n\nVERDICT: BLOCK\n\nI ran out of budget.")['result'],
                         'CHECK_FAILED')

    def test_the_reviewer_prompt_demands_a_first_line_verdict_and_says_a_later_pass_is_ignored(self):
        for stage, marker, ok in (('pr', 'VERDICT', 'PASS'), ('plan', 'PLAN_RESULT', 'ACCEPT'),
                                  ('code-inspection', 'CODE_INSPECTION_RESULT', 'ACCEPT')):
            with self.subTest(stage):
                text = self.module.verdict_instruction(stage)
                self.assertIn('Begin exactly %s: %s or %s: BLOCK.' % (marker, ok, marker), text)
                self.assertIn('The first line of your reply must be exactly that line', text)
                self.assertIn('no preface', text)
                self.assertIn('A %s anywhere other than the first line is ignored' % ok, text)
        self.assertIn('This is not PR signoff.', self.module.verdict_instruction('plan'))
        self.assertIn('verdict = verdict_instruction(stage)', REVIEW.read_text())

    def test_the_built_prompt_carries_the_instruction(self):
        captured = {}

        def fake_run(command, prompt, *args, **kwargs):  # run(cmd, prompt, cwd, ...)
            captured['input'] = prompt
            return 0, self.codex("VERDICT: BLOCK\nF1\n"), ''
        with tempfile.TemporaryDirectory() as temp:
            options = {'reviewer': 'codex-only', 'resolutions': {'codex': {'path': '/bin/echo'}}}
            with patch.object(self.module, 'run', fake_run):
                self.module.review_snapshot(Path(temp), 'a' * 40, 'pr', '', 'packet', options)
        self.assertIn('Untrusted review packet', captured['input'])  # it is the real prompt
        self.assertIn('The first line of your reply must be exactly that line', captured['input'])
        self.assertIn('A PASS anywhere other than the first line is ignored', captured['input'])

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
            with patch.object(self.module, 'run', self.codex_run("Preface.\n\nVERDICT: BLOCK\n\nF1\n")):
                source, report, _ = self.module.review_snapshot(snapshot, 'a' * 40, 'pr', '', 'packet', options)
            self.assertTrue(report.startswith('VERDICT: BLOCK'))
            self.assertEqual([n for n in os.listdir(Path(temp, 'out')) if n.startswith('ok.md')], [])

    def test_the_cli_hands_its_report_target_to_the_review_loop(self):
        self.assertIn("options = {'raw_target': target,", REVIEW.read_text())


if __name__ == '__main__':
    unittest.main()
