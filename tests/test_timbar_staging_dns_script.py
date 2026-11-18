"""Behaviour tests for the pinned TIMBAR staging DNS script (GoodQA goodqa#16393).

The fixture is byte-identical to the pinned file (test_guard_pinned_routes checks its digest against the table).

Nothing here contacts Cloudflare or reads a real secret: the secret tool and the HTTP send are replaced, and the one real
process run passes an argument, which the script refuses before it does anything. SCRIPT=<path> selects the script under
test (default: the pinned one); pointing it at the unhardened first draft shows these tests failing first.
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = Path(os.environ.get('SCRIPT') or HERE / 'fixtures' / 'pinned_routes' / 'cf_dns_timbar_staging.py')
TOKEN = 'cfut_' + 'Ab3_' * 10  # synthetic; has the shape the script accepts
ZONE_ID = 'ab' * 16
NAME, IPV4, ZONE = 'timbar-staging.transition2.ai', '159.203.13.118', 'transition2.ai'
ZONE_OK = (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE}]})
RECORD = {'type': 'A', 'name': NAME, 'content': IPV4, 'proxied': False, 'ttl': 300}
NONE_YET = (200, {'success': True, 'result': []})
CREATED = (200, {'success': True, 'result': dict(RECORD, id='cd' * 16)})


def load():
    spec = importlib.util.spec_from_file_location('cf_dns_timbar_staging_under_test', str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Run:
    """One run of main() with a fake secret tool and a scripted list of HTTP answers."""

    def __init__(self, answers=(), secret=TOKEN + '\n', returncode=0, tool_error=None, argv=('x',), send_error=None):
        self.mod = load()
        self.requests, self.tool_calls = [], []
        answers = list(answers)

        def tool(args, **kwargs):
            self.tool_calls.append((args, kwargs))
            if tool_error is not None:
                raise tool_error
            return subprocess.CompletedProcess(args, returncode, stdout=secret.encode(), stderr=b'')

        def send(request):
            self.requests.append(request)
            if send_error is not None:
                raise send_error
            status, body = answers.pop(0)
            return status, body if isinstance(body, bytes) else json.dumps(body).encode()

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.mod.subprocess, 'run', tool), mock.patch.object(self.mod, 'send', send), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.code = self.mod.main(list(argv))
        self.out, self.err = out.getvalue(), err.getvalue()
        self.left = answers

    @property
    def methods(self):
        return [r.get_method() for r in self.requests]


class ScriptTests(unittest.TestCase):
    def assertNoSecret(self, run, *values):
        for value in (TOKEN,) + values:
            self.assertNotIn(value, run.out + run.err)

    def test_creates_the_one_record(self):
        run = Run([ZONE_OK, NONE_YET, CREATED])
        self.assertEqual((run.code, run.err), (0, ''))
        self.assertEqual(run.out, 'OK created: A %s -> %s, DNS only, TTL 300\n' % (NAME, IPV4))
        self.assertEqual(run.methods, ['GET', 'GET', 'POST'])
        self.assertEqual([r.full_url for r in run.requests], [
            'https://api.cloudflare.com/client/v4/zones?name=' + ZONE,
            'https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s' % (ZONE_ID, NAME),
            'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % ZONE_ID])
        self.assertEqual(json.loads(run.requests[2].data), {
            'type': 'A', 'name': NAME, 'content': IPV4, 'ttl': 300, 'proxied': False,
            'comment': 'TIMBAR staging (IP-restricted at nginx)'})
        for request in run.requests:
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
            self.assertNotIn(TOKEN, request.full_url)
        self.assertNoSecret(run)

    def test_reads_one_secret_with_a_fixed_command_and_environment(self):
        run = Run([ZONE_OK, NONE_YET, CREATED])
        self.assertEqual(len(run.tool_calls), 1)
        args, kwargs = run.tool_calls[0]
        self.assertEqual(args, ['/opt/homebrew/bin/gcloud', 'secrets', 'versions', 'access', 'latest', '--secret',
                                'GOODQA_CLOUDFLARE_API_TOKEN', '--project', 'goodqa-28dd3'])
        self.assertEqual(sorted(kwargs['env']), ['CLOUDSDK_CORE_DISABLE_PROMPTS', 'HOME', 'PATH'])
        self.assertEqual(kwargs['env']['PATH'], '/opt/homebrew/bin:/usr/bin:/bin')
        self.assertEqual((kwargs['stdin'], kwargs['stderr']), (subprocess.DEVNULL, subprocess.DEVNULL))
        self.assertNotIn('shell', kwargs)
        self.assertTrue(kwargs['timeout'])

    def test_home_for_the_secret_tool_ignores_the_environment(self):
        with mock.patch.dict(os.environ, {'HOME': '/nonexistent/planted'}):
            run = Run([ZONE_OK, NONE_YET, CREATED])
        self.assertNotEqual(run.tool_calls[0][1]['env']['HOME'], '/nonexistent/planted')

    def test_already_present_is_success_without_a_write(self):
        run = Run([ZONE_OK, (200, {'success': True, 'result': [dict(RECORD, ttl=1)]})])
        self.assertEqual((run.code, run.methods), (0, ['GET', 'GET']))
        self.assertEqual(run.out, 'OK already present: A %s -> %s, DNS only\n' % (NAME, IPV4))

    def test_any_other_record_on_the_name_is_a_conflict_and_nothing_is_written(self):
        rows = {
            'other address': [dict(RECORD, content='192.0.2.9')],
            'proxied': [dict(RECORD, proxied=True)],
            'cname': [{'type': 'CNAME', 'name': NAME, 'content': 'elsewhere.example', 'proxied': False}],
            'two records': [RECORD, dict(RECORD, content='192.0.2.9')],
            'wanted twice': [RECORD, RECORD],
            'other name': [dict(RECORD, name='x.' + ZONE)],
        }
        for label, existing in rows.items():
            with self.subTest(label):
                run = Run([ZONE_OK, (200, {'success': True, 'result': existing})])
                self.assertEqual((run.code, run.methods, run.out), (4, ['GET', 'GET'], ''))
                self.assertIn('CONFLICT', run.err)
                self.assertIn('nothing was changed', run.err)
                self.assertNotIn('192.0.2.9', run.err)
                self.assertNotIn('elsewhere.example', run.err)

    def test_zone_not_visible_stops_before_any_record_call(self):
        rows = {
            'no zone': (200, {'success': True, 'result': []}),
            'another zone': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': 'x' + ZONE}]}),
            'two zones': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE}] * 2}),
            'forbidden': (403, {'success': False, 'errors': [{'code': 9109, 'message': 'no ' + TOKEN}]}),
            'not json': (200, b'<html>' + TOKEN.encode()),
            'a list': (200, [1, 2]),
            'odd id': (200, {'success': True, 'result': [{'id': '../' + 'a' * 29, 'name': ZONE}]}),
            'success missing': (200, {'result': [{'id': ZONE_ID, 'name': ZONE}]}),
        }
        for label, answer in rows.items():
            with self.subTest(label):
                run = Run([answer])
                self.assertEqual((run.code, run.methods, run.out), (4, ['GET'], ''))
                self.assertIn('FAILED zone', run.err)
                self.assertNoSecret(run)

    def test_a_failed_or_malformed_lookup_never_writes(self):
        rows = {
            'server error': (500, {'success': False, 'errors': [{'code': 1000, 'message': TOKEN}]}),
            'no result list': (200, {'success': True, 'result': None}),
            'not success': (200, {'success': False, 'result': []}),
            'odd rows': (200, {'success': True, 'result': ['x']}),
            'too large': (200, b' ' * ((1 << 20) + 1)),
        }
        for label, answer in rows.items():
            with self.subTest(label):
                run = Run([ZONE_OK, answer])
                self.assertEqual((run.code, run.methods, run.out), (4, ['GET', 'GET'], ''))
                self.assertIn('nothing was changed', run.err)
                self.assertNoSecret(run)

    def test_a_failed_create_reports_codes_only(self):
        echo = {'success': False, 'result': None,
                'errors': [{'code': 81057, 'message': 'bad ' + TOKEN}, {'code': True}, {'code': 'x' + TOKEN}, 'y']}
        run = Run([ZONE_OK, NONE_YET, (400, echo)])
        self.assertEqual((run.code, run.out), (5, ''))
        self.assertEqual(run.err, 'FAILED create: HTTP 400, codes [81057]; run again to see whether the record exists\n')

    def test_a_create_answer_that_is_not_the_wanted_record_is_not_success(self):
        for label, result in (('other content', dict(RECORD, content='192.0.2.9')), ('proxied', dict(RECORD, proxied=True)),
                              ('missing', None)):
            with self.subTest(label):
                run = Run([ZONE_OK, NONE_YET, (200, {'success': True, 'result': result})])
                self.assertEqual((run.code, run.out), (5, ''))

    def test_secret_failures_stop_before_any_request(self):
        rows = {
            'tool failed': dict(returncode=1, secret='partial-' + TOKEN),
            'two lines': dict(secret=TOKEN + '\nsecond-line-value-0123456789\n'),
            'spaces': dict(secret='Bearer ' + TOKEN),
            'empty': dict(secret=''),
            'short': dict(secret='abc123'),
            'header injection': dict(secret=TOKEN + '\r\nX-Other: 1'),
            'timeout': dict(tool_error=subprocess.TimeoutExpired(['gcloud', TOKEN], 60)),
            'missing tool': dict(tool_error=FileNotFoundError(TOKEN)),
        }
        for label, kwargs in rows.items():
            with self.subTest(label):
                run = Run([], **kwargs)
                self.assertEqual((run.code, run.requests, run.out), (3, [], ''))
                self.assertIn('FAILED secret', run.err)
                self.assertNoSecret(run, 'second-line-value', 'abc123')

    def test_arguments_are_refused_before_anything_runs(self):
        for argv in ([], ['x', 'auto'], ['x', 'find', ZONE], ['x', '--help'], ['x', 'OTHER_SECRET', ZONE, NAME, '192.0.2.1']):
            with self.subTest(argv=argv):
                run = Run([], argv=argv)
                self.assertEqual((run.code, run.tool_calls, run.requests, run.out), (2, [], [], ''))

    def test_a_network_error_that_quotes_the_request_is_not_echoed(self):
        run = Run([], send_error=OSError('connect failed for Bearer ' + TOKEN))
        self.assertEqual((run.code, run.out), (4, ''))
        self.assertIn('HTTP 0', run.err)
        self.assertNoSecret(run)

    def test_an_unexpected_error_prints_its_class_name_only(self):
        mod = load()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(mod, 'run', side_effect=RuntimeError('boom ' + TOKEN)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mod.main(['x'])
        self.assertEqual((code, out.getvalue(), err.getvalue()), (70, '', 'FAILED unexpected: RuntimeError\n'))
        with mock.patch.object(mod, 'run', side_effect=KeyboardInterrupt(TOKEN)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(mod.main(['x']), 70)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())

    def test_no_proxy_from_the_environment_and_no_redirects(self):
        with mock.patch.dict(os.environ, {'https_proxy': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
                                          'all_proxy': 'http://127.0.0.1:9'}):
            mod = load()
        for handler in mod._OPENER.handlers:
            self.assertFalse(isinstance(handler, urllib.request.ProxyHandler) and getattr(handler, 'proxies', None))
        redirects = [h for h in mod._OPENER.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirects), 1)
        self.assertIsNone(redirects[0].redirect_request(None, None, 302, 'Found', {}, 'https://example.test/'))

    def test_the_text_names_one_secret_and_prints_in_one_place(self):
        text = SCRIPT.read_text()
        self.assertEqual(text.count('print('), 2)
        self.assertEqual(sorted(set(__import__('re').findall(r'\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET_KEY|API_KEY)\b', text))),
                         ['GOODQA_CLOUDFLARE_API_TOKEN'])
        for word in ('getenv', 'os.environ', 'open(', 'argparse', 'logging', 'shell=True', 'eval(', 'exec('):
            self.assertNotIn(word, text.replace('_OPENER.open(', ''))

    def test_the_real_file_refuses_an_argument_under_isolated_python(self):
        done = subprocess.run([sys.executable, '-I', str(SCRIPT), 'auto'], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=30, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((done.returncode, done.stdout), (2, b''))
        self.assertIn(b'takes no arguments', done.stderr)


if __name__ == '__main__':
    unittest.main()
