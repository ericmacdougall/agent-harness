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
ZONE_OK = (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE, 'status': 'active'}]})
RECORD = {'type': 'A', 'name': NAME, 'content': IPV4, 'proxied': False, 'ttl': 300}
NONE_YET = (200, {'success': True, 'result': []})
NEW_ID = 'cd' * 16
CREATED = (200, {'success': True, 'result': dict(RECORD, id=NEW_ID)})
CONFIRMED = (200, {'success': True, 'result': [dict(RECORD, id=NEW_ID)]})
RECORDS_URL = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % ZONE_ID


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
        run = Run([ZONE_OK, NONE_YET, CREATED, CONFIRMED])
        self.assertEqual((run.code, run.err), (0, ''))
        self.assertEqual(run.out, 'OK created: A %s -> %s, DNS only, TTL 300\n' % (NAME, IPV4))
        self.assertEqual(run.methods, ['GET', 'GET', 'POST', 'GET'])
        self.assertEqual(run.left, [])
        self.assertEqual([r.full_url for r in run.requests], [
            'https://api.cloudflare.com/client/v4/zones?name=' + ZONE,
            'https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s' % (ZONE_ID, NAME),
            RECORDS_URL, RECORDS_URL + '?name=' + NAME])
        self.assertEqual(json.loads(run.requests[2].data), {
            'type': 'A', 'name': NAME, 'content': IPV4, 'ttl': 300, 'proxied': False,
            'comment': 'TIMBAR staging (IP-restricted at nginx)'})
        for request in run.requests:
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
            self.assertNotIn(TOKEN, request.full_url)
        self.assertNoSecret(run)

    def test_reads_one_secret_with_a_fixed_command_and_environment(self):
        run = Run([ZONE_OK, NONE_YET, CREATED, CONFIRMED])
        self.assertEqual(len(run.tool_calls), 1)
        args, kwargs = run.tool_calls[0]
        self.assertEqual(args, ['/opt/homebrew/bin/gcloud', 'secrets', 'versions', 'access', 'latest', '--secret',
                                'GOODQA_CLOUDFLARE_API_TOKEN', '--project', 'goodqa-28dd3'])
        self.assertEqual(sorted(kwargs['env']), ['CLOUDSDK_CORE_DISABLE_FILE_LOGGING', 'CLOUDSDK_CORE_DISABLE_PROMPTS',
                                                 'CLOUDSDK_CORE_LOG_HTTP', 'HOME', 'PATH'])
        # These two beat a persisted log_http / file-logging setting (checked against a throwaway gcloud config).
        self.assertEqual((kwargs['env']['CLOUDSDK_CORE_LOG_HTTP'], kwargs['env']['CLOUDSDK_CORE_DISABLE_FILE_LOGGING']),
                         ('false', 'true'))
        self.assertEqual(kwargs['env']['PATH'], '/opt/homebrew/bin:/usr/bin:/bin')
        self.assertEqual((kwargs['stdin'], kwargs['stderr']), (subprocess.DEVNULL, subprocess.DEVNULL))
        self.assertNotIn('shell', kwargs)
        self.assertTrue(kwargs['timeout'])

    def test_home_for_the_secret_tool_ignores_the_environment(self):
        with mock.patch.dict(os.environ, {'HOME': '/nonexistent/planted'}):
            run = Run([ZONE_OK, NONE_YET, CREATED, CONFIRMED])
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
            'another zone': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': 'x' + ZONE, 'status': 'active'}]}),
            'pending zone': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE, 'status': 'pending'}]}),
            'no status': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE}]}),
            'deeply nested': (200, b'[' * 200000),
            'two zones': (200, {'success': True, 'result': [{'id': ZONE_ID, 'name': ZONE, 'status': 'active'}] * 2}),
            'forbidden': (403, {'success': False, 'errors': [{'code': 9109, 'message': 'no ' + TOKEN}]}),
            'not json': (200, b'<html>' + TOKEN.encode()),
            'a list': (200, [1, 2]),
            'odd id': (200, {'success': True, 'result': [{'id': '../' + 'a' * 29, 'name': ZONE, 'status': 'active'}]}),
            'success missing': (200, {'result': [{'id': ZONE_ID, 'name': ZONE, 'status': 'active'}]}),
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
        for label, result in (('other content', dict(RECORD, content='192.0.2.9', id=NEW_ID)),
                              ('proxied', dict(RECORD, proxied=True, id=NEW_ID)), ('missing', None),
                              ('no id', RECORD), ('odd id', dict(RECORD, id='../' + 'a' * 29)), ('id not text', dict(RECORD, id=7))):
            with self.subTest(label):
                run = Run([ZONE_OK, NONE_YET, (200, {'success': True, 'result': result})])
                self.assertEqual((run.code, run.out, run.methods), (5, '', ['GET', 'GET', 'POST']))

    def test_a_record_that_appears_during_the_create_undoes_this_runs_record_only(self):
        mine, other = dict(RECORD, id=NEW_ID), dict(RECORD, content='192.0.2.9', id='ef' * 16)
        rows = {
            'another address beside it': [mine, other],
            'a cname beside it': [mine, {'type': 'CNAME', 'name': NAME, 'content': 'elsewhere.example', 'id': 'ef' * 16}],
            'only the other one': [other],
            'the same record under another id': [dict(RECORD, id='ef' * 16)],
        }
        for label, now in rows.items():
            with self.subTest(label):
                run = Run([ZONE_OK, NONE_YET, CREATED, (200, {'success': True, 'result': now}),
                           (200, {'success': True, 'result': {'id': NEW_ID}})])
                self.assertEqual((run.code, run.out, run.left), (4, '', []))
                self.assertEqual(run.methods, ['GET', 'GET', 'POST', 'GET', 'DELETE'])
                self.assertEqual(run.requests[4].full_url, RECORDS_URL + '/' + NEW_ID)
                self.assertIsNone(run.requests[4].data)
                self.assertIn('the record this run created was removed', run.err)
                self.assertNotIn('192.0.2.9', run.err)

    def test_a_failed_undo_says_what_is_left(self):
        other = dict(RECORD, content='192.0.2.9', id='ef' * 16)
        for label, answer in (('server error', (500, {'success': False, 'errors': [{'code': 1000, 'message': TOKEN}]})),
                              ('not success', (200, {'success': False})), ('no answer', (200, b''))):
            with self.subTest(label):
                run = Run([ZONE_OK, NONE_YET, CREATED, (200, {'success': True, 'result': [dict(RECORD, id=NEW_ID), other]}),
                           answer])
                self.assertEqual((run.code, run.out), (5, ''))
                self.assertIn('FAILED undo', run.err)
                self.assertIn('remove A %s -> %s by hand' % (NAME, IPV4), run.err)
                self.assertNoSecret(run)

    def test_an_unreadable_confirmation_deletes_nothing(self):
        for label, answer in (('server error', (500, {})), ('not a list', (200, {'success': True, 'result': None})),
                              ('odd rows', (200, {'success': True, 'result': ['x']})),
                              ('not listed yet', (200, {'success': True, 'result': []})),
                              ('listed but changed', (200, {'success': True, 'result': [dict(RECORD, proxied=True, id=NEW_ID)]})),
                              ('listed twice', (200, {'success': True, 'result': [dict(RECORD, id=NEW_ID)] * 2})),
                              ('empty row', (200, {'success': True, 'result': [{}]})),
                              ('row without id', (200, {'success': True, 'result': [RECORD]})),
                              ('row with odd id', (200, {'success': True, 'result': [dict(RECORD, id='../' + 'a' * 29)]})),
                              ('row with id not text', (200, {'success': True, 'result': [dict(RECORD, id=7)]})),
                              ('row for another name', (200, {'success': True, 'result': [
                                  dict(RECORD, id='ef' * 16, name='x.' + ZONE, content='192.0.2.9')]})),
                              ('row without type or content', (200, {'success': True, 'result': [
                                  {'id': 'ef' * 16, 'name': NAME}]})),
                              ('mine beside a malformed row', (200, {'success': True, 'result': [
                                  dict(RECORD, id=NEW_ID), {}]})),
                              ('mine beside a row for another name', (200, {'success': True, 'result': [
                                  dict(RECORD, id=NEW_ID), dict(RECORD, id='ef' * 16, name='x.' + ZONE)]}))):
            with self.subTest(label):
                run = Run([ZONE_OK, NONE_YET, CREATED, answer])
                self.assertEqual((run.code, run.out, run.methods), (5, '', ['GET', 'GET', 'POST', 'GET']))
                self.assertIn('FAILED confirm', run.err)

    def test_delete_is_never_sent_on_any_other_path(self):
        for answers in ([ZONE_OK, NONE_YET, CREATED, CONFIRMED], [ZONE_OK, (200, {'success': True, 'result': [RECORD]})],
                        [ZONE_OK, (200, {'success': True, 'result': [dict(RECORD, content='192.0.2.9')]})],
                        [ZONE_OK, NONE_YET, (400, {'success': False})], [(403, {})]):
            run = Run(answers)
            self.assertNotIn('DELETE', run.methods)

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

    def test_the_real_send_ignores_proxies_refuses_redirects_and_returns_error_bodies(self):
        # The real send() and opener against listeners on 127.0.0.1 only; the Authorization value is synthetic.
        import http.server
        import threading
        hits = {'proxy': 0, 'target': 0, 'origin': []}

        def server(kind):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    if kind != 'origin':
                        hits[kind] += 1
                        self.send_response(200)
                        self.end_headers()
                        return
                    hits['origin'].append(self.path)
                    if self.path == '/redirect':
                        self.send_response(302)
                        self.send_header('Location', 'http://127.0.0.1:%d/stolen' % ports['target'])
                        self.end_headers()
                        return
                    body = b'{"success": false}'
                    self.send_response(403 if self.path == '/forbidden' else 200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 5)
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)
            return httpd.server_address[1]

        ports = {}
        for kind in ('proxy', 'target', 'origin'):
            ports[kind] = server(kind)
        proxy = 'http://127.0.0.1:%d' % ports['proxy']
        with mock.patch.dict(os.environ, {'http_proxy': proxy, 'HTTP_PROXY': proxy, 'all_proxy': proxy, 'no_proxy': ''}):
            mod = load()
            answers = []
            for path in ('/ok', '/forbidden', '/redirect'):
                request = urllib.request.Request('http://127.0.0.1:%d%s' % (ports['origin'], path),
                                                 headers={'Authorization': 'Bearer ' + TOKEN})
                answers.append(mod.send(request))
        self.assertEqual([a[0] for a in answers], [200, 403, 302])
        self.assertEqual(answers[1][1], b'{"success": false}')
        self.assertEqual(hits, {'proxy': 0, 'target': 0, 'origin': ['/ok', '/forbidden', '/redirect']})

    def test_the_text_names_one_secret_and_prints_in_one_place(self):
        text = SCRIPT.read_text()
        self.assertEqual(text.count('print('), 2)
        self.assertEqual(sorted(set(__import__('re').findall(r'\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET_KEY|API_KEY)\b', text))),
                         ['GOODQA_CLOUDFLARE_API_TOKEN'])
        for word in ('getenv', 'os.environ', 'open(', 'argparse', 'import logging', 'shell=True', 'eval(', 'exec('):
            self.assertNotIn(word, text.replace('_OPENER.open(', ''))

    def test_the_real_file_refuses_an_argument_under_isolated_python(self):
        done = subprocess.run([sys.executable, '-I', str(SCRIPT), 'auto'], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=30, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((done.returncode, done.stdout), (2, b''))
        self.assertIn(b'takes no arguments', done.stderr)


if __name__ == '__main__':
    unittest.main()
