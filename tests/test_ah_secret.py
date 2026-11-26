"""`ah secret` (harness/hooks/ah_secret.py): a secret goes from the clipboard to a store without passing through argv, an
environment, stdout or stderr; `exec` hands it to one child's environment and masks it in that child's output.

Every store and clipboard tool is a FAKE executable on PATH in a temporary directory (gcloud, security, pbpaste, pbcopy,
wl-paste). Each fake records its argv, its environment and its stdin, so the tests can prove where the value went.
The values are synthetic.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

VALUE = b'sk-test-' + b'Zq9' * 12 + b'!$"\'`;|&'  # synthetic, with shell metacharacters

FAKE = textwrap.dedent('''\
    import json, os, sys
    state = os.environ['FAKE_STATE']
    tool = sys.argv.pop(1)
    data = b'' if tool in ('pbpaste', 'wl-paste') or sys.stdin.isatty() else sys.stdin.buffer.read()
    n = len(os.listdir(os.path.join(state, 'calls')))
    open(os.path.join(state, 'calls', '%04d.stdin' % n), 'wb').write(data)
    with open(os.path.join(state, 'calls', '%04d.json' % n), 'w') as f:
        json.dump({'tool': tool, 'argv': sys.argv[1:], 'env': dict(os.environ)}, f)
    gcp = os.path.join(state, 'gcp')
    def out(b):
        sys.stdout.buffer.write(b); sys.stdout.flush()
    a = sys.argv[1:]
    if tool in ('pbpaste', 'wl-paste'):
        p = os.path.join(state, 'clipboard')
        out(open(p, 'rb').read() if os.path.exists(p) else b'')
    elif tool in ('pbcopy',) or (tool == 'wl-copy'):
        open(os.path.join(state, 'clipboard'), 'wb').write(data)
    elif tool == 'gcloud':
        assert a[0] == 'secrets', a
        pos = [x for x in a[1:] if not x.startswith('--')]
        flags = dict(x[2:].split('=', 1) for x in a if x.startswith('--') and '=' in x)
        if pos[0] == 'describe':
            sys.exit(0 if os.path.isdir(os.path.join(gcp, pos[1])) else 1)
        if pos[0] == 'create':
            os.makedirs(os.path.join(gcp, pos[1]))
            if 'set-annotations' in flags:
                open(os.path.join(gcp, pos[1], 'annotations'), 'w').write(flags['set-annotations'])
        elif pos[0] == 'update':
            open(os.path.join(gcp, pos[1], 'annotations'), 'w').write(flags['update-annotations'])
        elif pos[:2] == ['versions', 'add']:
            assert flags.get('data-file') == '-', a
            d = os.path.join(gcp, pos[2])
            k = len([x for x in os.listdir(d) if x.startswith('v')]) + 1
            open(os.path.join(d, 'v%d' % k), 'wb').write(data)
            out(('projects/fake/secrets/%s/versions/%d\\n' % (pos[2], k)).encode())
        elif pos[:2] == ['versions', 'access']:
            d = os.path.join(gcp, flags['secret'])
            k = len([x for x in os.listdir(d) if x.startswith('v')])
            out(open(os.path.join(d, 'v%d' % k), 'rb').read())
        elif pos[0] == 'list':
            for name in sorted(os.listdir(gcp)) if os.path.isdir(gcp) else []:
                out(('projects/fake/secrets/%s\\n' % name).encode())
        elif pos[0] == 'delete':
            import shutil; shutil.rmtree(os.path.join(gcp, pos[1]))
    elif tool == 'security':
        kc = os.path.join(state, 'keychain'); os.makedirs(kc, exist_ok=True)
        if a == ['-i']:
            words = data.decode().split()
            assert words[0] == 'add-generic-password', words
            name = words[words.index('-s') + 1]
            open(os.path.join(kc, name), 'wb').write(bytes.fromhex(words[words.index('-X') + 1]))
        elif a[0] == 'find-generic-password':
            out(open(os.path.join(kc, a[a.index('-s') + 1]), 'rb').read() + b'\\n')
    ''')


class Fakes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ah-secret-')
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.bin, self.state, self.home = self.tmp / 'bin', self.tmp / 'state', self.tmp / 'home'
        for d in (self.bin, self.state / 'calls', self.home):
            d.mkdir(parents=True)
        (self.bin / 'fake.py').write_text(FAKE)
        for tool in ('gcloud', 'security', 'pbpaste', 'pbcopy'):
            path = self.bin / tool
            path.write_text('#!/bin/sh\nexec %s %s %s "$@"\n' % (sys.executable, self.bin / 'fake.py', tool))
            path.chmod(0o755)

    def clip(self, data):
        (self.state / 'clipboard').write_bytes(data)

    def ah(self, *args, stdin=b''):
        env = {'PATH': '%s:/usr/bin:/bin' % self.bin, 'HOME': str(self.home), 'FAKE_STATE': str(self.state)}
        done = subprocess.run([sys.executable, str(HOOKS / 'ah.py'), 'secret', *args], input=stdin, env=env,
                              capture_output=True, timeout=60, check=False)
        return done

    def calls(self):
        out = []
        for meta in sorted((self.state / 'calls').glob('*.json')):
            record = json.loads(meta.read_text())
            record['stdin'] = meta.with_suffix('.stdin').read_bytes()
            out.append(record)
        return out

    def assert_value_only_on_stdin(self, done, values, tool='gcloud'):
        for value in values:
            text = value.decode()
            self.assertNotIn(value, done.stdout)
            self.assertNotIn(value, done.stderr)
            for call in self.calls():
                self.assertFalse(any(text in a for a in call['argv']), call['argv'])
                self.assertFalse(any(text in v for v in call['env'].values()))
            self.assertTrue(any(value in c['stdin'] or value.hex().encode() in c['stdin']
                                for c in self.calls() if c['tool'] == tool))


class PutTests(Fakes):
    def test_clipboard_to_gcp_byte_exact_and_cleared(self):
        self.clip(VALUE + b'\n')  # a copied key often ends with a newline
        done = self.ah('put', 'OPENAI_KEY')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        result = json.loads(done.stdout)
        self.assertEqual(result['stored'], [{'name': 'OPENAI_KEY', 'store': 'gcp', 'version': '1', 'bytes': len(VALUE)}])
        self.assertEqual(result['clipboard'], 'cleared')
        self.assertEqual((self.state / 'clipboard').read_bytes(), b'')
        adds = [c for c in self.calls() if c['tool'] == 'gcloud' and c['argv'][1:3] == ['versions', 'add']]
        self.assertEqual(len(adds), 1)
        self.assertEqual(adds[0]['stdin'], VALUE)  # byte-exact on stdin
        self.assertIn('--data-file=-', adds[0]['argv'])
        creates = [c for c in self.calls() if c['tool'] == 'gcloud' and c['argv'][1] == 'create']
        self.assertIn('--replication-policy=automatic', creates[0]['argv'])
        self.assert_value_only_on_stdin(done, [VALUE])
        # a second put adds a version and does not create again
        self.clip(VALUE[::-1])
        again = json.loads(self.ah('put', 'OPENAI_KEY', '--keep-clipboard').stdout)
        self.assertEqual(again['stored'][0]['version'], '2')
        self.assertEqual(again['clipboard'], 'kept')
        self.assertEqual(len([c for c in self.calls() if c['tool'] == 'gcloud' and c['argv'][1] == 'create']), 1)

    def test_lines_with_fields_and_labels(self):
        keys = [b'key-' + bytes([65 + i]) * 30 for i in range(3)]
        self.clip(b'acme prod|' + keys[0] + b'\r\n\n beta|' + keys[1] + b'\ngamma |' + keys[2] + b'\n')
        done = self.ah('put', 'LEAD', '--lines', '--sep', '|', '--field', '2', '--label-field', '1')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        stored = json.loads(done.stdout)['stored']
        self.assertEqual([s['name'] for s in stored], ['LEAD-1', 'LEAD-2', 'LEAD-3'])
        for i, key in enumerate(keys, 1):
            self.assertEqual((self.state / 'gcp' / ('LEAD-%d' % i) / 'v1').read_bytes(), key)
        self.assertEqual((self.state / 'gcp/LEAD-1/annotations').read_text(), 'label=acme prod')
        self.assertEqual((self.state / 'gcp/LEAD-3/annotations').read_text(), 'label=gamma')
        self.assertEqual((self.state / 'clipboard').read_bytes(), b'')
        self.assert_value_only_on_stdin(done, keys)

    def test_lines_without_fields(self):
        self.clip(b'first-value-1234\n\nsecond-value-5678\n')
        done = self.ah('put', 'K', '--lines')
        self.assertEqual([s['name'] for s in json.loads(done.stdout)['stored']], ['K-1', 'K-2'])
        self.assertEqual((self.state / 'gcp/K-2/v1').read_bytes(), b'second-value-5678')

    def test_a_label_that_looks_like_the_key_stores_nothing(self):
        self.clip(b'acme|' + b'X' * 40 + b'\n')
        done = self.ah('put', 'LEAD', '--lines', '--sep', '|', '--field', '1', '--label-field', '2')
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b'X' * 40, done.stdout + done.stderr)
        self.assertFalse((self.state / 'gcp').exists())
        self.assertNotEqual((self.state / 'clipboard').read_bytes(), b'')  # kept: nothing was stored

    def test_empty_clipboard_stores_nothing(self):
        self.clip(b'  \n')
        done = self.ah('put', 'X')
        self.assertEqual(json.loads(done.stdout)['code'], 'empty')
        self.assertFalse((self.state / 'gcp').exists())

    def test_keychain_goes_through_security_stdin(self):
        self.clip(VALUE)
        done = self.ah('put', 'KC', '--to', 'keychain')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual((self.state / 'keychain/KC').read_bytes(), VALUE)
        calls = [c for c in self.calls() if c['tool'] == 'security']
        self.assertEqual(calls[0]['argv'], ['-i'])
        for call in self.calls():  # neither the value nor its hex form is on any argv
            self.assertFalse(any(VALUE.hex() in a for a in call['argv']))
        self.assert_value_only_on_stdin(done, [VALUE], tool='security')

    def test_file_store_is_0600_and_from_stdin(self):
        target = self.tmp / 'vault' / 'k.txt'
        done = self.ah('put', 'F', '--from', 'stdin', '--to', 'file:%s' % target, stdin=VALUE)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(target.read_bytes(), VALUE)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(done.stdout)['clipboard'], 'not used')
        self.assertNotIn(VALUE, done.stdout + done.stderr)


class ExecListTests(Fakes):
    def test_exec_puts_the_value_in_the_child_env_only_and_masks_output(self):
        self.clip(VALUE)
        self.ah('put', 'TOK')
        script = 'import os,sys; v=os.environ["MY_TOKEN"]; print("out:"+v); sys.stderr.write("err:"+v[:5]+v[5:]+"\\n")'
        done = self.ah('exec', '--env', 'MY_TOKEN=TOK', '--', sys.executable, '-c', script)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(VALUE, done.stdout + done.stderr)
        self.assertIn(b'out:[REDACTED:ah-secret]', done.stdout)
        self.assertIn(b'err:[REDACTED:ah-secret]', done.stderr)
        code = self.ah('exec', '--env', 'MY_TOKEN=TOK', '--', sys.executable, '-c', 'import sys; sys.exit(7)')
        self.assertEqual(code.returncode, 7)

    def test_list_prints_names_only(self):
        self.clip(VALUE)
        self.ah('put', 'A1')
        done = self.ah('list')
        self.assertEqual(json.loads(done.stdout)['names'], ['A1'])
        self.assertNotIn(VALUE, done.stdout)


class RmTests(Fakes):
    def test_rm_is_refused_for_a_worker_and_runs_for_the_owner(self):
        """The release 1001 red team: docs said the command guard gated rm; it was deleted, and rm had no check."""
        target = self.tmp / 'vault'
        target.mkdir()
        self.ah('put', 'K', '--from', 'stdin', '--to', 'file:%s/' % target, stdin=VALUE)
        self.assertTrue((target / 'K').exists())

        def rm(**env):
            full = {'PATH': '%s:/usr/bin:/bin' % self.bin, 'HOME': str(self.home), 'FAKE_STATE': str(self.state), **env}
            return subprocess.run([sys.executable, str(HOOKS / 'ah.py'), 'secret', 'rm', 'K', '--store',
                                   'file:%s' % target], env=full, capture_output=True, timeout=60, check=False)
        for env in ({'AH_ROLE': 'worker', 'AH_ROLE_SOURCE': 'ah-sandbox:worker'},
                    {'AH_ROLE': 'reviewer', 'AH_ROLE_SOURCE': 'ah-sandbox:reviewer'}, {'CLAUDECODE': '1'}):
            done = rm(**env)
            self.assertEqual(done.returncode, 3, done.stdout)
            self.assertIn(b'only the owner or a supervisor', done.stdout)
            self.assertTrue((target / 'K').exists())
        done = rm()   # the owner's terminal: no agent marker, no AH_ROLE
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse((target / 'K').exists())


class MaskerTests(unittest.TestCase):
    def test_values_split_across_chunks_are_masked(self):
        import redact
        value = b'abcdefghij'
        for cut in range(1, 12):
            data = b'xx' + value + b'yy' + value
            masker = redact.ExactMasker([value])
            out = b''.join(masker.feed(data[i:i + cut]) for i in range(0, len(data), cut)) + masker.flush()
            self.assertEqual(out, b'xx[REDACTED:ah-secret]yy[REDACTED:ah-secret]', cut)
        self.assertEqual(redact.mask_values('a secret-1234 b', ['secret-1234']), 'a [REDACTED:ah-secret] b')


if __name__ == '__main__':
    unittest.main()
