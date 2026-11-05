"""The one-off pinned routes and the credential-script refusal (GoodQA goodqa#14518).

Every command string here is DATA handed to command_guard.decide(); nothing in this file runs a candidate command or reads
a real credential. Files are synthetic and live in a temporary HOME. CG_HOOKS_DIR points the tests at an older guard to
show them failing first.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

SH_REL = 'unit-mig/t2-rclone/user-run-store-dropbox-secret.sh'
PY_REL = 'unit-mig/cf-dns/cf_dns_prod_move.py'
BASE = '.agent-harness/work/dev-decom/'
SH_TEXT = b'#!/bin/bash\nconf=~/.config/rclone/rclone.conf\n'
PY_TEXT = b'#!/usr/bin/env python3\nSECRET = "GOODQA_CLOUDFLARE_API_TOKEN"\n'
PY_ARGS = ['list', 'set-ttl --name connect.example.test --ttl 60 --expect-ttl 300',
           'set-content --name example.test --content 192.0.2.1 --expect-content 192.0.2.2']


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        env = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        # A fixed clock, so these do not start failing on the expiry date before the table is removed.
        clock = mock.patch.object(cg.time, 'time', return_value=cg.PINNED_ROUTE_EXPIRES - 86400)
        clock.start()
        self.addCleanup(clock.stop)
        self.sh = self.write(BASE + SH_REL, SH_TEXT)
        self.py = self.write(BASE + PY_REL, PY_TEXT)
        table = mock.patch.object(cg, 'PINNED_ROUTES', (
            (SH_REL, sha(SH_TEXT), cg.PINNED_ROUTES[0][2] if hasattr(cg, 'PINNED_ROUTES') else ''),
            (PY_REL, sha(PY_TEXT), cg.PINNED_ROUTES[1][2] if hasattr(cg, 'PINNED_ROUTES') else ''),
        ), create=True)
        table.start()
        self.addCleanup(table.stop)

    def write(self, rel, data):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def verdict(self, command):
        return cg.decide(command, cwd=str(self.home))[0]

    def assertRefused(self, command):
        self.assertEqual(self.verdict(command), 'block', command)

    def assertAllowed(self, command):
        self.assertEqual(self.verdict(command), 'allow', command)


class PinnedRouteTests(Base):
    def test_exact_invocations_are_allowed(self):
        self.assertAllowed('/bin/bash %s' % self.sh)
        for args in PY_ARGS:
            self.assertAllowed('/usr/bin/python3 -I %s %s' % (self.py, args))

    def test_changed_invocations_are_refused(self):
        sh, py = self.sh, self.py
        rows = [
            '/bin/bash %s extra' % sh,
            '/bin/bash %s | tee %s/out' % (sh, self.home),
            '/bin/bash %s > %s/out' % (sh, self.home),
            '/bin/bash %s; true' % sh,
            'true && /bin/bash %s' % sh,
            '/bin/bash  %s' % sh,
            '/bin/bash %s\n' % sh,
            '/bin/bash -x %s' % sh,
            'bash %s' % sh,
            'sh %s' % sh,
            'source %s' % sh,
            'bash < %s' % sh,
            str(sh),
            'FOO=1 /bin/bash %s' % sh,
            'env -i /bin/bash %s' % sh,
            '/usr/bin/python3 %s list' % py,
            'python3 -I %s list' % py,
            '/usr/bin/python3 -I %s' % py,
            '/usr/bin/python3 -I %s delete' % py,
            '/usr/bin/python3 -I %s list extra' % py,
            '/usr/bin/python3 -I %s list | tee %s/out' % (py, self.home),
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60' % py,
            '/usr/bin/python3 -I %s set-content --name $(id) --content 192.0.2.1 --expect-content 192.0.2.2' % py,
            '/usr/bin/python3 -I %s set-content --name x --content $(id) --expect-content 192.0.2.2' % py,
            '/usr/bin/python3 -I %s set-content --name x --content 192.0.2.1 --expect-content $(id)' % py,
            '/usr/bin/python3 -I %s set-ttl --name $(id) --ttl 60 --expect-ttl 300' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl $(id) --expect-ttl 300' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60 --expect-ttl $(id)' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60 --expect-ttl 300 --extra' % py,
            '/bin/sh %s' % sh,
            '/usr/local/bin/bash %s' % sh,
            '/usr/local/bin/python3 -I %s list' % py,
            '/bin/bash %s' % py,
            '/usr/bin/python3 -I %s list' % sh,
        ]
        for command in rows:
            with self.subTest(command=command):
                self.assertRefused(command)

    def test_modified_script_at_the_pinned_path_is_refused(self):
        self.sh.write_bytes(SH_TEXT + b'# changed\n')
        self.py.write_bytes(PY_TEXT + b'# changed\n')
        self.assertRefused('/bin/bash %s' % self.sh)
        self.assertRefused('/usr/bin/python3 -I %s list' % self.py)

    def test_copy_at_another_path_is_refused(self):
        sh = self.write('elsewhere/copy.sh', SH_TEXT)
        py = self.write('elsewhere/copy.py', PY_TEXT)
        self.assertRefused('/bin/bash %s' % sh)
        self.assertRefused('/usr/bin/python3 -I %s list' % py)

    def test_symlink_at_the_pinned_path_is_refused(self):
        target = self.write('elsewhere/target.sh', SH_TEXT)
        self.sh.unlink()
        self.sh.symlink_to(target)
        self.assertRefused('/bin/bash %s' % self.sh)

    def test_missing_file_gives_no_route(self):
        self.sh.unlink()
        self.assertFalse(cg.pinned_route('/bin/bash %s' % self.sh))

    def test_routes_end_at_expiry(self):
        command = '/bin/bash %s' % self.sh
        self.assertTrue(cg.pinned_route(command, now=cg.PINNED_ROUTE_EXPIRES - 1))
        self.assertFalse(cg.pinned_route(command, now=cg.PINNED_ROUTE_EXPIRES))
        with mock.patch.object(cg.time, 'time', return_value=cg.PINNED_ROUTE_EXPIRES):
            self.assertRefused(command)

    def test_read_failure_gives_no_route(self):
        with mock.patch.object(cg, '_read_prefix', side_effect=OSError):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % self.sh))

    def test_only_a_plain_home_gives_a_route(self):
        command = '/bin/bash %s' % self.sh
        self.assertTrue(cg.pinned_route(command))
        for home in ('', 'relative/home', str(self.home) + ';id', str(self.home) + ' x', '$(id)'):
            with self.subTest(home=home), mock.patch.dict(os.environ, {'HOME': home}):
                self.assertFalse(cg.pinned_route(command))
                path = '%s/%s%s' % (home, BASE, SH_REL)
                self.assertFalse(cg.pinned_route('/bin/bash %s' % path))
        with mock.patch.dict(os.environ):
            del os.environ['HOME']
            self.assertFalse(cg.pinned_route(command))

    def test_a_home_with_shell_syntax_and_a_true_copy_gets_no_route(self):
        home = str(self.home) + '/a;id;'
        target = Path(home) / BASE / SH_REL
        target.parent.mkdir(parents=True)
        target.write_bytes(SH_TEXT)
        with mock.patch.dict(os.environ, {'HOME': home}):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % target))

    def test_a_command_list_gets_no_route(self):
        self.assertFalse(cg.pinned_route(['/bin/bash', str(self.sh)]))

    def test_a_policy_file_cannot_add_a_route(self):
        policy = self.home / 'policy.json'
        rogue = self.write('x/rogue.sh', b'#!/bin/bash\ncat ~/.config/rclone/rclone.conf\n')
        policy.write_text(json.dumps({'PINNED_ROUTES': [['x/rogue.sh', sha(b''), '/bin/bash {path}']],
                                      'pinned_routes': [['x/rogue.sh', sha(b''), '/bin/bash {path}']]}))
        compiled = cg.Compiled(cg.load_policy(path=str(policy)), cwd=str(self.home))
        self.assertEqual(cg.decide('/bin/bash %s' % rogue, compiled, cwd=str(self.home))[0], 'block')


class CredentialScriptTests(Base):
    def test_other_scripts_naming_the_credentials_are_refused(self):
        sh = self.write('x/run.sh', b'#!/bin/bash\nwc -c ~/.config/rclone/rclone.conf\n')
        py = self.write('x/run.py', b'open("/any/.config/rclone/rclone.conf")\n')
        token = self.write('x/token.py', b'name = "GOODQA_CLOUDFLARE_API_TOKEN"\n')
        dump = self.write('x/dump.sh', b'#!/bin/bash\nrclone config show\n')
        dump2 = self.write('x/dump2.sh', b'rclone  config  dump\n')
        noext = self.write('x/noext', b'#!/usr/bin/env python3\nopen("/any/.config/rclone/rclone.conf")\n')
        for command in ('bash %s' % sh, 'sh %s' % sh, str(sh), 'source %s' % sh, 'bash < %s' % sh, 'python3 %s' % py,
                        'python3 -I %s' % token, '/usr/bin/python3 %s --flag' % token, 'bash %s' % dump,
                        'bash %s' % dump2, str(noext), 'python3.12 %s' % py, 'python3.9 -I %s' % token,
                        'python3 -W ignore %s' % py, 'python3 -X utf8 %s' % py, 'bash -euo pipefail %s' % sh,
                        'bash -o pipefail %s' % sh, 'echo x >> %s; bash %s' % (sh, sh)):
            with self.subTest(command=command):
                self.assertRefused(command)

    def test_harness_tools_are_not_refused(self):
        """Every hook and helper the harness ships, run by path. A mention of rclone must not stop them."""
        files = sorted(p for d in ('harness/hooks', 'harness/bin', 'scripts', 'tools') for p in (ROOT / d).glob('*')
                       if p.is_file() and p.suffix in ('.py', '.sh'))
        self.assertGreater(len(files), 20)
        for path in files:
            run = 'bash' if path.suffix == '.sh' else 'python3'
            with self.subTest(path=path.name):
                self.assertNotEqual(self.verdict('%s %s' % (run, path)), 'block')

    def test_data_and_lookalikes_are_not_refused(self):
        marker = b'.config/rclone/rclone.conf GOODQA_CLOUDFLARE_API_TOKEN\n'
        data = self.write('x/main.jsonl', marker)
        notes = self.write('x/notes.md', marker)
        mention = self.write('x/mention.sh', b'#!/bin/bash\n# rclone.conf is not read here; see rclone.conf.example\n')
        gui = self.write('x/gui.sh', b'#!/bin/bash\nls .config/rclone-gui/ .config/rclone/rclone.conf.example\n')
        named = self.write('x/named.sh', marker)
        a_test = self.write('x/test_thing.py', marker)
        other_guard = self.write('other/harness/hooks/command_guard.py', marker)
        canary = self.write('x/tests/live_guard_canary.py', marker)
        for command in ('python3 -m json_tool %s' % data, 'bash < %s' % notes, 'bash %s' % data, 'bash %s' % mention,
                        'bash %s' % gui, 'bash -n %s' % named, '/bin/bash -n %s' % named, 'sh -n %s' % named,
                        'python3 -I %s' % a_test, 'python3 %s doctor' % other_guard, 'python3 %s' % canary,
                        'python3 -m unittest discover -s %s' % named.parent):
            with self.subTest(command=command):
                self.assertNotEqual(self.verdict(command), 'block')

    def test_the_credential_file_stays_refused_directly(self):
        conf = self.home / '.config/rclone/rclone.conf'
        self.assertRefused('cat %s' % conf)
        self.assertRefused('gcloud secrets versions access latest --secret=GOODQA_CLOUDFLARE_API_TOKEN')

    def test_controls_stay_allowed(self):
        plain = self.write('x/plain.sh', b'#!/bin/bash\necho hello\n')
        plain_py = self.write('x/plain.py', b'print("hello")\n')
        named = self.write('x/named.sh', b'#!/bin/bash\nconf=~/.config/rclone/rclone.conf\n')
        binary = self.write('bin/tool', b'\x7fELF\x00\x00 .config/rclone/rclone.conf GOODQA_CLOUDFLARE_API_TOKEN')
        shebinary = self.write('bin/tool.sh', b'#!/bin/sh\n\x00.config/rclone/rclone.conf\n')
        for command in ('bash %s' % plain, 'python3 %s' % plain_py, '%s --version' % binary, str(shebinary), 'cat %s' % named,
                        'grep -c rclone %s' % named, 'shasum -a 256 %s' % named, 'python3 -m unittest tests.test_x',
                        'rclone listremotes', 'ls %s' % named.parent):
            with self.subTest(command=command):
                self.assertAllowed(command)

    def test_the_guard_may_run_itself(self):
        self.assertNotEqual(self.verdict('python3 %s --help' % cg.__file__), 'block')

    def test_a_script_past_the_read_limit_is_not_read(self):
        """Documents the text-only limit, so a change to it is a decision rather than an accident."""
        far = self.write('x/far.py', b'#' * cg.CREDENTIAL_SCRIPT_READ + b'\n.config/rclone/rclone.conf\n')
        self.assertAllowed('python3 %s' % far)


class TableTests(unittest.TestCase):
    def test_the_table_is_exactly_these_two_pins(self):
        self.assertEqual([(r[0], r[1]) for r in cg.PINNED_ROUTES], [
            (SH_REL, '92438a47d6b8083266e42922a2d151d0d0d65475fcc20744ea54359f2af501f3'),
            (PY_REL, '30c688923554c09f93128a7d9b89831557acd06d1f04949c235b09ea05cf89a6'),
        ])

    def test_expiry_is_fixed(self):
        self.assertEqual(time_string(cg.PINNED_ROUTE_EXPIRES), '2026-11-09T00:00:00Z')



def time_string(epoch):
    import time as _time
    return _time.strftime('%Y-%m-%dT%H:%M:%SZ', _time.gmtime(epoch))


if __name__ == '__main__':
    unittest.main()
