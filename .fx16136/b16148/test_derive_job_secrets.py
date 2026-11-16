"""goodqa#16148 spec v4 AC-1, AC-2, AC-9, NEG-1, NEG-2, NEG-3, NEG-13: derive-job-secrets.py.

Fake values only. The ownership tests need root (fchown to 0:64910), so they run in a throwaway
container: run_derive_tests.sh starts one with this directory mounted and --network none. The
compose parity test needs the docker compose CLI and runs on the host (it skips elsewhere).
Run:  python3 -m unittest -v test_derive_job_secrets
"""
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'derive-job-secrets.py')
spec = importlib.util.spec_from_file_location('derive_job_secrets', SCRIPT)
derive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(derive)

MARKER = 'FAKEpemMARKER0123456789abcdefghijKLMNOPqrst'
IS_ROOT = os.geteuid() == 0
LINE = 'job secret github-app-private-key: '

STUB_GETENT = r'''#!/usr/bin/env python3
import os, sys
root = os.environ['FAKE_NSS_ROOT']
with open(os.path.join(root, 'argv.log'), 'a') as f:
    f.write(repr(sys.argv) + '\n')
db = sys.argv[1]
files = {'group': ['etc/group', 'nss-group'], 'passwd': ['etc/passwd', 'nss-passwd']}[db]
rows = []
for rel in files:
    p = os.path.join(root, rel)
    if os.path.exists(p):
        rows += [l for l in open(p).read().splitlines() if l]
if len(sys.argv) > 2:
    want = sys.argv[2]
    rows = [r for r in rows if r.split(':')[0] == want or r.split(':')[2] == want]
    if not rows:
        sys.exit(2)
print('\n'.join(rows))
'''

STUB_GROUPADD = r'''#!/usr/bin/env python3
import os, sys
root = os.environ['FAKE_NSS_ROOT']
with open(os.path.join(root, 'argv.log'), 'a') as f:
    f.write(repr(sys.argv) + '\n')
args = sys.argv[1:]
assert args[:2] == ['-R', root], args
with open(os.path.join(root, 'etc/group'), 'a') as f:
    f.write('%s:x:%s:\n' % (args[-1], args[args.index('-g') + 1]))
'''


class FakeHost:
    def __init__(self, api_env=None):
        self.root = tempfile.mkdtemp(prefix='derive-root-', dir=os.environ.get('DERIVE_TEST_TMP'))
        os.chmod(self.root, 0o755)
        os.makedirs(self.p('etc/goodqa'), mode=0o755)
        os.chmod(self.p('etc/goodqa'), 0o755)
        with open(self.p('etc/group'), 'w') as f:
            f.write('root:x:0:\nadm:x:4:syslog\n')
        with open(self.p('etc/passwd'), 'w') as f:
            f.write('root:x:0:0:root:/root:/bin/bash\n')
        self.bin = self.p('stub-bin')
        os.makedirs(self.bin)
        for name, body in (('getent', STUB_GETENT), ('groupadd', STUB_GROUPADD)):
            with open(os.path.join(self.bin, name), 'w') as f:
                f.write(body)
            os.chmod(os.path.join(self.bin, name), 0o755)
        self.sentinel = self.p('sentinel')
        with open(self.sentinel, 'w') as f:
            f.write('sentinel')
        if api_env is not None:
            self.write_api_env(api_env)

    def p(self, rel):
        return os.path.join(self.root, rel)

    def write_api_env(self, data):
        if isinstance(data, str):
            data = data.encode()
        with open(self.p('etc/goodqa/api.env'), 'wb') as f:
            f.write(data)

    def env(self):
        return {'PATH': self.bin + ':' + os.environ['PATH'], 'FAKE_NSS_ROOT': self.root}

    def run(self, argv=(), hooks=None):
        saved = dict(os.environ)
        os.environ.update(self.env())
        try:
            return derive.run(list(argv), root=self.root, hooks=hooks)
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def secret(self):
        return self.p('etc/goodqa/job-secrets/github-app-private-key')

    def sentinel_state(self):
        st = os.lstat(self.sentinel)
        return (st.st_uid, st.st_gid, st.st_mode, open(self.sentinel, 'rb').read())

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def api(value, extra=''):
    return 'DATABASE_URL=postgres://fake\n%sGITHUB_APP_PRIVATE_KEY=%s\nOTHER=1\n' % (extra, value)


class ParseTests(unittest.TestCase):
    """AC-1: the value exactly as compose `format: raw` would deliver it."""

    def ok(self, text, expected):
        self.assertEqual(derive.parse_api_env(text.encode()), expected.encode())

    def refused(self, text, reason):
        with self.assertRaises(derive.Refused) as cm:
            derive.parse_api_env(text if isinstance(text, bytes) else text.encode())
        self.assertEqual(str(cm.exception), reason)

    def test_derive_parse_plain(self):
        self.ok(api(MARKER), MARKER)

    def test_derive_parse_base64_with_equals(self):
        self.ok(api('TUlJRkFLRQ=='), 'TUlJRkFLRQ==')

    def test_derive_parse_double_quoted(self):
        self.ok(api('"%s"' % MARKER), '"%s"' % MARKER)

    def test_derive_parse_single_quoted(self):
        self.ok(api("'%s'" % MARKER), "'%s'" % MARKER)

    def test_derive_parse_trailing_spaces(self):
        self.ok(api(MARKER + '   '), MARKER + '   ')

    def test_derive_parse_inner_hash_kept(self):
        self.ok(api('abc # def'), 'abc # def')

    def test_derive_parse_leading_key_whitespace(self):
        self.ok('  GITHUB_APP_PRIVATE_KEY=%s\n' % MARKER, MARKER)

    def test_derive_parse_crlf(self):
        self.ok('A=1\r\nGITHUB_APP_PRIVATE_KEY=%s\r\nB=2\r\n' % MARKER, MARKER)

    def test_derive_parse_comment_line_ignored(self):
        self.ok('#GITHUB_APP_PRIVATE_KEY=commented\n' + api(MARKER), MARKER)

    def test_derive_parse_export(self):
        self.refused('export GITHUB_APP_PRIVATE_KEY=%s\n' % MARKER, 'export form')

    def test_derive_parse_duplicate(self):
        self.refused(api(MARKER) + 'GITHUB_APP_PRIVATE_KEY=second\n', 'more than one GITHUB_APP_PRIVATE_KEY line')

    def test_derive_parse_missing(self):
        self.refused('DATABASE_URL=x\n', 'no GITHUB_APP_PRIVATE_KEY line')

    def test_derive_parse_empty(self):
        self.refused(api(''), 'empty value')

    def test_derive_parse_tab(self):
        self.refused(api('abc\tdef'), 'value holds a byte outside printable ASCII')

    def test_derive_parse_cr_inside(self):
        self.refused(b'GITHUB_APP_PRIVATE_KEY=ab\rcd\n', 'value holds a byte outside printable ASCII')

    def test_derive_parse_non_ascii(self):
        self.refused('GITHUB_APP_PRIVATE_KEY=caf\u00e9\n', 'value holds a byte outside printable ASCII')

    def test_derive_parse_invalid_utf8(self):
        self.refused(b'GITHUB_APP_PRIVATE_KEY=ab\xffcd\n', 'value holds a byte outside printable ASCII')

    def test_derive_parse_line_compose_refuses(self):
        self.refused('BAD KEY=1\n' + api(MARKER), 'api.env has a line compose would refuse')


@unittest.skipUnless(shutil.which('docker') and not IS_ROOT, 'compose parity runs on the host with the docker CLI')
class ComposeParityTests(unittest.TestCase):
    """AC-1 parity: derive's value equals what the real `docker compose config` gives the api service."""

    COMPOSE = os.path.join(HERE, 'compose.yaml')

    def test_api_env_file_is_format_raw(self):
        text = open(self.COMPOSE).read()
        block = text[text.index('\n  api:\n'):]
        block = block[:block.index('\n  web:\n')]
        self.assertIn('      - path: /etc/goodqa/api.env\n        format: raw\n', block)

    def test_derive_value_equals_compose_value(self):
        accepted = [MARKER, 'TUlJRkFLRQ==', '"%s"' % MARKER, "'%s'" % MARKER, MARKER + '   ', 'abc # def', 'x=y=z']
        tmp = tempfile.mkdtemp(prefix='parity-', dir=os.environ.get('DERIVE_TEST_TMP'))
        try:
            for i, value in enumerate(accepted):
                for eol in ('\n', '\r\n'):
                    envp = os.path.join(tmp, 'api-%d.env' % i)
                    with open(envp, 'w', newline='') as f:
                        f.write('A=1%sGITHUB_APP_PRIVATE_KEY=%s%sB=2%s' % (eol, value, eol, eol))
                    comp = os.path.join(tmp, 'compose.yaml')
                    with open(comp, 'w') as f:
                        f.write(textwrap.dedent('''\
                            services:
                              api:
                                image: busybox:1.36
                                env_file:
                                  - path: %s
                                    format: raw
                            ''' % envp))
                    out = subprocess.run(['docker', 'compose', '-f', comp, 'config', '--format', 'json'],
                                         capture_output=True, text=True, timeout=60, check=True).stdout
                    composed = json.loads(out)['services']['api']['environment']['GITHUB_APP_PRIVATE_KEY']
                    derived = derive.parse_api_env(open(envp, 'rb').read()).decode()
                    self.assertEqual(derived, composed, 'value %d eol %r' % (i, eol))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(IS_ROOT, 'ownership tests need root: run_derive_tests.sh runs them in a throwaway container')
class DeriveTests(unittest.TestCase):
    def setUp(self):
        self.h = FakeHost(api(MARKER))

    def tearDown(self):
        self.h.close()

    def assert_file_ok(self, value=MARKER):
        st = os.lstat(self.h.secret())
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o7777), (0, 64910, 0o440))
        d = os.lstat(os.path.dirname(self.h.secret()))
        self.assertEqual((d.st_uid, d.st_gid, d.st_mode & 0o7777), (0, 0, 0o711))
        self.assertEqual(open(self.h.secret(), 'rb').read(), value.encode())

    # ---- AC-2 ----
    def test_written_then_unchanged(self):
        self.assertEqual(self.h.run(), ('written', 0))
        self.assert_file_ok()
        self.assertIn('goodqa-jobsecret:x:64910:', open(self.h.p('etc/group')).read())
        m1 = os.lstat(self.h.secret()).st_mtime_ns
        time.sleep(0.02)
        self.assertEqual(self.h.run(), ('unchanged', 0))
        self.assertEqual(os.lstat(self.h.secret()).st_mtime_ns, m1)

    def test_no_temp_left_after_abrupt_stop_between_write_and_rename(self):
        pid = os.fork()
        if pid == 0:
            try:
                self.h.run(hooks={'before_rename': lambda _t: os.kill(os.getpid(), signal.SIGKILL)})
            finally:
                os._exit(3)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        d = os.path.dirname(self.h.secret())
        self.assertTrue(any(n.startswith('.tmp-') for n in os.listdir(d)))
        self.assertFalse(os.path.exists(self.h.secret()))
        self.assertEqual(self.h.run(), ('written', 0))
        self.assertEqual(sorted(os.listdir(d)), ['github-app-private-key'])
        self.assert_file_ok()

    def test_symlink_planted_at_target_before_rename_never_touches_outside(self):
        before = self.h.sentinel_state()
        self.h.run()  # create dir and file
        os.unlink(self.h.secret())
        self.h.write_api_env(api(MARKER + 'X'))

        def plant(_tmp):
            os.symlink(self.h.sentinel, self.h.secret())

        self.assertEqual(self.h.run(hooks={'before_rename': plant}), ('written', 0))
        self.assert_file_ok(MARKER + 'X')
        self.assertEqual(self.h.sentinel_state(), before)

    def test_temp_swapped_for_a_link_before_rename_is_refused(self):
        before = self.h.sentinel_state()

        def swap(tmp):
            d = os.path.dirname(self.h.secret())
            os.unlink(os.path.join(d, tmp))
            os.symlink(self.h.sentinel, os.path.join(d, tmp))

        word, code = self.h.run(hooks={'before_rename': swap})
        self.assertEqual((word, code), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(self.h.sentinel_state(), before)
        self.assertEqual(self.h.run()[1], 2)  # the link at the target is refused next time too

    def test_temp_swapped_for_a_hardlink_before_rename_is_refused(self):
        # A regular file that is not the one this run wrote: only the inode check can tell.
        other = self.h.p('etc/other-key')
        with open(other, 'wb') as f:
            f.write(b'other-bytes')
        os.chown(other, 0, 64910)
        os.chmod(other, 0o440)

        def swap(tmp):
            d = os.path.dirname(self.h.secret())
            os.unlink(os.path.join(d, tmp))
            os.link(other, os.path.join(d, tmp))

        self.assertEqual(self.h.run(hooks={'before_rename': swap}), ('REFUSED the secret file changed during the write', 2))
        self.assertEqual(open(other, 'rb').read(), b'other-bytes')

    # ---- AC-9 ----
    def test_check_same_different(self):
        self.assertEqual(self.h.run(['--check']), ('different', 0))
        self.h.run()
        self.assertEqual(self.h.run(['--check']), ('same', 0))
        self.h.write_api_env(api(MARKER + 'NEW'))
        self.assertEqual(self.h.run(['--check']), ('different', 0))
        self.assertEqual(self.h.run(), ('written', 0))
        self.assert_file_ok(MARKER + 'NEW')
        self.assertEqual(self.h.run(['--check']), ('same', 0))

    def test_check_writes_nothing(self):
        self.h.run(['--check'])
        self.assertFalse(os.path.exists(os.path.dirname(self.h.secret())))
        self.assertNotIn('goodqa-jobsecret', open(self.h.p('etc/group')).read())

    # ---- NEG-1 ----
    def test_refusals_leave_the_old_file(self):
        self.h.run()
        m = os.lstat(self.h.secret()).st_mtime_ns
        for text, reason in [
            ('DATABASE_URL=x\n', 'no GITHUB_APP_PRIVATE_KEY line'),
            (api(MARKER) + 'GITHUB_APP_PRIVATE_KEY=x\n', 'more than one GITHUB_APP_PRIVATE_KEY line'),
            ('export GITHUB_APP_PRIVATE_KEY=x\n', 'export form'),
            (api(''), 'empty value'),
            (b'GITHUB_APP_PRIVATE_KEY=a\rb\n', 'value holds a byte outside printable ASCII'),
            (api('a\tb'), 'value holds a byte outside printable ASCII'),
            (b'GITHUB_APP_PRIVATE_KEY=a\x01b\n', 'value holds a byte outside printable ASCII'),
        ]:
            self.h.write_api_env(text)
            self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
            self.assert_file_ok()
            self.assertEqual(os.lstat(self.h.secret()).st_mtime_ns, m)
        os.chmod(self.h.p('etc/goodqa/api.env'), 0o000)
        os.rename(self.h.p('etc/goodqa/api.env'), self.h.p('etc/goodqa/api.env.gone'))
        self.assertEqual(self.h.run(), ('REFUSED api.env unreadable', 2))
        self.assert_file_ok()

    # ---- NEG-2 ----
    def _refused_and_sentinel(self, setup):
        before = self.h.sentinel_state()
        setup()
        word, code = self.h.run()
        self.assertEqual(code, 2, word)
        self.assertTrue(word.startswith('REFUSED '))
        self.assertEqual(self.h.sentinel_state(), before)
        return word

    def test_neg2_dir_is_symlink(self):
        os.makedirs(self.h.p('elsewhere'))
        self._refused_and_sentinel(lambda: os.symlink(self.h.p('elsewhere'), self.h.p('etc/goodqa/job-secrets')))
        self.assertEqual(os.listdir(self.h.p('elsewhere')), [])

    def test_neg2_dir_symlink_to_a_conforming_dir(self):
        # The link target has the right owner and mode, so only O_NOFOLLOW refuses it.
        os.makedirs(self.h.p('elsewhere'))
        os.chown(self.h.p('elsewhere'), 0, 0)
        os.chmod(self.h.p('elsewhere'), 0o711)
        self._refused_and_sentinel(lambda: os.symlink(self.h.p('elsewhere'), self.h.p('etc/goodqa/job-secrets')))
        self.assertEqual(os.listdir(self.h.p('elsewhere')), [])

    def test_neg2_target_symlink_to_a_conforming_file_with_the_same_value(self):
        # Without O_NOFOLLOW this would read as `unchanged`.
        def s():
            self.h.run()
            os.unlink(self.h.secret())
            twin = self.h.p('etc/twin')
            with open(twin, 'wb') as f:
                f.write(MARKER.encode())
            os.chown(twin, 0, 64910)
            os.chmod(twin, 0o440)
            os.symlink(twin, self.h.secret())
        self.assertEqual(self._refused_and_sentinel(s), 'REFUSED the secret file is a symlink or unreadable')

    def test_neg2_dir_owned_by_non_root(self):
        def s():
            os.mkdir(self.h.p('etc/goodqa/job-secrets'), 0o711)
            os.chown(self.h.p('etc/goodqa/job-secrets'), 1000, 1000)
        self.assertEqual(self._refused_and_sentinel(s), 'REFUSED job-secrets has another owner, mode or type')

    def test_neg2_dir_group_writable(self):
        def s():
            os.mkdir(self.h.p('etc/goodqa/job-secrets'))
            os.chmod(self.h.p('etc/goodqa/job-secrets'), 0o731)
        self._refused_and_sentinel(s)

    def test_neg2_parent_world_writable(self):
        self._refused_and_sentinel(lambda: os.chmod(self.h.p('etc/goodqa'), 0o757))

    def test_neg2_target_is_symlink(self):
        def s():
            self.h.run()
            os.unlink(self.h.secret())
            os.symlink(self.h.sentinel, self.h.secret())
        self._refused_and_sentinel(s)

    def test_neg2_target_is_directory(self):
        def s():
            self.h.run()
            os.unlink(self.h.secret())
            os.mkdir(self.h.secret())
        self._refused_and_sentinel(s)

    # ---- NEG-3 ----
    def _group_refused(self, group_lines, reason, passwd_lines=''):
        with open(self.h.p('etc/group'), 'a') as f:
            f.write(group_lines)
        with open(self.h.p('etc/passwd'), 'a') as f:
            f.write(passwd_lines)
        self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
        self.assertFalse(os.path.exists(self.h.secret()))

    def test_neg3_gid_taken_by_another_name(self):
        self._group_refused('other:x:64910:\n', 'gid 64910 has another name')

    def test_neg3_group_has_member(self):
        self._group_refused('goodqa-jobsecret:x:64910:alice\n', 'group goodqa-jobsecret has members')

    def test_neg3_name_has_another_gid(self):
        self._group_refused('goodqa-jobsecret:x:64911:\n', 'group name goodqa-jobsecret has another gid')

    def test_neg3_primary_gid(self):
        self._group_refused('', 'an account has gid 64910 as its primary group', 'svc:x:999:64910::/:/bin/false\n')

    # ---- NEG-13 (NSS only) ----
    def _nss_refused(self, rel, line, reason):
        with open(self.h.p(rel), 'w') as f:
            f.write(line)
        self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
        self.assertFalse(os.path.exists(self.h.secret()))

    def test_neg13_nss_gid_other_name(self):
        self._nss_refused('nss-group', 'ldapgrp:x:64910:\n', 'gid 64910 has another name')

    def test_neg13_nss_member(self):
        self._nss_refused('nss-group', 'goodqa-jobsecret:x:64910:bob\n', 'group goodqa-jobsecret has members')

    def test_neg13_nss_primary_gid(self):
        self._nss_refused('nss-passwd', 'ldapuser:x:5000:64910::/:/bin/false\n', 'an account has gid 64910 as its primary group')

    # ---- AC-7: the value never in output or any spawned argv ----
    def test_value_never_in_stdout_stderr_or_argv(self):
        env = dict(os.environ, **self.h.env())
        code = 'import importlib.util,sys; s=importlib.util.spec_from_file_location("d", %r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); sys.exit(m.main(root=%r))' % (SCRIPT, self.h.root)
        for argv in ([], [], ['--check']):
            r = subprocess.run([sys.executable, '-I', '-c', code, *argv], env=env, capture_output=True, timeout=60)
            out = r.stdout.decode() + r.stderr.decode()
            self.assertEqual(r.stderr, b'')
            self.assertEqual(len(r.stdout.decode().splitlines()), 1)
            self.assertTrue(r.stdout.decode().startswith(LINE))
            for i in range(0, len(MARKER) - 15):
                self.assertNotIn(MARKER[i:i + 16], out)
        log = open(self.h.p('argv.log')).read()
        self.assertTrue(log)
        for i in range(0, len(MARKER) - 15):
            self.assertNotIn(MARKER[i:i + 16], log)


if __name__ == '__main__':
    unittest.main()
