"""goodqa#16148 spec v4 AC-11, NEG-14, NEG-15 and build conditions R1, R2: apply-job-secrets-host.py.

Root-only (backups are root 0600 via fchown): run_derive_tests.sh runs this in the throwaway
container next to the derive tests. Fake host trees only; stub getent and docker on PATH.
"""
import importlib.util
import os
import shutil
import stat
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('apply_host', os.path.join(HERE, 'apply-job-secrets-host.py'))
ah = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ah)
IS_ROOT = os.geteuid() == 0

COMPOSE = '''services:
  api:
    image: goodqa-api:abc # rw-ship abc
    env_file:
      - path: /etc/goodqa/api.env
        format: raw
  job-dispatcher:
    <<: *hardening
    image: goodqa-job-dispatcher:abc-1 # rw-ship abc 1
    read_only: true
    tmpfs: ["/tmp"]
    env_file:
      - path: /etc/goodqa/dispatcher.env
        format: raw
    networks: [dispatch-app, edge]
    mem_limit: 384m

  job-dispatcher-create-guard:
    image: goodqa-job-dispatcher:abc-1
    group_add: ["999"]

networks:
  edge: {}
'''
ENV = b'JOB_DISPATCH_TOKEN=fake-token\nJOB_ENV_SCAN__NODE_ENV=production\n'

STUB_GETENT = '''#!/bin/sh
f="$FAKE_ROOT/nss-group"; [ -f "$f" ] || exit 2
grep -E "^($2):|^[^:]*:[^:]*:($2):" "$f" || exit 2
'''
STUB_DOCKER = '''#!/bin/sh
echo "$*" >> "$FAKE_ROOT/docker.log"
[ -f "$FAKE_ROOT/compose-invalid" ] && exit 1
exit 0
'''


@unittest.skipUnless(IS_ROOT, 'needs root (backups are root 0600): runs in the throwaway container')
class HostApplyTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='apply-root-', dir=os.environ.get('DERIVE_TEST_TMP'))
        self.dir = os.path.join(self.root, 'opt/goodqa/infra/selfhost/app')
        self.env_dir = os.path.join(self.root, 'etc/goodqa')
        os.makedirs(self.dir)
        os.makedirs(self.env_dir, mode=0o700)
        with open(self.p('compose'), 'w') as f:
            f.write(COMPOSE)
        os.chown(self.p('compose'), 1000, 1000)
        os.chmod(self.p('compose'), 0o664)
        with open(self.p('env'), 'wb') as f:
            f.write(ENV)
        os.chmod(self.p('env'), 0o600)
        bin_dir = os.path.join(self.root, 'bin')
        os.makedirs(bin_dir)
        for n, body in (('getent', STUB_GETENT), ('docker', STUB_DOCKER)):
            with open(os.path.join(bin_dir, n), 'w') as f:
                f.write(body)
            os.chmod(os.path.join(bin_dir, n), 0o755)
        self.saved = dict(os.environ)
        os.environ['PATH'] = bin_dir + ':' + os.environ['PATH']
        os.environ['FAKE_ROOT'] = self.root

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)
        shutil.rmtree(self.root, ignore_errors=True)

    def p(self, which):
        return {'compose': os.path.join(self.dir, 'compose.yaml'), 'env': os.path.join(self.env_dir, 'dispatcher.env')}[which]

    def read(self, which):
        with open(self.p(which), 'rb') as f:
            return f.read()

    def derive_done(self):
        """What derive-job-secrets.py leaves: the group (seen through NSS) and the 0711 directory."""
        with open(os.path.join(self.root, 'nss-group'), 'w') as f:
            f.write('goodqa-jobsecret:x:64910:\n')
        d = os.path.join(self.env_dir, 'job-secrets')
        os.mkdir(d)
        os.chown(d, 0, 0)
        os.chmod(d, 0o711)

    def run_cmd(self, *argv, hooks=None):
        return ah.run(['--dir', self.dir, '--env-dir', self.env_dir, *argv], hooks=hooks)

    def check(self):
        lines, code = self.run_cmd('--check')
        self.assertEqual(code, 0)
        return dict(l.rsplit(': ', 1) for l in lines)

    # ---- AC-11 ----
    def test_check_on_a_fresh_host(self):
        self.assertEqual(set(self.check().values()), {'absent'})

    def test_apply_refuses_before_derive(self):
        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
        self.assertEqual(code, 2)
        self.assertIn('derive-job-secrets.py must run first', lines[0])
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.read('env'), ENV)

    def test_apply_then_apply_again_then_restore(self):
        self.derive_done()
        cst0 = os.stat(self.p('compose'))
        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030000Z'), (['job secrets host apply: applied'], 0))
        self.assertEqual(set(self.check().values()), {'present'})
        comp = self.read('compose').decode()
        block = comp[comp.index('  job-dispatcher:\n'):comp.index('  job-dispatcher-create-guard:')]
        self.assertIn(ah.GROUP_LINE + '\n', block)
        self.assertIn(ah.VOL_LINE + '\n', block)
        self.assertTrue(self.read('env').endswith(ah.ENV_LINE.encode() + b'\n'))
        cst = os.stat(self.p('compose'))
        self.assertEqual((cst.st_uid, cst.st_gid, stat.S_IMODE(cst.st_mode)), (cst0.st_uid, cst0.st_gid, 0o664))
        for which, orig in (('compose', COMPOSE.encode()), ('env', ENV)):
            b = self.p(which) + '.pre-16148-20261116T030000Z'
            bst = os.lstat(b)
            self.assertEqual((bst.st_uid, bst.st_gid, stat.S_IMODE(bst.st_mode)), (0, 0, 0o600))
            with open(b, 'rb') as f:
                self.assertEqual(f.read(), orig)
        m = (os.stat(self.p('compose')).st_mtime_ns, os.stat(self.p('env')).st_mtime_ns)
        time.sleep(0.02)
        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030100Z'), (['job secrets host apply: unchanged'], 0))
        self.assertEqual((os.stat(self.p('compose')).st_mtime_ns, os.stat(self.p('env')).st_mtime_ns), m)
        self.assertFalse(os.path.exists(self.p('env') + '.pre-16148-20261116T030100Z'))
        self.assertEqual(self.run_cmd('restore'), (['job secrets host restore: restored'], 0))
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.read('env'), ENV)

    def test_apply_validates_compose_with_docker(self):
        self.derive_done()
        self.run_cmd('apply', '--stamp', '20261116T030000Z')
        log = open(os.path.join(self.root, 'docker.log')).read()
        self.assertIn('compose -f %s/.compose.yaml.validate-' % self.dir, log)
        self.assertIn('config -q', log)
        self.assertEqual([e for e in os.listdir(self.dir) if 'validate' in e or '.tmp-' in e], [])

    # ---- R1: restore keeps later changes ----
    def test_restore_keeps_a_later_release_pin_and_a_later_env_key(self):
        self.derive_done()
        self.run_cmd('apply', '--stamp', '20261116T030000Z')
        comp = self.read('compose').decode().replace('goodqa-job-dispatcher:abc-1 # rw-ship abc 1', 'goodqa-job-dispatcher:def-2 # rw-ship def 2')
        with open(self.p('compose'), 'w') as f:
            f.write(comp)
        with open(self.p('env'), 'ab') as f:
            f.write(b'LATER_KEY=added-after\n')
        self.assertEqual(self.run_cmd('restore')[1], 0)
        self.assertEqual(self.read('compose'), COMPOSE.replace('abc-1 # rw-ship abc 1', 'def-2 # rw-ship def 2').encode())
        self.assertEqual(self.read('env'), ENV + b'LATER_KEY=added-after\n')

    def test_restore_refuses_a_changed_marked_line(self):
        self.derive_done()
        self.run_cmd('apply', '--stamp', '20261116T030000Z')
        comp = self.read('compose').decode().replace('/run/goodqa-secrets:ro"]', '/run/goodqa-secrets:rw"]')
        with open(self.p('compose'), 'w') as f:
            f.write(comp)
        lines, code = self.run_cmd('restore')
        self.assertEqual(code, 2)
        self.assertIn('marked line in compose.yaml was changed', lines[0])

    # ---- NEG-14: partial apply ----
    def test_neg14_stopped_between_files(self):
        self.derive_done()

        def stop():
            raise KeyboardInterrupt('stopped between the two writes')

        with self.assertRaises(KeyboardInterrupt):
            self.run_cmd('apply', '--stamp', '20261116T030000Z', hooks={'between_files': stop})
        st = self.check()
        self.assertEqual(st['dispatcher.env ' + ah.ENV_KEY], 'present')
        self.assertEqual(st['compose job-dispatcher mount'], 'absent')
        self.assertEqual(st['compose job-dispatcher group_add'], 'absent')
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030500Z'), (['job secrets host apply: applied'], 0))
        self.assertEqual(set(self.check().values()), {'present'})
        self.assertEqual(self.run_cmd('restore')[1], 0)
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.read('env'), ENV)

    # ---- NEG-15: failed apply leaves everything ----
    def test_neg15_invalid_compose_changes_nothing(self):
        self.derive_done()
        open(os.path.join(self.root, 'compose-invalid'), 'w').close()
        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
        self.assertEqual(code, 2)
        self.assertIn('does not validate', lines[0])
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.read('env'), ENV)
        self.assertEqual(sorted(os.listdir(self.dir)), ['compose.yaml'])
        self.assertEqual(sorted(e for e in os.listdir(self.env_dir) if e != 'job-secrets'), ['dispatcher.env'])

    def test_neg15_existing_backup_is_never_overwritten(self):
        self.derive_done()
        b = self.p('env') + '.pre-16148-20261116T030000Z'
        with open(b, 'wb') as f:
            f.write(b'earlier backup')
        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
        self.assertEqual(code, 2)
        with open(b, 'rb') as f:
            self.assertEqual(f.read(), b'earlier backup')
        self.assertEqual(self.read('compose'), COMPOSE.encode())
        self.assertEqual(self.read('env'), ENV)

    # ---- conflicts and unsafe paths ----
    def _conflict(self, compose=None, env=None, expect=None):
        self.derive_done()
        if compose is not None:
            with open(self.p('compose'), 'w') as f:
                f.write(compose)
        if env is not None:
            with open(self.p('env'), 'wb') as f:
                f.write(env)
        before = (self.read('compose'), self.read('env'))
        self.assertEqual(self.check()[expect], 'conflict')
        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
        self.assertEqual(code, 2)
        self.assertIn('conflict', lines[0])
        self.assertEqual((self.read('compose'), self.read('env')), before)

    def test_conflict_dispatcher_has_other_volumes(self):
        self._conflict(compose=COMPOSE.replace('    mem_limit: 384m\n', '    mem_limit: 384m\n    volumes: ["/x:/y"]\n'), expect='compose job-dispatcher mount')

    def test_conflict_other_service_mounts_the_secrets(self):
        self._conflict(compose=COMPOSE.replace('    group_add: ["999"]\n', '    volumes: ["/etc/goodqa/job-secrets:/s:ro"]\n'), expect='compose job-dispatcher mount')

    def test_conflict_env_key_with_another_value(self):
        self._conflict(env=ENV + ah.ENV_KEY.encode() + b'=/elsewhere\n', expect='dispatcher.env ' + ah.ENV_KEY)

    def test_conflict_dir_with_wrong_mode(self):
        self.derive_done()
        os.chmod(os.path.join(self.env_dir, 'job-secrets'), 0o755)
        self.assertEqual(self.check()['dir /etc/goodqa/job-secrets'], 'conflict')
        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030000Z')[1], 2)

    def test_symlinked_compose_is_refused(self):
        self.derive_done()
        real = os.path.join(self.root, 'real-compose.yaml')
        os.rename(self.p('compose'), real)
        os.symlink(real, self.p('compose'))
        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
        self.assertEqual(code, 2)
        self.assertIn('symlink', lines[0])
        with open(real) as f:
            self.assertEqual(f.read(), COMPOSE)

    def test_symlinked_env_dir_is_refused(self):
        lines, code = ah.run(['--dir', self.dir, '--env-dir', os.path.join(self.root, 'envlink'), '--check'])
        self.assertEqual(code, 2)
        os.symlink(self.env_dir, os.path.join(self.root, 'envlink'))
        lines, code = ah.run(['--dir', self.dir, '--env-dir', os.path.join(self.root, 'envlink'), '--check'])
        self.assertEqual(code, 2)
        self.assertIn('symlink', lines[0])

    # ---- R2: retention ----
    def test_prune_keeps_the_newest_three_backups(self):
        names = ['dispatcher.env.pre-16148-2026111%dT000000Z' % i for i in range(1, 6)]
        for n in names:
            with open(os.path.join(self.env_dir, n), 'w') as f:
                f.write('b')
        with open(os.path.join(self.env_dir, 'dispatcher.env.pre-16148-notastamp'), 'w') as f:
            f.write('keep')
        dfd = ah.open_dir(self.env_dir)
        try:
            ah.prune_backups(dfd, 'dispatcher.env')
        finally:
            os.close(dfd)
        left = sorted(e for e in os.listdir(self.env_dir) if '.pre-16148-' in e)
        self.assertEqual(left, sorted(names[2:] + ['dispatcher.env.pre-16148-notastamp']))

    def test_usage(self):
        self.assertEqual(self.run_cmd()[1], 2)
        self.assertEqual(self.run_cmd('apply', '--stamp', 'bad')[1], 2)


if __name__ == '__main__':
    unittest.main()
