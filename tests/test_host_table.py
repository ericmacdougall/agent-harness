"""Host table and ssh target resolution (goodqa#14548 AC-4): resolved-hostname keys, loopback, timeout, empty table."""

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import host_table

FAKE_SSH = '''#!/bin/sh
# canned `ssh -G`: reads $FAKE_SSH_DIR/<target>.txt (the last argument); FAKE_SSH_SLEEP delays; unknown target fails
for last; do :; done
[ -n "$FAKE_SSH_SLEEP" ] && sleep "$FAKE_SSH_SLEEP"
[ -f "$FAKE_SSH_DIR/$last.txt" ] || exit 255
cat "$FAKE_SSH_DIR/$last.txt"
[ -n "$FAKE_SSH_LOG" ] && echo "$@" >> "$FAKE_SSH_LOG"
exit 0
'''


def canned(hostname, port=22, proxycommand=None, proxyjump=None):
    lines = ['user eric', 'hostname %s' % hostname, 'port %d' % port]
    if proxycommand:
        lines.append('proxycommand ' + proxycommand)
    if proxyjump:
        lines.append('proxyjump ' + proxyjump)
    return '\n'.join(lines) + '\n'


class SshStub(unittest.TestCase):
    """A fake `ssh` first on PATH and a fixture resource_policy.json."""
    HOSTS = {'dev2.example.test': {'role': 'worker', 'ah_run': '/opt/ah/ah_run.py'},
             'mac2.example.test': {'role': 'interactive', 'ah_run': False},
             'pve.example.test:2222': {'role': 'external'},
             'tunnel.example.test:2200': {'role': 'worker', 'ah_run': False}}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hosttable-'); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.stubs = root / 'stubs'; self.stubs.mkdir()
        self.bin = root / 'bin'; self.bin.mkdir()
        ssh = self.bin / 'ssh'; ssh.write_text(FAKE_SSH); ssh.chmod(ssh.stat().st_mode | stat.S_IXUSR)
        self.policy = root / 'resource_policy.json'
        self.write_policy(hosts=self.HOSTS, self_names=['mac-1', 'mac-1.local'])
        patcher = mock.patch.dict(os.environ, {'PATH': '%s:%s' % (self.bin, os.environ['PATH']), 'FAKE_SSH_DIR': str(self.stubs)})
        patcher.start(); self.addCleanup(patcher.stop)
        os.environ.pop('FAKE_SSH_SLEEP', None); os.environ.pop('FAKE_SSH_LOG', None)

    def write_policy(self, **data):
        if 'self_names' in data:
            data['self'] = data.pop('self_names')
        self.policy.write_text(json.dumps(data))

    def stub(self, target, hostname, **kw):
        (self.stubs / (target + '.txt')).write_text(canned(hostname, **kw))

    def classify(self, target, args=()):
        return host_table.classify(target, args, policy=self.policy)


class HostTable(SshStub):
    def test_load_reads_hosts_and_lowercases_keys(self):
        table = host_table.load(self.policy)
        self.assertEqual(table['dev2.example.test']['ah_run'], '/opt/ah/ah_run.py')
        self.write_policy(hosts={'DEV2.Example.Test': {'role': 'worker'}})
        self.assertIn('dev2.example.test', host_table.load(self.policy))

    def test_missing_file_corrupt_file_and_missing_key_give_an_empty_table(self):
        self.assertEqual(host_table.load(Path(self.temp.name) / 'nope.json'), {})
        self.policy.write_text('{corrupt'); self.assertEqual(host_table.load(self.policy), {})
        self.policy.write_text('[1, 2]'); self.assertEqual(host_table.load(self.policy), {})
        self.write_policy(modes={}); self.assertEqual(host_table.load(self.policy), {})
        self.write_policy(hosts=['x']); self.assertEqual(host_table.load(self.policy), {})

    def test_alias_resolves_to_the_entry_keyed_by_hostname(self):
        self.stub('dev2', 'dev2.example.test')
        found = self.classify('dev2')
        self.assertEqual((found.kind, found.name, found.role, found.ah_run), ('table', 'dev2.example.test', 'worker', '/opt/ah/ah_run.py'))

    def test_a_table_keyed_by_the_alias_is_not_found(self):
        # the table is keyed by the resolved hostname: an entry named after the alias alone must not match
        self.write_policy(hosts={'dev2': {'role': 'worker', 'ah_run': '/x'}})
        self.stub('dev2', 'dev2.example.test')
        self.assertEqual(self.classify('dev2').kind, 'external')

    def test_name_port_keys(self):
        self.stub('pve', 'pve.example.test', port=2222)
        self.stub('pve-default', 'pve.example.test')
        self.assertEqual(self.classify('pve').name, 'pve.example.test:2222')
        self.assertEqual(self.classify('pve').role, 'external')
        self.assertIsNone(self.classify('pve-default').name)  # port 22 is not the :2222 entry
        self.stub('t', 'tunnel.example.test', port=2200)
        self.assertEqual((self.classify('t').kind, self.classify('t').ah_run), ('table', False))

    def test_loopback_on_the_default_port_is_local(self):
        for name in ('localhost', '127.0.0.1', '::1'):
            self.stub(name, name)
            self.assertEqual(self.classify(name).kind, 'local', name)

    def test_the_hosts_own_names_are_local(self):
        self.stub('me', 'mac-1.local')
        self.assertEqual(self.classify('me').kind, 'local')

    def test_loopback_on_another_port_is_external(self):
        self.stub('localhost', 'localhost', port=2222)
        found = self.classify('localhost', ['-p', '2222'])
        self.assertEqual((found.kind, found.reason), ('external', 'loopback-tunnel'))

    def test_loopback_with_proxy_is_external(self):
        self.stub('localhost', 'localhost', proxyjump='jump.example.test')
        self.assertEqual(self.classify('localhost', ['-J', 'jump']).kind, 'external')
        self.stub('localhost', 'localhost', proxycommand='nc %h %p')
        self.assertEqual(self.classify('localhost').kind, 'external')

    def test_a_table_host_behind_a_proxyjump_keeps_its_entry(self):
        self.stub('dev2', 'dev2.example.test', proxyjump='jump.example.test')
        self.assertEqual(self.classify('dev2').kind, 'table')

    def test_timeout_is_external_and_logged(self):
        self.stub('dev2', 'dev2.example.test')
        os.environ['FAKE_SSH_SLEEP'] = '5'
        told = []
        with mock.patch.object(host_table, 'RESOLVE_TIMEOUT', 0.3):
            found = host_table.classify('dev2', (), policy=self.policy, warn=told.append)
        self.assertEqual((found.kind, found.reason), ('external', 'resolve-timeout'))
        self.assertEqual(len(told), 1); self.assertIn('timed out', told[0])

    def test_error_is_external_and_logged(self):
        told = []
        found = host_table.classify('nohost', (), policy=self.policy, warn=told.append)
        self.assertEqual((found.kind, len(told)), ('external', 1))

    def test_no_ssh_binary_is_external(self):
        os.environ['PATH'] = '/nonexistent'
        self.assertEqual(self.classify('dev2').kind, 'external')

    def test_unknown_host_is_external(self):
        self.stub('who', 'who.example.test')
        found = self.classify('who')
        self.assertEqual((found.kind, found.role, found.reason), ('external', 'external', 'not-in-table'))

    def test_missing_policy_makes_everything_external_but_loopback_local(self):
        self.policy.unlink()
        self.stub('dev2', 'dev2.example.test'); self.stub('localhost', 'localhost')
        self.assertEqual(self.classify('dev2').kind, 'external')
        self.assertEqual(self.classify('localhost').kind, 'local')

    def test_ssh_options_reach_ssh_g(self):
        log = Path(self.temp.name) / 'ssh.log'; os.environ['FAKE_SSH_LOG'] = str(log)
        self.stub('dev2', 'dev2.example.test')
        self.classify('dev2', ['-p', '2222', '-o', 'StrictHostKeyChecking=no', '-J', 'jump'])
        self.assertEqual(log.read_text().split(), ['-G', '-p', '2222', '-o', 'StrictHostKeyChecking=no', '-J', 'jump', '--', 'dev2'])


class ParseSsh(unittest.TestCase):
    def test_options_with_values_flags_and_target(self):
        call = host_table.parse_ssh(['-p', '2222', '-o', 'StrictHostKeyChecking=no', '-J', 'jump', '-tt', 'user@dev2', 'git', 'log'])
        self.assertEqual((call.target, call.remote), ('user@dev2', ['git', 'log']))
        self.assertEqual(call.opts, ['-p', '2222', '-o', 'StrictHostKeyChecking=no', '-J', 'jump', '-tt'])
        self.assertEqual(call.resolve_args, ['-p', '2222', '-o', 'StrictHostKeyChecking=no', '-J', 'jump'])

    def test_attached_values_and_clusters(self):
        call = host_table.parse_ssh(['-p2222', '-oBatchMode=yes', '-fN', 'h', 'ls'])
        self.assertEqual(call.opts, ['-p2222', '-oBatchMode=yes', '-fN']); self.assertIn('f', call.flags)
        self.assertEqual(call.resolve_args, ['-p2222', '-oBatchMode=yes'])

    def test_every_value_option_takes_its_argument(self):
        for letter in 'pliJLobcDEeFImOQRSWwBP':
            call = host_table.parse_ssh(['-' + letter, 'VALUE', 'host', 'cmd'])
            self.assertEqual((call.target, call.remote), ('host', ['cmd']), letter)

    def test_double_dash_and_no_target(self):
        self.assertEqual(host_table.parse_ssh(['--', 'h', '-x']).remote, ['-x'])
        self.assertIsNone(host_table.parse_ssh(['-p', '22'])); self.assertIsNone(host_table.parse_ssh([]))

    def test_no_command(self):
        self.assertEqual(host_table.parse_ssh(['h']).remote, [])


if __name__ == '__main__':
    unittest.main()
