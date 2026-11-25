"""ah_local: the one reader of ~/.agent-harness/local.json. Tolerant (a missing or broken file is an empty one),
typed (a value of the wrong type is the default) and cached per process."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness' / 'hooks'))
import ah_local  # noqa: E402


class LocalConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'local.json'
        env = mock.patch.dict(os.environ, {'AH_LOCAL_CONFIG': str(self.path)})
        env.start()
        self.addCleanup(env.stop)
        ah_local.reset()
        self.addCleanup(ah_local.reset)

    def write(self, data):
        self.path.write_text(data if isinstance(data, str) else json.dumps(data))
        ah_local.reset()

    def test_missing_or_broken_file_is_empty(self):
        self.assertEqual(ah_local.load(), {})
        for bad in ('{not json', '[1, 2]', '"text"', ''):
            self.write(bad)
            self.assertEqual(ah_local.load(), {}, bad)
            self.assertEqual(ah_local.get('heavy_job_host', ''), '')
            self.assertEqual(ah_local.hosts(), {})
            self.assertEqual(ah_local.label('ahd'), 'com.agent-harness.ahd')

    def test_wrong_types_fall_back_to_the_default(self):
        self.write({'heavy_job_host': ['x'], 'remote_worktree_hosts': 'w1', 'hosts': ['w1']})
        self.assertEqual(ah_local.get('heavy_job_host', ''), '')
        self.assertEqual(ah_local.str_list('remote_worktree_hosts'), ())
        self.assertEqual(ah_local.hosts(), {})

    def test_hosts_filter_by_os_and_role(self):
        self.write({'hosts': {'w1': {'os': 'linux', 'role': 'worker'}, 'm1': {'os': 'macos'}, 'win': {'os': 'Windows'},
                              'odd': 'not a dict'}})
        self.assertEqual(ah_local.host_names(), ('w1', 'm1', 'win', 'odd'))
        self.assertEqual(ah_local.host_names(os_name='windows'), ('win',))
        self.assertEqual(ah_local.host_names(role='worker'), ('w1',))

    def test_label_prefix_is_validated_and_always_protected(self):
        self.write({'launchd_label_prefix': 'com.example.', 'protected_label_prefixes': ['org.other.', 3]})
        self.assertEqual(ah_local.label('ops-watch'), 'com.example.ops-watch')
        self.assertEqual(ah_local.protected_label_prefixes(), ('org.other.', 'com.example.'))
        for bad in ('com.example', 'com..x.', '../x.', 'com.ex ample.'):
            self.write({'launchd_label_prefix': bad})
            self.assertEqual(ah_local.label_prefix(), 'com.agent-harness.', bad)

    def test_read_once_per_process(self):
        self.write({'heavy_job_host': 'w1'})
        self.assertEqual(ah_local.get('heavy_job_host'), 'w1')
        self.path.write_text(json.dumps({'heavy_job_host': 'w2'}))
        self.assertEqual(ah_local.get('heavy_job_host'), 'w1')
        ah_local.reset()
        self.assertEqual(ah_local.get('heavy_job_host'), 'w2')

    def test_the_shipped_example_parses_and_names_only_placeholders(self):
        example = Path(__file__).resolve().parents[1] / 'harness' / 'local.json.example'
        self.write(example.read_text())
        self.assertEqual(ah_local.get('heavy_job_host'), 'worker-1')
        self.assertIn('win-box', ah_local.host_names(os_name='windows'))


if __name__ == '__main__':
    unittest.main()
