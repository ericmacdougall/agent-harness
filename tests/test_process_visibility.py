"""Offline diagnostic controls. Never invoke sudo or a privileged observer."""
import copy
import importlib.util
import os
import stat
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'harness/hooks/process_visibility.py'
spec = importlib.util.spec_from_file_location('process_visibility', MODULE)
pv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pv)


class View:
    def __init__(self, refs=()):
        self.refs = list(refs)
        self.row = {'start': 123, 'uids': [1000] * 4, 'namespaces': ['user:1', 'mnt:1'],
                    'uid_map': [[0, 0, 4294967295]]}
        self.changed = False
        self.calls = 0

    def boot(self):
        return '00000000-0000-0000-0000-000000000001'

    def snapshot(self, pid):
        self.calls += 1
        row = copy.deepcopy(self.row)
        if self.changed and self.calls > 1:
            row['start'] += 1
        return row

    def references(self, pid):
        return self.refs, True


class Diagnostic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name).resolve() / 'copy'
        self.target.mkdir()
        self.file = self.target / 'data'
        self.file.write_bytes(b'offline nonsecret fixture')
        st = self.file.stat()
        self.ref = (st.st_dev, st.st_ino)

    def observe(self, view, **kwargs):
        return pv.observe(str(self.target), [(42, 123)], view, caller_uid=1000, **kwargs)

    def test_direct_inode_hit_related_without_paths(self):
        result = self.observe(View([self.ref]))
        self.assertEqual(result['observations'][0]['relation'], 'RELATED')
        self.assertTrue(result['diagnostic_only'])
        self.assertNotIn(str(self.target), str(result))
        self.assertNotIn('UNRELATED', str(result))

    def test_no_hit_and_foreign_namespace_never_clear(self):
        for foreign in (False, True):
            view = View([(9999, 8888)])
            if foreign:
                view.row['namespaces'] = ['user:2', 'mnt:2']
            self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_wrong_start_uid_or_namespace_shape_unknown(self):
        for key, value in [('start', 999), ('uids', [1000, 0, 1000, 1000]),
                           ('namespaces', []), ('uid_map', [])]:
            view = View([self.ref])
            view.row[key] = value
            self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_partial_reference_inventory_never_reports_unrelated(self):
        view = View()
        view.references = lambda pid: ([], False)
        self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_pid_reuse_after_direct_hit_unknown(self):
        view = View([self.ref])
        view.changed = True
        self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_source_replaced_after_reference_read_unknown(self):
        view = View([self.ref])
        def refs(pid):
            self.target.rename(self.target.with_name('old'))
            self.target.mkdir()
            return [self.ref], True
        view.references = refs
        self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_symlink_target_and_oversized_requests_refuse(self):
        link = self.target.with_name('link')
        link.symlink_to(self.target)
        with self.assertRaises(pv.Refused):
            pv.observe(str(link), [(42, 123)], View(), caller_uid=1000)
        with self.assertRaises(pv.Refused):
            pv.observe(str(self.target), [(x, 123) for x in range(1, 11)], View(), caller_uid=1000)

    def test_inventory_cap_and_deleted_reference_unknown(self):
        result = self.observe(View(), max_entries=1)
        self.assertEqual(result['observations'][0]['relation'], 'UNKNOWN')
        view = View()
        view.references = lambda pid: ([], False)
        self.assertEqual(self.observe(view)['observations'][0]['relation'], 'UNKNOWN')

    def test_cli_fixed_account_and_source_policy(self):
        policy = {'caller_uid': 1000, 'caller_name': 'fixture', 'targets': {'/home/fixture/review-copy': [1, 2]}}
        with self.assertRaises(pv.Refused):
            pv.authorize('/home/fixture/.codex', {'SUDO_UID': '1000', 'SUDO_USER': 'fixture'}, 0, policy)
        with self.assertRaises(pv.Refused):
            pv.authorize('/home/fixture/review-copy', {'SUDO_UID': '0', 'SUDO_USER': 'root'}, 0, policy)
        with self.assertRaises(pv.Refused):
            pv.authorize('/home/fixture/review-copy', {'SUDO_UID': '1000', 'SUDO_USER': 'fixture'}, 1000, policy)

    def test_unreadable_deleted_or_foreign_reference_inventory_is_incomplete(self):
        for failure in (OSError('offline denied'), 'fixture (deleted)'):
            with mock.patch.object(pv.os, 'readlink', side_effect=(failure if isinstance(failure, Exception) else None),
                                   return_value=failure if isinstance(failure, str) else None), \
                    mock.patch.object(pv, 'bounded_names', side_effect=PermissionError('offline denied')):
                references, complete = pv.ProcView().references(42)
            self.assertEqual(references, [])
            self.assertFalse(complete)

    def test_fd_and_mapping_caps_are_incomplete(self):
        with mock.patch.object(pv.os, 'readlink', side_effect=PermissionError('offline denied')), \
                mock.patch.object(pv, 'bounded_names', side_effect=pv.Refused('metadata-cap')):
            references, complete = pv.ProcView().references(42)
        self.assertEqual(references, [])
        self.assertFalse(complete)

    def test_real_open_fd_and_hardlink_alias_match_source_inode(self):
        alias = self.target.with_name('alias')
        os.link(self.file, alias)
        fd = os.open(alias, os.O_RDONLY)
        try:
            observed = pv.identity(os.fstat(fd))
            self.assertEqual(self.observe(View([observed]))['observations'][0]['relation'], 'RELATED')
        finally:
            os.close(fd)

    def test_symlink_leaf_marks_source_inventory_incomplete(self):
        (self.target / 'link').symlink_to(self.file)
        result = self.observe(View())
        row = result['observations'][0]
        self.assertFalse(row['source_inventory_complete'])
        self.assertEqual(row['relation'], 'UNKNOWN')

    def test_policy_source_binding_cannot_select_replacement(self):
        with self.assertRaises(pv.Refused):
            self.observe(View([self.ref]), expected_target=(0, 1))

    def test_policy_duplicate_keys_and_untrusted_metadata_refuse(self):
        policy = self.target.with_name('policy.json')
        policy.write_text('{"v":1,"v":1}')
        trusted = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=0)
        with mock.patch.object(pv, 'POLICY', str(policy)), mock.patch.object(pv, 'protected'), \
                mock.patch.object(pv.os, 'fstat', return_value=trusted):
            with self.assertRaises(pv.Refused):
                pv.load_policy()
        bad = SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_nlink=1, st_uid=1000)
        with mock.patch.object(pv, 'POLICY', str(policy)), mock.patch.object(pv, 'protected'), \
                mock.patch.object(pv.os, 'fstat', return_value=bad):
            with self.assertRaises(pv.Refused):
                pv.load_policy()


if __name__ == '__main__':
    unittest.main()
