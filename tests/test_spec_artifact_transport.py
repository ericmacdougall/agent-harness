"""Read-only artifact authority through owned HTTP fixtures, never real services."""
import json
import os
from unittest import mock
import unittest

import test_spec_flow as base
import ticket_adapters as ta


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()


class ArtifactTransport(unittest.TestCase):
    def setUp(self):
        self.case = base.SpecFlowCase()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.case.attached()

    def read(self):
        adapter = ta.GoodQAAdapter(self.case.config)
        adapter.all_comments(base.ISSUE)
        return adapter, adapter.attachments(base.ISSUE)

    def test_real_http_hash_and_separate_empty_storage_headers(self):
        self.case.fake.artifact_gets.clear()
        with mock.patch.dict(os.environ, {'HTTP_PROXY': 'http://unused.invalid:9',
                                         'HTTPS_PROXY': 'http://unused.invalid:9', 'NETRC': '/nonexistent-fixture'}):
            _, rows = self.read()
        source = [r for r in rows if r['mime'] == 'text/markdown']
        self.assertTrue(source)
        self.assertTrue(all(isinstance(r.get('_spec_bytes'), bytes) for r in source))
        calls = self.case.fake.artifact_gets
        self.assertTrue(any(r['authorization'] for r in calls if '/read-target' in r['path']))
        self.assertTrue(any('/download/' in r['path'] for r in calls))
        self.assertTrue(all(not r['authorization'] and not r['cookie'] for r in calls if '/download/' in r['path']))

    def test_redirect_targets_headers_private_origins_and_byte_caps_refuse(self):
        for mode in ('redirect', 'target-redirect', 'off-origin', 'metadata', 'target-headers',
                     'target-oversize', 'oversize', 'stream-oversize', 'corrupt', 'missing'):
            with self.subTest(mode=mode):
                self.case.fake.artifact_mode = mode
                self.case.fake.artifact_gets.clear()
                _, rows = self.read()
                self.assertTrue(all(r.get('_spec_error') and '_spec_bytes' not in r
                                    for r in rows if r['mime'] == 'text/markdown'))
                self.assertFalse(any('/forbidden-sink' in r['path'] for r in self.case.fake.artifact_gets))
                self.assertTrue(all(not r['authorization'] for r in self.case.fake.artifact_gets if '/download/' in r['path']))

    def test_private_connected_peer_receives_no_signed_request(self):
        adapter = ta.GoodQAAdapter(self.case.config)
        connection = mock.Mock()
        connection.sock.getpeername.return_value = ('127.0.0.1', 443)
        with mock.patch.object(ta.http.client, 'HTTPSConnection', return_value=connection):
            with self.assertRaises(ta.TicketSystemUnavailable):
                adapter._artifact_get(('https', 'goodqa-uploads.tor1.digitaloceanspaces.com', 443), '/fixture-object', 100)
        connection.request.assert_not_called()
        connection.close.assert_called_once()

    def test_unlisted_id_and_deleted_row_never_reach_read_target(self):
        adapter, rows = self.read()
        row = next(r for r in rows if r['mime'] == 'text/markdown')
        before = len(self.case.fake.artifact_gets)
        for changed in (dict(row, id='../outside'), dict(row, deletedAt='2026-11-22T01:00:00Z'),
                        dict(row, id='not-listed'), dict(row, sha256='f' * 64)):
            with self.assertRaises(ta.TicketSystemUnavailable):
                adapter.read_attachment(changed)
        self.assertEqual(len(self.case.fake.artifact_gets), before)

    def test_unavailable_current_artifact_cannot_select_older_spec(self):
        self.case.attached(base.SPEC.replace('cannot mark', 'must never mark'))
        self.case.fake.artifact_mode = 'missing'
        result = self.case.evaluate()
        self.assertFalse(result['ready'])
        self.assertTrue(any('source' in problem.lower() for problem in result['missing']))

    def test_only_current_source_missing_does_not_expose_old_legacy_source(self):
        changed = base.SPEC.replace('cannot mark', 'must never mark')
        self.case.attached(changed)
        records, _ = base.sf.ticket_records(self.case.fake.comments[base.ISSUE], 65536)
        current = [r for r in records if r['kind'] == 'spec'][-1]
        source = next(a for a in current['attachments'] if a['role'] == 'spec')
        self.case.fake.unavailable_artifact_ids = {source['id']}
        result = self.case.evaluate()
        self.assertFalse(result['ready'])
        self.assertTrue(any('older specs cannot substitute' in p for p in result['missing']), result)

    def test_production_origin_is_not_inferred_from_the_read_target(self):
        body = b'fixture bytes'
        expected = ta.hashlib.sha256(body).hexdigest()
        row = {'id':'listed-fixture', 'sha256':expected, 'commentId':'comment', 'completionState':'completed'}
        prod = 'https://goodqa-uploads.tor1.digitaloceanspaces.com'
        dev = 'https://goodqa-uploads-dev.tor1.digitaloceanspaces.com'
        for api, storage, allowed in [('https://goodqa.app/v1/mcp',prod,True),
                                      ('https://goodqa.app/v1/mcp',dev,False),
                                      ('https://custom.example.invalid/v1/mcp',prod,False)]:
            adapter = ta.GoodQAAdapter(dict(self.case.config,endpoint=api))
            adapter._listed_attachments = {row['id']:row}
            target = json.dumps({'download':{'url':storage+'/fixture'}}).encode()
            with mock.patch.object(adapter, '_artifact_get', side_effect=[target,body]) as get:
                if allowed:
                    self.assertEqual(adapter.read_attachment(row),body)
                    self.assertEqual(get.call_count,2)
                else:
                    with self.assertRaises(ta.TicketSystemUnavailable):
                        adapter.read_attachment(row)
                    self.assertEqual(get.call_count,1)



if __name__ == '__main__':
    unittest.main()
