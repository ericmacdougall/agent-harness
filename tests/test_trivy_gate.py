"""goodqa#15295: the pinned Trivy gate never passes silently, scans only the commit and lets accepted risks lapse.

A fake trivy (and a fake docker) stands in for the real tool here; the real pinned image is exercised on a
Docker host separately (REALLY_TESTED T169-REAL in the owner WAL).
"""

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import trivy_gate as tg  # noqa: E402

TODAY = dt.date(2026, 11, 8)
FAKE = f'''#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
record = os.environ.get("FAKE_TRIVY_RECORD")
if record:
    target = args[-1]
    listing = sorted(os.path.relpath(os.path.join(d, f), target) for d, _, fs in os.walk(target) for f in fs)
    with open(record, "w") as handle:
        json.dump({{"argv0": sys.argv[0], "args": args, "files": listing}}, handle)
code = int(os.environ.get("FAKE_TRIVY_EXIT", "0"))
report = os.environ.get("FAKE_TRIVY_REPORT")
if report and code == 0:
    out = args[args.index("--output") + 1]
    with open(report) as src, open(out, "w") as dst:
        dst.write(src.read())
sys.exit(code)
'''
VULN = {'SchemaVersion': 2, 'Results': [
    {'Target': 'requirements.txt', 'Class': 'lang-pkgs', 'Type': 'pip', 'Vulnerabilities': [
        {'VulnerabilityID': 'CVE-2023-32681', 'PkgName': 'requests', 'InstalledVersion': '2.19.0',
         'FixedVersion': '2.31.0', 'Severity': 'HIGH', 'Title': 'Unintended leak of Proxy-Authorization header'},
        {'VulnerabilityID': 'CVE-2020-0001', 'PkgName': 'requests', 'InstalledVersion': '2.19.0',
         'Severity': 'LOW'}]},
    {'Target': 'Dockerfile', 'Class': 'config', 'Misconfigurations': [
        {'ID': 'DS002', 'AVDID': 'AVD-DS-0002', 'Title': 'Image user should not be root', 'Severity': 'HIGH',
         'Status': 'FAIL', 'CauseMetadata': {'Code': {'Lines': [{'Content': 'ENV TOKEN=AKIAABCDEFGHIJKLMNOP'}]}}},
        {'ID': 'DS026', 'AVDID': 'AVD-DS-0026', 'Title': 'No HEALTHCHECK', 'Severity': 'HIGH', 'Status': 'PASS'}]},
]}
CLEAN = {'SchemaVersion': 2, 'Results': [{'Target': 'requirements.txt', 'Class': 'lang-pkgs', 'Type': 'pip'}]}


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)


class TrivyGate(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        git(self.repo, 'config', 'user.email', 'test@example.invalid')
        git(self.repo, 'config', 'user.name', 'test')
        self.binary = self.root / 'trivy'
        self.binary.write_text(FAKE)
        self.binary.chmod(0o700)
        self.pin = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.record = self.root / 'record.json'
        self.env = mock.patch.dict(os.environ, {'FAKE_TRIVY_RECORD': str(self.record)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def commit(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'fixture')

    def report(self, data):
        path = self.root / 'report.json'
        path.write_text(json.dumps(data))
        os.environ['FAKE_TRIVY_REPORT'] = str(path)

    def run_gate(self, **kwargs):
        options = {'binary': str(self.binary), 'sha256': self.pin, 'today': TODAY}
        options.update(kwargs)
        code, lines = tg.scan(self.repo, **options)
        return code, '\n'.join(lines)

    def vulnerable_fixture(self, extra=None):
        files = {'requirements.txt': 'requests==2.19.0\n', 'Dockerfile': 'FROM python:3.12\n'}
        files.update(extra or {})
        self.commit(files)
        self.report(VULN)

    def test_ac1_known_vulnerable_dependency_fails_naming_package_and_cve(self):
        self.vulnerable_fixture()
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)
        self.assertIn('CVE-2023-32681 requests 2.19.0, fixed in 2.31.0', out)
        self.assertIn('AVD-DS-0002', out)
        self.assertNotIn('CVE-2020-0001', out)  # LOW is out of scope
        self.assertNotIn('AVD-DS-0026', out)  # a passing check is not a finding
        args = json.loads(self.record.read_text())['args']
        self.assertEqual(args[:3], ['fs', '--scanners', 'vuln,misconfig'])
        self.assertIn('HIGH,CRITICAL', args)

    def test_ac2_clean_fixture_passes(self):
        self.commit({'requirements.txt': 'requests==2.31.0\n'})
        self.report(CLEAN)
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)
        self.assertIn('PASS', out)

    def ignore(self, until, ident='CVE-2023-32681', **extra):
        entry = {'id': ident, 'statement': 'only used in a test fixture', 'expired_at': until, **extra}
        return {'.agent-harness/trivy-ignore.json': json.dumps({'ignores': [entry]})}

    def test_ac3_an_ignore_past_expired_at_stops_suppressing(self):
        self.vulnerable_fixture(self.ignore('2026-11-07'))
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)
        self.assertIn('ignore entry CVE-2023-32681 expired 2026-11-07', out)
        self.assertIn('HIGH CVE-2023-32681 requests', out)

    def test_a_current_ignore_suppresses_only_its_id_and_package(self):
        files = self.ignore('2026-12-31')
        self.vulnerable_fixture(files)
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)  # the Dockerfile misconfig is still unaccepted
        self.assertIn('ignored CVE-2023-32681 requests', out)
        self.assertNotIn('HIGH CVE-2023-32681', out)
        self.commit(self.ignore('2026-12-31', package='urllib3'))
        code, out = self.run_gate()
        self.assertIn('HIGH CVE-2023-32681 requests', out)

    def test_ignore_entries_must_carry_statement_and_bounded_expiry(self):
        for entry in ({'id': 'CVE-1', 'statement': 'x'}, {'id': 'CVE-1', 'expired_at': '2026-12-01'},
                      {'id': 'CVE-1', 'statement': 'x', 'expired_at': '9999-12-31'},
                      {'id': 'CVE-1', 'statement': 'x', 'expired_at': 'soon'}):
            with self.subTest(entry=entry):
                self.vulnerable_fixture({'.agent-harness/trivy-ignore.json': json.dumps({'ignores': [entry]})})
                code, out = self.run_gate()
                self.assertEqual(code, 2, out)

    def test_ac4_wrong_pin_is_refused_before_execution(self):
        self.vulnerable_fixture()
        code, out = self.run_gate(sha256='0' * 64)
        self.assertEqual(code, 2, out)
        self.assertIn('does not match the pinned SHA-256', out)
        self.assertFalse(self.record.exists(), 'the unpinned binary must not run')
        code, out = self.run_gate(sha256=None)
        self.assertEqual(code, 2, out)

    def test_neg2_the_hashed_copy_runs_not_the_original_path(self):
        self.vulnerable_fixture()
        self.run_gate()
        argv0 = json.loads(self.record.read_text())['argv0']
        self.assertNotEqual(Path(argv0).resolve(), self.binary.resolve())
        self.assertIn('trivygate-', argv0)

    def test_neg1_database_or_run_failure_is_exit_2_not_pass(self):
        self.vulnerable_fixture()
        with mock.patch.dict(os.environ, {'FAKE_TRIVY_EXIT': '1'}):
            code, out = self.run_gate()
        self.assertEqual(code, 2, out)
        self.assertIn('not a pass', out)
        os.environ['FAKE_TRIVY_REPORT'] = str(self.root / 'missing.json')
        code, out = self.run_gate()
        self.assertEqual(code, 2, out)
        (self.root / 'garbage.json').write_text('{"Results": "nope"}')
        os.environ['FAKE_TRIVY_REPORT'] = str(self.root / 'garbage.json')
        code, out = self.run_gate()
        self.assertEqual(code, 2, out)

    def test_neg3_no_lockfile_is_nothing_scanned_not_clean(self):
        self.commit({'README.md': 'hello\n', 'tool.py': 'print(1)\n'})
        self.report(CLEAN)
        code, out = self.run_gate()
        self.assertEqual(code, 2, out)
        self.assertIn('NOTHING_SCANNED', out)
        self.assertFalse(self.record.exists())

    def test_neg4_code_excerpts_and_secret_values_are_never_printed(self):
        report = json.loads(json.dumps(VULN))
        report['Results'].append({'Target': 'app.env', 'Class': 'secret', 'Secrets': [
            {'RuleID': 'aws-access-key-id', 'Severity': 'CRITICAL', 'Match': 'AKIAABCDEFGHIJKLMNOP'}]})
        self.commit({'requirements.txt': 'requests==2.19.0\n'})
        self.report(report)
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)
        self.assertNotIn('AKIA', out)

    def test_only_the_commit_is_scanned_and_repo_trivyignore_is_not_honoured(self):
        self.vulnerable_fixture({'.trivyignore': 'CVE-2023-32681\n'})
        (self.repo / 'untracked-secret.txt').write_text('not committed\n')
        (self.repo / 'requirements.txt').write_text('requests==2.31.0\n')  # uncommitted edit
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)
        record = json.loads(self.record.read_text())
        self.assertNotIn('untracked-secret.txt', record['files'])
        self.assertIn('requirements.txt', record['files'])
        ignorefile = record['args'][record['args'].index('--ignorefile') + 1]
        self.assertNotEqual(Path(ignorefile).name, '.trivyignore')
        self.assertIn('trivygate-', ignorefile)

    def test_archive_links_leaving_the_scan_directory_are_refused(self):
        self.commit({'requirements.txt': 'requests==2.31.0\n'})
        os.symlink('/etc', self.repo / 'escape')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'link')
        self.report(CLEAN)
        code, out = self.run_gate()
        self.assertEqual(code, 2, out)
        self.assertIn('link leaves the scan directory', out)
        self.assertFalse(self.record.exists())

    def test_missing_binary_is_exit_2(self):
        self.commit({'requirements.txt': 'requests==2.31.0\n'})
        code, out = self.run_gate(binary=str(self.root / 'absent'))
        self.assertEqual(code, 2, out)
        self.assertIn('not found', out)

    def test_image_runner_requires_a_digest_and_mounts_the_export_read_only(self):
        self.vulnerable_fixture()
        code, out = self.run_gate(sha256=None, image='aquasec/trivy:0.74.0')
        self.assertEqual(code, 2, out)
        self.assertIn('pinned by digest', out)
        bindir = self.root / 'bin'
        bindir.mkdir()
        docker = bindir / 'docker'
        docker.write_text(f'''#!{sys.executable}
import json, os, shutil, sys
args = sys.argv[1:]
mounts = dict(a.split(":", 1)[::-1] for a in (args[i + 1] for i, v in enumerate(args) if v == "-v"))
json.dump(args, open(os.environ["FAKE_TRIVY_RECORD"], "w"))
host_out = [h for c, h in ((k, v) for k, v in mounts.items()) if c == "/out"][0]
shutil.copy(os.environ["FAKE_TRIVY_REPORT"], os.path.join(host_out, "report.json"))
''')
        docker.chmod(0o700)
        digest = 'aquasec/trivy:0.74.0@sha256:' + 'a' * 64
        with mock.patch.dict(os.environ, {'PATH': f'{bindir}{os.pathsep}{os.environ["PATH"]}'}):
            code, out = self.run_gate(sha256=None, image=digest)
        self.assertEqual(code, 1, out)
        args = json.loads(self.record.read_text())
        self.assertIn(digest, args)
        self.assertTrue(any(a.endswith(':/src:ro') for a in args), args)
        self.assertEqual(args[args.index(digest) + 1], 'fs')

    def test_exactly_one_runner(self):
        self.vulnerable_fixture()
        code, out = self.run_gate(image='aquasec/trivy@sha256:' + 'a' * 64)
        self.assertEqual(code, 2, out)
        self.assertIn('exactly one runner', out)


class DeliverPrepareScan(unittest.TestCase):
    """deliver.py prepare --scan trivy refuses before any generation, push or PR exists."""

    @classmethod
    def setUpClass(cls):
        import deliver  # noqa: PLC0415
        cls.deliver = deliver

    def args(self, *extra):
        argv = ['deliver.py', 'prepare', '--task', 't', '--original', '/x', '--original-branch', 'main', *extra]
        with mock.patch.object(sys, 'argv', argv):
            return self.deliver.parse_args()

    def run_prepare(self, code, last):
        args = self.args('--scan', 'trivy', '--trivy-image', 'aquasec/trivy@sha256:' + 'a' * 64)
        inputs = (Path('/src'), 'feat', 'f' * 40, 'b' * 40, 'kit')
        with mock.patch.object(self.deliver, 'target_preflight', return_value=[]), \
                mock.patch.object(self.deliver, 'source_inputs', return_value=inputs), \
                mock.patch.object(tg, 'scan', return_value=(code, ['trivy: scanned 1', last])) as scan, \
                mock.patch.object(self.deliver, 'Workflow', side_effect=AssertionError('no generation')), \
                mock.patch.object(self.deliver, 'matching_origins', side_effect=AssertionError('no remote')):
            with self.assertRaises(self.deliver.DeliveryError) as caught:
                self.deliver.prepare(args)
        self.assertEqual(scan.call_args.kwargs['rev'], 'f' * 40)
        return caught.exception

    def test_findings_refuse_with_scan_findings(self):
        error = self.run_prepare(1, 'trivy: FAIL, 1 HIGH/CRITICAL finding(s)')
        self.assertEqual((error.status, error.code, error.facts['reason']), ('BLOCKED_POLICY', 2, 'SCAN_FINDINGS'))

    def test_an_incomplete_scan_refuses_as_unavailable(self):
        error = self.run_prepare(2, 'trivy: trivy exited 1 (database unavailable or scan error); not a pass')
        self.assertEqual(error.facts['reason'], 'SCAN_UNAVAILABLE')

    def test_scan_is_off_by_default(self):
        self.assertIsNone(self.args().scan)


if __name__ == '__main__':
    unittest.main()
