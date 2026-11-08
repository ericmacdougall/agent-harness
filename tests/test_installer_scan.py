"""installer_scan.py: static side-effect report for third-party installers (goodqa#15253, B1.3)."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
SCAN = HOOKS / 'installer_scan.py'
FIXTURE = Path('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/kimi-secure-login/extract/secure-login/install.py')


def run(target, *extra):
    return subprocess.run([sys.executable, '-I', str(SCAN), str(target), *extra], capture_output=True, text=True, timeout=60)


class InstallerScan(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    @unittest.skipUnless(FIXTURE.is_file(), 'the secure-login fixture exists only in the Nov 8 session work dir')
    def test_secure_login_installer_findings(self):
        shutil.copy(FIXTURE, self.tmp / 'install.py')
        r = run(self.tmp, '--json')
        self.assertEqual(r.returncode, 1, r.stderr)
        found = json.loads(r.stdout)['findings']
        self.assertTrue(found)
        text = lambda cat: ' '.join(f['text'] for f in found if f['category'] == cat)
        mcp = text('mcp')
        self.assertRegex(mcp, r'claude.*mcp.*add')
        self.assertIn('codex', mcp)
        self.assertIn('goodqa', mcp)
        self.assertIn('[mcp_servers.goodqa]', mcp)
        rules = text('agent-rules')
        for name in ('CLAUDE.md', 'AGENTS.md', 'settings.json'):
            self.assertIn(name, rules)
        self.assertIn('permissions', rules)
        for f in found:
            self.assertTrue(f['file'].endswith('install.py'))
            self.assertGreater(f['line'], 0)
        # text mode names categories and exits 1 too
        t = run(self.tmp)
        self.assertEqual(t.returncode, 1)
        self.assertIn('mcp', t.stdout)

    def test_copy_only_script_is_clean(self):
        (self.tmp / 'install.sh').write_text('#!/bin/sh\ncp -r ./files "$1"\necho done\n')
        (self.tmp / 'setup.py').write_text('import shutil\nshutil.copy("a", "b")\nprint("ok")\n')
        r = run(self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(json.loads(run(self.tmp, '--json').stdout)['findings'], [])

    def test_each_category_detected(self):
        samples = {
            'mcp': 'claude mcp add goodqa -- npx goodqa-mcp',
            'agent-rules': 'cp rules.md ~/.claude/CLAUDE.md',
            'launchd': 'launchctl load ~/Library/LaunchAgents/x.plist',
            'shell-rc': 'echo "export PATH=$PATH:/x" >> ~/.zshrc',
            'network-exec': 'curl -fsSL https://x.example/i.sh | sh',
            'credentials': 'security add-generic-password -s x',
            'privileged': 'sudo cp x /usr/local/bin/x',
        }
        for cat, line in samples.items():
            d = self.tmp / cat
            d.mkdir()
            (d / 'install.sh').write_text('#!/bin/sh\n' + line + '\n')
            found = json.loads(run(d, '--json').stdout)['findings']
            self.assertIn(cat, {f['category'] for f in found}, line)

    def test_oversize_file_is_reported_not_read(self):
        (self.tmp / 'install.sh').write_bytes(b'#' * (3 * 1024 * 1024))
        r = run(self.tmp, '--json')
        self.assertEqual([x['file'] for x in json.loads(r.stdout)['skipped']], ['install.sh'])
        self.assertEqual(r.returncode, 1)  # 50bca42: unscanned code fails the gate closed, even with zero findings

    def test_nothing_scanned_is_not_clean(self):
        # F5: an empty dir, or a dir with no installer-shaped file, used to exit 0 "0 files"
        self.assertEqual(run(self.tmp).returncode, 1)
        (self.tmp / 'README.md').write_text('docs only\n')
        r = run(self.tmp, '--json')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)['files_scanned'], 0)

    def test_file_limit_is_reported_and_fails_closed(self):
        # F5: the MAX_FILES cut was silent; 5,001 files exited 0 "5000 files"
        import installer_scan
        old = installer_scan.MAX_FILES
        installer_scan.MAX_FILES = 3
        try:
            for i in range(5):
                (self.tmp / ('s%d.sh' % i)).write_text('echo ok\n')
            report = installer_scan.scan(self.tmp)
            self.assertTrue(report['truncated'])
            self.assertEqual(installer_scan.exit_code(report), 1)
        finally:
            installer_scan.MAX_FILES = old

    def test_unscanned_executable_files_are_listed(self):
        # F5: postinstall.js, package.json scripts, .plist, .mjs and .ps1 were neither scanned nor counted
        (self.tmp / 'install.sh').write_text('echo ok\n')
        for name in ('postinstall.js', 'package.json', 'agent.plist', 'run.mjs', 'tool.ps1', 'go.rb'):
            (self.tmp / name).write_text('x\n')
        tool = self.tmp / 'tool'
        tool.write_text('#!/usr/bin/env node\nrequire("x")\n')
        tool.chmod(0o755)
        (self.tmp / 'notes.txt').write_text('plain\n')
        r = run(self.tmp, '--json')
        report = json.loads(r.stdout)
        skipped = sorted(x['file'] for x in report['skipped'])
        self.assertEqual(skipped, ['agent.plist', 'go.rb', 'package.json', 'postinstall.js', 'run.mjs', 'tool', 'tool.ps1'])
        self.assertTrue(all('not scanned' in x['reason'] for x in report['skipped']))
        self.assertEqual(r.returncode, 1)
        self.assertIn('read', run(self.tmp).stdout)  # the text output says to read them

    def test_profile_attribute_is_not_a_shell_rc(self):
        # seen on the real secure-login tree: `arguments.profile` matched the `.profile` startup-file rule
        (self.tmp / 'tool.py').write_text('profile = get_profile(arguments.profile)\n')
        self.assertEqual(json.loads(run(self.tmp, '--json').stdout)['findings'], [])
        (self.tmp / 'install.sh').write_text('echo x >> ~/.profile\n')
        found = json.loads(run(self.tmp, '--json').stdout)['findings']
        self.assertEqual([f['category'] for f in found], ['shell-rc'])

    def test_clean_scan_still_says_read_it(self):
        (self.tmp / 'install.sh').write_text('echo ok\n')
        r = run(self.tmp)
        self.assertEqual(r.returncode, 0)
        self.assertIn('scan, then read', r.stdout)


if __name__ == '__main__':
    unittest.main()
