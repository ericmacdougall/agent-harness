"""The shipped harness names no owner project, host or person: those live in ~/.agent-harness/local.json
(docs/local-config.md). Fails when one of the names below reappears under harness/ or in the installers, unless
tests/data/project_names_allowlist.json lists that (file, name) pair with a reason."""
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / 'tests' / 'data' / 'project_names_allowlist.json'
TERMS = ('t2scan', 'hawkeye', 'dev2', 't2-dev', 'ah-mac-mini', 'ah-spectre', 'yates', 'optinrouter', 'parentproof',
         'timbar', 'streamd', 'fabric', 'pve', 'transition2', 'pgpool', 'coordinator-v2', 'pp-ci', 'claude-rc',
         'ericmacdougall', 'tisha', 'larkspur')
NAMES = re.compile(r'(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])' % '|'.join(re.escape(t) for t in TERMS), re.I)
PERSON = re.compile(r'\bEric\b')  # case-sensitive: "generic" and "numeric" are fine
SCOPE = ('harness', 'install.py', 'install_codex.py', 'install_tui_plugin.py', 'log_backup_install.py',
         'netwatch_install.py', 'mission_control_install.py')
SKIP = ('harness/mission_control/web/vendor/',)  # third-party minified bundles


def tracked_files():
    out = subprocess.run(['git', 'ls-files', '--', *SCOPE], cwd=ROOT, capture_output=True, text=True, check=True)
    return [p for p in out.stdout.splitlines() if p and not p.startswith(SKIP)]


def find_names(text):
    found = {m.group(1).lower() for m in NAMES.finditer(text)}
    if PERSON.search(text):
        found.add('eric')
    return found


class NoProjectNames(unittest.TestCase):
    def test_the_matcher_catches_each_name_and_skips_lookalikes(self):
        self.assertEqual(find_names('ssh t2-dev; route to dev2 for Eric'), {'t2-dev', 'dev2', 'eric'})
        self.assertEqual(find_names('mcp__hawkeye__run and the T2Scan adapter'), {'hawkeye', 't2scan'})
        self.assertEqual(find_names('a generic numeric fabricated approve; dev25 and xdev2'), set())

    def test_no_owner_names_under_harness_or_in_installers(self):
        allowed = {(e['path'], e['term']) for e in json.loads(ALLOWLIST.read_text())['allow']}
        hits = []
        for rel in tracked_files():
            try:
                text = (ROOT / rel).read_text(encoding='utf-8')
            except (UnicodeDecodeError, OSError):
                continue
            hits += [(rel, term) for term in sorted(find_names(text)) if (rel, term) not in allowed]
        self.assertEqual(hits, [], 'owner-specific names belong in ~/.agent-harness/local.json, not the harness')

    def test_every_allowlist_entry_is_still_needed(self):
        stale = []
        for entry in json.loads(ALLOWLIST.read_text())['allow']:
            self.assertTrue(entry.get('reason'), entry)
            path = ROOT / entry['path']
            if not path.exists() or entry['term'] not in find_names(path.read_text(encoding='utf-8')):
                stale.append(entry['path'])
        self.assertEqual(stale, [])


if __name__ == '__main__':
    unittest.main()
