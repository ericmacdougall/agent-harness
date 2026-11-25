"""goodqa#17008 and goodqa#17155: wal_paths.relation, the one path test of the session-WAL and configuration guards.

Every spelling of a path into, above or possibly into a protected root must get the same answer from the relation,
from the file-tool rule (wal_paths.file_tool_refusal) and from the shell rule (command_guard). Paths are data; nothing
here writes outside a temporary HOME."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import wal_paths as wp  # noqa: E402

# (spelling under {h}, relation to the WAL tree)
TREE_TABLE = [
    ('{h}/.claude/wals', wp.IN),
    ('{h}/.claude/wals/s/main.jsonl', wp.IN),
    ('{h}/.claude//wals/./s/main.jsonl', wp.IN),
    ('{h}/.claude/plugins/../wals/s/main.jsonl', wp.IN),
    ('{h}/.claude/wa{{l,}}s/s/main.jsonl', wp.IN),
    ('{h}/.c*/wals/s/main.jsonl', wp.POSSIBLY_IN),
    ('{h}/.claude/wal?/s/main.jsonl', wp.POSSIBLY_IN),
    ('{h}/.claude/wal[s]/s', wp.POSSIBLY_IN),
    ('{h}/.claude/w*', wp.POSSIBLY_IN),
    ('{h}/link/wals/s/main.jsonl', wp.IN),          # {h}/link -> {h}/.claude
    ('{h}/link/wal?/s', wp.POSSIBLY_IN),
    ('{h}/link/x/../wals/s', wp.IN),                # `..` after a link goes up from the link's target
    ('{h}/.c*/../.claude/wals/s', wp.POSSIBLY_IN),  # `..` after a pattern
    ('{h}/.claude', wp.ABOVE),
    ('{h}', wp.ABOVE),
    ('/', wp.ABOVE),
    ('{h}/.c*', wp.POSSIBLY_ABOVE),
    ('{h}/*', wp.POSSIBLY_ABOVE),
    ('{h}/.claude/walsx/s', None),
    ('{h}/.claude/plugins/wals', None),
    ('{h}/.claude/[!w]*/s', None),
    ('/tmp/x', None),
]
CONFIG_TABLE = [
    ('{h}/.claude/CLAUDE.md', wp.IN),
    ('{h}/.claude/claude.md', wp.IN),               # case-insensitive volumes
    ('{h}/.claude/settings.json', wp.IN),
    ('{h}/.claude/settings.local.json', wp.IN),
    ('{h}/.claude/settings*.json', wp.POSSIBLY_IN),
    ('{h}/.c*/CLAUDE.md', wp.POSSIBLY_IN),
    ('{h}/.codex/config.toml', wp.IN),
    ('{h}/.codex/hooks.json', wp.IN),
    ('{h}/link/CLAUDE.md', wp.IN),
    ('{h}/.claude', wp.ABOVE),
    ('{h}/.codex', wp.ABOVE),
    ('{h}/.claude/CLAUDE.md.bak', None),
    ('{h}/.claude/CLAUDE.md/x', None),              # nothing lives inside a file
    ('{h}/.claude/settings.yaml', None),
    ('{h}/.codex/sessions/x.jsonl', None),
    ('{h}/repo/CLAUDE.md', None),
]


class Relation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='wal-rel-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        (self.home / '.claude/wals/s').mkdir(parents=True)
        (self.home / '.claude/plugins').mkdir()
        (self.home / '.codex').mkdir()
        (self.home / 'link').symlink_to(self.home / '.claude')
        env = {k: v for k, v in os.environ.items() if k not in ('CLAUDE_CONFIG_DIR', 'CODEX_HOME')}
        env['HOME'] = str(self.home)
        patch = mock.patch.dict(os.environ, env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def spell(self, text):
        return text.format(h=self.home)

    def test_the_wal_tree_table(self):
        got = [(t, wp.tree_relation(self.spell(t))) for t, _ in TREE_TABLE]
        self.assertEqual(got, TREE_TABLE)

    def test_the_configuration_table(self):
        got = [(t, wp.config_relation(self.spell(t))) for t, _ in CONFIG_TABLE]
        self.assertEqual(got, CONFIG_TABLE)

    def test_the_file_tool_rule_agrees_with_the_relation(self):
        for text, rel in TREE_TABLE:
            refused = wp.file_tool_refusal('Write', {'file_path': self.spell(text)}) is not None
            self.assertEqual(refused, rel in wp.LANDS, text)

    def test_below_toward_tree_names_the_next_entry_or_an_unknown_one(self):
        self.assertEqual(wp.below_toward_tree(str(self.home)), '.claude')
        self.assertEqual(wp.below_toward_tree(str(self.home / '.claude')), 'wals')
        self.assertEqual(wp.below_toward_tree(self.spell('{h}/.c*')), '*')
        self.assertIsNone(wp.below_toward_tree(str(self.home / '.claude/wals')))
        self.assertIsNone(wp.below_toward_tree('/tmp'))

    def test_a_brace_blow_up_counts_every_group_as_a_pattern(self):
        many = str(self.home) + '/.claude/' + '{a,b}' * 8 + 'wals/s'  # 256 expansions, past the limit
        self.assertEqual(wp.tree_relation(many), wp.POSSIBLY_IN)
        self.assertLessEqual(len(wp._braces(many)), wp.BRACE_LIMIT)

    def test_configured_homes_count(self):
        alt = self.home / 'alt'
        (alt / 'wals').mkdir(parents=True)
        codex = self.home / 'cx'
        codex.mkdir()
        with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': str(alt), 'CODEX_HOME': str(codex)}):
            self.assertEqual(wp.tree_relation(str(alt / 'wals/s/main.jsonl')), wp.IN)
            self.assertEqual(wp.config_relation(str(alt / 'settings.json')), wp.IN)
            self.assertEqual(wp.config_relation(str(codex / 'hooks.json')), wp.IN)

    def test_non_paths_have_no_relation(self):
        for value in (None, '', 'relative/wals', '/x\x00/wals', 42):
            self.assertIsNone(wp.relation(value, wp.wal_roots()))


if __name__ == '__main__':
    unittest.main()
