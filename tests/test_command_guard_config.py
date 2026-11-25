"""goodqa#17155, the Bash half: a command that names CLAUDE.md, a settings file or a Codex config file only reads it.

Every command string here is DATA handed to command_guard.decide(); nothing in this file executes a row. All protected
files live in a temporary HOME. CG_HOOKS_DIR points the same rows at another implementation (failing first, mutants)."""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402

MD = '~/.claude/CLAUDE.md'

TICKET_FORMS = [  # the five forms of the ticket, each in both spellings of the home
    "printf 'x' >> ~/.claude/CLAUDE.md", "printf 'x' >> @HOME@/.claude/CLAUDE.md",
    'cp /tmp/new.md ~/.claude/CLAUDE.md', 'cp /tmp/new.md @HOME@/.claude/CLAUDE.md',
    'python3 -c "open(\'@HOME@/.claude/CLAUDE.md\',\'a\').write(\'x\')"',
    'python3 - <<\'E\'\nimport os\nopen(os.path.expanduser("~/.claude/CLAUDE.md"), "a").write("x")\nE',
    "sed -i 's/a/b/' ~/.claude/CLAUDE.md", "sed -i '' 's/a/b/' ~/.claude/CLAUDE.md",
    'echo x | tee -a ~/.claude/CLAUDE.md', 'echo x | tee -a @HOME@/.claude/CLAUDE.md',
]
BLOCK = [
    'echo x > ~/.claude/settings.json', 'echo x >> ~/.claude/settings.local.json', 'echo x > ~/.claude/settings.team.json',
    'echo x > ~/.codex/config.toml', 'echo x >> ~/.codex/hooks.json', 'echo x >| ~/.claude/CLAUDE.md',
    'echo x &>> ~/.claude/CLAUDE.md', ': <> ~/.claude/CLAUDE.md', 'echo x >> "$HOME/.claude/CLAUDE.md"',
    'echo x >> ${HOME}/.claude/CLAUDE.md', 'echo x >> ~/.CLAUDE/claude.MD', 'echo x >> ~/.claude/../.claude/CLAUDE.md',
    'cd ~/.claude && echo x >> CLAUDE.md', 'cd ~ && echo x >> .claude/CLAUDE.md', 'F=~/.claude/CLAUDE.md; echo x >> "$F"',
    'D=~/.claude; echo x >> $D/CLAUDE.md', 'for f in ~/.claude/CLAUDE.md; do echo x >> "$f"; done',
    'echo x >> ~/lnk/CLAUDE.md', 'echo x >> ~/hard.md', 'echo x >> ~/.claude/CLAUDE.m?', 'cp /tmp/a ~/.claude/{CLAUDE,x}.md',
    'cp /tmp/CLAUDE.md ~/.claude/', 'install -m 600 /tmp/a ~/.claude/CLAUDE.md', 'mv /tmp/a ~/.claude/CLAUDE.md',
    'mv ~/.claude/CLAUDE.md /tmp/a', 'ln -sf /tmp/a ~/.claude/CLAUDE.md', 'ln ~/.claude/CLAUDE.md /tmp/hard',
    'rsync /tmp/a ~/.claude/CLAUDE.md', 'cp -t ~/.claude /tmp/CLAUDE.md', 'dd if=/tmp/a of=$HOME/.claude/CLAUDE.md',
    'curl -o ~/.claude/CLAUDE.md https://example.invalid/a', 'sort -o ~/.claude/CLAUDE.md /tmp/a', 'touch ~/.claude/CLAUDE.md',
    'chmod 777 ~/.claude/CLAUDE.md', 'rm ~/.claude/CLAUDE.md', 'truncate -s 0 ~/.claude/CLAUDE.md', 'vim ~/.claude/CLAUDE.md',
    'timeout 5 tee ~/.claude/CLAUDE.md', 'env tee ~/.claude/CLAUDE.md', 'sudo tee -a ~/.claude/CLAUDE.md',
    'exec -a cat tee ~/.claude/CLAUDE.md', 'env -C ~/.claude tee CLAUDE.md', 'echo x | xargs -I{} tee ~/.claude/CLAUDE.md',
    'echo ~/.claude/CLAUDE.md | xargs tee', 'find ~/.claude -name CLAUDE.md -exec tee {} \\;',
    'find ~ -name CLAUDE.md -delete', 'bash -c "echo x >> ~/.claude/CLAUDE.md"', "ssh host 'echo x >> ~/.claude/CLAUDE.md'",
    "ssh host 'echo x >> /home/eric/.claude/CLAUDE.md'", 'python3 tool.py ~/.claude/CLAUDE.md',
    "perl -pi -e 's/a/b/' ~/.claude/CLAUDE.md", 'node -e "require(\'fs\').appendFileSync(process.env.HOME+\'/.claude/CLAUDE.md\',\'x\')"',
    'python3 -c "from pathlib import Path; (Path.home()/\'.claude\'/\'CLAUDE.md\').write_text(\'x\')"',
    'python3 -c "import os; os.rename(\'/tmp/a\', os.path.expanduser(\'~/.claude/settings.json\'))"',
    'python3 -c "import os; os.system(\'echo x >> ~/.claude/CLAUDE.md\')"',
    "awk '{print > \"/tmp/o\"}' ~/.claude/CLAUDE.md", 'sed -n w/tmp/o ~/.claude/CLAUDE.md', 'uniq /tmp/a ~/.claude/CLAUDE.md',
    'python3 -m json.tool /tmp/a ~/.claude/settings.json', 'rg --pre sh x ~/.claude/CLAUDE.md',
    '[() { tee "$2"; }; [ -f ~/.claude/CLAUDE.md ]', './cat ~/.claude/CLAUDE.md', 'cat() { tee "$1"; }; cat ~/.claude/CLAUDE.md', 'echo x >> $CLAUDE_CONFIG_DIR/CLAUDE.md',
    'D=$(cd ~/.claude && pwd); echo x >> $D/CLAUDE.md', 'git checkout -- ~/.claude/CLAUDE.md',
    "cat >> ~/.claude/CLAUDE.md <<'E'\nwords\nE", "trap 'echo x >> ~/.claude/CLAUDE.md' EXIT",
]
ALLOW = [
    'cat ~/.claude/CLAUDE.md', 'grep -n Hard ~/.claude/CLAUDE.md', 'head -5 ~/.claude/CLAUDE.md', 'diff ~/.claude/CLAUDE.md /tmp/a',
    'git hash-object ~/.claude/CLAUDE.md', 'git diff --no-index ~/.claude/CLAUDE.md /tmp/a', "sed -n '1,20p' ~/.claude/CLAUDE.md",
    'jq .hooks ~/.claude/settings.json', 'wc -l < ~/.claude/CLAUDE.md', 'cp ~/.claude/CLAUDE.md /tmp/backup.md', 'ls -la ~/.claude',
    'test -f ~/.claude/CLAUDE.md && echo yes', '[[ -f ~/.claude/CLAUDE.md ]] && echo yes',
    '[ -f ~/.claude/CLAUDE.md ] && echo yes', 'timeout 5 cat ~/.claude/CLAUDE.md',
    'LC_ALL=C grep x ~/.claude/CLAUDE.md', 'bash -c "cat ~/.claude/CLAUDE.md"', "ssh host 'cat ~/.claude/CLAUDE.md'",
    'find ~/.claude -name CLAUDE.md -exec cat {} \\;', 'shasum -a 256 ~/.claude/CLAUDE.md', 'tail -n 3 ~/.codex/config.toml',
    'python3 -c "print(open(\'@HOME@/.claude/CLAUDE.md\').read())"', 'cat ~/.claude/CLAUDE.md > /tmp/copy.md',
    # text that only mentions the file (class 17149, 17083, 17084, 17099, 17103, 17104, 17105)
    'echo "edit ~/.claude/CLAUDE.md by hand"', 'git commit -m "docs: mention ~/.claude/CLAUDE.md and settings.json"',
    'python3 ~/.claude/hooks/wal_note.py --note "agents can write ~/.claude/CLAUDE.md"',
    'python3 tool.py --reason "~/.claude/CLAUDE.md"', "grep -rn 'CLAUDE.md' src", 'grep -rn "~/.claude/CLAUDE.md" docs',
    "cat > /tmp/note.txt <<'E'\nagents must not write ~/.claude/CLAUDE.md\nE", 'echo CLAUDE.md', 'rg settings.json tests',
    'python3 - <<\'E\'\nprint("see ~/.claude/CLAUDE.md for the rules")\nE',
    # other files of the same name
    'echo x >> CLAUDE.md', 'echo x >> ~/repo/CLAUDE.md', 'cp a ~/repo/.claude/settings.json', 'sed -i s/a/b/ src/CLAUDE.md',
    'echo x >> ~/.claude/projects/p/memory/CLAUDE.md', 'echo x > ~/.claude/settings/extra.json',
    # `T=$(mktemp -d); echo x > "$T/.claude/CLAUDE.md"` is not here: the older log-delete rule refuses it with or without this one
]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-config-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        for rel in ('.claude/CLAUDE.md', '.claude/settings.json', '.codex/config.toml', '.codex/hooks.json', 'repo/CLAUDE.md',
                    'repo/.claude/settings.json', 'repo/src/CLAUDE.md', 'repo/.git/HEAD'):
            path = cls.home / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('x\n')
        os.symlink(cls.home / '.claude', cls.home / 'lnk')
        os.link(cls.home / '.claude/CLAUDE.md', cls.home / 'hard.md')
        cls.policy = cg.load_policy(path=str(cls.home / 'no-such-policy.json'))
        cls._patch = mock.patch.dict(os.environ, {'HOME': str(cls.home)})
        cls._patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._patch.stop()
        cls._tmp.cleanup()

    def decide(self, command):
        cwd = str(self.home / 'repo')
        return cg.decide(command.replace('@HOME@', str(self.home)), cg.Compiled(self.policy, home=str(self.home), cwd=cwd), cwd=cwd)

    def wrong(self, rows, want):
        self.assertGreater(len(rows), 0)
        out = []
        for row in rows:
            verdict, message = self.decide(row)
            if (verdict == 'block') != (want == 'block'):
                out.append('%r -> %s %s' % (row, verdict, message.splitlines()[:1]))
        self.assertEqual(out, [], '%d of %d rows wrong:\n%s' % (len(out), len(rows), '\n'.join(out)))


class Contract(Base):
    def test_the_five_ticket_forms_are_refused(self):
        self.wrong(TICKET_FORMS, 'block')

    def test_other_ways_to_write_are_refused(self):
        self.wrong(BLOCK, 'block')

    def test_reads_and_mentions_are_allowed(self):
        self.wrong(ALLOW, 'allow')

    def test_the_refusal_is_this_rule_and_names_the_route(self):
        verdict, message = self.decide("printf 'x' >> ~/.claude/CLAUDE.md")
        self.assertEqual(verdict, 'block')
        self.assertIn('protected-config', message)
        self.assertIn('Read tool', message)


class Failure(Base):
    """The rule's own failure refuses only a command whose text names one of the files."""

    def test_a_missing_module_refuses_only_a_named_file(self):
        with mock.patch.dict(sys.modules, {'command_guard_config': None}):
            self.assertEqual(self.decide("echo x >> ~/.claude/CLAUDE.md")[0], 'block')
            self.assertNotEqual(self.decide('ls src')[0], 'block')

    def test_a_raising_rule_refuses_only_a_named_file(self):
        import command_guard_config
        with mock.patch.object(command_guard_config, 'judge_command', side_effect=KeyError('x')):
            self.assertEqual(self.decide("echo x >> ~/.claude/CLAUDE.md")[0], 'block')
            self.assertNotEqual(self.decide('ls src')[0], 'block')


class OneList(unittest.TestCase):
    def test_the_fallback_pattern_covers_every_entry_of_the_one_list(self):
        import protected_paths
        for entry in protected_paths.PROTECTED_WRITE_GLOBS:
            self.assertTrue(re.search(cg.CONFIG_FILE_TEXT, '~/' + entry.replace('*', '.local')), entry)


if __name__ == '__main__':
    unittest.main()
