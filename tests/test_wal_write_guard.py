"""goodqa#17008: nothing but the sanctioned writers writes a session WAL.

A row of ~/.claude/wals/<session>/main.jsonl is read as main's own by provenance, the chat-send allow-list and other
grants. command_guard used to allow `>>`, `tee -a` and interpreter one-liners into it, and no hook refused the Write or
Edit tools there. Now one predicate (harness/hooks/wal_paths.py) decides "in the WAL tree" for command_guard (shell
writes, rule wal-forgery) and for wal.py's PreToolUse hook (file tools). wal_note.py, the sanctioned writer, may be
aimed by a sub-agent only at its own WAL (rule wal-actor). Commands are data passed to decide(), never run, except the
two wal_note.py runs, which write into a temporary HOME."""

import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402
import wal  # noqa: E402
import wal_paths  # noqa: E402

SESSION = 'sess1'
AGENT = 'a1'
NOTE = 'python3 ~/.claude/hooks/wal_note.py'

# every shell write shape; {w} is a WAL file, {d} its session directory
WRITES = [
    'echo x >> {w}', 'echo x > {w}', 'echo x &>> {w}', 'printf x | tee -a {w}', 'printf x | tee {w}',
    'dd if=/tmp/x of={w} conv=notrunc oflag=append', 'cp /tmp/x {w}', 'cp /tmp/x {d}/', 'mv /tmp/x {w}',
    'install -m 600 /tmp/x {w}', 'sed -i s/a/b/ {w}', 'perl -pi -e s/a/b/ {w}', 'sort -o {w} /tmp/x',
    'cat /tmp/x | sponge {w}', 'curl -o {w} https://example.invalid/x', 'rsync /tmp/x {w}', 'scp h:x {w}',
    'touch {w}', 'ln -s {w} /tmp/alias', 'ln {w} /tmp/hard', 'cp -l {w} /tmp/hard', 'exec 3<> {w}',
    'cat /tmp/x 1<> {w}', 'cat > {w} <<EOF\nx\nEOF',
    "python3 -c \"open('{w}','a').write('x')\"",
    "python3 -c \"import pathlib; pathlib.Path('{w}').open('a').write('x')\"",
    "python3 -c \"import os; os.open('{w}', os.O_WRONLY | os.O_APPEND)\"",
    "python3 -c \"print('x', file=open('{w}', mode='a'))\"",
    "perl -e 'open(my $f, \">>\", \"{w}\"); print $f 1'",
    "node -e \"require('fs').appendFileSync('{w}', 'x')\"",
    "ruby -e \"File.open('{w}', 'a') {{ |f| f.puts 1 }}\"",
    "python3 - <<'EOF'\nopen('{w}', 'a').write('x')\nEOF",
    # reached another way: a variable, cd and a relative name, .., braces, a glob, an unresolvable target
    'W={w}; echo x >> "$W"', 'cd {d} && echo x >> {name}', 'echo x >> {d}/../{session}/{name}',
    'echo x >> {d}/{{{name},y}}', 'echo x >> "$(ls -d ~/.claude/wals/*)/{name}"',
    # behind a launcher, a shell string and an unknown program's shell text
    'flock /tmp/l sh -c "echo x >> {w}"', 'timeout 5 tee -a {w} < /tmp/x', 'env A=1 tee -a {w} < /tmp/x',
    "bash -c 'printf x >> {w}'", "mytool -c 'echo x >> {w}'", 'nohup -Z 1 tee -a {w} < /tmp/x',
    # the inverted rule: a program not proven to only read its operand is refused (unknown programs included)
    'rclone copyto r:x {w}', 'rclone copy r:x {d}', 'tar -xf /tmp/x.tar -C {d}', 'tar -czf {d}/x.tgz /tmp/x',
    'zip {d}/x.zip /tmp/x', 'unzip -o /tmp/x.zip -d {d}', 'ex -sc wq {w}', 'vim -es -c wq {w}', 'gzip {w}',
    'chmod 666 {w}', 'mkfifo {d}/x', 'split -b 1 /tmp/x {d}/', 'patch {w} /tmp/x.diff', 'yq -i .a=1 {w}',
    'sqlite3 {d}/x.db "create table t(a)"', 'mytool --out={w}', 'mytool -o{w}', 'uniq /tmp/x {w}',
    'git -C {d} init', 'docker cp c:/x {w}', 'curl --output-dir {d} -O https://example.invalid/x',
    'python3 -m json.tool /tmp/x {w}', 'cd {d} && mytool {name}',
    # a program run on paths that come from elsewhere in the command
    "awk '{{print > \"{w}\"}}' /etc/hosts", "awk '{{print > FILENAME}}' {w}", 'sed "w {w}" /tmp/x',
    'find {d} -name {name} -exec sh -c "echo x >> {{}}" \\;', 'find {d} -fprint {w}',
    'xargs -I@ sh -c "echo x >> @" <<< {w}', 'ls {d}/*.jsonl | while read f; do echo x >> "$f"; done',
    'for f in {d}/*.jsonl; do echo x >> "$f"; done', 'ls {d}/*.jsonl | xargs -n1 cp /tmp/x',
    # interpreter code that gets the path from argv, the environment or stdin
    "python3 -c \"import sys; open(sys.argv[1],'a').write('x')\" {w}",
    "W={w} python3 -c \"import os; open(os.environ['W'],'a').write('x')\"",
    "echo {w} | python3 -c \"import sys; open(sys.stdin.read().strip(),'a').write('x')\"",
    "python3 -c \"import runpy, sys; runpy.run_path(sys.argv[1], run_name='__main__')\" ~/.claude/hooks/wal_note.py "
    "--wal {w} --event note --note x",
    # red-team round 1 (024b13b1): a program given by path is judged by its name; `-` is an operand; target-directory
    # copies; extraction into a directory above the tree; a directory inside the tree makes relative names count;
    # code that loads the harness's own writer; readers with an output-file option
    '/usr/bin/uniq /tmp/x {w}', '/bin/chmod 666 {w}', '/usr/bin/vim -es -c wq {w}', '/usr/bin/gzip {w}',
    '/usr/bin/patch {w} /tmp/x.diff', 'cat /tmp/x | uniq - {w}', 'cat /tmp/x | xxd -r -p - {w}',
    'command uniq - {w}', 'cp -t {d} /tmp/x', 'cp --target-directory={d} /tmp/x', 'install -t {d} /tmp/x',
    'cp -R /tmp/stage/wals {d}/../../', 'tar -xf /tmp/x.tar -C {d}/../..', 'cd {d}/../.. && tar -xf /tmp/x.tar',
    'unzip /tmp/x.zip -d {d}/../..', "cd {d} && python3 -c \"open('{name}','a').write('x')\"",
    "cd {d} && perl -e 'open(F, \">>{name}\"); print F 1'",
    "cd {d} && node -e \"require('fs').appendFileSync('{name}','x')\"",
    "cd {d} && awk 'BEGIN{{print \"x\" >> \"{name}\"}}'", "cd {d} && sed -n 'w {name}' /tmp/x",
    'cd {d}; cd /tmp; cd -; echo x >> {name}',
    "python3 -c \"import sys; sys.path.insert(0, '{d}/../../hooks'); from wal import append; append('{w}', {{}})\"",
    'cat /tmp/x | less -o {w}', 'tree -o {w} /tmp',
]
READS = [
    'cat {w}', 'tail -n 5 {w}', 'jq . {w}', 'grep -c x {w}', 'wc -l < {w}', 'ls -la {d}',
    "python3 -c \"import json; rows = []; [rows.append(json.loads(l)) for l in open('{w}')]; print(len(rows))\"",
    "python3 -c \"import sys; [sys.stdout.write(l) for l in open('{w}')]\"",
    'cp {w} /tmp/backup.jsonl', 'rsync -a {d}/ /tmp/b/', 'rclone copy {d} remote:b', 'tar -cf /tmp/w.tar {d}',
    'find {d} -name "*.jsonl" | xargs wc -l', 'find {d} -name "*.jsonl" -exec wc -l {{}} +',
    'tar -czf /tmp/w.tgz -C {d} .', 'gzip -c {w} > /tmp/x.gz', 'sed -n 1p {w}', "awk 'NR==1' {w}",
    "perl -ne 'print if /x/' {w}", 'diff {w} /tmp/x', 'sha256sum {w}', 'python3 -m json.tool {w}',
    'ls {d} | xargs -I@ cp {d}/@ /tmp/b/', 'jq -c . {w} > /tmp/out.jsonl', 'stat {w}', 'uniq {w}',
    'while read f; do wc -l "$f"; done < <(ls {d}/*.jsonl)', 'grep -c x {w} > /tmp/count', 'xxd {w} | head',
    "cat {w} | python3 -c \"import sys; print(sum(1 for _ in sys.stdin))\"",
    'rclone copy {d} remote:b --include "*.jsonl"', 'cd {d} && ls -la && wc -l {name}',
]


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='cg-wal-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        self.dir = self.home / '.claude/wals' / SESSION
        self.dir.mkdir(parents=True)
        self.main = self.dir / 'main.jsonl'
        self.agent = self.dir / ('agent-%s.jsonl' % AGENT)
        self.other = self.dir / 'agent-b2.jsonl'
        for p in (self.main, self.agent, self.other):
            p.write_text('{"event":"session"}\n')
        (self.home / 'w').mkdir()
        env = {k: v for k, v in os.environ.items() if k != 'CLAUDE_CONFIG_DIR'}
        env['HOME'] = str(self.home)
        patch = mock.patch.dict(os.environ, env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home / 'w'))

    def decide(self, command, caller=None, ps=False):
        self.compiled.caller = caller
        return cg.decide(command, self.compiled, cwd=str(self.home / 'w'), ps=ps)

    def fill(self, row, path):
        return row.format(w=path, d=path.parent, name=path.name, session=SESSION)


class ShellWrites(Case):
    def test_every_write_shape_is_refused_for_main_and_agent_wals(self):
        misses = []
        for path in (self.main, self.agent):
            for row in WRITES:
                for caller in (None, {'kind': 'main', 'session': SESSION}):
                    verdict, message = self.decide(self.fill(row, path), caller)
                    # an older log rule may refuse first (unzip -o: log-delete); either way the WAL is not written
                    if verdict != 'block' or not ('wal-forgery' in message or '[log_delete/log-delete]' in message):
                        misses.append((path.name, row, caller and caller['kind'], verdict, message[:120]))
        self.assertEqual(misses, [])

    def test_the_tilde_form_and_powershell_add_content(self):
        for command, ps in (('echo x >> ~/.claude/wals/%s/main.jsonl' % SESSION, False),
                            ('Add-Content -Path %s -Value x' % self.main, True)):
            verdict, message = self.decide(command, ps=ps)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-forgery', message, command)

    def test_a_symlinked_parent_and_a_configured_claude_home(self):
        link = self.home / 'w/alias'
        link.symlink_to(self.dir)
        self.assertIn('wal-forgery', self.decide('echo x >> %s/main.jsonl' % link)[1])
        alt = self.home / 'alt-claude'
        (alt / 'wals' / SESSION).mkdir(parents=True)
        with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': str(alt)}):
            self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home / 'w'))
            verdict, message = self.decide('echo x >> %s/wals/%s/main.jsonl' % (alt, SESSION))
        self.assertEqual(verdict, 'block')
        self.assertIn('wal-forgery', message)

    def test_a_script_that_writes_the_tree_is_refused(self):
        # a shell script on disk is read; an interpreter script written earlier in the same command is judged in full
        body = "open('%s','a').write('x')" % self.main
        (self.home / 'w/x.sh').write_text('echo x >> %s\n' % self.main)
        for command in ('bash x.sh', 'sh %s/w/x.sh' % self.home, 'printf %%s "%s" > x.py; python3 x.py' % body,
                        "cat > x.py <<'E'\n%s\nE\npython3 x.py" % body):
            verdict, message = self.decide(command)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-forgery', message, command)

    def test_property_unknown_programs_and_readers_at_any_operand_position(self):
        # generated (seed 17008): an unknown program given a WAL operand in any position and form is refused; a proven
        # reader given the same operand is not
        rng = random.Random(17008)
        filler = ['-v', '--quiet', 'a.txt', '/tmp/y', '-n', '3', 'x=1']
        readers = sorted(n for n in cg.WAL_READERS if n.isalpha() and '-' not in n and n not in ('print',))
        misses = []
        for case in range(240):
            path = rng.choice((self.main, self.agent, self.dir))
            form = rng.choice(('{p}', '--file={p}', '-o{p}', 'of={p}', '{p}'))
            words = [rng.choice(filler) for _ in range(rng.randint(0, 5))]
            words.insert(rng.randint(0, len(words)), form.format(p=path))
            unknown = 'zq' + ''.join(rng.choice('abcdefghij') for _ in range(5))
            # given by name or by a path (a program by path is judged by its name), with a `-` operand or not
            program = rng.choice(('', '/usr/local/bin/', './', '~/bin/')) + unknown
            if rng.random() < 0.3:
                words.insert(rng.randint(0, len(words)), '-')
            verdict, message = self.decide(' '.join([program] + words))
            if verdict != 'block' or 'wal-forgery' not in message:
                misses.append(('unknown', unknown, words, verdict))
            if form == '{p}':
                reader = rng.choice(readers)
                verdict, message = self.decide(' '.join([reader] + [w for w in words if w != 'x=1']))
                if 'wal-forgery' in message:
                    misses.append(('reader', reader, words, verdict))
        self.assertEqual(misses, [])

    def test_a_partial_install_without_the_predicate_still_refuses(self):
        # wal_paths.py missing beside the hook: the analyser keeps running on its inline fallback, not the launcher's
        stage = self.home / 'stage'
        stage.mkdir()
        for name in ('command_guard.py', 'command_guard_hook.py', 'redact.py', 'safe_input.py', 'caller_identity.py'):
            (stage / name).write_bytes((HOOKS / name).read_bytes())
        for command, rule in (('echo x >> %s' % self.main, 'wal-forgery'), ('gzip %s' % self.agent, 'wal-forgery'),
                              ('ls /', None)):
            payload = {'tool_name': 'Bash', 'tool_input': {'command': command}, 'session_id': SESSION,
                       'cwd': str(self.home / 'w')}
            done = subprocess.run([sys.executable, str(stage / 'command_guard_hook.py'), 'hook'],
                                  input=json.dumps(payload), capture_output=True, text=True, timeout=60,
                                  env=dict(os.environ), check=False)
            if rule:
                self.assertEqual(done.returncode, 2, command)
                self.assertIn(rule, done.stderr, command)
            else:
                self.assertEqual(done.returncode, 0, done.stderr[-300:])
                self.assertNotIn('crashed', done.stderr)

    def test_the_predicate_module_is_one_of_the_guards_own_files(self):
        # replacing wal_paths.py beside the hook would switch the WAL rule off, so it is protected like the guard
        for hooks in ('~/.claude/hooks', '~/.codex/agent-harness'):
            for command in ('echo x > %s/wal_paths.py' % hooks, 'rm %s/wal_paths.py' % hooks):
                self.assertEqual(self.decide(command)[0], 'block', command)

    @unittest.expectedFailure
    def test_known_limit_an_interpreter_script_already_on_disk(self):
        # KNOWN LIMIT (reported to the coordinator): the guard does not read a Python script that already sits on
        # disk, because the harness's own tools name the WAL tree and write it; a file tool can create such a
        # script outside the tree. This test flips to an unexpected success once the route is closed.
        (self.home / 'w/x.py').write_text("open('%s','a').write('x')\n" % self.main)
        self.assertEqual(self.decide('python3 x.py')[0], 'block')

    def test_the_refusal_names_the_sanctioned_route_and_the_callers_own_wal(self):
        message = self.decide('echo x >> %s' % self.main, {'kind': 'agent', 'agent': AGENT, 'session': SESSION})[1]
        self.assertIn('wal_note.py --wal %s' % wal_paths.own_wal(SESSION, AGENT), message)


class Actor(Case):
    AGENT_CALLER = {'kind': 'agent', 'agent': AGENT, 'session': SESSION}

    def test_a_sub_agent_cannot_aim_wal_note_at_main_or_another_agent(self):
        rows = ['%s --wal {main} --event result --note x', '%s --wal={main} --event result --note x',
                '%s --event result --wal {other} --note x', 'W={main}; %s --wal "$W" --event result --note x',
                '%s --wal "$(cat /tmp/which)" --event result --note x',
                '~/.claude/hooks/wal_note.py --wal {main} --event result --note x %s',
                "bash -c '%s --wal {main} --event result --note x'",
                'flock /tmp/l %s --wal {main} --event result --note x',
                # the script after an interpreter option with a value, and the module form
                'python3 -X dev ~/.claude/hooks/wal_note.py --wal {main} --event result --note x',
                'python3 -I -X utf8 ~/.claude/hooks/wal_note.py --wal {main} --event result --note x',
                'cd ~/.claude/hooks && python3 -m wal_note --wal {main} --event result --note x',
                # every harness tool given --wal writes there (ah note runs wal_note.py as a child), and argparse
                # takes an abbreviation of --wal
                'ah note --wal {main} --event decision --note x', 'ah note --wa {main} --event decision --note x',
                'python3 ~/.claude/hooks/ah.py note --wal={main} --event decision --note x',
                'python3 ~/.claude/hooks/deliver.py prepare --wal {other}']
        for row in rows:
            command = (row % NOTE if '%s' in row else row).format(main=self.main, other=self.other)
            if command.endswith(' ' + NOTE):
                command = command[:-len(NOTE) - 1]
            verdict, message = self.decide(command, self.AGENT_CALLER)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-actor', message, command)
            self.assertIn(str(wal_paths.own_wal(SESSION, AGENT)), message, command)

    def test_a_sub_agent_cannot_set_the_actor_ah_stamps(self):
        for command in ('AH_AGENT_ID=main ah task status --task t --stage s --note x',
                        'export AGENT_ID=main; ah task done --task t', 'env AH_AGENT_ID=main ah task status'):
            verdict, message = self.decide(command, self.AGENT_CALLER)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-actor', message, command)

    def test_a_sub_agent_cannot_name_the_main_wal_harness_tools_notify(self):
        # red-team T2 (5b1b372d): escalation.py writes a LADDER decision row through wal_note.py into the WAL named by
        # AGENT_HARNESS_MAIN_WAL or --notify-wal, and peer_review.py passes the variable on
        esc = 'python3 ~/.claude/hooks/escalation.py reset --task t --code c --detail d'
        for row in ('AGENT_HARNESS_MAIN_WAL={main} %s' % esc, 'export AGENT_HARNESS_MAIN_WAL={main}; %s' % esc,
                    'env AGENT_HARNESS_MAIN_WAL={main} %s' % esc, 'declare -x AGENT_HARNESS_MAIN_WAL={main}; %s' % esc,
                    'AGENT_HARNESS_MAIN_WAL=$(cat /tmp/w) python3 ~/.claude/hooks/peer_review.py pr',
                    '%s --notify-wal {main}' % esc, '%s --notify-wal={main}' % esc, '%s --notify-w {other}' % esc,
                    '%s --notify-wal "$(cat /tmp/w)"' % esc):
            command = row.format(main=self.main, other=self.other)
            verdict, message = self.decide(command, self.AGENT_CALLER)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-actor', message, command)
        # main may name it; a sub-agent may aim --notify-wal at its own WAL; mentioning the name is not setting it
        main = {'kind': 'main', 'session': SESSION}
        self.assertEqual(self.decide('AGENT_HARNESS_MAIN_WAL=%s %s' % (self.main, esc), main)[0], 'allow')
        own = wal_paths.own_wal(SESSION, AGENT)
        self.assertEqual(self.decide('%s --notify-wal %s' % (esc, own), self.AGENT_CALLER)[0], 'allow')
        self.assertEqual(self.decide('grep -n AGENT_HARNESS_MAIN_WAL ~/.claude/hooks/escalation.py',
                                     self.AGENT_CALLER)[0], 'allow')

    def test_an_unproven_caller_cannot_write_main_but_may_write_an_agent_wal(self):
        unknown = {'kind': 'unknown', 'session': SESSION}
        self.assertIn('wal-actor', self.decide('%s --wal %s --event result --note x' % (NOTE, self.main), unknown)[1])
        self.assertEqual(self.decide('%s --wal %s --event result --note x' % (NOTE, self.agent), unknown)[0], 'allow')

    def test_own_wal_and_main_are_allowed(self):
        own = wal_paths.own_wal(SESSION, AGENT)
        self.assertEqual(self.decide('%s --wal %s --event result --note x' % (NOTE, own), self.AGENT_CALLER)[0],
                         'allow')
        main = {'kind': 'main', 'session': SESSION}
        for target in (self.main, self.other):
            command = "%s --wal %s --event result --note 'echo a >> b'" % (NOTE, target)
            self.assertEqual(self.decide(command, main)[0], 'allow', command)

    def test_the_hook_reads_the_caller_from_the_payload(self):
        self.assertEqual(cg.hook_caller({'agent_id': AGENT, 'session_id': SESSION})['kind'], 'agent')
        self.assertEqual(cg.hook_caller({'session_id': SESSION})['kind'], 'unknown')  # no agent_id is not proof
        self.assertEqual(cg.hook_caller(None)['kind'], 'unknown')


class WalNoteItself(Case):
    def run_note(self, *argv):
        return subprocess.run([sys.executable, str(HOOKS / 'wal_note.py')] + list(argv), capture_output=True,
                              text=True, timeout=60, env=dict(os.environ), check=False)

    def test_wal_note_still_writes_and_takes_no_abbreviated_options(self):
        done = self.run_note('--wal', str(self.main), '--event', 'result', '--note', 'still writes')
        self.assertEqual(done.returncode, 0, done.stderr[-300:])
        self.assertIn('still writes', self.main.read_text())
        done = self.run_note('--wa', str(self.main), '--event', 'result', '--note', 'abbreviated')
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn('abbreviated', self.main.read_text())


class Allowed(Case):
    def test_reads_and_the_wal_as_a_source_are_allowed(self):
        callers = (None, {'kind': 'main', 'session': SESSION}, {'kind': 'agent', 'agent': AGENT, 'session': SESSION})
        refused = [(row, caller and caller['kind'], v) for row in READS for path in (self.main, self.agent)
                   for caller in callers for v in [self.decide(self.fill(row, path), caller)[0]] if v != 'allow']
        self.assertEqual(refused, [])


class Landing(Case):
    """Copies whose contents land in the tree through a directory above it (red-team C5), with the source on disk."""

    def setUp(self):
        super().setUp()
        self.stage = self.home / 'w/stage'
        (self.stage / 'wals' / SESSION).mkdir(parents=True)
        (self.stage / 'wals' / SESSION / 'main.jsonl').write_text('{}\n')
        (self.home / 'w/notes').mkdir()
        self.claude = self.home / '.claude'

    def test_a_copy_of_a_tree_into_a_directory_above_it_is_refused(self):
        for command in ('rsync -a {s}/ {c}/', 'ditto {s} {c}', 'rclone copy {s} {c}', 'cp -R {s}/wals {c}/',
                        'cp -a {s}/. {c}/', 'cd {c} && cp -R {s}/wals .', 'scp -r {s}/wals {c}',
                        'cp -R {h}/w/s* {c}/'):
            command = command.format(s=self.stage, c=self.claude, h=self.home)
            verdict, message = self.decide(command)
            self.assertEqual(verdict, 'block', command)
            self.assertIn('wal-forgery', message, command)

    def test_copies_that_cannot_reach_the_tree_are_allowed(self):
        for command in ('cp -R {h}/w/notes {c}/', 'rsync -a {h}/w/notes/ /tmp/b/', 'rsync -a {c}/wals/ /tmp/b/',
                        'tar -xf /tmp/x.tar -C /tmp/out', 'cp {h}/w/notes/a {h}/w/b'):
            command = command.format(c=self.claude, h=self.home)
            self.assertEqual(self.decide(command)[0], 'allow', command)


class EveryWalTool(Case):
    def test_every_harness_tool_that_takes_wal_is_judged_by_who_runs_it(self):
        # a contract over the repository: each tool declaring --wal is refused for a sub-agent aiming it at main's WAL,
        # unless it only reads --wal (cg.WAL_FLAG_READERS); a new --wal tool joins this test without an edit
        agent = {'kind': 'agent', 'agent': AGENT, 'session': SESSION}
        tools = sorted(p.name for p in HOOKS.glob('*.py') if '"--wal"' in p.read_text(errors='replace')
                       or "'--wal'" in p.read_text(errors='replace'))
        self.assertIn('wal_note.py', tools)
        self.assertIn('ah.py', tools)
        wrong = []
        for tool in tools:
            command = 'python3 ~/.claude/hooks/%s sub --wal %s --note x' % (tool, self.main)
            verdict, message = self.decide(command, agent)
            refused = 'wal-actor' in message
            if refused == (tool in cg.WAL_FLAG_READERS):
                wrong.append((tool, verdict))
        self.assertEqual(wrong, [])

    def test_every_wal_option_a_hook_declares_is_judged(self):
        # every option ending in `wal` that takes a value is a WAL_OPTIONS option, or only read (spec_flow.py's
        # --owners-wal); a new one fails here until the guard knows it
        import re
        agent = {'kind': 'agent', 'agent': AGENT, 'session': SESSION}
        found = set()
        for p in HOOKS.glob('*.py'):
            text = p.read_text(errors='replace')
            for option in re.findall(r'''['"](--[a-z-]*wal)['"]''', text):
                found.add((p.name, option))
        self.assertIn(('escalation.py', '--notify-wal'), found)
        wrong = []
        for tool, option in sorted(found):
            if option == '--no-wal' or tool in cg.WAL_FLAG_READERS:  # a switch with no value; a reader
                continue
            command = 'python3 ~/.claude/hooks/%s sub %s %s --note x' % (tool, option, self.main)
            if 'wal-actor' not in self.decide(command, agent)[1]:
                wrong.append((tool, option))
        self.assertEqual(wrong, [])


class FileTools(Case):
    def refusal(self, tool, key, value, cwd=None, agent=None):
        data = {'tool_name': tool, 'tool_input': {key: value}, 'session_id': SESSION, 'cwd': cwd or str(self.home)}
        if agent:
            data['agent_id'] = agent
        return wal.file_tool_refusal(data)

    def test_every_file_tool_is_denied_in_the_tree_for_main_and_agents(self):
        for tool, key in (('Write', 'file_path'), ('Edit', 'file_path'), ('MultiEdit', 'file_path'),
                          ('NotebookEdit', 'notebook_path')):
            for agent in (None, AGENT):
                for value, cwd in ((str(self.main), None), (str(self.agent), None),
                                   ('~/.claude/wals/%s/main.jsonl' % SESSION, None), ('main.jsonl', str(self.dir)),
                                   (str(self.main).replace('.claude/wals', '.Claude/WALS'), None)):
                    with self.subTest(tool=tool, agent=agent, value=value):
                        self.assertIsNotNone(self.refusal(tool, key, value, cwd, agent))
            self.assertIsNone(self.refusal(tool, key, str(self.home / 'w/notes.md')))
        self.assertIsNone(self.refusal('Read', 'file_path', str(self.main)))

    def test_the_hook_denies_and_records_a_count_only(self):
        payload = {'tool_name': 'Write', 'tool_input': {'file_path': str(self.main), 'content': 'x'},
                   'session_id': SESSION, 'tool_use_id': 'toolu_1', 'agent_id': AGENT}
        done = subprocess.run([sys.executable, str(HOOKS / 'wal.py'), 'pretool'], input=json.dumps(payload),
                              capture_output=True, text=True, timeout=60, env=dict(os.environ), check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-300:])
        out = json.loads(done.stdout)
        self.assertEqual(out['hookSpecificOutput']['permissionDecision'], 'deny')
        rows = [json.loads(l) for l in self.agent.read_text().splitlines()]
        self.assertEqual(rows[-1].get('refused'), 'wal-write')
        self.assertNotIn(str(self.main), self.agent.read_text())


class SharedPredicate(Case):
    def test_both_guards_agree_with_the_one_predicate(self):
        paths = [str(self.main), str(self.agent), str(self.dir), str(self.home / '.claude/wals'),
                 str(self.home / '.claude/walsx/x.jsonl'), str(self.home / '.claude/projects/p/s.jsonl'),
                 str(self.home / 'w/main.jsonl'), str(self.home / 'w/wals.md')]
        for path in paths:
            inside = wal_paths.in_wal_tree(path, self.compiled.session_wal_roots)
            shell = 'wal-forgery' in self.decide('echo x >> %s' % path)[1]
            tool = wal.file_tool_refusal({'tool_name': 'Write', 'tool_input': {'file_path': path}}) is not None
            self.assertEqual((inside, shell, tool), (inside, inside, inside), path)
        self.assertTrue(wal_paths.in_wal_tree(str(self.main)))
        self.assertFalse(wal_paths.in_wal_tree(str(self.home / 'w/main.jsonl')))

    def test_dotdot_after_a_link_resolves_as_the_kernel_does(self):
        # red-team C1: `link/..` goes up from the link's target, so normalising before resolving misses the tree
        (self.home / '.claude/plugins').mkdir()
        (self.home / 'w/p').symlink_to(self.home / '.claude/plugins')
        path = '%s/w/p/../wals/%s/main.jsonl' % (self.home, SESSION)
        self.assertTrue(wal_paths.in_wal_tree(path))
        self.assertEqual(wal_paths.wal_owner(path)[1], 'main')
        self.assertIn('wal-forgery', self.decide('echo x >> %s' % path)[1])
        self.assertIn('wal-forgery', self.decide('cd %s && echo x >> p/../wals/%s/main.jsonl'
                                                 % (self.home / 'w', SESSION))[1])
        self.assertIsNotNone(wal.file_tool_refusal({'tool_name': 'Write', 'tool_input': {'file_path': path},
                                                    'agent_id': AGENT, 'session_id': SESSION}))
        agent = {'kind': 'agent', 'agent': AGENT, 'session': SESSION}
        own_through_link = '%s/w/p/../wals/%s/agent-%s.jsonl' % (self.home, SESSION, AGENT)
        self.assertEqual(self.decide('%s --wal %s --event x --note y' % (NOTE, own_through_link), agent)[0], 'allow')
        self.assertIn('wal-actor', self.decide('%s --wal %s --event x --note y' % (NOTE, path), agent)[1])

    def test_the_wal_file_names_agree(self):
        for value in ('a1', 'Foo', 'z-x', 'a/b', '', None, 'x' * 200):
            self.assertEqual(wal.safe_id(value), wal_paths.safe_id(value), value)


if __name__ == '__main__':
    unittest.main()
