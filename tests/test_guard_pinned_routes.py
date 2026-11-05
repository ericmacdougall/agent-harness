"""The one-off pinned routes and the credential-script refusal (GoodQA goodqa#14518).

Every command string here is DATA handed to command_guard.decide(); nothing in this file runs a candidate command or reads
a real credential. Files are synthetic and live in a temporary HOME. CG_HOOKS_DIR points the tests at an older guard to
show them failing first.
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

SH_REL = 'unit-mig/t2-rclone/user-run-store-dropbox-secret.sh'
PY_REL = 'unit-mig/cf-dns/cf_dns_prod_move.py'
BASE = '.agent-harness/work/dev-decom/'
SH_TEXT = b'#!/bin/bash\nconf=~/.config/rclone/rclone.conf\n'
PY_TEXT = b'#!/usr/bin/env python3\nSECRET = "GOODQA_CLOUDFLARE_API_TOKEN"\n'
PY_ARGS = ['list', 'set-ttl --name connect.example.test --ttl 60 --expect-ttl 300',
           'set-content --name example.test --content 192.0.2.1 --expect-content 192.0.2.2']


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        env = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        # A fixed clock, so these do not start failing on the expiry date before the table is removed.
        clock = mock.patch.object(cg.time, 'time', return_value=cg.PINNED_ROUTE_EXPIRES - 86400)
        clock.start()
        self.addCleanup(clock.stop)
        self.sh = self.write(BASE + SH_REL, SH_TEXT)
        self.py = self.write(BASE + PY_REL, PY_TEXT)
        table = mock.patch.object(cg, 'PINNED_ROUTES', (
            (SH_REL, sha(SH_TEXT), cg.PINNED_ROUTES[0][2] if hasattr(cg, 'PINNED_ROUTES') else ''),
            (PY_REL, sha(PY_TEXT), cg.PINNED_ROUTES[1][2] if hasattr(cg, 'PINNED_ROUTES') else ''),
        ), create=True)
        table.start()
        self.addCleanup(table.stop)

    def write(self, rel, data):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def verdict(self, command):
        return cg.decide(command, cwd=str(self.home))[0]

    def assertRefused(self, command):
        self.assertEqual(self.verdict(command), 'block', command)

    def assertAllowed(self, command):
        self.assertEqual(self.verdict(command), 'allow', command)


class PinnedRouteTests(Base):
    def test_exact_invocations_are_allowed(self):
        self.assertAllowed('/bin/bash %s' % self.sh)
        for args in PY_ARGS:
            self.assertAllowed('/usr/bin/python3 -I %s %s' % (self.py, args))

    def test_changed_invocations_are_refused(self):
        sh, py = self.sh, self.py
        rows = [
            '/bin/bash %s extra' % sh,
            '/bin/bash %s | tee %s/out' % (sh, self.home),
            '/bin/bash %s > %s/out' % (sh, self.home),
            '/bin/bash %s; true' % sh,
            'true && /bin/bash %s' % sh,
            '/bin/bash  %s' % sh,
            '/bin/bash %s\n' % sh,
            '/bin/bash -x %s' % sh,
            'bash %s' % sh,
            'sh %s' % sh,
            'source %s' % sh,
            'bash < %s' % sh,
            str(sh),
            'FOO=1 /bin/bash %s' % sh,
            'env -i /bin/bash %s' % sh,
            '/usr/bin/python3 %s list' % py,
            'python3 -I %s list' % py,
            '/usr/bin/python3 -I %s' % py,
            '/usr/bin/python3 -I %s delete' % py,
            '/usr/bin/python3 -I %s list extra' % py,
            '/usr/bin/python3 -I %s list | tee %s/out' % (py, self.home),
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60' % py,
            '/usr/bin/python3 -I %s set-content --name $(id) --content 192.0.2.1 --expect-content 192.0.2.2' % py,
            '/usr/bin/python3 -I %s set-content --name x --content $(id) --expect-content 192.0.2.2' % py,
            '/usr/bin/python3 -I %s set-content --name x --content 192.0.2.1 --expect-content $(id)' % py,
            '/usr/bin/python3 -I %s set-ttl --name $(id) --ttl 60 --expect-ttl 300' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl $(id) --expect-ttl 300' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60 --expect-ttl $(id)' % py,
            '/usr/bin/python3 -I %s set-ttl --name x --ttl 60 --expect-ttl 300 --extra' % py,
            '/bin/sh %s' % sh,
            '/usr/local/bin/bash %s' % sh,
            '/usr/local/bin/python3 -I %s list' % py,
            '/bin/bash %s' % py,
            '/usr/bin/python3 -I %s list' % sh,
        ]
        for command in rows:
            with self.subTest(command=command):
                self.assertRefused(command)

    def test_modified_script_at_the_pinned_path_is_refused(self):
        self.sh.write_bytes(SH_TEXT + b'# changed\n')
        self.py.write_bytes(PY_TEXT + b'# changed\n')
        self.assertRefused('/bin/bash %s' % self.sh)
        self.assertRefused('/usr/bin/python3 -I %s list' % self.py)

    def test_copy_at_another_path_is_refused(self):
        sh = self.write('elsewhere/copy.sh', SH_TEXT)
        py = self.write('elsewhere/copy.py', PY_TEXT)
        self.assertRefused('/bin/bash %s' % sh)
        self.assertRefused('/usr/bin/python3 -I %s list' % py)

    def test_symlink_at_the_pinned_path_is_refused(self):
        target = self.write('elsewhere/target.sh', SH_TEXT)
        self.sh.unlink()
        self.sh.symlink_to(target)
        self.assertRefused('/bin/bash %s' % self.sh)

    def test_missing_file_gives_no_route(self):
        self.sh.unlink()
        self.assertFalse(cg.pinned_route('/bin/bash %s' % self.sh))

    def test_routes_end_at_expiry(self):
        command = '/bin/bash %s' % self.sh
        self.assertTrue(cg.pinned_route(command, now=cg.PINNED_ROUTE_EXPIRES - 1))
        self.assertFalse(cg.pinned_route(command, now=cg.PINNED_ROUTE_EXPIRES))
        with mock.patch.object(cg.time, 'time', return_value=cg.PINNED_ROUTE_EXPIRES):
            self.assertRefused(command)

    def test_read_failure_gives_no_route(self):
        with mock.patch.object(cg, '_read_prefix', side_effect=OSError):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % self.sh))

    def test_only_a_plain_home_gives_a_route(self):
        command = '/bin/bash %s' % self.sh
        self.assertTrue(cg.pinned_route(command))
        for home in ('', 'relative/home', str(self.home) + ';id', str(self.home) + ' x', '$(id)'):
            with self.subTest(home=home), mock.patch.dict(os.environ, {'HOME': home}):
                self.assertFalse(cg.pinned_route(command))
                path = '%s/%s%s' % (home, BASE, SH_REL)
                self.assertFalse(cg.pinned_route('/bin/bash %s' % path))
        with mock.patch.dict(os.environ):
            del os.environ['HOME']
            self.assertFalse(cg.pinned_route(command))

    def test_a_home_with_shell_syntax_and_a_true_copy_gets_no_route(self):
        home = str(self.home) + '/a;id;'
        target = Path(home) / BASE / SH_REL
        target.parent.mkdir(parents=True)
        target.write_bytes(SH_TEXT)
        with mock.patch.dict(os.environ, {'HOME': home}):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % target))

    def test_a_command_list_gets_no_route(self):
        self.assertFalse(cg.pinned_route(['/bin/bash', str(self.sh)]))

    def test_a_policy_file_cannot_add_a_route(self):
        policy = self.home / 'policy.json'
        text = b'#!/bin/bash\ncat ~/.config/rclone/rclone.conf\n'
        # Under the routes' own base with its true hash, so only the table can be what refuses it.
        rogue = self.write(BASE + 'rogue.sh', text)
        row = ['rogue.sh', sha(text), '/bin/bash {path}']
        policy.write_text(json.dumps({'PINNED_ROUTES': [row], 'pinned_routes': [row]}))
        compiled = cg.Compiled(cg.load_policy(path=str(policy)), cwd=str(self.home))
        self.assertEqual(cg.decide('/bin/bash %s' % rogue, compiled, cwd=str(self.home))[0], 'block')

    def test_the_path_in_the_shape_is_literal(self):
        command = '/bin/bash %s' % self.sh
        self.assertIn('.agent-harness', command)
        self.assertFalse(cg.pinned_route(command.replace('.agent-harness', 'xagent-harness')))

    def test_a_file_past_the_read_limit_gets_no_route(self):
        big = b'#' * (cg.CREDENTIAL_SCRIPT_READ + 1)
        self.sh.write_bytes(big)
        table = ((SH_REL, sha(big), cg.PINNED_ROUTES[0][2]), cg.PINNED_ROUTES[1])
        with mock.patch.object(cg, 'PINNED_ROUTES', table):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % self.sh))

    def test_a_home_with_a_space_and_a_true_copy_gets_no_route(self):
        home = str(self.home) + '/a b'
        target = Path(home) / BASE / SH_REL
        target.parent.mkdir(parents=True)
        target.write_bytes(SH_TEXT)
        with mock.patch.dict(os.environ, {'HOME': home}):
            self.assertFalse(cg.pinned_route('/bin/bash %s' % target))


class CredentialScriptTests(Base):
    def test_other_scripts_naming_the_credentials_are_refused(self):
        sh = self.write('x/run.sh', b'#!/bin/bash\nwc -c ~/.config/rclone/rclone.conf\n')
        py = self.write('x/run.py', b'open("/any/.config/rclone/rclone.conf")\n')
        token = self.write('x/token.py', b'name = "GOODQA_CLOUDFLARE_API_TOKEN"\n')
        dump = self.write('x/dump.sh', b'#!/bin/bash\nrclone config show\n')
        dump2 = self.write('x/dump2.sh', b'rclone  config  dump\n')
        noext = self.write('x/noext', b'#!/usr/bin/env python3\nopen("/any/.config/rclone/rclone.conf")\n')
        for command in ('bash %s' % sh, 'sh %s' % sh, str(sh), 'source %s' % sh, 'bash < %s' % sh, 'python3 %s' % py,
                        'python3 -I %s' % token, '/usr/bin/python3 %s --flag' % token, 'bash %s' % dump,
                        'bash %s' % dump2, str(noext), 'python3.12 %s' % py, 'python3.9 -I %s' % token,
                        'python3 -W ignore %s' % py, 'python3 -X utf8 %s' % py, 'bash -euo pipefail %s' % sh,
                        'bash -o pipefail %s' % sh, 'echo x >> %s; bash %s' % (sh, sh)):
            with self.subTest(command=command):
                self.assertRefused(command)

    def test_harness_tools_are_not_refused(self):
        """Every hook and helper the harness ships, run by path. A mention of rclone must not stop them."""
        files = sorted(p for d in ('harness/hooks', 'harness/bin', 'scripts', 'tools') for p in (ROOT / d).glob('*')
                       if p.is_file() and p.suffix in ('.py', '.sh'))
        self.assertGreater(len(files), 20)
        for path in files:
            run = 'bash' if path.suffix == '.sh' else 'python3'
            with self.subTest(path=path.name):
                self.assertNotEqual(self.verdict('%s %s' % (run, path)), 'block')

    def test_data_and_lookalikes_are_not_refused(self):
        marker = b'.config/rclone/rclone.conf GOODQA_CLOUDFLARE_API_TOKEN\n'
        data = self.write('x/main.jsonl', marker)
        notes = self.write('x/notes.md', marker)
        mention = self.write('x/mention.sh', b'#!/bin/bash\n# rclone.conf is not read here; see rclone.conf.example\n')
        gui = self.write('x/gui.sh', b'#!/bin/bash\nls .config/rclone-gui/ .config/rclone/rclone.conf.example\n')
        named = self.write('x/named.sh', marker)
        a_test = self.write('x/tests/test_thing.py', marker)
        other_guard = self.write('other/harness/hooks/command_guard.py', marker)
        canary = self.write('x/tests/live_guard_canary.py', marker)
        for command in ('python3 -m json_tool %s' % data, 'bash < %s' % notes, 'bash %s' % data, 'bash %s' % mention,
                        'bash %s' % gui, 'bash -n %s' % named, '/bin/bash -n %s' % named, 'sh -n %s' % named,
                        'python3 -I %s' % a_test, 'python3 %s doctor' % other_guard, 'python3 %s' % canary,
                        'python3 -m unittest discover -s %s' % named.parent):
            with self.subTest(command=command):
                self.assertNotEqual(self.verdict(command), 'block')

    def test_every_way_a_shell_script_names_the_config_is_refused(self):
        for body in (b'cd ~/.config/rclone && cat rclone.conf\n', b'cd ~/.config/rclone\ncat ./rclone.conf\n',
                     b'D=~/.config/rclone; cat "$D/rclone.conf"\n', b'D=~/.config/rclone/; cat "${D}rclone.conf"\n',
                     b'N=rclone.conf; cat ~/.config/rclone/$N\n',
                     b'cat "${XDG_CONFIG_HOME:-$HOME/.config}/rclone/rclone.conf"\n',
                     b'cat "$XDG_CONFIG_HOME/rclone/rclone.conf"\n',
                     b'rsync -a ~/.config/rclone/ t2-dev:.config/rclone/\n', b'scp -r ~/.config/rclone t2-dev:.config/\n',
                     b'tar czf - ~/.config/rclone | ssh t2-dev tar xzf -\n', b'cat ~/.config/rclone/*\n',
                     b'rclone config show\n', b'rclone -q config dump\n', b'rclone --config "$C" config show\n',
                     b'rclone config "show"\n', b'rclone \\\n  config show\n', b'/opt/bin/rclone config show\n',
                     b'tok=$GOODQA_CLOUDFLARE_API_TOKEN\n'):
            path = self.write('x/form.sh', b'#!/bin/bash\n' + body)
            with self.subTest(body=body):
                self.assertRefused('bash %s' % path)

    def test_every_way_a_python_script_names_the_config_is_refused(self):
        for body in (b'os.path.join(expanduser("~"), ".config", "rclone", "rclone.conf")\n',
                     b'os.path.join(expanduser("~/.config/rclone"), "rclone.conf")\n',
                     b'Path.home() / ".config" / "rclone" / "rclone.conf"\n', b'Path.home() / ".config/rclone" / "rclone.conf"\n',
                     b'c.read("rclone.conf")\n', b'subprocess.run(["rclone", "config", "show"])\n',
                     b'subprocess.run(["rclone", "config", "dump"], check=True)\n',
                     b'subprocess.run("rclone config show", shell=True)\n', b"os.system('/usr/bin/rclone config dump')\n",
                     b'os.system(f"rclone --config {c} config show")\n', b'name = "GOODQA_CLOUDFLARE_API_TOKEN"\n'):
            path = self.write('x/form.py', body)
            with self.subTest(body=body):
                self.assertRefused('python3 %s' % path)

    def test_prose_is_not_a_read(self):
        """A row in a table or a rule's wording mentions the dump command. These stopped owners during the evacuation."""
        for rel, body in (('x/table.py', b'a("X01", "Agent ran `rclone config show`, leaking tokens", "none")\n'),
                          ('x/rules.py', b'R("S02", "Never run config-dumping commands (rclone config show, gh auth token).")\n'),
                          ('x/comment.py', b'# GOODQA_CLOUDFLARE_API_TOKEN and .config/rclone/rclone.conf are not used here\n'),
                          ('x/indented.py', b'def f():\n    # rclone config show would print tokens\n    return 1\n'),
                          ('x/comment.sh', b'#!/bin/bash\n# never: cat ~/.config/rclone/rclone.conf or rclone config show\n'),
                          ('x/lookalike.py', b'open("rclone.conf.example")\nprint("~/.config/rclone-gui/")\n'),
                          ('x/verbs.sh', b'#!/bin/bash\nrclone config file\nrclone listremotes\n')):
            path = self.write(rel, body)
            run = 'python3' if rel.endswith('.py') else 'bash'
            with self.subTest(body=body):
                self.assertAllowed('%s %s' % (run, path))

    def test_a_test_outside_a_tests_folder_gets_no_skip(self):
        marker = b'open("/any/.config/rclone/rclone.conf")\n'
        for rel in ('x/test_rclone.py', 'x/test_token.py', 'x/tests/helper.py', 'x/tests/test_thing.txt'):
            path = self.write(rel, marker)
            with self.subTest(rel=rel):
                self.assertRefused('python3 %s' % path)

    def test_each_of_the_guards_own_names_is_skipped(self):
        for name in ('command_guard.py', 'command_guard_hook.py', 'command_guard_corpus.py', 'live_guard_canary.py',
                     'holds_guard.py'):
            path = self.write('own/' + name, b'open("/any/.config/rclone/rclone.conf")\n')
            with self.subTest(name=name):
                self.assertNotEqual(self.verdict('python3 %s' % path), 'block')

    def test_a_named_runner_decides_whatever_the_file_is_called(self):
        marker = b'cat ~/.config/rclone/rclone.conf\n'
        py_marker = b'open("/x/.config/rclone/rclone.conf")\n'
        for rel, run, data in (('x/deploy', 'bash %s', marker), ('x/steps.txt', 'bash %s', marker), ('x/go.command', 'bash %s', marker),
                               ('x/go.ksh', 'ksh %s', marker), ('x/cred.env', '. %s', marker), ('x/setup', 'source %s', marker),
                               ('x/tool', 'python3 %s', py_marker), ('x/go.py3', 'python3 %s', py_marker),
                               ('x/GO.PY', 'python3 %s', py_marker)):
            path = self.write(rel, data)
            with self.subTest(rel=rel):
                self.assertRefused(run % path)

    def test_a_script_run_by_its_own_path_is_judged_by_suffix_or_shebang(self):
        marker = b'cat ~/.config/rclone/rclone.conf\n'
        for rel, data in (('x/a.bash', marker), ('x/a.zsh', marker), ('x/a.sh', marker), ('x/A.SH', marker),
                          ('x/gosh', b'#!/bin/sh\n' + marker), ('x/gozsh', b'#!/bin/zsh\n' + marker),
                          ('x/gopy', b'#!/usr/bin/env python3\nopen("/x/.config/rclone/rclone.conf")\n')):
            path = self.write(rel, data)
            with self.subTest(rel=rel):
                self.assertRefused(str(path))
        self.assertAllowed(str(self.write('x/data.txt', marker)))

    def test_versioned_pythons_get_the_check(self):
        path = self.write('x/named.py', b'open("/any/.config/rclone/rclone.conf")\n')
        for name in ('python3', 'python3.12', 'python3.13t', 'python3.12-intel64', 'pythonw', 'pypy3.10', '/usr/bin/python3.12'):
            with self.subTest(name=name):
                self.assertRefused('%s %s' % (name, path))

    def test_options_and_arguments_do_not_hide_the_script(self):
        sh = self.write('x/named.sh', b'#!/bin/bash\nwc -c ~/.config/rclone/rclone.conf\n')
        py = self.write('x/named.py', b'open("/any/.config/rclone/rclone.conf")\n')
        for command in ('bash -eou pipefail %s' % sh, 'bash -oe pipefail %s' % sh, 'bash -eoux pipefail %s' % sh, 'bash -- %s' % sh,
                        'bash -noprofile %s' % sh, 'bash --norc %s' % sh, 'bash --rcfile /dev/null %s' % sh, 'bash +o pipefail %s' % sh,
                        'bash -n +n %s' % sh, 'bash %s -c prod' % sh, 'bash %s --command x' % sh, 'timeout 60 bash %s' % sh,
                        'env X=1 bash %s' % sh, 'cat %s | bash' % sh, 'python3 %s -m prod' % py, 'python3 %s -c x' % py,
                        'python3 -W ignore %s' % py, 'python3 -Wignore %s' % py, 'python3 -IX utf8 %s' % py,
                        'python3 --check-hash-based-pycs always %s' % py, 'python3 -- %s' % py):
            with self.subTest(command=command):
                self.assertRefused(command)
        for command in ('bash -n %s' % sh, 'bash -en %s' % sh, 'python3 -m %s' % py, 'python3 -Im %s' % py,
                        'python3 -c %s' % repr('print(1)')):
            with self.subTest(command=command):
                self.assertNotEqual(self.verdict(command), 'block')

    def test_a_padded_script_cannot_outlast_the_time_limit(self):
        """A quadratic regex here once turned a log deletion on the last line into an allow, by passing the guard's limit."""
        delete = b'rm -rf ~/.claude/projects\n'
        read = b'cat ~/.config/rclone/rclone.conf\n'
        for count in (3000, 25000, 100000):
            pad = b'rclone -a ' * count
            for last in (delete, read):
                path = self.write('x/padded.sh', b'#!/bin/bash\n' + pad + b'\n' + last)
                started = time.monotonic()
                with self.subTest(count=count, last=last):
                    if len(pad) < 262144 or last is read:  # past 256 KiB the log rule does not read the file, on main too
                        self.assertRefused('bash %s' % path)
                    self.assertLess(time.monotonic() - started, cg.CREDENTIAL_SCRIPT_SECONDS + 2)

    def test_many_padded_scripts_cannot_use_up_the_time_limit(self):
        pad = b'#!/bin/bash\n' + b'rclone -a ' * 100000 + b'\n'
        names = ['x/p%d.sh' % i for i in range(7)]  # main reads at most 8 scripts per command
        scripts = [self.write(name, pad) for name in names]
        clean = self.write('x/clean.sh', b'#!/bin/bash\nrm -rf ~/.claude/projects\n')
        started = time.monotonic()
        self.assertRefused('; '.join('bash %s' % p for p in scripts + [clean]))
        self.assertLess(time.monotonic() - started, cg.CREDENTIAL_SCRIPT_SECONDS + 2)

    def test_the_check_failing_changes_nothing_else(self):
        clean = self.write('x/clean.sh', b'#!/bin/bash\nrm -rf ~/.claude/projects\n')
        plain = self.write('x/plain.sh', b'#!/bin/bash\necho hello\n')
        with mock.patch.object(cg.Analyzer, 'credential_script', side_effect=RuntimeError('boom')):
            self.assertRefused('bash %s' % clean)
            self.assertAllowed('bash %s' % plain)

    def test_copies_of_the_config_are_a_stated_gap(self):
        """Refused only by the later hardening change. This fails when that lands, so the docs get updated with it."""
        for command in ('cp -r ~/.config/rclone /backup/x', 'cp ~/.config/rclone/rclone.conf /backup/x',
                        'rsync -a ~/.config/rclone/ t2-dev:.config/rclone/'):
            with self.subTest(command=command):
                self.assertAllowed(command)

    def test_the_credential_file_stays_refused_directly(self):
        conf = self.home / '.config/rclone/rclone.conf'
        self.assertRefused('cat %s' % conf)
        self.assertRefused('gcloud secrets versions access latest --secret=GOODQA_CLOUDFLARE_API_TOKEN')

    def test_controls_stay_allowed(self):
        plain = self.write('x/plain.sh', b'#!/bin/bash\necho hello\n')
        plain_py = self.write('x/plain.py', b'print("hello")\n')
        named = self.write('x/named.sh', b'#!/bin/bash\nconf=~/.config/rclone/rclone.conf\n')
        binary = self.write('bin/tool', b'\x7fELF\x00\x00 .config/rclone/rclone.conf GOODQA_CLOUDFLARE_API_TOKEN')
        shebinary = self.write('bin/tool.sh', b'#!/bin/sh\n\x00.config/rclone/rclone.conf\n')
        for command in ('bash %s' % plain, 'python3 %s' % plain_py, '%s --version' % binary, str(shebinary), 'cat %s' % named,
                        'grep -c rclone %s' % named, 'shasum -a 256 %s' % named, 'python3 -m unittest tests.test_x',
                        'rclone listremotes', 'ls %s' % named.parent):
            with self.subTest(command=command):
                self.assertAllowed(command)

    def test_the_guard_may_run_itself(self):
        self.assertNotEqual(self.verdict('python3 %s --help' % cg.__file__), 'block')

    def test_a_script_past_the_read_limit_is_not_read(self):
        """Documents the text-only limit, so a change to it is a decision rather than an accident."""
        far = self.write('x/far.py', b'#' * cg.CREDENTIAL_SCRIPT_READ + b'\n.config/rclone/rclone.conf\n')
        self.assertAllowed('python3 %s' % far)


class TableTests(unittest.TestCase):
    def test_the_table_is_exactly_these_two_pins(self):
        self.assertEqual([(r[0], r[1]) for r in cg.PINNED_ROUTES], [
            (SH_REL, '92438a47d6b8083266e42922a2d151d0d0d65475fcc20744ea54359f2af501f3'),
            (PY_REL, '30c688923554c09f93128a7d9b89831557acd06d1f04949c235b09ea05cf89a6'),
        ])

    def test_expiry_is_fixed(self):
        self.assertEqual(time_string(cg.PINNED_ROUTE_EXPIRES), '2026-11-09T00:00:00Z')



def time_string(epoch):
    import time as _time
    return _time.strftime('%Y-%m-%dT%H:%M:%SZ', _time.gmtime(epoch))


if __name__ == '__main__':
    unittest.main()
