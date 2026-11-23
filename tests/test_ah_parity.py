"""ah_parity: installed hooks versus canonical main (self-serve spec AC-11, AC-12, AC-13 doctor side, AC-14; NEG-11, NEG-12).

Fixtures only: a local bare repository stands in for the canonical URL, every HOME is a temp directory, and the
"remote host" is the same constant program run through a fake ssh runner under another temp HOME. No network, no ssh.
Set AH_PARITY_MUTANT_DIR to run the suite against a broken copy of the module (failing-first evidence).
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.environ.get("AH_PARITY_MUTANT_DIR") or str(ROOT / "harness" / "hooks"))
import ah_parity  # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
CLAUDE_NAMES = ("ah.py", "merge_gate.py", "ah_parity.py")
CODEX_NAMES = ("ah.py", "merge_gate.py")
FILES = {"ah.py": b"print('ah')\n", "merge_gate.py": b"print('gate')\n", "ah_parity.py": b"print('parity')\n"}


def git(cwd, *args):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, capture_output=True, text=True, env=env).stdout.strip()


def sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class Fixture:
    """A canonical bare repo plus an installed Claude and Codex tree under a temp HOME."""

    def __init__(self, test):
        self.tmp = Path(tempfile.mkdtemp(prefix="parity-test-"))
        test.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)]))
        work = self.tmp / "work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        (work / "harness" / "hooks").mkdir(parents=True)
        (work / "install.py").write_text("HOOKS = %r\n" % (CLAUDE_NAMES,))
        (work / "install_codex.py").write_text("DELIVERY_HELPERS = %r\n" % (CODEX_NAMES,))
        for n, b in FILES.items():
            (work / "harness" / "hooks" / n).write_bytes(b)
        git(work, "add", "-A")
        git(work, "commit", "-q", "-m", "first")
        self.first = git(work, "rev-parse", "HEAD")
        (work / "harness" / "hooks" / "ah.py").write_bytes(b"print('ah v2')\n")
        git(work, "commit", "-q", "-am", "second")
        self.second = git(work, "rev-parse", "HEAD")
        self.bare = self.tmp / "canonical.git"
        git(self.tmp, "clone", "-q", "--bare", str(work), str(self.bare))
        self.url = "file://" + str(self.bare)
        self.files = dict(FILES, **{"ah.py": b"print('ah v2')\n"})
        self.home = self.install(self.tmp / "home-mac")
        self.remote_home = self.install(self.tmp / "home-remote")
        ah_parity.ALLOW_FILE = True
        test.addCleanup(setattr, ah_parity, "ALLOW_FILE", False)

    def install(self, home, codex=True):
        for rel, names in ((ah_parity.CLAUDE_DIR, CLAUDE_NAMES), (ah_parity.CODEX_DIR, CODEX_NAMES if codex else ())):
            d = home.joinpath(*rel)
            d.mkdir(parents=True, exist_ok=True)
            for n in names:
                (d / n).write_bytes(self.files[n])
        return home

    def claude(self, home, name):
        return home.joinpath(*ah_parity.CLAUDE_DIR, name)

    def runner(self, home=None, rc=0, record=None):
        """A fake ssh: run the piped program with `python3 -I -` under another HOME, exactly what ssh would run."""
        home = home or self.remote_home

        def run(argv, stdin=None, timeout=None):
            if record is not None:
                record.append((list(argv), stdin))
            if rc:
                return rc, "", "Connection refused"
            assert argv[0] == "ssh" and argv[-3:] == ["python3", "-I", "-"], argv
            p = subprocess.run([sys.executable, "-I", "-"], input=stdin, capture_output=True, text=True,
                               env={"HOME": str(home), "PATH": os.environ.get("PATH", "")})
            return p.returncode, p.stdout, p.stderr
        return run

    def verify(self, hosts=("mac",), ref=None, runner=None):
        return ah_parity.verify(hosts, ref, self.home, runner or self.runner(), self.url)


class Drift(unittest.TestCase):
    def test_clean_mac_is_clean(self):
        f = Fixture(self)
        r = f.verify()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["mac"]["claude"]["ok"], 3)  # non-vacuous: the hooks were really compared
        self.assertEqual(r["hosts"]["mac"]["codex"]["ok"], 2)
        self.assertEqual(r["ref"], f.second)

    def test_edited_installed_hook_is_reported_ac11(self):
        f = Fixture(self)
        f.claude(f.home, "merge_gate.py").write_bytes(b"print('tampered')\n")
        r = f.verify()
        self.assertFalse(r["ok"])
        v = r["hosts"]["mac"]
        self.assertEqual(v["status"], "DRIFT")
        self.assertEqual(v["claude"]["differ"], ["merge_gate.py"])
        self.assertEqual(ah_parity.exit_code(r), 1)

    def test_missing_hook_and_symlink_are_drift(self):
        f = Fixture(self)
        f.claude(f.home, "ah_parity.py").unlink()
        gate = f.claude(f.home, "merge_gate.py")
        gate.unlink()
        gate.symlink_to(f.tmp / "work" / "harness" / "hooks" / "merge_gate.py")  # right bytes, but a symlink
        v = f.verify()["hosts"]["mac"]
        self.assertEqual(v["claude"]["missing"], ["ah_parity.py"])
        self.assertEqual(v["claude"]["differ"], ["merge_gate.py"])

    def test_codex_copy_is_checked_and_absent_codex_is_not_drift(self):
        f = Fixture(self)
        f.home.joinpath(*ah_parity.CODEX_DIR, "ah.py").write_bytes(b"old\n")
        self.assertEqual(f.verify()["hosts"]["mac"]["codex"]["differ"], ["ah.py"])
        f2 = Fixture(self)
        subprocess.run(["rm", "-rf", str(f2.home.joinpath(*ah_parity.CODEX_DIR))])
        v = f2.verify()["hosts"]["mac"]
        self.assertEqual(v["status"], "CLEAN")
        self.assertFalse(v["codex"]["present"])

    def test_older_ancestor_ref_compares_against_that_commit(self):
        f = Fixture(self)
        self.assertEqual(f.verify(ref=f.first)["hosts"]["mac"]["claude"]["differ"], ["ah.py"])  # installed is v2

    def test_ref_not_on_main_is_unknown_not_clean(self):
        f = Fixture(self)
        stray = git(f.tmp / "work", "commit-tree", "-m", "x", f.second + "^{tree}")
        git(f.tmp / "work", "update-ref", "refs/heads/stray", stray)
        git(f.bare, "fetch", "-q", str(f.tmp / "work"), "stray:refs/heads/stray")
        r = f.verify(ref=stray)
        self.assertFalse(r["ok"])
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")
        self.assertEqual(ah_parity.exit_code(r), 3)
        self.assertEqual(f.verify(ref="HEAD")["hosts"]["mac"]["status"], "UNKNOWN")

    def test_canonical_unavailable_is_unknown_never_clean(self):
        f = Fixture(self)
        r = ah_parity.verify(("mac",), None, f.home, f.runner(), "file://" + str(f.tmp / "nope.git"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")
        self.assertEqual(ah_parity.exit_code(r), 3)


class Remote(unittest.TestCase):
    def test_remote_clean_and_drift(self):
        f = Fixture(self)
        self.assertTrue(f.verify(("mac", "t2-dev"))["ok"])
        f.claude(f.remote_home, "ah.py").write_bytes(b"stale\n")
        r = f.verify(("mac", "t2-dev"))
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["t2-dev"]["claude"]["differ"], ["ah.py"])
        self.assertFalse(r["ok"])

    def test_unreachable_remote_is_unknown_and_never_falls_back_to_local_neg12(self):
        f = Fixture(self)
        r = f.verify(("mac", "t2-dev"), runner=f.runner(rc=255))
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")
        self.assertFalse(r["ok"])
        self.assertEqual(ah_parity.exit_code(r), 3)

    def test_garbage_remote_output_is_unknown(self):
        f = Fixture(self)
        r = f.verify(("t2-dev",), runner=lambda a, s=None, t=None: (0, "not json\n", ""))
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")
        r = f.verify(("t2-dev",), runner=lambda a, s=None, t=None: (0, json.dumps({"claude": {}}) + "\n", ""))
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")

    def test_ssh_command_is_constant_and_names_travel_as_data(self):
        f = Fixture(self)
        rec = []
        f.verify(("t2-dev",), runner=f.runner(record=rec))
        argv, stdin = rec[0]
        self.assertEqual(argv, ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "t2-dev", "python3", "-I", "-"])
        self.assertTrue(all("merge_gate" not in a for a in argv))
        self.assertIn("merge_gate.py", stdin)
        self.assertEqual(ah_parity.main(["doctor", "--host", "mac", "--ref", "x;rm -rf /"], f.home, f.runner(), io.StringIO()), 3)

    def test_unknown_host_name_refused(self):
        f = Fixture(self)
        with self.assertRaises(ah_parity.ParityError):
            ah_parity.remote_collect("evil;host", {"claude": (), "codex": ()}, f.runner())


class Trust(unittest.TestCase):
    def codex_files(self, f):
        hooks = f.home / ".codex" / "hooks.json"
        cmds = ["python3 /x/a.py hook", "python3 /x/b.py hook", "python3 /x/c.py hook"]
        hooks.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": c, "timeout": 5}]} for c in cmds]}}))
        h0 = ah_parity.codex_hook_hash("pre_tool_use", None, {"type": "command", "command": cmds[0], "timeout": 5})
        conf = ('[hooks.state."%s:pre_tool_use:0:0"]\ntrusted_hash = "%s"\n\n[hooks.state."%s:pre_tool_use:1:0"]\n'
                'trusted_hash = "sha256:old"\n' % (hooks, h0, hooks))
        (f.home / ".codex" / "config.toml").write_text(conf)
        return hooks

    def test_untrusted_and_changed_hooks_are_listed_ac12(self):
        f = Fixture(self)
        self.codex_files(f)
        t = f.verify()["hosts"]["mac"]["trust"]
        self.assertEqual(t["untrusted"], ["pre_tool_use:2:0"])
        self.assertEqual(t["changed"], ["pre_tool_use:1:0"])
        self.assertEqual(ah_parity.exit_code(f.verify()), 0)
        self.assertEqual(ah_parity.exit_code(f.verify(), strict_trust=True), 1)

    def test_doctor_writes_nothing_neg11(self):
        f = Fixture(self)
        self.codex_files(f)

        def snapshot():
            return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in f.home.rglob("*") if p.is_file()}
        before = snapshot()
        ah_parity.main(["doctor", "--host", "mac"], f.home, f.runner(), io.StringIO())
        self.assertEqual(before, snapshot())
        src = Path(ah_parity.__file__).read_text()
        self.assertNotIn('"w"', src.replace('"w"),', ''))  # no write-mode open anywhere in the module

    def test_hash_algorithm_matches_ops_watch(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import ops_watch
        for matcher, handler in ((None, {"type": "command", "command": "c", "timeout": 3}),
                                 ("Bash", {"type": "command", "command": "d", "async": True, "extra": 1})):
            self.assertEqual(ah_parity.codex_hook_hash("stop", matcher, handler), ops_watch.codex_hook_hash("stop", matcher, handler))


class Probe(unittest.TestCase):
    def setup_home(self, f, rule=True, ah_body="import sys; sys.exit(0)\n"):
        (f.home / ".claude").mkdir(exist_ok=True)
        allow = ["Bash(python3 -I ~/.claude/hooks/ah.py ops *)"] if rule else ["Bash(ls *)"]
        (f.home / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": allow}}))
        f.claude(f.home, "ah.py").write_text(ah_body)

    @staticmethod
    def local(argv, stdin=None, timeout=None):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout, p.stderr

    def test_probe_passes_when_recipe_runs_in_dry_run(self):
        f = Fixture(self)
        self.setup_home(f)
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "PASS", r)

    def test_missing_allow_rule_is_a_limitation_with_p0_ticket_ac14(self):
        f = Fixture(self)
        self.setup_home(f, rule=False)
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "LIMITATION")
        self.assertEqual(r["ticket"]["priority"], "P0")

    def test_denied_recipe_is_a_limitation_not_a_pass(self):
        f = Fixture(self)
        self.setup_home(f, ah_body="import sys; sys.stderr.write('command_guard BLOCKED: x'); sys.exit(2)\n")
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "LIMITATION")
        self.assertIn("denied", r["reason"])

    def test_recipe_not_installed_yet_is_reported(self):
        f = Fixture(self)
        self.setup_home(f, ah_body="import sys; sys.stderr.write('invalid choice: ops'); sys.exit(2)\n")
        self.assertIn("not installed", ah_parity.probe(f.home, self.local)["reason"])

    def test_probe_runs_only_the_dry_run_recipe(self):
        f = Fixture(self)
        self.setup_home(f)
        seen = []
        ah_parity.probe(f.home, lambda a, s=None, t=None: (seen.append(a) or (0, "", "")))
        self.assertEqual(seen[0][-3:], ["ops", "repair", "--check"])
        self.assertNotIn("--apply", seen[0])

    def test_cli_probe_files_ticket_on_request(self):
        f = Fixture(self)
        self.setup_home(f, rule=False)
        calls = []
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)

        def runner(argv, stdin=None, timeout=None):
            calls.append(argv)
            if "ticket" in argv:
                return 0, "{}", ""
            return 0, "", ""
        buf = io.StringIO()
        code = ah_parity.main(["doctor", "--host", "mac", "--probe", "--file-ticket", "--json"], f.home, runner, buf)
        self.assertEqual(code, 1)  # the host is clean; the probe limitation alone makes the exit non-zero
        ticket_calls = [c for c in calls if "ticket" in c]
        self.assertEqual(len(ticket_calls), 1)
        self.assertEqual(ticket_calls[0][ticket_calls[0].index("--priority") + 1], "P0")
        self.assertTrue(json.loads(buf.getvalue())["probe"]["ticket_filed"])


class Cli(unittest.TestCase):
    def test_json_and_text_output_and_usage(self):
        f = Fixture(self)
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        buf = io.StringIO()
        self.assertEqual(ah_parity.main(["verify-parity", "--host", "mac", "--json"], f.home, f.runner(), buf), 0)
        self.assertEqual(json.loads(buf.getvalue())["hosts"]["mac"]["status"], "CLEAN")
        f.claude(f.home, "ah.py").write_bytes(b"x")
        buf = io.StringIO()
        self.assertEqual(ah_parity.main(["doctor", "--host", "mac"], f.home, f.runner(), buf), 1)
        self.assertIn("DIFFERS ah.py", buf.getvalue())
        self.assertEqual(ah_parity.main(["nonsense"], f.home, f.runner(), io.StringIO()), 2)


if __name__ == "__main__":
    unittest.main()
