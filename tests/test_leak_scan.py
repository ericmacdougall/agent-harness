"""Leak scanner and local policy profile (GoodQA #14538). Failing-first: these fail before scripts/leak_scan.py exists."""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
SCAN = ROOT / "scripts" / "leak_scan.py"
# Built at runtime so this file itself carries no real-looking token.
FAKE_GH = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def run_scan(files: dict, denylist: str | None = None, extra=()):
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for name, text in files.items():
            (repo / name).write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        cmd = [sys.executable, str(SCAN), "--repo", str(repo), *extra]
        if denylist is not None:
            deny = Path(tmp) / "deny.txt"
            deny.write_text(denylist, encoding="utf-8")
            cmd += ["--denylist", str(deny)]
        else:  # a rule that matches nothing: the denylist must exist and be non-empty (review F1)
            deny = Path(tmp) / "deny.txt"
            deny.write_text("zzz-never-matches-zzz\n", encoding="utf-8")
            cmd += ["--denylist", str(deny)]
        done = subprocess.run(cmd, capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr


class LeakScan(unittest.TestCase):
    def test_clean_repo_passes(self):
        code, out = run_scan({"a.md": "hello /Users/someone/x and a@example.invalid\n"})
        self.assertEqual(code, 0, out)

    def test_token_fails_without_echoing_secret(self):
        code, out = run_scan({"a.txt": f"token={FAKE_GH}\n"})
        self.assertEqual(code, 1, out)
        self.assertIn("a.txt:1", out)
        self.assertNotIn(FAKE_GH, out)

    def test_real_home_path_fails_but_placeholder_passes(self):
        self.assertEqual(run_scan({"a.md": "/Users/" + "jdoe/.claude\n"})[0], 1)
        self.assertEqual(run_scan({"a.md": "/home/" + "runner/work\n"})[0], 0)

    def test_denylist_blocks_and_is_not_echoed(self):
        code, out = run_scan({"a.md": "our customer Zorblax\n"}, denylist="# comment\n(?i)zorblax\n")
        self.assertEqual(code, 1, out)
        self.assertNotIn("Zorblax", out)

    def test_private_ip_and_tailnet_fail(self):
        self.assertEqual(run_scan({"a": "version 100." + "101.2\n"})[0], 0)  # three octets: not an address
        self.assertEqual(run_scan({"a": "host 100." + "101.2.4\n"})[0], 1)
        self.assertEqual(run_scan({"a": "box." + "tail1234.ts" + ".net\n"})[0], 1)
        # the whole RFC 6598 block fails; the edges just outside pass
        for ip, want in ((("100", "64", "0", "1"), 1), (("100", "127", "255", "254"), 1),
                       (("100", "63", "0", "1"), 0), (("100", "128", "0", "1"), 0)):
            ip = ".".join(ip)
            self.assertEqual(run_scan({"a": f"ip {ip}\n"})[0], want, "case")

    def test_zero_files_is_an_error_not_a_pass(self):
        code, out = run_scan({})
        self.assertEqual(code, 2, out)

    def test_history_mode_finds_removed_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*a): subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], check=True, capture_output=True)
            git("init", "-q")
            (repo / "a.txt").write_text(f"k={FAKE_GH}\n"); git("add", "-A"); git("commit", "-qm", "x")
            (repo / "a.txt").write_text("clean\n"); git("commit", "-qam", "y")
            (repo / "none").write_text("zzz-never-matches-zzz\n")  # untracked, so it is not scanned
            base = [sys.executable, str(SCAN), "--repo", str(repo), "--denylist", str(repo / "none")]
            self.assertEqual(subprocess.run(base, capture_output=True).returncode, 0)
            done = subprocess.run(base + ["--history"], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            self.assertNotIn(FAKE_GH, done.stdout + done.stderr)


class TrackedPolicyIsGeneric(unittest.TestCase):
    # Joined at runtime so this file itself holds none of the strings it forbids elsewhere.
    PERSONAL = tuple("".join(parts) for parts in (("frame", "bright"), ("goodqa-", "28dd3"), ("a19d", "343e"),
                                                  ("eric", "macdougall"), ("eric", "-org")))

    def test_local_overlay_sets_the_org_but_never_the_endpoint(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import ah
        import ah_local
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "local.json"
            local.write_text(json.dumps({"ticket_systems": {"goodqa": {
                "endpoint": "https://elsewhere.invalid/mcp", "org_id": "00000000-0000-4000-8000-00000000000a"}}}))
            with mock.patch.dict(os.environ, {"AH_LOCAL_CONFIG": str(local)}):
                ah_local.reset()
                try:
                    cfg = ah.goodqa_config()
                finally:
                    ah_local.reset()
        self.assertEqual(cfg["endpoint"], ah.GOODQA_TICKETS["endpoint"])
        self.assertEqual(cfg["org_id"], "00000000-0000-4000-8000-00000000000a")

    def test_tracked_policy_has_no_personal_identifiers(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import ah  # the GoodQA defaults moved here from commit_policy.json in release 1001
        text = json.dumps(ah.GOODQA_TICKETS).lower()
        for needle in self.PERSONAL:
            self.assertNotIn(needle, text)





def make_git(tmp, files, allow=None):
    repo = Path(tmp) / "r"
    repo.mkdir()
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

    def g(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env)
    g("init", "-q", "-b", "main")
    for name, text in files.items():
        (repo / name).write_text(text, encoding="utf-8")
    if allow is not None:
        (repo / ".leakscan-allow").write_text(allow, encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "c")
    return repo, g


def scan_repo(repo, tmp, *extra):
    deny = Path(tmp) / "deny.txt"
    deny.write_text("zzz-never-matches-zzz\n", encoding="utf-8")
    done = subprocess.run([sys.executable, str(SCAN), "--repo", str(repo), "--denylist", str(deny), *extra],
                          capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def ip(*octets):
    return ".".join(octets)  # built at runtime so this file holds no address


class ReviewFindings(unittest.TestCase):
    """GoodQA #14538 code-inspection findings F1, F2, F4, F6."""

    def scan_with(self, repo, *args, env=None):
        return subprocess.run([sys.executable, str(SCAN), "--repo", str(repo), *args],
                              capture_output=True, text=True, env=env)

    def test_missing_explicit_denylist_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "hello\n"})
            done = self.scan_with(repo, "--denylist", str(Path(tmp) / "nope.txt"))
            self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_empty_denylist_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "hello\n"})
            (Path(tmp) / "d.txt").write_text("# only a comment\n\n")
            done = self.scan_with(repo, "--denylist", str(Path(tmp) / "d.txt"))
            self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_require_denylist_without_one_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "hello\n"})
            env = dict(os.environ, HOME=tmp)
            env.pop("AGENT_HARNESS_LEAK_DENYLIST", None)
            done = self.scan_with(repo, "--require-denylist", env=env)
            self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_allowlisted_file_still_fails_on_network_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"fx.txt": f"host {ip('100', '64', '0', '9')} {FAKE_GH}\n"}, allow="fx.txt\n")
            code, out = scan_repo(repo, tmp)
            self.assertEqual(code, 1, out)
            self.assertIn("private-ipv4", out)
            self.assertNotIn("github-token", out)  # token rules are the only ones the allowlist skips

    def test_added_line_starting_with_plus_plus_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "a.txt").write_text("ok\n++ host " + ip("100", "64", "0", "9") + "\n")
            g("commit", "-qam", "d")
            code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~1..HEAD")
            self.assertEqual(code, 1, out)

    def test_merge_resolution_content_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "base\n"})
            g("checkout", "-qb", "side")
            (repo / "a.txt").write_text("side\n")
            g("commit", "-qam", "s")
            g("checkout", "-q", "main")
            (repo / "a.txt").write_text("main\n")
            g("commit", "-qam", "m")
            subprocess.run(["git", "-C", str(repo), "merge", "-q", "side"], capture_output=True)
            (repo / "a.txt").write_text("resolved " + ip("100", "64", "0", "9") + "\n")
            g("commit", "-qam", "merge resolution")
            code, out = scan_repo(repo, tmp, "--history", "--range", "main~1..main")
            self.assertEqual(code, 1, out)

    def test_symlink_target_and_path_name_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "ok\n"})
            os.symlink("/Users/" + "realperson/secret", repo / "link")
            (repo / ("box." + "t1.ts" + ".net")).write_text("x\n")
            g("add", "-A")
            g("commit", "-qm", "l")
            code, out = scan_repo(repo, tmp)
            self.assertEqual(code, 1, out)
            self.assertIn("link:symlink", out)
            self.assertIn("path:", out)

    def test_skipped_files_make_the_scan_incomplete_not_clean(self):
        """Kimi audit F04 (goodqa#14999): a tracked file the tree scan could not read is not a pass."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "b.bin").write_bytes(b"\0\1\2")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            code, out = scan_repo(repo, tmp)
            self.assertEqual(code, 2, out)
            self.assertIn("skipped=1", out)
            self.assertIn("incomplete", out)
            (repo / "c.txt").write_text(FAKE_GH + "\n")  # findings still report as findings (exit 1)
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            self.assertEqual(scan_repo(repo, tmp)[0], 1)

    def test_history_binary_diff_is_counted_but_not_fatal(self):
        """History mode is unchanged: a committed binary blob is diffed as text (-a) and does not fail the run."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "b.bin").write_bytes(b"\0\1\2")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "commit", "-qm", "bin"], check=True)
            code, out = scan_repo(repo, tmp, "--history")
            self.assertEqual(code, 0, out)  # git log -a diffs the blob as text, so nothing is skipped or failed

    def test_tree_read_is_bounded_before_buffering(self):
        """audit2 F-018 (goodqa#14999): an oversized file is refused from fstat and never read whole."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("leak_scan_mod", SCAN)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.txt"
            big.write_bytes(b"a" * 5000)
            small = Path(tmp) / "small.txt"
            small.write_bytes(b"b" * 50)
            real_read, asked = os.read, []

            def counting_read(fd, n):
                asked.append(n)
                return real_read(fd, n)
            with mock.patch.object(mod, "MAX_BYTES", 100), mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read_bytes")), mock.patch.object(mod.os, "read", side_effect=counting_read):
                self.assertIsNone(mod.read_capped(big))
                self.assertEqual(asked, [], "an oversized file was read at all")
                self.assertEqual(mod.read_capped(small), b"b" * 50)
                self.assertTrue(asked and max(asked) <= 101, asked)

    def test_not_a_git_repo_is_exit_2_not_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = scan_repo(Path(tmp), tmp)
            self.assertEqual(code, 2, out)






class RoundTwoFindings(unittest.TestCase):
    """Second code-inspection round (GoodQA #14538): F1 merge walk, F2 PEM header, F3 path echo, F4 installed copy,
    F6 broad allowlist, F7 rename and binary, F8 ticket sub-keys."""

    def test_token_added_then_removed_on_merged_side_branch_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "base\n"})
            g("checkout", "-qb", "side")
            (repo / "s.txt").write_text(f"k={FAKE_GH}\n")
            g("add", "-A")
            g("commit", "-qm", "add token")
            g("rm", "-q", "s.txt")
            g("commit", "-qm", "remove token")
            g("checkout", "-q", "main")
            (repo / "m.txt").write_text("main work\n")
            g("add", "-A")
            g("commit", "-qm", "main")
            g("merge", "-q", "--no-ff", "-m", "merge side", "side")
            code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~2..HEAD")
            self.assertEqual(code, 1, out)
            self.assertNotIn(FAKE_GH, out)

    def test_multiline_pem_key_header_is_found_in_tree_and_history(self):
        pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "A" * 64 + "\n-----END " + "RSA PRIVATE KEY-----\n"
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "fixture.txt").write_text(pem)
            g("add", "-A")
            g("commit", "-qm", "key")
            self.assertEqual(scan_repo(repo, tmp)[0], 1)
            self.assertEqual(scan_repo(repo, tmp, "--history", "--range", "HEAD~1..HEAD")[0], 1)

    def test_a_path_that_matches_a_rule_is_never_printed(self):
        host = "box." + "t1.ts" + ".net"
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {host + ".txt": "x\n"})
            for extra in ((), ("--history",)):
                code, out = scan_repo(repo, tmp, *extra)
                self.assertEqual(code, 1, out)
                self.assertNotIn(host, out)
                self.assertIn("path#", out)

    def test_broad_allowlist_pattern_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "ok\n"}, allow="*\n")
            self.assertEqual(scan_repo(repo, tmp)[0], 2)

    def test_pure_rename_to_a_flagged_name_and_binary_are_handled(self):
        host = "box." + "t1.ts" + ".net"
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"plain.txt": "content that is long enough to be a rename\n" * 5})
            (repo / "b.bin").write_bytes(b"\0\1\2")
            g("add", "-A")
            g("commit", "-qm", "bin")
            g("mv", "plain.txt", host + ".txt")
            g("commit", "-qm", "rename")
            code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~2..HEAD")
            self.assertEqual(code, 1, out)
            self.assertNotIn(host, out)
            self.assertIn("skipped=0", out)  # binary diffs are scanned as text (-a), not skipped




class RoundThreeFindings(unittest.TestCase):
    """Native round-3 review (GoodQA #14538): H1 line breaks, H2 migration, H3 metadata, M1-M5."""

    def test_unicode_and_control_line_breaks_do_not_hide_added_content(self):
        for sep in ("\r", "\x0c", "\x0b", "\x85", "\u2028"):
            with tempfile.TemporaryDirectory() as tmp:
                repo, g = make_git(tmp, {"a.txt": "ok\n"})
                (repo / "a.txt").write_text("ok\nhello" + sep + "host " + ip("100", "64", "0", "9") + "\n")
                g("commit", "-qam", "d")
                g("rm", "-q", "a.txt")
                g("commit", "-qm", "gone")
                code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~2..HEAD")
                self.assertEqual(code, 1, (repr(sep), out))

    def test_commit_message_and_author_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, g = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "a.txt").write_text("two\n")
            g("commit", "-qam", "Testing: ran in /Users/" + "realperson/x")
            code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~1..HEAD")
            self.assertEqual(code, 1, out)
            self.assertIn("commit-message", out)
            self.assertNotIn("realperson", out)

    def test_text_file_with_binary_suffix_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"creds.pdf": "k=" + FAKE_GH + "\n"})
            self.assertEqual(scan_repo(repo, tmp)[0], 1)

    def test_token_in_filename_is_not_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {FAKE_GH + ".txt": "x\n"})
            for extra in ((), ("--history",)):
                code, out = scan_repo(repo, tmp, *extra)
                self.assertEqual(code, 1, out)
                self.assertNotIn(FAKE_GH, out)

    def test_glob_allowlist_patterns_are_rejected(self):
        for pattern in ("[!z]*", "tests/*", "a?.txt"):
            with tempfile.TemporaryDirectory() as tmp:
                repo, _ = make_git(tmp, {"a.txt": "ok\n"}, allow=pattern + "\n")
                self.assertEqual(scan_repo(repo, tmp)[0], 2, pattern)



class RoundFourFindings(unittest.TestCase):
    """B1 delimiter smuggling, B2 non-dict projects, L5 migration route filter."""

    def test_x01_byte_in_message_or_author_does_not_hide_metadata(self):
        home = "/Users/" + "realperson/x"
        for where in ("message", "author"):
            with tempfile.TemporaryDirectory() as tmp:
                repo, g = make_git(tmp, {"a.txt": "ok\n"})
                (repo / "a.txt").write_text("two\n")
                env = dict(os.environ, GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_EMAIL="t@example.invalid",
                           GIT_COMMITTER_NAME="t", GIT_AUTHOR_NAME="t")
                msg = "subject"
                if where == "message":
                    msg = "subject\x01 " + home
                else:
                    env["GIT_AUTHOR_NAME"] = "n\x01 " + home
                subprocess.run(["git", "-C", str(repo), "commit", "-qam", msg], check=True, capture_output=True, env=env)
                code, out = scan_repo(repo, tmp, "--history", "--range", "HEAD~1..HEAD")
                self.assertEqual(code, 1, (where, out))
                self.assertNotIn("realperson", out)



class CodexInstallKeepsEnforcement(unittest.TestCase):
    """Native review F1: install_codex copied the generic policies over a host's personal values."""

if __name__ == "__main__":
    unittest.main()
