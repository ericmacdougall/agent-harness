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

    def test_tracked_policy_has_no_personal_identifiers(self):
        text = (ROOT / "harness" / "hooks" / "commit_policy.json").read_text().lower()
        for needle in self.PERSONAL:
            self.assertNotIn(needle, text)

    @mock.patch.dict(os.environ, clear=False)
    def test_local_profile_overrides_and_merges(self):
        os.environ.pop("AGENT_HARNESS_POLICY_LOCAL", None)  # other modules set it; this test uses the sibling file
        import commit_policy as cp
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "commit_policy.json"
            base.write_text((ROOT / "harness" / "hooks" / "commit_policy.json").read_text())
            (Path(tmp) / "commit_policy.local.json").write_text(json.dumps(
                {"backstop_repos": ["example\\.invalid/"],
                 "ticket_systems": {"goodqa": {"org_id": "00000000-0000-4000-8000-000000000001"}}}))
            policy = cp.load_policy(base)
        self.assertEqual(policy["backstop_repos"], ["example\\.invalid/"])
        goodqa = policy["ticket_systems"]["goodqa"]
        self.assertEqual(goodqa["org_id"], "00000000-0000-4000-8000-000000000001")
        self.assertIn("ref_pattern", goodqa)  # deep merge keeps tracked keys

    @mock.patch.dict(os.environ, clear=False)
    def test_bad_local_profile_fails_closed(self):
        os.environ.pop("AGENT_HARNESS_POLICY_LOCAL", None)  # other modules set it; this test uses the sibling file
        import commit_policy as cp
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "commit_policy.json"
            base.write_text((ROOT / "harness" / "hooks" / "commit_policy.json").read_text())
            (Path(tmp) / "commit_policy.local.json").write_text("{not json")
            with self.assertRaises(ValueError):
                cp.load_policy(base)



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

    def test_skipped_files_are_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_git(tmp, {"a.txt": "ok\n"})
            (repo / "b.bin").write_bytes(b"\0\1\2")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            code, out = scan_repo(repo, tmp)
            self.assertEqual(code, 0, out)
            self.assertIn("skipped=1", out)

    def test_not_a_git_repo_is_exit_2_not_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = scan_repo(Path(tmp), tmp)
            self.assertEqual(code, 2, out)


class PolicyOverrideIsNotABypass(unittest.TestCase):
    """Review F3: a variable on one command line must not swap the enforcement profile."""

    def setUp(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import commit_policy
        self.cp = commit_policy
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.base = Path(self.tmp) / "commit_policy.json"
        self.base.write_text((ROOT / "harness" / "hooks" / "commit_policy.json").read_text())

    def test_override_outside_tests_data_is_ignored(self):
        outside = Path(self.tmp) / "evil.json"
        outside.write_text(json.dumps({"backstop_repos": ["attacker\\.invalid/"]}))
        with mock.patch.dict(os.environ, {"AGENT_HARNESS_POLICY_LOCAL": str(outside)}):
            policy = self.cp.load_policy(self.base)
        self.assertNotIn("attacker\\.invalid/", policy.get("backstop_repos", []))

    def test_profile_cannot_set_enforcement_keys(self):
        (Path(self.tmp) / "commit_policy.local.json").write_text(json.dumps({"enforcement": "off"}))
        with mock.patch.dict(os.environ):
            os.environ.pop("AGENT_HARNESS_POLICY_LOCAL", None)
            with self.assertRaises(ValueError):
                self.cp.load_policy(self.base)

    def test_override_inside_tests_data_is_honoured_and_missing_file_raises(self):
        fixture = ROOT / "tests" / "data" / "policy_profile_fixture.json"
        with mock.patch.dict(os.environ, {"AGENT_HARNESS_POLICY_LOCAL": str(fixture)}):
            self.assertTrue(self.cp.load_policy(self.base)["backstop_repos"])
        missing = ROOT / "tests" / "data" / "does_not_exist.json"
        with mock.patch.dict(os.environ, {"AGENT_HARNESS_POLICY_LOCAL": str(missing)}):
            with self.assertRaises(ValueError):
                self.cp.load_policy(self.base)


class SpecPolicyProfile(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import spec_flow
        self.sf = spec_flow
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.base = self.tmp / "spec_policy.json"
        self.base.write_text((ROOT / "harness" / "hooks" / "spec_policy.json").read_text())

    def test_tracked_spec_policy_names_no_projects(self):
        self.assertEqual(self.sf.load_spec_policy(self.base)["projects"], {})

    def test_local_profile_supplies_projects_and_bad_one_fails_closed(self):
        local = self.tmp / "spec_policy.local.json"
        local.write_text(json.dumps({"projects": {"demo": {"project_id": "p", "org_id": "o"}}}))
        self.assertIn("demo", self.sf.load_spec_policy(self.base)["projects"])
        local.write_text("{nope")
        with self.assertRaises(ValueError):
            self.sf.load_spec_policy(self.base)
        local.write_text(json.dumps({"mode": "off"}))  # cannot weaken enforcement
        with self.assertRaises(ValueError):
            self.sf.load_spec_policy(self.base)


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
            self.assertIn("skipped=1", out)

    def test_ticket_system_overlay_cannot_change_endpoint(self):
        import commit_policy as cp
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "commit_policy.json"
            base.write_text((ROOT / "harness" / "hooks" / "commit_policy.json").read_text())
            (Path(tmp) / "commit_policy.local.json").write_text(json.dumps(
                {"ticket_systems": {"goodqa": {"endpoint": "https://attacker.invalid/"}}}))
            with mock.patch.dict(os.environ):
                os.environ.pop("AGENT_HARNESS_POLICY_LOCAL", None)
                with self.assertRaises(ValueError):
                    cp.load_policy(base)

    def test_installed_copy_ignores_override_even_with_home_tests_data(self):
        """An agent can create ~/tests/data; the override must still do nothing on an installed copy."""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            hooks = home / ".claude" / "hooks"
            hooks.mkdir(parents=True)
            for name in ("commit_policy.py", "commit_policy.json", "safe_input.py"):
                (hooks / name).write_text((ROOT / "harness" / "hooks" / name).read_text())
            (home / "tests" / "data").mkdir(parents=True)
            evil = home / "tests" / "data" / "x.json"
            evil.write_text(json.dumps({"backstop_repos": ["attacker\\.invalid/"]}))
            code = ("import sys; sys.path.insert(0, %r); import commit_policy as cp; "
                    "print('attacker' in repr(cp.load_policy().get('backstop_repos')))" % str(hooks))
            done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                  env=dict(os.environ, HOME=str(home), AGENT_HARNESS_POLICY_LOCAL=str(evil)))
            self.assertEqual(done.stdout.strip(), "False", done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
