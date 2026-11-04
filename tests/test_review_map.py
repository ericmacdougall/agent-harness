"""review_map.py: offline structure, attribution, redaction, injection and attach behavior."""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import review_map as rm  # noqa: E402

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
BAD_SUBJECT = "feat(x): </script><script>alert(1)</script>"


def sh(repo, *args, env=None):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="T", GIT_AUTHOR_EMAIL="t@example.com",
                            GIT_COMMITTER_NAME="T", GIT_COMMITTER_EMAIL="t@example.com", **(env or {})))


def make_repo(root: Path) -> list:
    repo = root / "repo"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("base\n")
    sh(repo, "add", "."); sh(repo, "commit", "-qm", "chore(x): base\n\nRefs: none (test)")
    sh(repo, "checkout", "-q", "-b", "feat/review-map-demo")
    (repo / "src").mkdir()
    (repo / "src" / "ledger.py").write_text("def apply(balance, amount):\n    return balance + amount\n")
    (repo / 'a"onmouseover=x.txt').write_text("hello\n")
    sh(repo, "add", "."); sh(repo, "commit", "-qm", BAD_SUBJECT + "\n\nWhy: ledger apply lets a negative amount through.\n"
       f"What: add apply with token {TOKEN} and mail dev@example.org.\nTesting: not run: demo\n"
       "Risk: precision loss when amount is a float.\nRefs: GoodQA goodqa#14388")
    first = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    (repo / "src" / "ledger.py").write_text("def apply(balance, amount):\n    if amount < 0:\n        raise ValueError(amount)\n    return balance + amount\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_ledger.py").write_text("def test_negative():\n    pass  # NEG-1\n")
    sh(repo, "add", "."); sh(repo, "commit", "-qm", "fix(x): reject negative amount found in red-team review\n\n"
       "Why: red-team finding 1 negative amount accepted by apply.\nWhat: raise ValueError.\nTesting: ok\nRefs: GoodQA goodqa#14388")
    second = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    return [repo, first, second]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo, self.first, self.second = make_repo(root)
        self.work = root / "work"; self.work.mkdir()
        self.wals = root / "wals"; (self.wals / "s1").mkdir(parents=True)
        self.out = root / "out"
        (self.work / "spec.md").write_text(
            "# Spec: demo\n\nTicket: GoodQA goodqa#14388\nAuthor: a\nClick-test: required\nSign-off: main\n\n## Outcome\n\nx\n\n"
            "## Scope\n\n- In: a.\n\n## Acceptance criteria\n\n- AC-1: rejects negatives. Verify by: test.\n\n"
            "## Negative cases\n\n- NEG-1 (AC-1): negative amount in apply must raise.\n- NEG-2 (AC-1): float amount loses precision.\n\n"
            "## Risks\n\n- ledger drift: add invariant.\n")
        (self.work / "report.md").write_text(
            f"Reviewer: native\nStage: code-inspection\nReviewed HEAD: {self.first}\nReviewed packet SHA-256: 0\n\n"
            "1. HIGH negative amount accepted by apply in src/ledger.py\n2. low naming nit in ledger module\nCODE_INSPECTION_RESULT: BLOCK\n")
        (self.work / "other-pr.md").write_text("Reviewed HEAD: " + "b" * 40 + "\n1. HIGH unrelated finding from another PR here\nVERDICT: BLOCK\n")
        (self.wals / "s1" / "main.jsonl").write_text(
            json.dumps({"at": "2026-11-04T00:00:00+00:00", "event": "decision", "note": f"chose strict apply at {self.first[:8]} for goodqa#14388"}) + "\n" +
            json.dumps({"at": "2026-11-04T00:01:00+00:00", "event": "decision", "note": "unrelated decision for goodqa#14388999 and feat/other"}) + "\n" +
            json.dumps({"at": "2026-11-04T00:02:00+00:00", "event": "status", "note": "PENDING_REAL_TEST X1: demo"}) + "\n")

    def generate(self, extra=()):
        buf = io.StringIO()
        with mock.patch.object(rm, "wal_root", return_value=self.wals), mock.patch.object(rm, "work_root", return_value=self.work), \
                contextlib.redirect_stdout(buf):
            code = rm.main(["generate", "--repo", str(self.repo), "--branch", "feat/review-map-demo", "--no-gh",
                            "--out-dir", str(self.out), *extra])
        return code, json.loads(buf.getvalue())


class GenerateTests(Base):
    def test_sections_sources_and_privacy(self):
        code, result = self.generate()
        self.assertEqual(code, 0, result)
        path = Path(result["path"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        page = path.read_text()
        for section in ("id=map", "id=why", "id=edges", "id=refine", "id=next", "id=prompts"):
            self.assertIn(section, page)
        self.assertGreaterEqual(result["counts"]["edges"], 3)       # NEG-1, NEG-2, risk, finding, commit risk
        self.assertGreaterEqual(result["counts"]["refinements"], 1)
        self.assertIn("NEG-1", page)
        self.assertIn("test_ledger.py", page)                        # refinement links the test file
        self.assertIn("ledger apply lets a negative amount through", page)
        self.assertIn("chose strict apply", page)                    # WAL decision attributed by SHA
        self.assertNotIn("unrelated finding", page)                  # NEG-7: other PR's report
        self.assertNotIn("14388999", page)                           # ticket-number prefix collision
        self.assertNotIn("feat/other", page)
        self.assertIn("goodqa#14388", " ".join(result["tickets"]))

    def test_no_external_reference_and_hash_pinned_script(self):
        page = Path(self.generate()[1]["path"]).read_text()
        self.assertIsNone(re.search(r"(?i)\b(?:src|href|action)\s*=\s*[\"']?(?:https?:|//|javascript:|data:)", page))
        self.assertNotIn("http://", page.replace("http://www.w3.org", ""))
        script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
        import base64, hashlib
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{digest}'", page)
        self.assertIn("default-src 'none'", page)
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write"):
            self.assertNotIn(banned, script)

    def test_redaction_failing_control(self):
        page = Path(self.generate()[1]["path"]).read_text()
        self.assertNotIn(TOKEN, page)
        self.assertNotIn("dev@example.org", page)
        self.assertNotIn("/Users/", page)
        with self.assertRaises(rm.MapError):          # the independent verifier is not vacuous
            rm.assert_no_leak("x " + TOKEN)
        for planted in ("npm_" + "a" * 36, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcd1234", "-----BEGIN RSA PRIVATE KEY-----",
                        "u@example.com", "/Users/alice/x", "A1b2C3d4" * 6):
            with self.assertRaises(rm.MapError, msg=planted):
                rm.assert_no_leak(planted)

    def test_html_injection_is_inert(self):
        page = Path(self.generate()[1]["path"]).read_text()
        self.assertNotIn("</script><script>alert(1)", page)
        self.assertEqual(page.count("<script>"), 1)
        self.assertNotIn('"onmouseover=', page.replace("&quot;onmouseover=", ""))
        self.assertIn("&lt;/script&gt;", page)

    def test_missing_sources_still_builds(self):
        empty = Path(self.tmp.name) / "empty"; empty.mkdir()
        with mock.patch.object(rm, "wal_root", return_value=empty), mock.patch.object(rm, "work_root", return_value=empty):
            model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False)
        page = rm.render(model)
        self.assertNotIn("negative amount in apply must raise", page)
        self.assertIn("Write the spec", page)

    def test_deterministic_bytes(self):
        a = Path(self.generate()[1]["path"]).read_bytes()
        b = Path(self.generate()[1]["path"]).read_bytes()
        self.assertEqual(a, b)

    def test_invalid_inputs_refused(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rm.main(["generate", "--repo", str(self.repo), "--branch=-evil", "--no-gh"]), 2)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                rm.main(["generate", "--repo", str(self.repo), "--pr", "1;id"])

    def test_large_diff_is_bounded(self):
        for i in range(12):
            (self.repo / f"f{i}.txt").write_text("x\n" * (i + 1))
        sh(self.repo, "add", "."); sh(self.repo, "commit", "-qm", "chore(x): many files\n\nRefs: none (test)")
        with mock.patch.object(rm, "MAX_FILES_DETAIL", 5):
            code, result = self.generate()
        self.assertEqual(code, 0)
        self.assertIn("Diff detail truncated", Path(result["path"]).read_text())

    def test_symlinked_output_dir_refused(self):
        real = Path(self.tmp.name) / "real"; real.mkdir()
        link = Path(self.tmp.name) / "link"; link.symlink_to(real)
        with contextlib.redirect_stdout(io.StringIO()):
            code = rm.main(["generate", "--repo", str(self.repo), "--branch", "feat/review-map-demo", "--no-gh", "--out-dir", str(link)])
        self.assertNotEqual(code, 0)


class AttachTests(Base):
    def test_requires_confirmation_and_checks_integrity(self):
        _, result = self.generate()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rm.main(["attach", "--map", result["path"]]), 2)          # no --yes
            Path(result["path"]).write_text(Path(result["path"]).read_text() + "tamper")
            self.assertEqual(rm.main(["attach", "--map", result["path"], "--yes"]), 3)  # sha mismatch

    def test_unreachable_project_reported_and_dry_run(self):
        _, result = self.generate()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = rm.main(["attach", "--map", result["path"], "--ticket", "GoodQA harness#5", "--yes"])
        self.assertEqual(code, 6)
        self.assertEqual(json.loads(buf.getvalue())["results"][0]["status"], "UNREACHABLE")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(rm.main(["attach", "--map", result["path"], "--dry-run"]), 0)
        self.assertEqual(json.loads(buf.getvalue())["results"][0]["status"], "DRY_RUN")

    def test_attach_uploads_once_with_fake_adapter(self):
        _, result = self.generate()
        posted, store = [], []

        class Adapter:
            def all_comments(self, _id): return list(store)
            def upload(self, project_id, name, mime, data, digest): posted.append(("upload", name, mime)); return "att1"
            def comment_with_files(self, issue, body, op, ids):
                posted.append(("comment", body, ids)); store.append({"id": "c1", "body": body}); return {"id": "c1"}

        class Ticket: id = "i1"

        class FakeSession:
            def __init__(self, ref, policy): self.adapter, self.ticket, self.project_id = Adapter(), Ticket(), "p1"

        import spec_flow
        outputs = []
        for _ in range(2):
            buf = io.StringIO()
            with mock.patch.object(spec_flow, "Session", FakeSession), contextlib.redirect_stdout(buf):
                rm.main(["attach", "--map", result["path"], "--yes"])
            outputs.append(json.loads(buf.getvalue())["results"][0]["status"])
        self.assertEqual(outputs, ["ATTACHED", "ALREADY_ATTACHED"])
        self.assertEqual(len([p for p in posted if p[0] == "upload"]), 1)
        self.assertIn(result["sha256"], posted[1][1])
        self.assertEqual(posted[0][2], "text/html")


class ReviewFindingsRegressions(Base):
    """Findings from the code-inspection of d585b1a, each with a failing control."""

    def gh_run(self, state="OPEN", extra_commits=(), head=None):
        real = rm.run

        def fake(argv, cwd=None, timeout=60, limit=800000):
            if argv[0] == "gh":
                shas = [self.first, self.second, *extra_commits]
                data = {"title": "t", "state": state, "url": "u", "baseRefName": "main", "headRefName": "feat/review-map-demo",
                        "headRefOid": head or self.second, "body": "Refs: GoodQA otherproj#9", "isDraft": True,
                        "commits": [{"oid": s} for s in shas], "statusCheckRollup": []}
                return 0, json.dumps(data)
            return real(argv, cwd=cwd, timeout=timeout, limit=limit)
        return fake

    def model(self, **kw):
        with mock.patch.object(rm, "run", self.gh_run(**kw)), mock.patch.object(rm, "wal_root", return_value=self.wals), \
                mock.patch.object(rm, "work_root", return_value=self.work):
            return rm.build_model(self.repo, 5, None)

    def test_f1_pr_body_never_names_attach_targets(self):
        model = self.model()
        self.assertEqual(model["tickets"], ["GoodQA goodqa#14388"])
        self.assertNotIn("otherproj", " ".join(model["tickets"]))

    def test_f2_branch_only_match_needs_exact_boundary(self):
        (self.work / "elsewhere.md").write_text("review of feat/review-map-demo-2 in another repo\n1. HIGH other repo finding that must not leak in\nVERDICT: BLOCK\n")
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        self.assertNotIn("other repo finding", json.dumps(model["reports"]))

    def test_f3_partial_pr_is_warned(self):
        model = self.model(extra_commits=("c" * 40,))
        self.assertTrue(any("not available locally" in w for w in model["meta"]["warnings"]))
        self.assertIn("Warning:", rm.render(model))
        model = self.model(head=self.first)
        self.assertTrue(any("not the PR head" in w for w in model["meta"]["warnings"]))

    def test_f4_long_identifiers_are_redacted_not_fatal(self):
        blob = "Zk9" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5"
        (self.repo / "go.sum").write_text(f"mod v1 h1:{blob}\n")
        sh(self.repo, "add", "."); sh(self.repo, "commit", "-qm", "chore(x): lockfile\n\nRefs: none (test)")
        code, result = self.generate()
        self.assertEqual(code, 0, result)
        self.assertNotIn(blob, Path(result["path"]).read_text())

    def test_f5_attach_is_bound_to_reviewed_bytes(self):
        _, result = self.generate()
        meta = Path(result["path"]).with_suffix(".meta.json")
        meta.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rm.main(["attach", "--map", result["path"], "--yes", "--ticket", "GoodQA goodqa#14388"]), 2)
            self.assertEqual(rm.main(["attach", "--map", result["path"], "--yes", "--ticket", "GoodQA goodqa#14388",
                                      "--expect-sha256", "0" * 64]), 3)

    def test_f7_stale_report_is_marked(self):
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        self.assertTrue(any("stale" in row["basis"] for row in model["refinements"]))


class RedTeamRegressions(Base):
    def test_r1_scan_truncation_is_disclosed(self):
        with mock.patch.object(rm, "MAX_SCAN", 1), mock.patch.object(rm, "wal_root", return_value=self.wals):
            model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        self.assertTrue(any("scan stopped" in w for w in model["meta"]["warnings"]))

    def test_r2_very_long_line_is_bounded(self):
        import time
        start = time.time()
        out = rm.scrub("a" * 200000)
        self.assertLess(time.time() - start, 5)
        self.assertIn("line truncated", out)

    def test_r3_control_character_split_secret_is_redacted(self):
        split = "sk-abcdefgh\u202eijklmnopqrstuv"
        self.assertNotIn("abcdefgh", rm.scrub(split))
        rm.assert_no_leak(rm.scrub(split))

    def test_r4_other_repo_report_naming_branch_is_not_attributed(self):
        (self.work / "other-repo-review.md").write_text("review of feat/review-map-demo in another repo\n1. HIGH leaked other repo finding text\nVERDICT: BLOCK\n")
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        self.assertNotIn("leaked other repo finding", json.dumps(model["reports"]))

    def test_r5_hostile_filenames_keep_their_hunks(self):
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        quoted = [f for f in model["diff"]["files"] if '"' in f["path"]]
        self.assertTrue(quoted)
        self.assertTrue(quoted[0]["hunks"], "hunks must not vanish for names git quotes")


class InspectionTwoRegressions(Base):
    def test_f1_wal_branch_only_note_is_not_attributed(self):
        (self.wals / "s1" / "main.jsonl").write_text(json.dumps({"at": "2026-11-04T00:00:00+00:00", "event": "decision",
            "note": "other repo decision on feat/review-map-demo about secret plans"}) + "\n")
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work])
        self.assertEqual([w for w in model["wal"] if "secret plans" in w["note"]], [])

    def test_f3_f4_rename_keeps_new_path_and_hunks(self):
        sh(self.repo, "mv", "src/ledger.py", "src/ledger2.py")
        (self.repo / "src" / "ledger2.py").write_text((self.repo / "src" / "ledger2.py").read_text() + "# moved\n")
        sh(self.repo, "add", "."); sh(self.repo, "commit", "-qm", "refactor(x): rename\n\nRefs: none (test)")
        model = rm.build_model(self.repo, None, "feat/review-map-demo", use_gh=False, roots=[self.work], wal=False)
        paths = [f["path"] for f in model["diff"]["files"]]
        self.assertIn("src/ledger2.py", paths)
        self.assertTrue(all(p for p in paths))

    def test_f3_bad_range_fails_loudly(self):
        with self.assertRaises(rm.MapError):
            rm.collect_diff(self.repo, "f" * 40, "e" * 40)


class DeepJsonTests(unittest.TestCase):
    def test_deep_nesting_is_refused_not_crashed(self):
        deep = "[" * 5000 + "]" * 5000
        with self.assertRaises(ValueError):
            rm.safe_json_loads(deep)
        self.assertEqual(rm.safe_json_loads('{"a": ["]"]}'), {"a": ["]"]})
        code = ("import sys; sys.path.insert(0, %r); import review_map as rm\n"
                "try:\n    rm.safe_json_loads('{\"a\":' * 20000 + '1' + '}' * 20000)\nexcept ValueError:\n    print('refused')\n") % str(HOOKS)
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "refused"))

    def test_wal_line_with_deep_nesting_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            wals = Path(tmp) / "s"; wals.mkdir()
            (wals / "main.jsonl").write_text('{"note": "x", "event": "decision", "x": ' + "[" * 5000 + "]" * 5000 + "}\n")
            with mock.patch.object(rm, "wal_root", return_value=Path(tmp)):
                self.assertEqual(rm.find_wal(["a" * 40], "feat/some-branch", ["GoodQA goodqa#1"], 0, 0), [])


if __name__ == "__main__":
    unittest.main()
