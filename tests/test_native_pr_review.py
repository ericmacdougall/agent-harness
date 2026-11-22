"""Native PR context and authorship controls against disposable local fixtures."""
import json
from pathlib import Path
import sys
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness/hooks"))
import native_pr_review as n

OWNER = "11111111-1111-4111-8111-111111111111"
ROOT_ID = "22222222-2222-4222-8222-222222222222"
ACCEPTANCE = "33333333-3333-4333-8333-333333333333"
ADVERSARIAL = "44444444-4444-4444-8444-444444444444"
WORKER = "55555555-5555-4555-8555-555555555555"
HEAD, BASE = "a" * 40, "b" * 40


def context():
    return {"version": 1, "repo": "fixture/project", "pr": 3, "head": HEAD, "base": BASE, "base_ref": "main",
            "head_ref": "codex/reviewed", "commits": [HEAD], "packet_sha256": "c" * 64, "tests_sha256": "d" * 64, "no_ci": True, "evidence_authors": [],
            "tickets": [{"ticket": "GoodQA fixture#3", "state": "in_review", "spec_core_sha": "2" * 64,
                         "review_sha256": "3" * 64, "evidence_sha256": "4" * 64, "release_records_sha256": "5" * 64, "missing": ["live proof pending"], "premerge_missing": []}]}


class NativeCallLiveness(TestCase):
    def setUp(self):
        from types import SimpleNamespace

        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.path = self.home / "disposable-native-transcript"
        self.command = "python3 /fixture/native_action.py --check"
        self.call = "call_fixture_a"
        self.tool = "exec-11111111-2222-3333-4444-555555555555"
        self.payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": ROOT_ID,
                        "tool_use_id": self.tool, "transcript_path": str(self.path)}
        self.header = self.row("session_meta", {"id": ROOT_ID, "session_id": ROOT_ID, "source": "vscode",
                                                "originator": "Codex Desktop", "thread_source": "user"})
        call_args = json.dumps({"cmd": self.command})
        self.pending = self.row("response_item", {"type": "custom_tool_call", "name": "exec", "call_id": self.call,
                                                 "input": f"text(await tools.exec_command({call_args}));"})
        self.write(self.header, self.pending)
        self.path.chmod(0o600)
        for patch in (mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.home))),
                      mock.patch.object(n, "_root_rollout", return_value=self.path)):
            patch.start()
            self.addCleanup(patch.stop)

    def row(self, kind, item):
        return {"timestamp": "2026-11-22T19:00:00Z", "type": kind, "payload": item}

    def write(self, *rows):
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def capture(self):
        binding = n.native_call_binding(self.payload, self.command)
        self.assertIsNotNone(binding)
        return binding

    def test_native_call_matches_actual_closed_tool_serialization(self):
        binding = self.capture()
        self.assertTrue(n.native_call_still_running(binding, match_command=lambda cmd: cmd == self.command))
        self.assertFalse(n.native_call_still_running(binding, match_command=lambda cmd: cmd == "other"))
        self.assertIsNone(n.native_call_binding(self.payload, "other command"))
        self.assertIsNone(n.native_call_binding(dict(self.payload, tool_use_id="call_unbound"), self.command))
        self.assertIsNone(n.native_call_binding(dict(self.payload, transcript_path="/elsewhere"), self.command))
        self.assertIsNone(n.native_call_binding(dict(self.payload, agent_id=OWNER), self.command))

    def test_output_or_command_execution_ends_binding_even_on_denial(self):
        binding = self.capture()
        for kind in ("function_call_output", "custom_tool_call_output"):
            for result in ("denied", "completed"):
                output = self.row("response_item", {"type": kind, "call_id": self.call, "output": result})
                self.write(self.header, self.pending, output)
                self.assertFalse(n.native_call_still_running(binding))
                self.assertIsNone(n.native_call_binding(self.payload, self.command))
        completed = self.row("event_msg", {"type": "item_completed", "thread_id": ROOT_ID,
                                          "item": {"type": "CommandExecution", "id": self.tool, "status": "failed"}})
        self.write(self.header, self.pending, completed)
        self.assertFalse(n.native_call_still_running(binding))

    def test_conflicting_or_unsupported_provider_input_never_mints(self):
        changed = self.row("response_item", {"type": "custom_tool_call", "name": "exec", "call_id": "call_other",
                                             "input": self.pending["payload"]["input"]})
        self.write(self.header, self.pending, changed)
        self.assertIsNone(n.native_call_binding(self.payload, self.command))
        changed["payload"]["input"] += " text(await tools.exec_command({}));"
        self.write(self.header, changed)
        self.assertIsNone(n.native_call_binding(self.payload, self.command))

    def test_shrunken_replaced_edited_and_overlimit_history_fail(self):
        binding = self.capture()
        data = self.path.read_bytes()
        self.write(self.header)
        self.assertFalse(n.native_call_still_running(binding))
        self.path.write_bytes(data.replace(b"native_action", b"native_change"))
        self.assertFalse(n.native_call_still_running(binding))
        self.path.write_bytes(data + b" " * (n.NATIVE_CALL_TAIL + 1) + b"\n")
        self.assertFalse(n.native_call_still_running(binding))
        self.path.write_bytes(data)
        self.path.rename(self.home / "old-fixture")
        self.path.write_bytes(data)
        self.assertFalse(n.native_call_still_running(binding))

    def test_missing_current_root_metadata_never_authenticates(self):
        binding = self.capture()
        with mock.patch.object(n, "_root_rollout", side_effect=ValueError("no current root binding")):
            self.assertFalse(n.native_call_still_running(binding))
            self.assertIsNone(n.native_call_binding(self.payload, self.command))


class NativeReviewContracts(TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.repo = Path(work.name).resolve()
        self.report = self.repo / "review.txt"
        self.report.write_text("VERDICT: PASS\nIndependent check performed.\n")
        self.owner_report = self.repo / "owner.json"
        self.owner_report.write_text(json.dumps({"owner": OWNER, "authors": {HEAD: [OWNER]}}))

    def event(self, *, agent=OWNER, cwd=None, code=0, text=None, command=None):
        return {"type": "event_msg", "timestamp": "2026-11-22T18:55:00Z", "payload": {
            "type": "item_completed", "thread_id": agent, "item": {
                "type": "CommandExecution", "source": "unified_exec_startup", "status": "completed", "exit_code": code,
                "cwd": str(cwd or self.repo), "command": command or ["/bin/zsh", "-lc", "set -eu\ngit commit -F message\ngit rev-parse HEAD"],
                "aggregated_output": text or f"[branch {HEAD[:7]}] fixture subject\n{HEAD}\n",
            }
        }}

    def test_native_authorship_binds_full_commit_subject_cwd_and_observed_completion(self):
        subjects = {HEAD: "fixture subject"}
        match = lambda event: n._commit_from_event(event, OWNER, self.repo, self.repo, subjects)
        self.assertEqual(match(self.event()), HEAD)
        self.assertIsNone(match(self.event(agent=ACCEPTANCE)))
        self.assertIsNone(match(self.event(cwd=self.repo / "elsewhere")))
        self.assertIsNone(match(self.event(code=1)))
        self.assertIsNone(match(self.event(text=f"[branch {HEAD[:7]}] wrong subject\n{HEAD}\n")))
        self.assertIsNone(match(self.event(command=["/bin/sh", "-c", "echo fixture\ngit rev-parse HEAD"])))
        self.assertIsNone(match(self.event(command=["/bin/sh", "-c",
                                                     "git commit -F message\ngit rev-parse HEAD\necho fixture"])))

    def test_native_authorship_accepts_desktop_local_file_uri(self):
        subjects = {HEAD: "fixture subject"}
        self.assertEqual(n._commit_from_event(self.event(cwd=self.repo.as_uri()), OWNER,
                                               self.repo, self.repo, subjects), HEAD)

    def test_native_authorship_accepts_scoped_commit_and_readback(self):
        command = [
            "/bin/zsh", "-lc",
            "set -eu\ngit commit -F ../message.txt --only -- hooks/review.py tests/test_review.py\n"
            "git rev-parse HEAD\ngit show --check --oneline HEAD\ngit status --short",
        ]
        subjects = {HEAD: "fixture subject"}
        self.assertEqual(n._commit_from_event(self.event(command=command), OWNER,
                                               self.repo, self.repo, subjects), HEAD)

    def test_native_authorship_refuses_ambiguous_cwd_and_commit_shapes(self):
        subjects = {HEAD: "fixture subject"}
        local = self.repo.as_uri()
        invalid_cwds = [
            "file://wrong.invalid" + self.repo.as_posix(), local + "?view=other", local + "#other",
            "file://localhost" + self.repo.as_posix(), local.rsplit("/", 1)[0] + "%2F" + self.repo.name,
            local + "/../" + self.repo.name, local + "%5C", local + "%252f",
            local + "%00", local + "?", local + "#",
            local.replace("file:///", "file:/", 1), self.repo.name,
        ]
        for cwd in invalid_cwds:
            with self.subTest(cwd=cwd):
                self.assertIsNone(n._commit_from_event(self.event(cwd=cwd), OWNER, self.repo, self.repo, subjects))
        invalid_shells = [
            "git commit -F message --only --",
            "git commit -F message --only -- ../outside.py",
            "git commit -F message --only -- /outside.py",
            "git commit -F message --only -- ':(glob)*'",
            "git commit -F message --only -- -outside.py",
            "git commit -F message --only --no-verify -- tracked.py",
            "git commit -F message --only -- tracked.py tracked.py",
            "git commit -F message --only -- " + " ".join(f"tracked{num}.py" for num in range(129)),
            "env git commit -F message --only -- tracked.py",
            "git -c user.name=Other commit -F message --only -- tracked.py",
            "git commit -F message --only -- tracked.py && echo fixture",
            "git commit -F message --only -- tracked.py; echo fixture",
            "set +e\ngit commit -F message --only -- tracked.py",
        ]
        for shell in invalid_shells:
            with self.subTest(shell=shell):
                command = ["/bin/zsh", "-lc",
                           "set -eu\n" + shell + "\ngit rev-parse HEAD\ngit show --check --oneline HEAD"]
                self.assertIsNone(n._commit_from_event(self.event(command=command), OWNER,
                                                      self.repo, self.repo, subjects))
        command = ["/bin/zsh", "-lc", "git commit -F message --only -- tracked.py\ngit rev-parse HEAD"]
        self.assertIsNone(n._commit_from_event(self.event(command=command), OWNER, self.repo, self.repo, subjects))

    def test_authored_sibling_worktree_binds_same_repository(self):
        actual_repo = self.repo / "primary"
        sibling = self.repo / "sibling"
        foreign = self.repo / "other"
        for checkout in (actual_repo, foreign):
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin",
                            "https://github.com/fixture/project.git"], check=True)
            subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=f@example.invalid",
                            "commit", "-q", "--allow-empty", "-m", "fixture subject"], check=True)
        subprocess.run(["git", "-C", str(actual_repo), "worktree", "add", "-q", "--detach", str(sibling)], check=True)
        subjects = {HEAD: "fixture subject"}
        self.assertEqual(n._commit_from_event(self.event(cwd=sibling), OWNER, actual_repo, self.repo, subjects), HEAD)
        self.assertEqual(n._commit_from_event(self.event(cwd=sibling.as_uri()), OWNER,
                                              actual_repo, self.repo, subjects), HEAD)
        self.assertIsNone(n._commit_from_event(self.event(cwd=foreign), OWNER, actual_repo, self.repo, subjects))
        self.assertIsNone(n._commit_from_event(self.event(cwd=foreign.as_uri()), OWNER, actual_repo,
                                              self.repo, subjects))

    def _message_scratch(self):
        scratch = self.repo / ".agent-harness/work" / ROOT_ID / "message-scratch"
        scratch.mkdir(parents=True, mode=0o700)
        checkout = scratch / "checkout"
        checkout.mkdir()
        for name in ("main", "other"):
            path = scratch / f"commit-message-{name}.txt"
            path.touch(mode=0o600)
        (scratch / "commit-message-alias.txt").symlink_to(scratch / "commit-message-main.txt")
        return scratch, checkout

    def test_native_authorship_rejects_unparsed_setup_and_message_operations(self):
        subjects = {HEAD: "fixture subject"}
        scratch, checkout = self._message_scratch()
        main_message = '"$base/commit-message-main.txt"'
        blocks = [
            "umask 077; true",
            "test -n fixture && true",
            "git add tracked.py && true",
            "git diff --check; true",
            f"GIT_DIR={self.repo}",
            f"python3 - {main_message} <<'PY'\nprint('fixture')\nPY",
            f"cat > {main_message} && true <<'EOF'\nfixture\nEOF",
            "cat > \"$base/commit-message-other.txt\" <<'EOF'\nfixture\nEOF",
        ]
        cases = [(setup, main_message) for setup in blocks] + [
            ("cat > \"$base/commit-message-alias.txt\" <<'EOF'\nfixture\nEOF", '"$base/commit-message-alias.txt"'),
            ("cat > .git/config <<'EOF'\nfixture\nEOF", ".git/config"),
            ("cat > ../commit-message-main.txt <<'EOF'\nfixture\nEOF", "../commit-message-main.txt"),
        ]
        for setup, message in cases:
            with self.subTest(setup=setup):
                command = ["/bin/zsh", "-lc",
                           f"set -eu\nbase={scratch}\n{setup}\ngit commit -F {message}\ngit rev-parse HEAD"]
                self.assertIsNone(n._commit_from_event(self.event(cwd=checkout, command=command), OWNER,
                                                      checkout, self.repo, subjects))

    def test_native_authorship_accepts_exact_historical_message_writers(self):
        subjects = {HEAD: "fixture subject"}
        scratch, checkout = self._message_scratch()
        message = '"$base/commit-message-main.txt"'
        writer_blocks = [
            f"cat > {message} <<'EOF'\nA literal commit message.\nEOF",
            f"python3 - {message} <<'PY'\nfrom pathlib import Path\nimport sys\n"
            "p = Path(sys.argv[1])\ns = p.read_text().replace('a', 'b').replace('c', 'd')\n"
            "p.write_text(s)\nPY",
        ]
        for writer in writer_blocks:
            with self.subTest(writer=writer):
                script = (f"set -eu\nbase={scratch}\ngit diff --check\ngit add tracked.py\n{writer}\n"
                          f"git commit -F {message}\ngit rev-parse HEAD")
                event = self.event(cwd=checkout, command=["/bin/zsh", "-lc", script])
                self.assertEqual(n._commit_from_event(event, OWNER, checkout, self.repo, subjects), HEAD)

    def test_complete_owner_declaration_and_pure_pass(self):
        n._authors(self.owner_report.read_bytes(), OWNER, ROOT_ID, [HEAD])
        n._authors(json.dumps({"owner": OWNER, "authors": {HEAD: sorted([OWNER, ROOT_ID])}}).encode(),
                   OWNER, ROOT_ID, [HEAD])
        for raw in (b'{"owner":"unknown","authors":{}}',
                    json.dumps({"owner": OWNER, "authors": {HEAD: [ACCEPTANCE]}}).encode()):
            with self.assertRaises(ValueError):
                n._authors(raw, OWNER, ROOT_ID, [HEAD])
        with self.assertRaises(ValueError):
            n._authors(self.owner_report.read_bytes(), OWNER, ROOT_ID, [HEAD, BASE])
        n._pure_review(self.report.read_bytes())
        for raw in (b"VERDICT: PASS-WITH-TICKETS\n", b"VERDICT: BLOCK\n",
                    b"VERDICT: PASS\nF1 a correctness problem\n", b"VERDICT: PASS\nVERDICT: BLOCK\n"):
            with self.assertRaises(ValueError):
                n._pure_review(raw)

    def test_witness_digest_binds_complete_review_context(self):
        values = context()
        args = (ACCEPTANCE, "2026-11-22T18:55:00Z", "2026-11-22T19:00:00Z", self.report.read_bytes())
        line = n.witness_line(values, "acceptance", *args)
        for field, replacement in (("base_ref", "feature"), ("head_ref", "codex/other"), ("base", "f" * 40), ("pr", 10),
                                   ("packet_sha256", "e" * 64), ("tests_sha256", "e" * 64), ("no_ci", False),
                                   ("commits", [BASE, HEAD])):
            self.assertNotEqual(line, n.witness_line(dict(values, **{field: replacement}), "acceptance", *args))
        self.assertNotEqual(line, n.witness_line(values, "adversarial", *args))

    def test_native_runner_pins_both_github_lookup_routes(self):
        import os

        run = mock.Mock(return_value=(0, "{}", ""))
        with mock.patch.dict(os.environ, {"GH_HOST": "enterprise.example.invalid"}):
            n.github_runner(["api", "repos/fixture/project/pulls/3"], 4, run=run)
            run.assert_called_once_with(["api", "--hostname", "github.com", "repos/fixture/project/pulls/3"], 4, None)
            run.reset_mock()
            n.github_runner(["pr", "checks", "3", "-R", "fixture/project", "--required"], 7, str(self.repo), run=run)
            run.assert_called_once_with(["pr", "checks", "3", "-R", "github.com/fixture/project", "--required"],
                                        7, str(self.repo))
            run.reset_mock()
            with self.assertRaisesRegex(ValueError, "unsupported native GitHub read"):
                n.github_runner(["api", "--hostname", "enterprise.example.invalid", "repos/fixture/project"], 4, run=run)
            with self.assertRaisesRegex(ValueError, "canonical repository"):
                n.github_runner(["pr", "view", "3", "-R", "enterprise.example.invalid/fixture/project"], 4, run=run)
            run.assert_not_called()

    def test_fresh_remote_ref_and_ci_proof(self):
        client = mock.Mock()
        pull = {"number": 3, "state": "open", "base": {"sha": BASE, "ref": "main", "repo": {"full_name": "fixture/project"}},
                "head": {"sha": HEAD, "ref": "codex/reviewed", "repo": {"full_name": "fixture/project"}}}
        client.json.return_value = pull
        valid = {"slug": "fixture/project", "number": 3, "head": HEAD, "no_ci": True, "unsettled": []}
        with mock.patch("merge_gate.evaluate_pr", return_value=(valid, [])):
            self.assertEqual(n._remote(client, "fixture/project", 3, HEAD, BASE), ("main", "codex/reviewed", True))
            pull["base"]["sha"] = HEAD
            with self.assertRaisesRegex(ValueError, "base or head changed"):
                n._remote(client, "fixture/project", 3, HEAD, BASE)
            pull["base"]["sha"] = BASE
            pull["head"]["repo"]["full_name"] = "fork/project"
            with self.assertRaisesRegex(ValueError, "same GitHub repository"):
                n._remote(client, "fixture/project", 3, HEAD, BASE)
            pull["head"]["repo"]["full_name"] = "fixture/project"
            for invalid_ref in ("main", "refs//broken", "refs/../main", "codex/test.lock"):
                with self.subTest(ref=invalid_ref), self.assertRaisesRegex(ValueError, "valid and distinct"):
                    pull["head"]["ref"] = invalid_ref
                    n._remote(client, "fixture/project", 3, HEAD, BASE)
        with mock.patch("merge_gate.evaluate_pr", return_value=(valid, ["a check failed"])):
            with self.assertRaisesRegex(ValueError, "CI is not eligible"):
                n._remote(client, "fixture/project", 3, HEAD, BASE)

    def test_three_roles_and_complete_native_commit_proof_required(self):
        bundle = self.repo / "bundle.json"
        proof = lambda agent, report: {"agent": agent, "report": str(report), "started": "2026-11-22T19:00:00Z",
                                       "ended": "2026-11-22T19:00:10Z"}
        receipts = {"root": ROOT_ID, "context": context(), "proofs": {
            "owner": proof(OWNER, self.owner_report), "acceptance": proof(ACCEPTANCE, self.report),
            "adversarial": proof(ADVERSARIAL, self.report),
        }}
        bundle.write_text(json.dumps(receipts))
        now = n.spec_flow._native_stamp("2026-11-22T19:01:00Z").timestamp()
        finished = n.spec_flow._native_stamp("2026-11-22T19:00:11Z")
        def proof_found(_identity, *_args, observe=None, **_kwargs):
            if observe is not None:
                observe(self.event())
            return finished
        with mock.patch.object(n, "_git", return_value="fixture subject"), \
             mock.patch.object(n.spec_flow, "_native_agent_source", return_value={"role": "fixture"}), \
             mock.patch.object(n.spec_flow, "_native_authored_witness", side_effect=proof_found):
            result = n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now,
                                     expected_digest=n.digest(bundle.read_bytes()))
            self.assertEqual(set(result["proofs"]), set(n.ROLES))
            with self.assertRaisesRegex(ValueError, "bundle digest changed"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now,
                                expected_digest="f" * 64)
            with self.assertRaisesRegex(ValueError, "root or proof set"):
                n.verify_bundle(bundle, context(), self.repo, root=OWNER, now=now)
            receipts["proofs"]["adversarial"]["agent"] = OWNER
            bundle.write_text(json.dumps(receipts))
            with self.assertRaisesRegex(ValueError, "distinct identities"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
            receipts["proofs"]["adversarial"]["agent"] = ADVERSARIAL
            bundle.write_text(json.dumps(receipts))
        with mock.patch.object(n, "_git", return_value="fixture subject"), \
             mock.patch.object(n.spec_flow, "_native_agent_source", return_value={"role": "fixture"}), \
             mock.patch.object(n.spec_flow, "_native_authored_witness", return_value=finished):
            with self.assertRaisesRegex(ValueError, "does not prove creation"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)

    def test_real_fixture_binds_owner_and_two_native_final_reports(self):
        self.exercise_native_bundle()

    def test_real_fixture_authenticates_typed_worker_and_checks_declared_membership(self):
        self.exercise_native_bundle(with_contributor=True)

    def exercise_native_bundle(self, *, with_contributor=False):
        import os
        import sqlite3
        from types import SimpleNamespace

        home = self.repo / "home"
        home.mkdir(mode=0o700)
        base = home / ".agent-harness/codex-wals" / ROOT_ID
        base.mkdir(parents=True, mode=0o700)
        storage = home / ".codex/sessions/2026/11/22"
        storage.mkdir(parents=True, mode=0o700)
        store = sqlite3.connect(home / ".codex/state_5.sqlite")
        self.addCleanup(store.close)
        store.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, source TEXT, thread_source TEXT,"
                      "originator TEXT, agent_path TEXT, agent_role TEXT, attached_thread_parent_id TEXT,"
                      "archived INTEGER, rollout_path TEXT, model_provider TEXT)")
        store.execute("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (ROOT_ID, "vscode", "user", "Codex Desktop", None, None, None, 0, None, "fixture"))
        start, end = "2026-11-22T19:00:00Z", "2026-11-22T19:00:10Z"
        proofs = {}
        initial_rows = []

        def put(path, rows):
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            path.chmod(0o600)

        people = [("owner", OWNER, self.owner_report), ("acceptance", ACCEPTANCE, self.report),
                  ("adversarial", ADVERSARIAL, self.report)]
        path_report = self.repo / "contribution.json"
        if with_contributor:
            self.owner_report.write_text(json.dumps({"owner": OWNER, "authors": {HEAD: [OWNER, WORKER]}}))
            path_report.write_text(json.dumps({"contributor": WORKER, "commits": {HEAD: ["worker.py"]}}))
            people.append(("contributor", WORKER, path_report))
        for role, agent, report in people:
            typed = "worker" if role == "contributor" else n.ROLES[role]
            line = n.witness_line(context(), role, agent, start, end, report.read_bytes())
            prior = n.witness_line(dict(context(), pr=9), role, agent, start, end, report.read_bytes())
            relative_agent = f"/root/{role}"
            source = {"subagent": {"thread_spawn": {"parent_thread_id": ROOT_ID, "depth": 1,
                                                     "agent_path": relative_agent, "agent_role": typed}}}
            rollout = storage / f"rollout-2026-11-22T19-00-00-{agent}.jsonl"
            store.execute("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (agent, json.dumps(source), "subagent", "Codex Desktop", relative_agent, typed,
                           None, 0, str(rollout), "fixture"))
            initial = {"at": "2026-11-22T18:54:58Z", "event": "SubagentStart", "agent_id": agent, "agent_type": typed}
            initial_rows.append(initial)
            put(base / f"agent-{agent}.jsonl", [initial, {"at": "2026-11-22T19:00:11Z", "event": "check", "note": prior},
                                                         {"at": "2026-11-22T19:00:11Z", "event": "check", "note": line}])
            def native_entry(kind, payload, timestamp="2026-11-22T18:54:59Z"):
                return {"timestamp": timestamp, "type": kind, "payload": payload}
            rows = [
                native_entry("session_meta", {"id": agent, "session_id": ROOT_ID, "parent_thread_id": ROOT_ID,
                                             "originator": "Codex Desktop", "thread_source": "subagent",
                                             "agent_role": typed, "agent_path": relative_agent, "source": source,
                                             "model_provider": "fixture", "subagent_history_start_ordinal": 2}),
                native_entry("session_meta", {"id": ROOT_ID, "session_id": ROOT_ID, "source": "vscode",
                                             "thread_source": "user", "originator": "Codex Desktop",
                                             "model_provider": "fixture"}),
                native_entry("event_msg", {"type": "thread_settings_applied", "thread_id": agent}),
            ]
            if role == "owner":
                rows.append(self.event())
            rows.append(native_entry("response_item", {"type": "message", "role": "assistant", "phase": "final_answer",
                                                       "status": "completed", "content": [{"type": "output_text", "text": prior + "\n" + line}]},
                                     "2026-11-22T19:00:12Z"))
            put(rollout, rows)
            proofs[role] = {"agent": agent, "report": str(report), "started": start, "ended": end}
        store.commit()
        put(base / "main.jsonl", initial_rows)
        bundle = self.repo / "native.json"
        document = {"root": ROOT_ID, "context": context(), "proofs": proofs}
        if with_contributor:
            worker_proof = proofs.pop("contributor")
            document["contributors"] = [worker_proof]
        bundle.write_text(json.dumps(document))
        self.assertEqual(os.stat(home / ".codex/state_5.sqlite").st_uid, os.getuid())
        now = n.spec_flow._native_stamp("2026-11-22T19:01:00Z").timestamp()
        with mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(home))), \
             mock.patch.object(n, "_git", return_value="fixture subject"), \
             mock.patch.object(n, "_changed_paths", return_value={"worker.py", "another-changed.py"}):
            passed = n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
            self.assertEqual(passed["context_sha256"], n.context_digest(context()))
            if with_contributor:
                self.assertIn(f"contributor:{WORKER}", passed["proofs"])
                document.pop("contributors")
                bundle.write_text(json.dumps(document))
                with self.assertRaisesRegex(ValueError, "exactly match the author's declaration"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                document["contributors"] = [dict(worker_proof, agent=ACCEPTANCE)]
                bundle.write_text(json.dumps(document))
                with self.assertRaisesRegex(ValueError, "distinct identities"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                document["contributors"] = [worker_proof]
                bundle.write_text(json.dumps(document))
                store.execute("UPDATE threads SET agent_role=? WHERE id=?", (n.ROLES["acceptance"], WORKER))
                store.commit()
                with self.assertRaisesRegex(n.spec_flow.SpecError, "metadata unavailable or conflicting"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                store.execute("UPDATE threads SET agent_role=? WHERE id=?", ("worker", WORKER))
                store.commit()
                old_report = path_report.read_text()
                path_report.write_text(json.dumps({"contributor": WORKER, "commits": {BASE: ["worker.py"]}}))
                with self.assertRaisesRegex(ValueError, "commit membership differs"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                path_report.write_text(json.dumps({"contributor": WORKER, "commits": {HEAD: ["unchanged.py"]}}))
                with self.assertRaisesRegex(ValueError, "path outside"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                path_report.write_text(json.dumps({"contributor": WORKER, "commits": {HEAD: ["another-changed.py"]}}))
                with self.assertRaisesRegex(ValueError, "WAL witness missing or mismatched"):
                    n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
                path_report.write_text(old_report)
            else:
                self.assertEqual(set(passed["proofs"]), set(n.ROLES))
            acceptance_wal = base / f"agent-{ACCEPTANCE}.jsonl"
            old_wal = acceptance_wal.read_text()
            with acceptance_wal.open("a") as append:
                append.write(old_wal.splitlines()[-1] + "\n")
            with self.assertRaisesRegex(ValueError, "WAL witness missing or mismatched"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
            acceptance_wal.write_text(old_wal)
            self.report.write_text("VERDICT: PASS\nChanged attachment content.\n")
            with self.assertRaisesRegex(ValueError, "WAL witness missing or mismatched"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)

    def staged_acceptance(self):
        core = "7" * 64
        ticket = "GoodQA fixture#3"
        records = [
            {"v": 1, "kind": "spec", "ticket": ticket, "_comment": "spec", "_at": "2026-11-22T18:50:00Z",
             "author": "agent:author", "actor": "agent:author", "ac": ["AC-1"], "spec_core_sha": core,
             "spec_file_sha": "a" * 64, "click_test": {"required": True},
             "reviews": [{"role": role, "verdict": "ACCEPT", "core_sha": core, "key": "agent:" + role}
                         for role in ("adversarial", "acceptance")],
             "attachments": [{"id": "spec-file", "role": "spec", "sha256": "a" * 64},
                             {"id": "spec-reviews", "role": "reviews", "sha256": "b" * 64}]},
            {"v": 1, "kind": "evidence", "ticket": ticket, "_comment": "evidence", "_at": "2026-11-22T18:55:00Z",
             "actor": "agent:evidence", "spec_core_sha": core, "ac": ["AC-1"], "commits": [{"sha": HEAD}],
             "attachments": [{"id": "log", "role": "log", "sha256": "c" * 64}]},
            {"v": 2, "kind": "click_test", "ticket": ticket, "actor": "agent:uploader",
             "_comment": "click", "_at": "2026-11-22T19:02:00Z", "spec_core_sha": core, "result": "pass",
             "covers_commits": [HEAD], "url": "http://127.0.0.1:60001", "deployed_commit": {"sha": HEAD},
             "pass_source": n.spec_flow.NATIVE_CLICK_SOURCE,
             "tester": {"kind": "agent", "family": "codex", "agent_type": n.spec_flow.NATIVE_CLICK_ROLE,
                        "identity": OWNER, "parent": ROOT_ID, "repo": "github.com/fixture/project",
                        "report_sha256": "d" * 64, "started_at": "2026-11-22T19:00:00Z",
                        "ended_at": "2026-11-22T19:01:00Z"},
             "attachments": [{"id": "report", "role": "report", "name": "staging.txt", "sha256": "e" * 64}]},
            {"v": 1, "kind": "signoff", "ticket": ticket, "_comment": "signed", "_at": "2026-11-22T19:03:00Z",
             "actor": "agent:signer", "by": "agent:signer", "signer_kind": "agent", "spec_core_sha": core},
        ]
        index = {a["id"]: {"commentId": r["_comment"], "completionState": "completed", "sha256": a["sha256"]}
                 for r in records for a in r.get("attachments", [])}
        return records, index, {"_label": ticket}

    def test_staged_receipt_defers_only_the_normal_live_location_check(self):
        records, index, issue = self.staged_acceptance()
        with mock.patch.object(n.spec_flow, "_native_click_record_proof"):
            normal = n.spec_flow.evaluate(records, index, issue)
            staged = n.spec_flow.evaluate(records, index, issue, staged_commit=HEAD, staged_repo="github.com/fixture/project")
        self.assertFalse(normal["ready"])
        self.assertEqual(len(normal["missing"]), 1)
        self.assertIn("not the live deployment", normal["missing"][0])
        self.assertTrue(staged["ready"], staged["missing"])

    def test_premerge_keeps_other_current_spec_gates_and_correct_candidate_proof(self):
        def assert_blocks(change, fragment):
            records, index, issue = self.staged_acceptance()
            change(records, index)
            with mock.patch.object(n.spec_flow, "_native_click_record_proof"):
                result = n.spec_flow.evaluate(records, index, issue, staged_commit=HEAD, staged_repo="github.com/fixture/project")
            self.assertFalse(result["ready"])
            self.assertTrue(any(fragment in problem for problem in result["missing"]), result["missing"])
        assert_blocks(lambda rows, _index: rows[0]["reviews"].pop(), "spec review")
        assert_blocks(lambda rows, _index: rows[1].update(ac=[]), "AC-1: no evidence")
        assert_blocks(lambda _rows, index: index.pop("log"), "execution logs")
        assert_blocks(lambda rows, _index: rows.pop(), "sign-off: none valid")
        assert_blocks(lambda rows, _index: rows[2].update(deployed_commit={"sha": BASE}), "exact candidate")
        assert_blocks(lambda rows, _index: rows[2]["tester"].update(repo="github.com/other/project"), "another repository")
        assert_blocks(lambda rows, _index: rows[2].update(covers_commits=[]), "evidence commits")
        assert_blocks(lambda rows, _index: rows[2].update(result="fail"), "latest click-test failed")
        assert_blocks(lambda _rows, index: index["report"].update(sha256="0" * 64), "does not verify")
        assert_blocks(lambda rows, _index: rows[0].update(author="agent:" + OWNER), "independent click-tester")

    def test_incomplete_premerge_claim_refuses_before_native_bundle_access(self):
        ctx = context()
        ctx["tickets"][0]["premerge_missing"] = ["sign-off: none valid"]
        with mock.patch.object(n.spec_flow, "read_regular") as read_file:
            with self.assertRaisesRegex(ValueError, "pre-merge verification is incomplete"):
                n.verify_bundle(self.repo / "unopened.json", ctx, self.repo)
        read_file.assert_not_called()

    def test_tracker_checks_exact_evidence_and_candidate_ancestry(self):
        from types import SimpleNamespace

        other = "f" * 40
        records, index, issue = self.staged_acceptance()
        issue["status"] = "in_review"
        tracker = mock.Mock()
        tracker.ticket = SimpleNamespace(id="fixture", label=issue["_label"])
        tracker.records.return_value = records, [], index
        tracker.latest_spec.return_value = records[0]
        tracker.adapter.issue.return_value = issue
        with mock.patch("commit_policy._commit_refs", return_value=[("goodqa", "fixture", 3)]), \
             mock.patch.object(n, "_git", return_value="fixture commit body"), \
             mock.patch.object(n.spec_flow, "Session", return_value=tracker), \
             mock.patch.object(n.spec_flow, "_native_click_record_proof"), \
             mock.patch.object(n, "_is_ancestor", side_effect=lambda _repo, older, _head: older != other):
            clean, _ = n._tracker_claims(self.repo, "fixture/project", [HEAD], HEAD)
            self.assertEqual(clean[0]["premerge_missing"], [])
            first_digest = clean[0]["release_records_sha256"]
            records[3]["_comment"] = "another-signoff"
            clean, _ = n._tracker_claims(self.repo, "fixture/project", [HEAD], HEAD)
            self.assertNotEqual(clean[0]["release_records_sha256"], first_digest)
            records[1]["commits"] = [{"sha": other}]
            records[2]["covers_commits"] = [other]
            blocked, _ = n._tracker_claims(self.repo, "fixture/project", [HEAD], HEAD)
            self.assertEqual(blocked[0]["premerge_missing"], [
                "commits: no current structured evidence names the exact candidate",
                "commits: current evidence includes a commit outside the exact candidate ancestry",
            ])


    def test_declared_contribution_paths_are_real_git_changes(self):
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "bootstrap.sh").write_text("fixture\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "bootstrap.sh"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c", "user.email=f@example.invalid",
                        "commit", "-q", "-m", "fixture contribution"], check=True)
        commit = n._git(self.repo, "rev-parse", "HEAD")
        members = {commit}
        as_report = lambda path: json.dumps({"contributor": WORKER, "commits": {commit: [path]}}).encode()
        n._contributor_report(as_report("bootstrap.sh"), WORKER, members, self.repo, {})
        with self.assertRaisesRegex(ValueError, "path outside"):
            n._contributor_report(as_report("another.sh"), WORKER, members, self.repo, {})
        with self.assertRaisesRegex(ValueError, "distinct changed paths"):
            n._contributor_report(as_report("../bootstrap.sh"), WORKER, members, self.repo, {})
