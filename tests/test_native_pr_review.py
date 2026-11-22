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
HEAD, BASE = "a" * 40, "b" * 40


def context():
    return {"version": 1, "repo": "fixture/project", "pr": 3, "head": HEAD, "base": BASE, "base_ref": "main",
            "commits": [HEAD], "packet_sha256": "c" * 64, "tests_sha256": "d" * 64, "no_ci": True, "evidence_authors": [],
            "tickets": [{"ticket": "GoodQA fixture#3", "state": "in_review", "spec_core_sha": "2" * 64,
                         "review_sha256": "3" * 64, "evidence_sha256": "4" * 64, "missing": ["live proof pending"]}]}


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
        self.assertIsNone(n._commit_from_event(self.event(cwd=foreign), OWNER, actual_repo, self.repo, subjects))

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
        for field, replacement in (("base_ref", "feature"), ("base", "f" * 40), ("pr", 10),
                                   ("packet_sha256", "e" * 64), ("tests_sha256", "e" * 64), ("no_ci", False),
                                   ("commits", [BASE, HEAD])):
            self.assertNotEqual(line, n.witness_line(dict(values, **{field: replacement}), "acceptance", *args))
        self.assertNotEqual(line, n.witness_line(values, "adversarial", *args))

    def test_fresh_remote_ref_and_ci_proof(self):
        client = mock.Mock()
        pull = {"number": 3, "state": "open", "base": {"sha": BASE, "ref": "main"}, "head": {"sha": HEAD}}
        client.json.return_value = pull
        valid = {"slug": "fixture/project", "number": 3, "head": HEAD, "no_ci": True, "unsettled": []}
        with mock.patch("merge_gate.evaluate_pr", return_value=(valid, [])):
            self.assertEqual(n._remote(client, "fixture/project", 3, HEAD, BASE), ("main", True))
            pull["base"]["sha"] = HEAD
            with self.assertRaisesRegex(ValueError, "base or head changed"):
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
            result = n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
            self.assertEqual(set(result["proofs"]), set(n.ROLES))
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

        for role, agent, report in (("owner", OWNER, self.owner_report), ("acceptance", ACCEPTANCE, self.report),
                                    ("adversarial", ADVERSARIAL, self.report)):
            typed = n.ROLES[role]
            line = n.witness_line(context(), role, agent, start, end, report.read_bytes())
            relative_agent = f"/root/{role}"
            source = {"subagent": {"thread_spawn": {"parent_thread_id": ROOT_ID, "depth": 1,
                                                     "agent_path": relative_agent, "agent_role": typed}}}
            rollout = storage / f"rollout-2026-11-22T19-00-00-{agent}.jsonl"
            store.execute("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (agent, json.dumps(source), "subagent", "Codex Desktop", relative_agent, typed,
                           None, 0, str(rollout), "fixture"))
            initial = {"at": "2026-11-22T18:54:58Z", "event": "SubagentStart", "agent_id": agent, "agent_type": typed}
            initial_rows.append(initial)
            put(base / f"agent-{agent}.jsonl", [initial, {"at": "2026-11-22T19:00:11Z", "event": "check", "note": line}])
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
                                                       "status": "completed", "content": [{"type": "output_text", "text": line}]},
                                     "2026-11-22T19:00:12Z"))
            put(rollout, rows)
            proofs[role] = {"agent": agent, "report": str(report), "started": start, "ended": end}
        store.commit()
        put(base / "main.jsonl", initial_rows)
        bundle = self.repo / "native.json"
        bundle.write_text(json.dumps({"root": ROOT_ID, "context": context(), "proofs": proofs}))
        self.assertEqual(os.stat(home / ".codex/state_5.sqlite").st_uid, os.getuid())
        now = n.spec_flow._native_stamp("2026-11-22T19:01:00Z").timestamp()
        with mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(home))), \
             mock.patch.object(n, "_git", return_value="fixture subject"):
            passed = n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
            self.assertEqual(passed["context_sha256"], n.context_digest(context()))
            self.report.write_text("VERDICT: PASS\nChanged attachment content.\n")
            with self.assertRaisesRegex(ValueError, "WAL witness missing or mismatched"):
                n.verify_bundle(bundle, context(), self.repo, root=ROOT_ID, now=now)
