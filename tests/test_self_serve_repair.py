"""self_serve repair round: the CLASSES behind the review findings, each with a guard that fails on the broken variant.

1. Nothing the caller hands in may choose where main is proven, where the policy lives, or what time it is.
2. A Codex root is not told apart from a Codex helper, so merge-class capabilities are Claude-main-only.
3. single_use binds the object (repo, PR, head), is spent only by an explicit consume(), and only by a proven actor.
4. The fallback denylist has a built-in floor that no policy can remove.
Run: python3 -m unittest tests.test_self_serve_repair   (from the repository root)
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cryptography
from tests.test_self_serve import HOOKS, NOW, SID, Env, body, evidence_for, make_key, ss

CRYPTO_DIR = os.path.dirname(os.path.dirname(cryptography.__file__))  # a child with a fake HOME has no user site
MERGE_CLASS = ("same_harness_fallback_review", "merge_reviewed_pr", "central_decisions_agent_steps")
PR = {"repo": "o/r", "pr": 7, "head": "a" * 40}


class Repair(Env):
    """Env plus the private seam armed the way a test arms it. The actor never carries a claude_dir."""

    def setUp(self):
        super().setUp()
        seam = mock.patch.dict(ss._SEAM, {"home": self.home, "claude_dir": str(self.claude), "clock": True})
        seam.start()
        self.addCleanup(seam.stop)
        self.legit = {"kind": "claude_main", "payload": {"session_id": SID, "transcript_path": str(self.transcript)}}

    def grant(self, cap="merge_reviewed_pr", actor="main", **kw):
        return super().grant(cap, actor=self.legit if actor == "main" else actor, **kw)

    def why(self, cap="merge_reviewed_pr", actor="main", **kw):
        return super().why(cap, actor=self.legit if actor == "main" else actor, **kw)

    def consume(self, cap="merge_reviewed_pr", actor="main", **kw):
        kw.setdefault("now", NOW)
        return ss.consume(cap, actor=self.legit if actor == "main" else actor, home=self.home, **kw)

    def scoped(self, scope, cap="merge_reviewed_pr", **extra):
        self.install(body(key_id=self.key_id, capabilities={cap: dict({"scope": scope}, **extra)}))

    def forged_main(self):
        """A fake claude dir with a transcript that satisfies caller_identity.is_main for that dir and no other."""
        fake = Path(self.home) / "fake-claude"
        transcript = fake / "projects" / "p" / (SID + ".jsonl")
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        return {"kind": "claude_main", "claude_dir": str(fake),
                "payload": {"session_id": SID, "transcript_path": str(transcript)}}


# ---------------------------------------------------------------- finding 1: the actor cannot choose the proof root

class ActorCannotChooseProofRoot(Repair):
    def test_forged_claude_dir_in_the_actor_is_not_main(self):
        forged = self.forged_main()
        self.assertEqual(self.why(actor=forged), "not_main")
        self.assertIsNone(self.grant(actor=forged))

    def test_forged_claude_dir_with_other_spellings_is_not_main(self):
        forged = self.forged_main()
        for key in ("claude_dir", "claude_home", "projects_dir", "home"):
            actor = {"kind": "claude_main", key: forged["claude_dir"], "payload": forged["payload"]}
            self.assertIsNone(self.grant(actor=actor), key)

    def test_the_real_transcript_proves_main_with_no_override(self):
        self.assertIsNotNone(self.grant())

    def test_an_actor_override_cannot_rescue_a_wrong_transcript_either(self):
        actor = copy.deepcopy(self.legit)
        actor["claude_dir"] = "/nonexistent"
        self.assertIsNotNone(self.grant(actor=actor))  # ignored, not honoured: the seam dir is the proof root

    def test_unarmed_proof_root_is_the_real_home_not_the_environment(self):
        forged = self.forged_main()
        with mock.patch.dict(ss._SEAM, {"claude_dir": None}), mock.patch.object(ss, "_real_home", return_value=self.home), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": forged["claude_dir"]}):
            self.assertEqual(self.why(actor=forged), "not_main")
            self.assertIsNotNone(self.grant())  # <real home>/.claude is where the genuine transcript lives

    def test_source_guard_the_library_never_reads_the_environment_or_an_actor_root(self):
        source = (Path(HOOKS) / "self_serve.py").read_text()
        self.assertIsNone(re.search(r"os\.environ|getenv|environb", source))
        self.assertIsNone(re.search(r"actor\s*(\.get\(|\[)\s*['\"](claude_dir|claude_home|home)", source))
        self.assertNotIn("expanduser", source, "~ expands from $HOME, which the caller controls")
        self.assertNotIn("Path.home", source)


# ---------------------------------------------------------------- finding 4: home and clock are not the caller's

class HomeAndClockAreNotCallerChoices(Repair):
    def test_unarmed_home_override_is_refused(self):
        with mock.patch.dict(ss._SEAM, {"home": None}), mock.patch.object(ss, "_real_home", return_value="/nonexistent-real"):
            self.assertEqual(self.why(), "home_override_refused")
            self.assertIsNone(ss.status(self.home, now=NOW)["policy_id"])
            self.assertFalse(ss.status(self.home)["enabled"])

    def test_unarmed_home_equal_to_the_real_home_is_fine(self):
        with mock.patch.dict(ss._SEAM, {"home": None}), mock.patch.object(ss, "_real_home", return_value=self.home):
            self.assertIsNotNone(ss.grant("merge_reviewed_pr", actor=self.legit, home=self.home, now=NOW))
            self.assertIsNotNone(ss.grant("merge_reviewed_pr", actor=self.legit, now=NOW))  # clamp aside: seam clock is on

    def test_a_missing_account_entry_denies_and_never_falls_back_to_home(self):
        with mock.patch.dict(ss._SEAM, {"home": None, "claude_dir": None}), \
                mock.patch.object(ss.pwd, "getpwuid", side_effect=KeyError("uid")), \
                mock.patch.dict(os.environ, {"HOME": self.home}):
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, now=NOW)[1], "home_unknown")
            self.assertEqual(ss.status()["reason"], "home_unknown")
            self.assertFalse(ss.revoke("all"))
        self.assertFalse(ss.revoked_dir(self.home).exists())

    def test_home_variable_does_not_move_the_policy(self):
        """Process level: HOME and CLAUDE_CONFIG_DIR both point at a throwaway tree holding a valid signed policy and a
        transcript that satisfies is_main there. The library must still read the real account's home and find no grant."""
        fake = os.path.realpath(tempfile.mkdtemp(prefix="ss-fakehome-", dir=self.home))
        pol = ss.policy_dir(fake)
        pol.mkdir(parents=True, mode=0o700)
        os.chmod(pol, 0o700)
        now = time.time()
        signed = ss.sign_policy(body(key_id=self.key_id, issued_at=ss.iso(now - 60), expires_at=ss.iso(now + 3600)), self.key)
        self.write(ss.policy_path(fake), signed)
        self.write(ss.pubkeys_path(fake), {"schema": "self-serve-pubkeys/1", "keys": [ss.public_record(self.pub)]})
        transcript = Path(fake) / ".claude" / "projects" / "p" / (SID + ".jsonl")
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        account = os.path.realpath(tempfile.mkdtemp(prefix="ss-account-", dir=self.home))  # stands in for the real account
        code = (
            "import sys, pwd, types; sys.path[:0] = [%r, %r]\n"
            "pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_dir=%r)\n"
            "import caller_identity, self_serve\n"
            "caller_identity.native_deny_reason = lambda payload: None\n"
            "actor = {'kind': 'claude_main', 'payload': {'session_id': %r, 'transcript_path': %r}}\n"
            "got, why = self_serve.explain('merge_reviewed_pr', actor=actor)\n"
            "print('GRANTED' if got else 'NONE', self_serve.status()['policy_id'], why)\n"
            % (HOOKS, CRYPTO_DIR, account, SID, str(transcript)))
        env = {"HOME": fake, "CLAUDE_CONFIG_DIR": str(Path(fake) / ".claude"), "PATH": os.environ.get("PATH", "")}
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        verdict, policy_id = out.stdout.split()[:2]
        self.assertEqual(verdict, "NONE", out.stdout)
        self.assertNotEqual(policy_id, "ab" * 16, "the library read the policy under the HOME variable")

    def test_unarmed_past_now_cannot_revive_an_expired_policy(self):
        real = time.time()
        self.install(body(key_id=self.key_id, issued_at=ss.iso(real - 7200), expires_at=ss.iso(real - 600)))
        with mock.patch.dict(ss._SEAM, {"clock": False}):
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, home=self.home, now=real - 3600)[1], "expired")
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, home=self.home)[1], "expired")
            self.assertFalse(ss.status(self.home, now=real - 3600)["enabled"])

    def test_unarmed_future_now_cannot_activate_a_policy_early(self):
        real = time.time()
        self.install(body(key_id=self.key_id, issued_at=ss.iso(real + 7200), expires_at=ss.iso(real + 9000)))
        with mock.patch.dict(ss._SEAM, {"clock": False}):
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, home=self.home, now=real + 7300)[1],
                             "not_yet_valid")

    def test_unarmed_now_within_the_skew_is_honoured(self):
        real = time.time()
        self.install(body(key_id=self.key_id, issued_at=ss.iso(real - 7200), expires_at=ss.iso(real + 100)))
        with mock.patch.dict(ss._SEAM, {"clock": False}):
            self.assertIsNotNone(ss.grant("merge_reviewed_pr", actor=self.legit, home=self.home, now=real - 100))
            # a later now inside the skew only ages the policy, which removes authority and never adds it
            self.assertIsNone(ss.grant("merge_reviewed_pr", actor=self.legit, home=self.home, now=real + 200))

    def test_unarmed_bad_clock_values_still_refused(self):
        with mock.patch.dict(ss._SEAM, {"clock": False}):
            for now in (float("nan"), "x", True, [1], float("inf")):
                self.assertIsNone(ss.grant("merge_reviewed_pr", actor=self.legit, home=self.home, now=now), now)

    def test_no_seam_value_is_set_by_importing_or_calling(self):
        self.assertEqual(set(ss._SEAM), {"home", "claude_dir", "clock"})
        code = ("import sys, pwd, types; pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_dir=%r); "
                "sys.path.insert(0, %r); import self_serve; self_serve.grant('merge_reviewed_pr', actor={}); "
                "print(self_serve._SEAM)" % (self.home, HOOKS))
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60,
                             env={"HOME": self.home, "PATH": os.environ.get("PATH", "")})
        self.assertEqual(out.stdout.strip(), "{'home': None, 'claude_dir': None, 'clock': False}", out.stderr)


# ---------------------------------------------------------------- finding 4: the fallback denylist has a floor

class FallbackFloor(Repair):
    CAP = "same_harness_fallback_review"
    DENIED = ("harness/hooks/auth.py", "src/auth/login.py", "db/migrations/001.sql", "app/migrate.py", "config/secrets.env",
              "harness/hooks/command_guard.py", "harness/hooks/merge_gate.py", "harness/hooks/self_serve.py",
              "keys/id.pem", "scripts/keygen.sh", ".env", "svc/.env.local", "AUTH/Readme.md", ".github/workflows/ci.yml",
              "harness/hooks/peer_review.py", "docs/../auth/x", "/etc/passwd", "a/\x00b", "ａuth/x.py")
    FINE = ("docs/readme.md", "src/render.py", "tests/test_thing.py", "harness/hooks/ah.py")

    def test_a_policy_with_no_denylist_still_blocks_the_floor(self):
        self.scoped({}, self.CAP)
        self.assertIsNotNone(self.grant(self.CAP, evidence={"changed_paths": list(self.FINE)}))
        for path in self.DENIED:
            self.assertEqual(self.why(self.CAP, evidence={"changed_paths": [path]}), "path_denylisted", repr(path))

    def test_one_denied_path_among_many_blocks_the_whole_change(self):
        self.scoped({}, self.CAP)
        self.assertIsNone(self.grant(self.CAP, evidence={"changed_paths": list(self.FINE) + ["db/migrations/2.sql"]}))

    def test_changed_paths_are_required_even_with_no_policy_denylist(self):
        self.scoped({}, self.CAP)
        for ev in (None, {}, {"changed_paths": []}, {"changed_paths": "docs/a.md"}, {"changed_paths": [1]}):
            self.assertIsNone(self.grant(self.CAP, evidence=ev), ev)

    def test_a_policy_denylist_is_added_to_the_floor_never_replaces_it(self):
        self.scoped({"denylist_paths": ["docs/*"]}, self.CAP)
        self.assertEqual(self.why(self.CAP, evidence={"changed_paths": ["docs/a.md"]}), "path_denylisted")
        self.assertEqual(self.why(self.CAP, evidence={"changed_paths": ["db/migrations/1.sql"]}), "path_denylisted")
        self.assertIsNotNone(self.grant(self.CAP, evidence={"changed_paths": ["src/x.py"]}))

    def test_a_repo_narrowing_cannot_lower_the_floor(self):
        self.scoped({}, self.CAP)
        ev = {"changed_paths": ["db/migrations/1.sql"], "repo_narrowing": {"denylist_paths": [], "repos": [], "allow": ["*"]}}
        self.assertIsNone(self.grant(self.CAP, evidence=ev))

    def test_the_floor_is_only_for_the_fallback_capability(self):
        self.scoped({}, "merge_reviewed_pr")
        self.assertIsNotNone(self.grant("merge_reviewed_pr", evidence=None))

    def test_floor_is_exported_for_the_consumer_to_share(self):
        self.assertTrue(ss.fallback_path_denied("db/migrations/1.sql"))
        self.assertFalse(ss.fallback_path_denied("docs/readme.md"))
        self.assertTrue(ss.fallback_path_denied(5))


# ---------------------------------------------------------------- finding 2: Codex root versus helper

class CodexRootIsNotMergeClass(Repair):
    ROOT = SimpleNamespace(origin="openai", reason="running_code_verified")

    def codex(self, cap, payload=None, **kw):
        actor = {"kind": "codex_root"}
        if payload is not None:
            actor["payload"] = payload
        with mock.patch.object(ss, "_origin_probe", return_value=self.ROOT):
            return ss.explain(cap, actor=actor, home=self.home, now=NOW, **kw)[1]

    def test_merge_class_is_claude_main_only(self):
        self.assertEqual(set(ss.CLAUDE_MAIN_ONLY), set(MERGE_CLASS))
        for cap in MERGE_CLASS:
            self.assertEqual(self.codex(cap), "codex_root_not_allowed", cap)
            self.assertIsNotNone(self.grant(cap, evidence=evidence_for(cap)), cap)  # Claude main still gets it

    def test_the_other_capabilities_still_work_for_a_verified_codex_root(self):
        for cap in set(ss.CAPABILITIES) - set(MERGE_CLASS):
            self.assertEqual(self.codex(cap), "granted", cap)

    def test_codex_helper_hints_in_the_payload_refuse(self):
        for payload in ({"thread_source": "subagent"}, {"parent_thread_id": "t-1"}, {"agent_role": "worker"},
                        {"agent_path": "/root/a"}, {"agent_id": "x"}, {"agent_type": "y"}):
            self.assertEqual(self.codex("harness_repair", payload), "helper_actor", payload)
        self.assertEqual(self.codex("harness_repair", {"thread_source": "user"}), "granted")

    def test_the_actor_cannot_widen_a_codex_root(self):
        actor = {"kind": "codex_root", "also_main": True, "claude_dir": self.home}
        with mock.patch.object(ss, "_origin_probe", return_value=self.ROOT):
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=actor, home=self.home, now=NOW)[1], "codex_root_not_allowed")


# ---------------------------------------------------------------- finding 3: single use

class SingleUse(Repair):
    def setUp(self):
        super().setUp()
        self.scoped({"single_use": True})

    def test_grant_cannot_hand_out_a_single_use_capability(self):
        self.assertEqual(self.why(evidence=dict(PR)), "single_use_requires_consume")
        self.assertIsNone(self.grant(evidence=dict(PR)))

    def test_consume_grants_once_per_object(self):
        got = self.consume(evidence=dict(PR))
        self.assertEqual(got["capability"], "merge_reviewed_pr")
        self.assertEqual(got["scope"], {"single_use": True})
        self.assertIsNone(self.consume(evidence=dict(PR)))
        self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, home=self.home, now=NOW,
                                    evidence=dict(PR), consume=True)[1], "already_used")
        self.assertIsNotNone(self.consume(evidence=dict(PR, pr=8)))
        self.assertIsNotNone(self.consume(evidence=dict(PR, head="b" * 40)))
        self.assertIsNotNone(self.consume(evidence=dict(PR, repo="o/other")))

    def test_the_caller_cannot_pick_another_key_for_the_same_object(self):
        for key in ("k1", "k2", "pr-7-" + "a" * 40, "", None, 7):
            got = self.consume(evidence=dict(PR, use_key=key))
            if key == "k1":
                self.assertIsNotNone(got)
            else:
                self.assertIsNone(got, key)

    def test_the_binding_fields_are_required_and_typed(self):
        for ev in (None, {}, {"repo": "o/r", "pr": 7}, dict(PR, head=""), dict(PR, head=None), dict(PR, pr=True),
                   dict(PR, pr=[7]), dict(PR, repo="x" * 513), {"use_key": "only-a-key"}):
            self.assertEqual(ss.explain("merge_reviewed_pr", actor=self.legit, home=self.home, now=NOW, evidence=ev,
                                        consume=True)[1], "use_binding_required", ev)

    def test_a_signed_policy_chooses_the_binding_and_unbound_fields_do_not_matter(self):
        self.scoped({"single_use": True, "single_use_bind": ["repo", "pr", "head", "report_sha256"]})
        self.assertIsNotNone(self.consume(evidence=dict(PR, report_sha256="r1", note="a")))
        self.assertIsNone(self.consume(evidence=dict(PR, report_sha256="r1", note="b")))
        self.assertIsNotNone(self.consume(evidence=dict(PR, report_sha256="r2")))
        self.assertIsNone(self.consume(evidence=dict(PR)))  # a bound field cannot be dropped

    def test_bad_binding_declarations_invalidate_the_policy(self):
        for bind in ("repo", [], [1], ["repo", "repo"], [""], ["repo"] * 3, {"a": 1}):
            self.install(body(key_id=self.key_id, capabilities={
                "merge_reviewed_pr": {"scope": {"single_use": True, "single_use_bind": bind}}}))
            self.assertIsNone(self.consume(evidence=dict(PR)), bind)

    def test_a_third_party_cannot_burn_a_legitimate_key(self):
        helper = copy.deepcopy(self.legit)
        helper["payload"]["agent_id"] = "helper-1"
        self.assertIsNone(self.consume(actor=helper, evidence=dict(PR)))
        self.assertIsNone(self.consume(actor={"kind": "claude_main"}, evidence=dict(PR)))
        self.assertIsNone(self.consume(actor=self.forged_main(), evidence=dict(PR)))
        self.assertIsNotNone(self.consume(evidence=dict(PR)))  # the real merge is not blocked

    def test_an_unwritable_audit_log_refuses_before_the_object_is_spent(self):
        os.makedirs(ss.audit_path(self.home).parent)
        os.mkdir(ss.audit_path(self.home))  # unwritable as a log
        self.assertIsNone(self.consume(evidence=dict(PR)))
        os.rmdir(ss.audit_path(self.home))
        self.assertIsNotNone(self.consume(evidence=dict(PR)), "the failed attempt must not have burned the object")

    def test_a_failed_precondition_does_not_spend(self):
        self.scoped({"single_use": True, "repos": ["o/r"]})
        self.assertIsNone(self.consume(evidence=dict(PR, repo="evil/x")))
        self.assertIsNotNone(self.consume(evidence=dict(PR)))

    def test_revocation_and_expiry_beat_a_spent_key_check_without_spending(self):
        ss.revoke("all", home=self.home)
        self.assertIsNone(self.consume(evidence=dict(PR)))
        self.assertEqual(os.listdir(ss._spent_dir(self.home)) if ss._spent_dir(self.home).exists() else [], [])

    def test_one_consumer_wins_a_race(self):
        results, gate = [], threading.Barrier(8)

        def run():
            gate.wait()
            results.append(self.consume(evidence=dict(PR)))
        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(sum(1 for r in results if r is not None), 1, results)

    def test_a_new_policy_id_starts_a_fresh_ledger(self):
        self.assertIsNotNone(self.consume(evidence=dict(PR)))
        self.install(body(key_id=self.key_id, policy_id="cd" * 16,
                          capabilities={"merge_reviewed_pr": {"scope": {"single_use": True}}}))
        self.assertIsNotNone(self.consume(evidence=dict(PR)))

    def test_consume_of_an_ordinary_capability_is_a_plain_grant(self):
        self.assertIsNone(self.consume("harness_repair"))  # not in this policy
        self.install(body(key_id=self.key_id))
        for _ in range(3):
            self.assertIsNotNone(self.consume("harness_repair"))
        self.assertFalse(ss._spent_dir(self.home).exists())

    def test_consume_audits_as_consume(self):
        self.consume(evidence=dict(PR))
        rows = [json.loads(line) for line in ss.audit_path(self.home).read_text().splitlines()]
        self.assertEqual([r["event"] for r in rows], ["consume"])
        self.assertNotIn("a" * 40, json.dumps(rows))

    def test_consume_never_raises(self):
        for kwargs in ({"actor": 5}, {"evidence": 5}, {"home": b"\xff"}, {"now": float("nan")}):
            kw = dict({"actor": self.legit, "home": self.home, "now": NOW, "evidence": dict(PR)}, **kwargs)
            self.assertIsNone(ss.consume("merge_reviewed_pr", **kw), kwargs)
        self.assertIsNone(ss.consume("nope", actor=self.legit, home=self.home))


class TtlIsPerGrantObject(Repair):
    def test_ttl_is_the_validity_of_one_returned_grant_not_a_cumulative_limit(self):
        self.install(body(key_id=self.key_id, capabilities={"harness_repair": {"scope": {}, "ttl_seconds": 60}}))
        self.assertEqual(self.grant("harness_repair", now=NOW)["expires_at"], ss.iso(NOW + 60))
        self.assertEqual(self.grant("harness_repair", now=NOW + 3600)["expires_at"], ss.iso(NOW + 3660))
        self.assertIsNone(self.grant("harness_repair", now=NOW + 86400))  # the policy expiry is the only hard limit

    def test_the_schema_says_so(self):
        schema = (Path(HOOKS).parents[1] / "docs" / "self-serve-policy.schema.json").read_text()
        self.assertIn("not a cumulative limit", schema)
        self.assertIn("single_use_bind", schema)


if __name__ == "__main__":
    unittest.main()
