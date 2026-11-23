"""self_serve: signed, purpose-bound, revocable policy. Every failure is no grant; nothing raises (AC-6, NEG-2, NEG-6)."""
import copy
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HOOKS = str(Path(__file__).resolve().parents[1] / "harness" / "hooks")
sys.path.insert(0, HOOKS)
import caller_identity as ci  # noqa: E402
import self_serve as ss  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
NOW = 1_800_000_000.0
POLICY_ID = "ab" * 16
SEED = 20261123


def make_key():
    key = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, raw


def evidence_for(cap):
    """The same-harness fallback always needs the changed paths (it has a built-in denylist floor); nothing else does."""
    return {"changed_paths": ["docs/readme.md"]} if cap == "same_harness_fallback_review" else None


def body(**over):
    out = {
        "schema": "self-serve/1", "purpose": "self-serve", "policy_id": POLICY_ID, "key_id": "",
        "issued_at": ss.iso(NOW - 3600), "expires_at": ss.iso(NOW + 86400),
        "capabilities": {c: {"scope": {}, "ttl_seconds": None} for c in ss.CAPABILITIES}, "disabled": [],
    }
    out.update(over)
    return out


class Env(unittest.TestCase):
    """A throwaway HOME with a pinned key and a signed policy. Nothing outside it is touched."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.realpath(tmp.name)
        self.claude = Path(self.home) / ".claude"
        self.transcript = self.claude / "projects" / "-x" / (SID + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("{}\n")
        non_native = mock.patch.object(ci, "native_deny_reason", return_value=None)
        non_native.start()
        self.addCleanup(non_native.stop)
        self.key, self.pub = make_key()
        self.key_id = ss.key_id_of(self.pub)
        pol = ss.policy_dir(self.home)
        pol.mkdir(parents=True, mode=0o700)
        os.chmod(pol, 0o700)
        self.install(body(key_id=self.key_id))
        # The private test seam: home, proof root and clock are fixed by the library in production and by this in tests.
        seam = mock.patch.dict(ss._SEAM, {"home": self.home, "claude_dir": str(self.claude), "clock": True})
        seam.start()
        self.addCleanup(seam.stop)
        self.main = {"kind": "claude_main", "payload": {"session_id": SID, "transcript_path": str(self.transcript)}}

    # --- fixtures
    def write(self, path, data, mode=0o600):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        Path(path).write_bytes(raw)
        os.chmod(path, mode)

    def pins(self, records=None):
        records = [ss.public_record(self.pub)] if records is None else records
        self.write(ss.pubkeys_path(self.home), {"schema": "self-serve-pubkeys/1", "keys": records})

    def install(self, policy, sign=True, key=None):
        self.pins()
        signed = ss.sign_policy(policy, key or self.key) if sign else policy
        self.write(ss.policy_path(self.home), signed)
        return signed

    def grant(self, cap="merge_reviewed_pr", actor="main", **kw):
        kw.setdefault("now", NOW)
        return ss.grant(cap, actor=self.main if actor == "main" else actor, home=self.home, **kw)

    def why(self, cap="merge_reviewed_pr", actor="main", **kw):
        kw.setdefault("now", NOW)
        return ss.explain(cap, actor=self.main if actor == "main" else actor, home=self.home, **kw)[1]


class ValidGrant(Env):
    def test_main_gets_grant_with_contract_shape(self):
        got = self.grant()
        self.assertEqual(set(got), {"capability", "policy_id", "key_id", "expires_at", "scope"})
        self.assertEqual((got["capability"], got["policy_id"], got["key_id"]), ("merge_reviewed_pr", POLICY_ID, self.key_id))
        self.assertEqual(got["expires_at"], ss.iso(NOW + 86400))

    def test_every_capability_grants(self):
        for cap in ss.CAPABILITIES:
            self.assertIsNotNone(self.grant(cap, evidence=evidence_for(cap)), cap)

    def test_null_expiry_is_allowed(self):
        self.install(body(key_id=self.key_id, expires_at=None))
        self.assertIsNone(self.grant()["expires_at"])

    def test_ttl_clamps_to_policy_expiry(self):
        caps = {"merge_reviewed_pr": {"scope": {}, "ttl_seconds": 60}, "harness_repair": {"scope": {}, "ttl_seconds": 10 ** 9}}
        self.install(body(key_id=self.key_id, capabilities=caps))
        self.assertEqual(self.grant()["expires_at"], ss.iso(NOW + 60))
        self.assertEqual(self.grant("harness_repair")["expires_at"], ss.iso(NOW + 86400))

    def test_codex_root_with_verified_origin_gets_grant(self):
        seen = SimpleNamespace(origin="openai", reason="running_code_verified")
        with mock.patch.object(ss, "_origin_probe", return_value=seen):
            self.assertIsNotNone(self.grant("harness_repair", actor={"kind": "codex_root"}))  # merge class is Claude-only

    def test_codex_root_rejected_for_other_origins(self):
        for seen in (SimpleNamespace(origin="claude", reason="running_claude_code_verified"),
                     SimpleNamespace(origin="unknown", reason="probe_failed"),
                     SimpleNamespace(origin="openai", reason="code_identity_unverified")):
            with mock.patch.object(ss, "_origin_probe", return_value=seen):
                self.assertIsNone(self.grant("harness_repair", actor={"kind": "codex_root"}), seen)
        with mock.patch.object(ss, "_origin_probe", side_effect=RuntimeError("boom")):
            self.assertIsNone(self.grant("harness_repair", actor={"kind": "codex_root"}))


class ActorProof(Env):
    def test_helper_subagent_gets_nothing(self):  # NEG-10
        for extra in ({"agent_id": "a1"}, {"agent_type": "general"}):
            actor = copy.deepcopy(self.main)
            actor["payload"].update(extra)
            self.assertEqual(self.why(actor=actor), "helper_actor")
        seen = SimpleNamespace(origin="openai", reason="running_code_verified")
        with mock.patch.object(ss, "_origin_probe", return_value=seen):
            self.assertIsNone(self.grant("harness_repair", actor={"kind": "codex_root", "payload": {"agent_id": "x"}}))

    def test_unproven_actors(self):
        for actor in (None, {}, {"kind": "main"}, {"kind": "claude_main"}, {"kind": "claude_main", "payload": "x"},
                      "claude_main", {"kind": "claude_main", "payload": {"session_id": SID}}):
            self.assertIsNone(self.grant(actor=actor), actor)

    def test_transcript_outside_projects_is_not_main(self):
        other = Path(self.home) / "elsewhere.jsonl"
        other.write_text("{}\n")
        actor = copy.deepcopy(self.main)
        actor["payload"]["transcript_path"] = str(other)
        self.assertEqual(self.why(actor=actor), "not_main")

    def test_native_runtime_is_not_claude_main(self):
        with mock.patch.object(ci, "native_deny_reason", return_value="native_origin_has_no_main_admission"):
            self.assertEqual(self.why(), "not_main")


class PolicyFailures(Env):
    """AC-6: absent, expired, revoked or tampered policy is today's behavior."""

    def test_absent_policy(self):
        os.unlink(ss.policy_path(self.home))
        self.assertEqual(self.why(), "file_unreadable")

    def test_absent_policy_dir_and_empty_home_write_nothing(self):
        with tempfile.TemporaryDirectory() as empty:
            empty = os.path.realpath(empty)
            self.assertIsNone(ss.grant("merge_reviewed_pr", actor=self.main, now=NOW, home=empty))
            self.assertEqual(os.listdir(empty), [])
            self.assertFalse(ss.status(empty, now=NOW)["enabled"])

    def test_expired(self):
        self.assertIsNone(self.grant(now=NOW + 86400))
        self.assertEqual(self.why(now=NOW + 86401), "expired")
        self.assertIsNotNone(self.grant(now=NOW + 86399))

    def test_not_yet_valid(self):
        self.assertEqual(self.why(now=NOW - 3600 - ss.CLOCK_SKEW_SECONDS - 1), "not_yet_valid")

    def test_inverted_window(self):
        self.install(body(key_id=self.key_id, expires_at=ss.iso(NOW - 7200)))
        self.assertIsNone(self.grant(now=NOW - 7300))

    def test_tampered_body_fails_signature(self):
        signed = json.loads(ss.policy_path(self.home).read_bytes())
        for edit in (lambda p: p["capabilities"]["merge_reviewed_pr"]["scope"].update({"repos": ["a/b"]}),
                     lambda p: p.update(expires_at=None), lambda p: p.update(disabled=["pool_cleanup"]),
                     lambda p: p.update(policy_id="cd" * 16), lambda p: p.update(issued_at=ss.iso(NOW - 10))):
            forged = copy.deepcopy(signed)
            edit(forged)
            self.write(ss.policy_path(self.home), forged)
            self.assertEqual(self.why(), "bad_signature")

    def test_broken_signature_variants(self):
        signed = json.loads(ss.policy_path(self.home).read_bytes())
        for sig in ("", "AAAA", signed["signature"][:-2], signed["signature"] + "=", "!!!!", signed["signature"][::-1]):
            forged = dict(signed, signature=sig)
            self.write(ss.policy_path(self.home), forged)
            self.assertIsNone(self.grant(), sig)
        self.write(ss.policy_path(self.home), dict(signed, signature=7))
        self.assertIsNone(self.grant())

    def test_signature_by_unpinned_key(self):  # NEG-2 forged enable
        other, _ = make_key()
        self.install(body(key_id=self.key_id), key=other)
        self.assertEqual(self.why(), "bad_signature")

    def test_wrong_key_id(self):  # NEG-2
        self.install(body(key_id="0123456789abcdef"))
        self.assertEqual(self.why(), "key_not_pinned")

    def test_deleted_pins_give_no_grant_not_a_crash(self):
        os.unlink(ss.pubkeys_path(self.home))
        self.assertEqual(self.why(), "file_unreadable")

    def test_signing_key_file_absent_is_irrelevant_to_verification(self):
        self.assertFalse(ss.private_key_path(self.home).exists())
        self.assertIsNotNone(self.grant())

    def test_revoked_pin_record(self):
        self.pins([dict(ss.public_record(self.pub), revoked=True)])
        self.assertEqual(self.why(), "key_not_pinned")

    def test_pin_record_with_wrong_key_id_is_malformed(self):
        self.pins([dict(ss.public_record(self.pub), key_id="0" * 16)])
        self.assertEqual(self.why(), "pins_malformed")

    def test_pin_file_garbage(self):
        for raw in (b"", b"[]", b"{", b'{"schema":"x","keys":[]}', b'{"schema":"self-serve-pubkeys/1","keys":{}}'):
            self.write(ss.pubkeys_path(self.home), raw)
            self.assertIsNone(self.grant(), raw)

    def test_wrong_purpose_even_if_validly_signed(self):  # NEG-2
        for purpose in ("decision", "", None, "self-serve ", "Self-Serve"):
            self.install(body(key_id=self.key_id, purpose=purpose))
            self.assertIsNone(self.grant(), purpose)

    def test_wrong_schema_and_extra_keys(self):
        for edit in ({"schema": "self-serve/2"}, {"extra": 1}, {"policy_id": "short"}, {"key_id": "ZZ" * 8},
                     {"issued_at": "2026-11-23 00:00:00"}, {"expires_at": 5}, {"capabilities": []}):
            self.install(body(**dict({"key_id": self.key_id}, **edit)))
            self.assertIsNone(self.grant(), edit)

    def test_unknown_capability_in_policy_fails_whole_policy(self):
        caps = {"merge_reviewed_pr": {"scope": {}}, "take_a_password": {"scope": {}}}
        self.install(body(key_id=self.key_id, capabilities=caps))
        self.assertEqual(self.why(), "unknown_capability")

    def test_unknown_capability_requested(self):
        for cap in ("take_a_password", "", None, 5, "MERGE_REVIEWED_PR"):
            self.assertIsNone(self.grant(cap), cap)

    def test_bad_capability_entries(self):
        for entry in ({}, {"scope": []}, {"scope": {}, "ttl_seconds": 0}, {"scope": {}, "ttl_seconds": True},
                      {"scope": {}, "ttl_seconds": "5"}, {"scope": {}, "x": 1}, {"scope": {"repos": "a/b"}},
                      {"scope": {"denylist_paths": [1]}}, {"scope": {"single_use": "yes"}}):
            self.install(body(key_id=self.key_id, capabilities={"merge_reviewed_pr": entry}))
            self.assertIsNone(self.grant(), entry)

    def test_capability_not_in_policy(self):
        self.install(body(key_id=self.key_id, capabilities={"merge_reviewed_pr": {"scope": {}}}))
        self.assertIsNotNone(self.grant())
        self.assertEqual(self.why("harness_repair"), "capability_not_granted")

    def test_disabled_capability(self):
        self.install(body(key_id=self.key_id, disabled=["merge_reviewed_pr"]))
        self.assertEqual(self.why(), "capability_disabled")
        self.assertIsNotNone(self.grant("harness_repair"))
        self.install(body(key_id=self.key_id, disabled=["nope"]))
        self.assertIsNone(self.grant("harness_repair"))

    def test_duplicate_json_keys_rejected(self):
        signed = json.dumps(json.loads(ss.policy_path(self.home).read_bytes()))
        dup = signed[:-1] + ', "purpose": "self-serve"}'
        self.write(ss.policy_path(self.home), dup.encode())
        self.assertEqual(self.why(), "policy_json")

    def test_non_finite_and_non_object_json(self):
        for raw in (b"NaN", b"[]", b'"x"', b"null", b"\xff\xfe", b"{" * 5000):
            self.write(ss.policy_path(self.home), raw)
            self.assertIsNone(self.grant(), raw[:10])

    def test_oversize_policy(self):
        self.write(ss.policy_path(self.home), b" " * (ss.MAX_BYTES + 1))
        self.assertEqual(self.why(), "file_too_large")

    def test_file_modes_and_types(self):
        path = ss.policy_path(self.home)
        for mode in (0o660, 0o640, 0o604, 0o666):
            os.chmod(path, mode)
            self.assertEqual(self.why(), "file_unsafe", oct(mode))
        os.chmod(path, 0o400)
        self.assertIsNotNone(self.grant())

    def test_symlinked_policy_refused(self):
        real = Path(self.home) / "real.json"
        real.write_bytes(ss.policy_path(self.home).read_bytes())
        os.chmod(real, 0o600)
        os.unlink(ss.policy_path(self.home))
        os.symlink(real, ss.policy_path(self.home))
        self.assertEqual(self.why(), "file_unreadable")

    def test_hardlinked_policy_refused(self):
        os.link(ss.policy_path(self.home), Path(self.home) / "second")
        self.assertEqual(self.why(), "file_unsafe")

    def test_fifo_policy_refused_without_blocking(self):
        os.unlink(ss.policy_path(self.home))
        os.mkfifo(ss.policy_path(self.home), 0o600)
        self.assertEqual(self.why(), "file_unsafe")

    def test_writable_policy_dir_refused(self):
        os.chmod(ss.policy_dir(self.home), 0o770)
        self.assertEqual(self.why(), "policy_dir_unsafe")

    def test_symlinked_policy_dir_refused(self):
        moved = Path(self.home) / "moved"
        os.rename(ss.policy_dir(self.home), moved)
        os.symlink(moved, ss.policy_dir(self.home))
        self.assertEqual(self.why(), "policy_dir_unsafe")

    def test_bad_clock_values(self):
        for now in (float("nan"), "x", True, [1]):
            self.assertIsNone(ss.grant("merge_reviewed_pr", actor=self.main, now=now, home=self.home), now)


class PurposeBinding(Env):
    """A signature by the central-decisions key must not verify (NEG-2)."""

    def decisions_style_sign(self, policy):
        import central_decisions as cd
        sig = self.key.sign(cd.signed_message("tc-1", cd.canonical(policy)))
        return dict(policy, signature=ss.b64url(sig))

    def test_decisions_domain_signature_does_not_verify_even_if_key_pinned_for_self_serve(self):
        policy = body(key_id=self.key_id)
        self.write(ss.policy_path(self.home), self.decisions_style_sign(policy))
        self.assertEqual(self.why(), "bad_signature")

    def test_signature_without_the_self_serve_domain_does_not_verify(self):
        policy = body(key_id=self.key_id)
        self.write(ss.policy_path(self.home), dict(policy, signature=ss.b64url(self.key.sign(ss.canonical(policy)))))
        self.assertEqual(self.why(), "bad_signature")

    def test_key_pinned_only_for_decisions_gives_no_grant(self):
        import central_decisions as cd
        record = {"key_id": cd.key_id_of(self.pub), "public_key": ss.b64url(self.pub), "purpose": "decision"}
        self.pins([record])
        policy = body(key_id=cd.key_id_of(self.pub))
        self.write(ss.policy_path(self.home), ss.sign_policy(policy, self.key))
        self.assertEqual(self.why(), "key_not_pinned")

    def test_decisions_key_id_does_not_match_self_serve_key_id(self):
        import central_decisions as cd
        self.assertNotEqual(cd.key_id_of(self.pub), ss.key_id_of(self.pub))

    def test_pin_record_for_another_purpose_is_ignored(self):
        self.pins([dict(ss.public_record(self.pub), purpose="decision")])
        self.assertEqual(self.why(), "key_not_pinned")

    def test_real_central_decisions_pin_file_is_not_consulted(self):
        pin = Path(self.home) / ".agent-harness" / "decisions"
        pin.mkdir(parents=True)
        self.write(pin / "trusted-keys.json", {"keys": [{"key_id": self.key_id}]})
        self.pins([])
        self.assertEqual(self.why(), "key_not_pinned")


class KillSwitchAndRevoke(Env):
    """NEG-6: any agent may revoke, it is honoured at once, and nothing here can undo it."""

    def test_kill_switch_file_refuses_everything(self):
        for cap in ss.CAPABILITIES:
            self.assertIsNotNone(self.grant(cap, evidence=evidence_for(cap)))
        Path(ss.kill_switch_path(self.home)).write_text("")
        for cap in ss.CAPABILITIES:
            self.assertEqual(self.why(cap), "kill_switch", cap)
        self.assertTrue(ss.status(self.home, now=NOW)["kill_switch"])
        self.assertFalse(ss.status(self.home, now=NOW)["enabled"])

    def test_kill_switch_as_directory_or_symlink_still_counts(self):
        os.mkdir(ss.kill_switch_path(self.home))
        self.assertEqual(self.why(), "kill_switch")
        os.rmdir(ss.kill_switch_path(self.home))
        os.symlink("/nonexistent-target", ss.kill_switch_path(self.home))
        self.assertEqual(self.why(), "kill_switch")

    def test_unreadable_policy_dir_is_a_kill_switch(self):
        with mock.patch.object(ss.os, "lstat", side_effect=PermissionError()):
            self.assertTrue(ss.kill_switch_active(self.home))
            self.assertIsNone(self.grant())

    def test_revoke_all_is_immediate(self):
        self.assertIsNotNone(self.grant())
        self.assertTrue(ss.revoke("all", home=self.home))
        for cap in ss.CAPABILITIES:
            self.assertEqual(self.why(cap), "revoked")
        self.assertEqual(ss.status(self.home, now=NOW)["reason"], "revoked")

    def test_revoke_policy_id_only_that_policy(self):
        self.assertTrue(ss.revoke(POLICY_ID, home=self.home))
        self.assertEqual(self.why(), "revoked")
        self.install(body(key_id=self.key_id, policy_id="cd" * 16))  # a newly signed policy, signed by the user's key
        self.assertIsNotNone(self.grant())

    def test_revoke_one_capability(self):
        self.assertTrue(ss.revoke("pool_cleanup", home=self.home))
        self.assertEqual(self.why("pool_cleanup"), "revoked")
        self.assertIsNotNone(self.grant("harness_repair"))
        self.assertNotIn("pool_cleanup", ss.status(self.home, now=NOW)["capabilities"])

    def test_revoke_is_idempotent_and_validates_targets(self):
        self.assertTrue(ss.revoke("all", home=self.home))
        self.assertTrue(ss.revoke("all", home=self.home))
        for bad in ("../x", "", None, "ab" * 15, "unknown_cap", "ALL"):
            self.assertFalse(ss.revoke(bad, home=self.home), bad)
        self.assertEqual(sorted(os.listdir(ss.revoked_dir(self.home))), ["all"])

    def test_revoke_works_with_no_policy_and_does_not_need_proof(self):
        os.unlink(ss.policy_path(self.home))
        self.assertTrue(ss.revoke("all", home=self.home))

    def test_module_offers_no_reenable_path(self):
        for name in dir(ss):
            self.assertFalse(name.startswith(("enable", "unrevoke", "unrevoke", "reenable", "clear", "unkill")), name)

    def test_revoked_path_that_is_not_a_directory_fails_closed(self):
        Path(ss.revoked_dir(self.home)).write_text("x")
        self.assertEqual(self.why(), "revoked")

    def test_status_after_revoke_lists_no_enabled(self):
        ss.revoke(POLICY_ID, home=self.home)
        got = ss.status(self.home, now=NOW)
        self.assertFalse(got["enabled"])
        self.assertTrue(got["revoked"])


class Scope(Env):
    def scoped(self, scope, cap="merge_reviewed_pr", **extra):
        self.install(body(key_id=self.key_id, capabilities={cap: dict({"scope": scope}, **extra)}))

    def test_scope_is_returned_as_a_copy(self):
        self.scoped({"repos": ["o/r"], "note": {"a": 1}})
        got = self.grant(evidence={"repo": "o/r"})
        got["scope"]["note"]["a"] = 2
        self.assertEqual(self.grant(evidence={"repo": "O/R"})["scope"]["note"]["a"], 1)

    def test_repos(self):
        self.scoped({"repos": ["o/r"]})
        self.assertIsNotNone(self.grant(evidence={"repo": "o/r"}))
        for ev in (None, {}, {"repo": "o/other"}, {"repo": 5}, "o/r", {"repo": ""}):
            self.assertIsNone(self.grant(evidence=ev), ev)

    def test_denylist_paths(self):
        self.scoped({"denylist_paths": ["harness/hooks/self_serve*", "*migrations/*", "**/secrets*"]})
        ok = {"changed_paths": ["docs/a.md", "src/x.py"]}
        self.assertIsNotNone(self.grant(evidence=ok))
        for paths in (["harness/hooks/self_serve.py"], ["./harness/hooks/Self_Serve.py"], ["db/migrations/001.sql"],
                      ["a/b/secrets.env"], ["docs/a.md", "harness/hooks/self_serve_x.py"], ["/harness/hooks/self_serve.py"],
                      ["harness//hooks/../hooks/self_serve.py"]):
            self.assertEqual(self.why(evidence={"changed_paths": paths}), "path_denylisted", paths)
        for ev in (None, {}, {"changed_paths": []}, {"changed_paths": "docs/a.md"}, {"changed_paths": [1]}):
            self.assertIsNone(self.grant(evidence=ev), ev)

    def test_single_use_is_spent_only_by_consume(self):  # the full matrix is in test_self_serve_repair
        self.scoped({"single_use": True})
        pr = {"repo": "o/r", "pr": 1, "head": "abc"}
        self.assertEqual(self.why(evidence=pr), "single_use_requires_consume")
        self.assertIsNone(self.grant(evidence=pr))
        spent = lambda ev: ss.explain("merge_reviewed_pr", actor=self.main, home=self.home, now=NOW, evidence=ev, consume=True)  # noqa: E731
        self.assertEqual(spent({})[1], "use_binding_required")
        self.assertEqual(spent(pr)[1], "granted")
        self.assertEqual(spent(pr)[1], "already_used")
        self.assertEqual(spent(dict(pr, pr=2))[1], "granted")

    def test_evidence_must_be_a_mapping(self):
        self.assertIsNone(self.grant(evidence=["x"]))

    def test_repo_file_can_only_narrow(self):
        self.scoped({"repos": ["o/r", "o/s"], "denylist_paths": ["a/*"]})
        ev = {"repo": "o/r", "changed_paths": ["b/x"]}
        self.assertIsNotNone(self.grant(evidence=ev))
        self.assertIsNone(self.grant(evidence=dict(ev, repo_narrowing={"repos": ["o/s"]})))  # narrows away o/r
        self.assertIsNone(self.grant(evidence=dict(ev, repo_narrowing={"denylist_paths": ["b/*"]})))
        self.assertIsNone(self.grant(evidence=dict(ev, repo_narrowing={"disable": ["merge_reviewed_pr"]})))

    def test_repo_file_cannot_widen(self):
        self.scoped({"repos": ["o/r"], "denylist_paths": ["a/*"]})
        wide = {"repos": ["o/r", "evil/x"], "denylist_paths": [], "allow": ["a/*"], "capabilities": ["harness_repair"],
                "scope": {"repos": ["evil/x"]}, "disable": []}
        self.assertIsNone(self.grant(evidence={"repo": "evil/x", "changed_paths": ["b"], "repo_narrowing": wide}))
        self.assertIsNone(self.grant(evidence={"repo": "o/r", "changed_paths": ["a/x"], "repo_narrowing": wide}))
        self.assertIsNone(self.grant("harness_repair", evidence={"repo_narrowing": wide}))  # not in this policy

    def test_narrowing_malformed_fails_closed(self):
        for bad in ("x", ["a"], {"repos": "o/r"}, {"disable": [1]}):
            self.assertIsNone(self.grant(evidence={"repo_narrowing": bad}), bad)

    def test_narrowing_repos_when_policy_has_none(self):
        self.assertIsNotNone(self.grant(evidence={"repo": "o/r"}))
        self.assertIsNone(self.grant(evidence={"repo": "o/x", "repo_narrowing": {"repos": ["o/r"]}}))
        self.assertIsNotNone(self.grant(evidence={"repo": "o/r", "repo_narrowing": {"repos": ["o/r"]}}))


class NeverRaises(Env):
    def test_internal_errors_become_none(self):
        for target in ("_load_policy", "_prove_actor", "kill_switch_active", "_revoked", "_audit", "_crypto"):
            with mock.patch.object(ss, target, side_effect=RuntimeError("boom")):
                self.assertIsNone(self.grant(), target)
                self.assertIsInstance(ss.status(self.home, now=NOW), dict)
                if target not in ("_prove_actor", "_audit"):  # status never proves an actor or audits
                    self.assertFalse(ss.status(self.home, now=NOW)["enabled"], target)

    def test_missing_cryptography_is_no_grant(self):
        with mock.patch.dict(sys.modules, {"cryptography": None, "cryptography.exceptions": None}):
            self.assertEqual(self.why(), "no_crypto")

    def test_odd_arguments(self):
        for kwargs in ({"actor": 5}, {"actor": None}, {"evidence": 5}, {"home": 5}, {"home": b"\xff"}):
            kw = dict({"actor": self.main, "home": self.home, "now": NOW}, **kwargs)
            self.assertIsNone(ss.grant("merge_reviewed_pr", **kw), kwargs)

    def test_audit_failure_means_no_grant(self):
        os.makedirs(ss.audit_path(self.home).parent)
        os.mkdir(ss.audit_path(self.home))  # unwritable as a log
        self.assertIsNone(self.grant())

    def test_fuzzed_policy_files_never_raise_or_grant(self):
        rng = random.Random(SEED)
        good = ss.policy_path(self.home).read_bytes()
        for _ in range(300):
            raw = bytearray(good)
            for _ in range(rng.randint(1, 6)):
                kind = rng.choice("flip drop insert trunc".split())
                if not raw:
                    break
                i = rng.randrange(len(raw))
                if kind == "flip":
                    raw[i] ^= 1 << rng.randrange(8)
                elif kind == "drop":
                    del raw[i]
                elif kind == "insert":
                    raw.insert(i, rng.randrange(256))
                else:
                    del raw[i:]
            if bytes(raw) == good:
                continue
            self.write(ss.policy_path(self.home), bytes(raw))
            got, _ = ss.explain("merge_reviewed_pr", actor=self.main, now=NOW, home=self.home)
            if got is not None:  # a mutation that kept the signed bytes meaningful is only OK if it re-verifies
                self.assertEqual(json.loads(bytes(raw))["signature"], json.loads(good)["signature"])
                self.assertEqual({k: v for k, v in json.loads(bytes(raw)).items() if k != "signature"},
                                 {k: v for k, v in json.loads(good).items() if k != "signature"})


class AuditAndStatus(Env):
    def test_grant_writes_an_audit_row_without_secrets(self):
        self.grant()
        rows = [json.loads(line) for line in ss.audit_path(self.home).read_text().splitlines()]
        self.assertEqual([r["event"] for r in rows], ["grant"])
        self.assertEqual(set(rows[0]), {"at", "event", "capability", "policy_id", "actor", "expires_at"})
        self.assertEqual(oct(os.stat(ss.audit_path(self.home)).st_mode & 0o777), "0o600")

    def test_denials_write_nothing(self):
        self.assertIsNone(self.grant("nope"))
        self.assertFalse(ss.audit_path(self.home).exists())

    def test_status_shape(self):
        self.install(body(key_id=self.key_id, disabled=["pool_cleanup"]))
        got = ss.status(self.home, now=NOW)
        self.assertEqual(set(got), {"enabled", "policy_id", "capabilities", "disabled", "key_id", "kill_switch",
                                    "revoked", "expires_at", "reason"})
        self.assertEqual((got["policy_id"], got["key_id"], got["disabled"]), (POLICY_ID, self.key_id, ["pool_cleanup"]))
        self.assertNotIn("pool_cleanup", got["capabilities"])
        self.assertEqual(len(got["capabilities"]), 5)

    def test_status_on_failure_is_disabled(self):
        os.unlink(ss.policy_path(self.home))
        got = ss.status(self.home, now=NOW)
        self.assertFalse(got["enabled"])
        self.assertEqual(got["capabilities"], [])

    def test_paths_match_the_contract(self):
        self.assertEqual(ss.policy_path("/h"), Path("/h/.agent-harness/policy/self-serve.json"))
        self.assertEqual(ss.kill_switch_path("/h"), Path("/h/.agent-harness/policy/disabled"))
        self.assertEqual(ss.private_key_path("/h"), Path("/h/.agent-harness/private/self-serve/ed25519.key"))
        self.assertEqual(ss.policy_path(), Path(self.home) / ".agent-harness/policy/self-serve.json")  # the armed test home
        account = os.path.join(self.home, "account")  # production: the account's home from the password database, not $HOME
        entry = SimpleNamespace(pw_dir=account)
        with mock.patch.dict(ss._SEAM, {"home": None}), mock.patch.object(ss.pwd, "getpwuid", return_value=entry), \
                mock.patch.dict(os.environ, {"HOME": "/elsewhere"}):
            self.assertEqual(ss.policy_path(), Path(account) / ".agent-harness/policy/self-serve.json")


class ImportSafety(unittest.TestCase):
    def test_import_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.realpath(tmp)
            code = ("import sys; sys.path.insert(0, %r); import self_serve; "
                    "bad = [m for m in ('cryptography', 'native_context', 'caller_identity') if m in sys.modules]; "
                    "print(','.join(bad))" % HOOKS)
            out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=home,
                                 env={"HOME": home, "PATH": os.environ.get("PATH", "")}, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout.strip(), "")
            self.assertEqual(os.listdir(home), [])

    def test_cli_status_is_read_only_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.realpath(tmp)
            # The test seam stands in for the account home, so this stays hermetic on a machine that has a real policy.
            code = ("import sys; sys.path.insert(0, %r); import self_serve; self_serve._SEAM['home'] = %r; "
                    "raise SystemExit(self_serve.main(['status']))" % (HOOKS, home))
            out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=home,
                                 env={"HOME": home, "PATH": os.environ.get("PATH", "")}, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(json.loads(out.stdout)["enabled"])
            self.assertEqual(os.listdir(home), [])

    def test_the_real_cli_prints_json_and_leaves_a_foreign_home_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.realpath(tmp)
            account = os.path.join(home, "account")  # the child's password-database home: empty, so nothing real is read
            os.mkdir(account)
            code = ("import pwd, runpy, sys, types; pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_dir=%r); "
                    "sys.argv = ['self_serve.py', 'status']; runpy.run_path(%r, run_name='__main__')"
                    % (account, os.path.join(HOOKS, "self_serve.py")))
            out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=home,
                                 env={"HOME": home, "PATH": os.environ.get("PATH", "")}, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(json.loads(out.stdout)["enabled"])
            self.assertEqual(os.listdir(account), [])
            self.assertEqual(os.listdir(home), ["account"])


class SchemaFile(unittest.TestCase):
    def test_schema_matches_the_closed_capability_list_and_policy_fields(self):
        schema = json.loads((Path(HOOKS).parents[1] / "docs" / "self-serve-policy.schema.json").read_text())
        self.assertEqual(tuple(schema["properties"]["capabilities"]["properties"]), ss.CAPABILITIES)
        self.assertEqual(tuple(schema["properties"]["disabled"]["items"]["enum"]), ss.CAPABILITIES)
        self.assertEqual(set(schema["properties"]), ss.TOP_KEYS)
        self.assertFalse(schema["additionalProperties"])

    def test_signed_fixture_fits_the_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((Path(HOOKS).parents[1] / "docs" / "self-serve-policy.schema.json").read_text())
        key, pub = make_key()
        jsonschema.validate(ss.sign_policy(body(key_id=ss.key_id_of(pub)), key), schema)


if __name__ == "__main__":
    unittest.main()
