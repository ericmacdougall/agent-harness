"""Network-free installer rehearsals using the actual fixed host agent.

Deterministic safety contracts have zero allowed false acceptances. Every
negative case asserts refusal and preserved installed bytes. No statistical
reliability claim is made from this finite regression corpus.
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/bootstrap_native_review.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_native_review", SCRIPT)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.homes = {host: self.root / host for host in bootstrap.HOSTS}
        self.payloads = {name: base64.b64encode(("# new " + name + "\n").encode()).decode()
                         for name in bootstrap.FILES}
        hosts = {}
        for host, home in self.homes.items():
            hosts[host] = {}
            for edition in bootstrap.EDITIONS:
                directory = home / edition
                directory.mkdir(parents=True)
                hosts[host][edition] = {}
                for index, name in enumerate(bootstrap.FILES):
                    old = None
                    if index > 1:
                        value = ("# old " + host + edition + name + "\n").encode()
                        (directory / name).write_bytes(value)
                        (directory / name).chmod(0o600)
                        old = {"sha256": bootstrap.sha(value), "mode": 0o600}
                    hosts[host][edition][name] = old
        self.manifest = {"version": 1, "repository": bootstrap.REPOSITORY,
                         "candidate": "a" * 40, "bootstrap_sha256": bootstrap.sha(SCRIPT.read_bytes()),
                         "payloads": {name: bootstrap.sha(base64.b64decode(value))
                                      for name, value in self.payloads.items()}, "hosts": hosts,
                         "qualification": {key: "b" * 64 for key in ("spec_core_sha256", "acceptance_report_sha256", "adversarial_report_sha256", "tests_evidence_sha256")}}
        self.transaction = bootstrap.sha(json.dumps(self.manifest, sort_keys=True).encode())
        self.events = []

    def request(self, host, phase):
        return {"phase": phase, "transaction": self.transaction,
                "expected": self.manifest["hosts"][host], "payloads": self.payloads}

    def agent(self, host, request):
        self.events.append((host, request["phase"]))
        source = bootstrap.AGENT_SOURCE + "\nprint(json.dumps(run_agent(json.loads(sys.stdin.read()))))\n"
        result = subprocess.run([sys.executable, "-c", source], input=json.dumps(request).encode(),
                                env=dict(os.environ, HOME=str(self.homes[host])),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        return json.loads(result.stdout)

    def run_phase(self, host, phase):
        return self.agent(host, self.request(host, phase))

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mode & 0o7777)
                for home in self.homes.values() for edition in bootstrap.EDITIONS
                for path in (home / edition).iterdir() if path.is_file()}

    def state(self, host):
        return self.homes[host] / ".agent-harness/work/native-review-bootstrap" / self.transaction

    def transaction_run(self, mode, runner=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return bootstrap.transact(self.manifest, self.payloads, mode, runner or self.agent)

    def five_generation(self):
        # Extracted read-only using ast.literal_eval from the real committed
        # 7f2c954951a0d977ba40f1283b20ff86c19ad820 AGENT_SOURCE. The test
        # requires no Git executable or repository history at runtime.
        source = bootstrap.AGENT_SOURCE.replace(', "ticket_adapters.py")', ')')
        self.assertEqual(bootstrap.sha(source.encode()),
                         "ed318f23fd02612ceb6c939290721bbe936a6f5c4ec319bc1589e666954c583a")
        manifest = json.loads(json.dumps(self.manifest))
        del manifest["payloads"]["ticket_adapters.py"]
        for host in bootstrap.HOSTS:
            for edition in bootstrap.EDITIONS:
                del manifest["hosts"][host][edition]["ticket_adapters.py"]
        transaction = bootstrap.sha(json.dumps(manifest, sort_keys=True).encode())
        def request(host, phase):
            return {"phase": phase, "transaction": transaction,
                    "expected": manifest["hosts"][host],
                    "payloads": {name: value for name, value in self.payloads.items()
                                 if name != "ticket_adapters.py"}}
        return source, request

    def test_five_prepared_reservation_blocks_six_and_wrong_generation_rollback(self):
        source, old_request = self.five_generation()
        before = self.snapshot()
        with mock.patch.object(bootstrap, "AGENT_SOURCE", source):
            for host in bootstrap.HOSTS:
                self.agent(host, old_request(host, "prepare"))
        for host in bootstrap.HOSTS:
            for phase in ("check", "prepare", "rollback-check", "rollback"):
                with self.subTest(host=host, phase=phase), self.assertRaisesRegex(RuntimeError, "another target transaction"):
                    self.run_phase(host, phase)
        self.assertEqual(before, self.snapshot())

    def test_six_prepared_reservation_blocks_old_five_rollback(self):
        source, old_request = self.five_generation()
        before = self.snapshot()
        for host in bootstrap.HOSTS:
            self.run_phase(host, "prepare")
        with mock.patch.object(bootstrap, "AGENT_SOURCE", source):
            for host in bootstrap.HOSTS:
                for phase in ("prepare", "rollback-check", "rollback"):
                    with self.subTest(host=host, phase=phase), self.assertRaisesRegex(RuntimeError, "another target transaction"):
                        self.agent(host, old_request(host, phase))
        self.assertEqual(before, self.snapshot())

    def test_old_five_crash_lock_blocks_new_six_even_without_active_record(self):
        source, old_request = self.five_generation()
        with mock.patch.object(bootstrap, "AGENT_SOURCE", source):
            self.agent("local", old_request("local", "prepare"))
        root = self.state("local").parent
        (root / "active.json").unlink()
        (root / "target-lock").mkdir()
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.run_phase("local", "prepare")
        self.assertEqual(before, self.snapshot())

    def test_old_five_recovery_then_six_transaction_restores_all_bytes_and_modes(self):
        source, old_request = self.five_generation()
        before = self.snapshot()
        with mock.patch.object(bootstrap, "AGENT_SOURCE", source):
            for phase in ("prepare", "apply-check", "apply", "verify", "finalize",
                          "rollback-check", "rollback-prepare", "rollback", "rollback-verify", "rollback-finalize"):
                for host in bootstrap.HOSTS:
                    self.agent(host, old_request(host, phase))
        self.assertEqual(before, self.snapshot())
        self.transaction_run("apply")
        for home in self.homes.values():
            for edition in bootstrap.EDITIONS:
                self.assertEqual((home / edition / "ticket_adapters.py").read_bytes(),
                                 base64.b64decode(self.payloads["ticket_adapters.py"]))
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_cross_generation_reservation_mutant_accepts_forbidden_overlap(self):
        source, old_request = self.five_generation()
        with mock.patch.object(bootstrap, "AGENT_SOURCE", source):
            self.agent("local", old_request("local", "prepare"))
        with self.assertRaisesRegex(RuntimeError, "another target transaction"):
            self.run_phase("local", "prepare")
        # This controlled mutant removes both common active-record guards.
        # Its unsafe prepare proves the preceding refusal is non-vacuous.
        guard = 'active["transaction"] != transaction and active["state"] not in ("verified", "rolled-back")'
        self.assertEqual(bootstrap.AGENT_SOURCE.count(guard), 2)
        mutant = bootstrap.AGENT_SOURCE.replace(guard, "False")
        before = self.snapshot()
        with mock.patch.object(bootstrap, "AGENT_SOURCE", mutant):
            accepted = self.run_phase("local", "prepare")
        self.assertEqual(accepted["phase"], "prepared")
        self.assertEqual(before, self.snapshot())

    def test_check_is_read_only_and_both_hosts(self):
        before = self.snapshot()
        self.transaction_run("check")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.events, [(host, "check") for host in bootstrap.HOSTS])
        self.assertFalse(self.state("local").exists())

    def test_actual_two_host_install_and_guarded_rollback(self):
        before = self.snapshot()
        self.transaction_run("apply")
        self.assertEqual(self.events[:4], [("local", "check"), ("t2-dev", "check"),
                                          ("local", "prepare"), ("t2-dev", "prepare")])
        for home in self.homes.values():
            for edition in bootstrap.EDITIONS:
                for name in bootstrap.FILES:
                    path = home / edition / name
                    self.assertEqual(path.read_bytes(), base64.b64decode(self.payloads[name]))
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_other_host_drift_prevents_all_writes(self):
        (self.homes["t2-dev"] / bootstrap.EDITIONS[0] / "spec_flow.py").write_text("drift")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.transaction_run("apply")
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.state("local").exists())

    def test_new_file_must_be_absent(self):
        path = self.homes["local"] / bootstrap.EDITIONS[0] / "native_pr_review.py"
        path.write_text("unexpected")
        path.chmod(0o600)
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.transaction_run("apply")
        self.assertEqual(before, self.snapshot())

    def test_symlink_payload_refused(self):
        target = self.homes["local"] / bootstrap.EDITIONS[0] / "native_pr_review.py"
        target.symlink_to(self.root / "missing")
        with self.assertRaises(RuntimeError):
            self.transaction_run("apply")
        self.assertTrue(target.is_symlink())

    def test_post_prepare_remote_backup_corruption_prevents_both_host_writes(self):
        before = self.snapshot()
        def corrupt(host, request):
            result = self.agent(host, request)
            if (host, request["phase"]) == ("t2-dev", "prepare"):
                (self.state(host) / "2.backup").write_text("corrupted after prepare")
            return result
        with self.assertRaisesRegex(RuntimeError, "backup missing or digest mismatch"):
            self.transaction_run("apply", corrupt)
        self.assertEqual(before, self.snapshot())
        self.assertNotIn(("local", "apply"), self.events)

    def test_missing_empty_backup_refused_before_apply_and_rollback(self):
        path = self.homes["local"] / bootstrap.EDITIONS[0] / "spec_flow.py"
        path.write_bytes(b"")
        self.manifest["hosts"]["local"][bootstrap.EDITIONS[0]]["spec_flow.py"] = {"sha256": bootstrap.sha(b""), "mode": 0o600}
        self.transaction = bootstrap.sha(json.dumps(self.manifest, sort_keys=True).encode())
        self.run_phase("local", "prepare")
        (self.state("local") / "2.backup").unlink()
        before = self.snapshot()
        for phase in ("apply-check", "apply", "rollback-check", "rollback"):
            with self.subTest(phase=phase), self.assertRaisesRegex(RuntimeError, "backup missing"):
                self.run_phase("local", phase)
        self.assertEqual(before, self.snapshot())

    def test_both_hosts_prepared_before_apply_and_prepare_failure_halts(self):
        def fail_remote(host, request):
            if (host, request["phase"]) == ("t2-dev", "prepare"):
                raise RuntimeError("unknown transport outcome")
            return self.agent(host, request)
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "unknown transport"):
            self.transaction_run("apply", fail_remote)
        self.assertEqual(before, self.snapshot())
        self.assertTrue((self.state("local") / "journal.json").exists())
        self.assertNotIn(("local", "apply"), self.events)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())
        for host in bootstrap.HOSTS:
            active = json.loads((self.state(host).parent / "active.json").read_text())
            self.assertEqual(active["state"], "rolled-back")

    def test_unknown_unprepared_remote_changes_refuse_abort(self):
        self.run_phase("local", "prepare")
        path = self.homes["t2-dev"] / bootstrap.EDITIONS[0] / "spec_flow.py"
        path.write_text("unknown remote change")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(json.loads((self.state("local").parent / "active.json").read_text())["state"], "prepared")

    def test_second_verify_failure_keeps_first_host_reserved(self):
        def fail_remote(host, request):
            if (host, request["phase"]) == ("t2-dev", "verify"):
                raise RuntimeError("unknown second verification")
            return self.agent(host, request)
        with self.assertRaisesRegex(RuntimeError, "second verification"):
            self.transaction_run("apply", fail_remote)
        active = json.loads((self.state("local").parent / "active.json").read_text())
        self.assertEqual(active["state"], "verified-pending")
        competing = self.request("local", "prepare")
        competing["transaction"] = "c" * 64
        with self.assertRaisesRegex(RuntimeError, "another target transaction"):
            self.agent("local", competing)
        self.assertNotIn(("local", "finalize"), self.events)

    def test_partial_rollback_keeps_both_reservations(self):
        self.transaction_run("apply")
        def fail_remote(host, request):
            if (host, request["phase"]) == ("t2-dev", "rollback"):
                raise RuntimeError("unknown rollback")
            return self.agent(host, request)
        with self.assertRaisesRegex(RuntimeError, "unknown rollback"):
            self.transaction_run("rollback", fail_remote)
        active = json.loads((self.state("local").parent / "active.json").read_text())
        self.assertEqual(active["state"], "rolled-back-pending")
        remote_active = json.loads((self.state("t2-dev").parent / "active.json").read_text())
        self.assertEqual(remote_active["state"], "rolling-back")
        competing = self.request("local", "prepare")
        competing["transaction"] = "d" * 64
        with self.assertRaisesRegex(RuntimeError, "another target transaction"):
            self.agent("local", competing)
        # Explicit retry rechecks old/new bytes and can finish both hosts.
        self.transaction_run("rollback")
        for host in bootstrap.HOSTS:
            active = json.loads((self.state(host).parent / "active.json").read_text())
            self.assertEqual(active["state"], "rolled-back")

    def test_rollback_reserves_before_first_write_even_from_verified(self):
        self.transaction_run("apply")
        original = bootstrap.AGENT_SOURCE
        mutant = original.replace('atomic(path, backup, mode=old["mode"])', 'raise ValueError("injected restore interruption")')
        self.assertNotEqual(original, mutant)
        with mock.patch.object(bootstrap, "AGENT_SOURCE", mutant), \
             self.assertRaisesRegex(RuntimeError, "injected restore interruption"):
            self.run_phase("local", "rollback")
        active = json.loads((self.state("local").parent / "active.json").read_text())
        self.assertEqual(active["state"], "rolling-back")

    def test_writable_target_ancestor_refused(self):
        (self.homes["local"] / ".claude").chmod(0o777)
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "untrusted directory"):
            self.transaction_run("apply")
        self.assertEqual(before, self.snapshot())

    def test_writable_cache_ancestor_refused(self):
        home = self.homes["local"]
        bootstrap.cached_payloads(self.manifest, self.payloads, home=home)
        (home / ".agent-harness/work").chmod(0o777)
        with self.assertRaisesRegex(ValueError, "untrusted directory"):
            bootstrap.cached_payloads(self.manifest, home=home)

    def test_second_host_apply_failure_preserves_partial_state_and_explicit_rollback(self):
        before = self.snapshot()
        def fail_remote(host, request):
            if (host, request["phase"]) == ("t2-dev", "apply"):
                raise RuntimeError("unknown transport outcome")
            return self.agent(host, request)
        with self.assertRaises(RuntimeError):
            self.transaction_run("apply", fail_remote)
        self.assertNotEqual(before, self.snapshot())
        self.assertNotIn(("local", "verify"), self.events)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_post_prepare_drift_refuses_apply(self):
        self.run_phase("local", "prepare")
        (self.homes["local"] / bootstrap.EDITIONS[0] / "spec_flow.py").write_text("new owner bytes")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.run_phase("local", "apply")
        self.assertEqual(before, self.snapshot())

    def test_post_install_drift_on_second_host_blocks_rollback_on_both(self):
        self.transaction_run("apply")
        (self.homes["t2-dev"] / bootstrap.EDITIONS[1] / "spec_flow.py").write_text("new owner bytes")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "changed installed bytes"):
            self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_backup_corruption_blocks_rollback(self):
        self.transaction_run("apply")
        (self.state("t2-dev") / "2.backup").write_text("corrupted")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "backup missing or digest mismatch"):
            self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_interrupted_apply_and_rollback_can_restore_owned_bytes(self):
        before = self.snapshot()
        self.run_phase("local", "prepare")
        journal_path = self.state("local") / "journal.json"
        journal = json.loads(journal_path.read_text())
        journal["phase"] = "applying"
        journal_path.write_text(json.dumps(journal))
        first = self.homes["local"] / bootstrap.EDITIONS[0] / bootstrap.FILES[0]
        first.write_bytes(base64.b64decode(self.payloads[bootstrap.FILES[0]]))
        first.chmod(0o600)
        self.run_phase("local", "rollback")
        self.assertEqual(before, self.snapshot())
        # An interrupted rollback resumes only after its bytes pass preflight.
        journal = json.loads(journal_path.read_text())
        journal["phase"] = "rolling-back"
        journal_path.write_text(json.dumps(journal))
        self.run_phase("local", "rollback")
        self.assertEqual(before, self.snapshot())

    def test_crash_lock_halts_instead_of_automatic_retry(self):
        self.run_phase("local", "prepare")
        (self.state("local").parent / "target-lock").mkdir()
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.run_phase("local", "apply")
        self.assertEqual(before, self.snapshot())

    def test_different_manifest_cannot_replace_prepared_transaction(self):
        self.run_phase("local", "prepare")
        before = self.snapshot()
        request = self.request("local", "prepare")
        request["transaction"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "another target transaction"):
            self.agent("local", request)
        self.assertEqual(before, self.snapshot())

    def test_predecessor_mode_drift_refused(self):
        path = self.homes["local"] / bootstrap.EDITIONS[0] / "spec_flow.py"
        path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.run_phase("local", "check")

    def test_real_predecessor_modes_preserved_after_install_and_rollback(self):
        modes = (0o600, 0o644, 0o700, 0o755)
        index = 0
        for host, home in self.homes.items():
            for edition in bootstrap.EDITIONS:
                for name in bootstrap.FILES:
                    old = self.manifest["hosts"][host][edition][name]
                    if old is not None:
                        mode = modes[index % len(modes)]
                        index += 1
                        (home / edition / name).chmod(mode)
                        old["mode"] = mode
        self.transaction = bootstrap.sha(json.dumps(self.manifest, sort_keys=True).encode())
        before = self.snapshot()
        self.transaction_run("apply")
        for home in self.homes.values():
            for edition in bootstrap.EDITIONS:
                for name in bootstrap.FILES:
                    self.assertEqual((home / edition / name).stat().st_mode & 0o7777, 0o600)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_identical_predecessor_bytes_still_restore_original_mode(self):
        host, edition, name = "local", bootstrap.EDITIONS[0], "spec_flow.py"
        path = self.homes[host] / edition / name
        path.write_bytes(base64.b64decode(self.payloads[name]))
        path.chmod(0o700)
        self.manifest["hosts"][host][edition][name] = {"sha256": bootstrap.sha(path.read_bytes()), "mode": 0o700}
        self.transaction = bootstrap.sha(json.dumps(self.manifest, sort_keys=True).encode())
        before = self.snapshot()
        self.transaction_run("apply")
        self.assertEqual(path.stat().st_mode & 0o7777, 0o600)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_unsafe_predecessor_modes_refused(self):
        for mode in (0o666, 0o777, 0o4600):
            manifest = json.loads(json.dumps(self.manifest))
            manifest["hosts"]["local"][bootstrap.EDITIONS[0]]["spec_flow.py"]["mode"] = mode
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "predecessor hash or mode"):
                bootstrap.validate_manifest(json.dumps(manifest), SCRIPT.read_bytes())

    def test_offline_recovery_uses_exact_cached_bytes_without_git_or_compile(self):
        home = self.homes["local"]
        self.assertEqual(bootstrap.cached_payloads(self.manifest, self.payloads, home=home), self.payloads)
        before = self.snapshot()
        self.transaction_run("apply")
        with mock.patch.object(bootstrap.Path, "home", return_value=home), \
             mock.patch.object(bootstrap, "git", side_effect=AssertionError("network/Git forbidden")), \
             mock.patch.object(bootstrap, "load_payloads", side_effect=AssertionError("compile forbidden")):
            recovered = bootstrap.release_payloads(self.manifest, rollback=True)
        self.assertEqual(recovered, self.payloads)
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())

    def test_modified_recovery_cache_refused(self):
        home = self.homes["local"]
        bootstrap.cached_payloads(self.manifest, self.payloads, home=home)
        directory = home / ".agent-harness/work/native-review-bootstrap-cache" / self.transaction
        (directory / "spec_flow.py").write_text("changed cached bytes")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            bootstrap.cached_payloads(self.manifest, home=home)
        with self.assertRaisesRegex(ValueError, "cache changed"):
            bootstrap.cached_payloads(self.manifest, self.payloads, home=home)

    def test_manifest_raw_pin_refuses_before_source_fetch(self):
        path = self.root / "release.json"
        path.write_text(json.dumps(self.manifest))
        with mock.patch.object(sys, "argv", [str(SCRIPT), "--manifest", str(path), "--manifest-sha256", "0" * 64]), \
             mock.patch.object(bootstrap, "release_payloads", side_effect=AssertionError("must not fetch")), \
             self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            bootstrap.main()

    def test_remote_strict_host_key_and_wrong_phase_refused(self):
        request = self.request("t2-dev", "apply-check")
        result = subprocess.CompletedProcess([], 0, json.dumps({"transaction": self.transaction, "phase": "applied"}).encode(), b"")
        with mock.patch.object(bootstrap.subprocess, "run", return_value=result) as runner, \
             self.assertRaisesRegex(RuntimeError, "phase readback"):
            bootstrap.invoke("t2-dev", request)
        self.assertIn("StrictHostKeyChecking=yes", runner.call_args.args[0])

    def test_manifest_hash_and_closed_fields(self):
        valid = json.dumps(self.manifest).encode()
        self.assertEqual(bootstrap.validate_manifest(valid, SCRIPT.read_bytes()), self.manifest)
        with self.assertRaisesRegex(ValueError, "program digest"):
            bootstrap.validate_manifest(valid, b"mutated installer")
        mutations = [("repository", "https://example.com/fork.git"), ("candidate", "main"),
                     ("hosts", {"local": self.manifest["hosts"]["local"]}),
                     ("qualification", {"spec_core_sha256": "b" * 64}),
                     ("payloads", {**self.manifest["payloads"], "policy.py": "a" * 64})]
        for field, value in mutations:
            broken = dict(self.manifest, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                bootstrap.validate_manifest(json.dumps(broken), SCRIPT.read_bytes())

    def test_caller_identity_required_by_release_and_fixed_host_agent(self):
        manifest = json.loads(json.dumps(self.manifest))
        del manifest["payloads"]["caller_identity.py"]
        with self.assertRaisesRegex(ValueError, "closed release payload"):
            bootstrap.validate_manifest(json.dumps(manifest), SCRIPT.read_bytes())
        request = self.request("local", "check")
        request["payloads"] = dict(request["payloads"])
        del request["payloads"]["caller_identity.py"]
        with self.assertRaisesRegex(RuntimeError, "closed payload set"):
            self.agent("local", request)

    def test_ticket_adapter_required_by_release_and_fixed_host_agent(self):
        manifest = json.loads(json.dumps(self.manifest))
        del manifest["payloads"]["ticket_adapters.py"]
        with self.assertRaisesRegex(ValueError, "closed release payload"):
            bootstrap.validate_manifest(json.dumps(manifest), SCRIPT.read_bytes())
        request = self.request("local", "check")
        request["payloads"] = dict(request["payloads"])
        del request["payloads"]["ticket_adapters.py"]
        with self.assertRaisesRegex(RuntimeError, "closed payload set"):
            self.agent("local", request)

    def test_predecessor_guard_mutant_is_demonstrably_unsafe(self):
        path = self.homes["local"] / bootstrap.EDITIONS[0] / "spec_flow.py"
        path.write_text("foreign repair that must survive")
        with self.assertRaisesRegex(RuntimeError, "predecessor drift"):
            self.run_phase("local", "check")
        broken = bootstrap.AGENT_SOURCE.replace("if current(path) != old:", "if False:")
        self.assertNotEqual(broken, bootstrap.AGENT_SOURCE)
        with mock.patch.object(bootstrap, "AGENT_SOURCE", broken):
            result = self.run_phase("local", "check")
        self.assertEqual(result["phase"], "checked")
        self.assertEqual(path.read_text(), "foreign repair that must survive")

    def test_real_git_payload_rehearsal_checks_committed_bytes(self):
        checkout = self.root / "source"
        checkout.mkdir()
        bootstrap.git("init", str(checkout))
        hooks = checkout / "harness/hooks"
        hooks.mkdir(parents=True)
        for name in bootstrap.FILES:
            (hooks / name).write_bytes(base64.b64decode(self.payloads[name]))
        bootstrap.git("add", ".", cwd=checkout)
        bootstrap.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture", cwd=checkout)
        self.manifest["candidate"] = bootstrap.git("rev-parse", "HEAD", cwd=checkout).decode().strip()
        self.assertEqual(bootstrap.load_payloads(self.manifest, checkout), self.payloads)
        # Network-free real installer rehearsal from Git objects through both
        # actual host-agent subprocesses, including persisted backup/readback.
        self.payloads = bootstrap.load_payloads(self.manifest, checkout)
        self.transaction = bootstrap.sha(json.dumps(self.manifest, sort_keys=True).encode())
        before = self.snapshot()
        self.transaction_run("apply")
        self.transaction_run("rollback")
        self.assertEqual(before, self.snapshot())
        # Working bytes are irrelevant; the release uses exact Git objects.
        (hooks / "spec_flow.py").write_text("uncommitted mutation")
        self.assertEqual(bootstrap.load_payloads(self.manifest, checkout), self.payloads)
        self.manifest["payloads"]["spec_flow.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "payload digest mismatch"):
            bootstrap.load_payloads(self.manifest, checkout)
        # Removing the digest gate is a deliberate mutant. The golden source
        # record differs from its declared release and must not be accepted.
        source = SCRIPT.read_text().replace('sha(data) != manifest["payloads"][name]', "False")
        namespace = {"__name__": "bootstrap_mutant"}
        exec(compile(source, str(SCRIPT), "exec"), namespace)
        self.assertEqual(namespace["load_payloads"](self.manifest, checkout), self.payloads)


if __name__ == "__main__":
    unittest.main()
