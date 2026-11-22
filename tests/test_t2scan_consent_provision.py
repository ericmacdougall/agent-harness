"""Operator sequencing and protected broker provisioning tests with synthetic inputs."""
from pathlib import Path
import json
import shlex
from types import SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import provision_t2scan_consent as provision
import t2scan_consent_install as linux


class ProvisionSequence(unittest.TestCase):
    def test_preflight_denial_never_enrolls_or_signs(self):
        remote = Mock(side_effect=provision.Refusal("target refused"))
        enroll, sign = Mock(), Mock()
        with self.assertRaises(provision.Refusal):
            provision.activate(remote, enroll, sign)
        enroll.assert_not_called()
        sign.assert_not_called()
        self.assertEqual(remote.call_args_list[0].args, ("check", None))

    def test_provisioning_failure_never_emits_signed_capsule(self):
        remote = Mock(side_effect=[None, provision.Refusal("could not verify broker")])
        enroll, sign = Mock(return_value=b"just a fixture"), Mock()
        with self.assertRaises(provision.Refusal):
            provision.activate(remote, enroll, sign)
        enroll.assert_called_once_with()
        sign.assert_not_called()

    def test_signed_capsule_only_after_independent_enrollment_and_root_install(self):
        events = []
        def remote(phase, signer):
            events.append((phase, signer))
        def enroll():
            events.append(("enroll", None))
            return b"human hardware public key fixture"
        def sign():
            events.append(("sign", None))
        provision.activate(remote, enroll, sign)
        self.assertEqual(events, [("check", None), ("enroll", None),
                                  ("install", b"human hardware public key fixture"), ("sign", None)])

    def test_remote_install_ack_without_expected_asset_hashes_is_refused(self):
        assets = {"verifier": b"verifier", "worker": b"worker", "service": b"service", "socket": b"socket"}
        options = SimpleNamespace(issuer="operator", fingerprint="SHA256:" + "A" * 43, ref="a" * 40)
        invoke = provision.remote_factory("/fixture", assets, options, 501)
        payload = {"signer_sha256": "d" * 64, "public_key": provision.base64str(b"public")}
        with patch.object(provision, "ssh", return_value=b'{"status":"install","result":{}}'):
            with self.assertRaisesRegex(provision.Refusal, "unconfirmed"):
                invoke("install", payload)

    def test_privileged_worker_is_isolated_and_composed_from_exact_reviewed_bytes(self):
        assets = {name: (ROOT / path).read_bytes() for name, path in provision.SOURCES.items()}
        options = SimpleNamespace(issuer="operator", fingerprint="SHA256:" + "A" * 43, ref="a" * 40)
        invoke = provision.remote_factory("/private/known-hosts", assets, options, 501)
        with patch.object(provision, "ssh", return_value=b'{"status":"check","result":{}}') as remote:
            self.assertEqual(invoke("check", None), {})
        known, command = remote.call_args.args
        request = json.loads(remote.call_args.kwargs["input"])
        self.assertEqual(known, "/private/known-hosts")
        self.assertEqual(request, dict(phase="check", issuer=options.issuer, fingerprint=options.fingerprint,
                                       uid=501, payload=None))
        argv = shlex.split(command)
        self.assertEqual(argv[:-1], ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c"])
        self.assertTrue(argv[-1].startswith(assets["worker"].decode("utf-8")))
        self.assertIn(repr(assets["verifier"]), argv[-1])
        compile(argv[-1], "pinned-remote-worker", "exec")

    def test_export_is_published_only_after_detached_verification(self):
        for failure in (True, False):
            with self.subTest(verification_refused=failure):
                stage = Path(self.enterContext(tempfile.TemporaryDirectory()))
                (stage / "scoped-assignments.json").write_bytes(b"scope fixture")
                signer = stage / "signer"
                signer.write_bytes(b"fixture executable")
                (stage / "issuer.pem").write_bytes(b"fixture public key")
                options = SimpleNamespace(ref="a" * 40, run="run_fixture")
                item = {"assignment": "executive-synthesis", "work_item_id": "wrk_item", "task_key": "test-task",
                        "packet_sha256": "b" * 64}
                challenge = dict(run_id=options.run, project_id="prj_fixture", provider="codex", model="gpt-6-astra",
                                 mode="direct", issuer="operator", audience="target", created_at=40, expires_at=80,
                                 assignments=[item])

                def execute(argv, **kwargs):
                    if argv[0] == "proposal":
                        Path(argv[-1]).write_text(json.dumps(challenge))
                    elif argv[0] == str(signer):
                        Path(argv[-1]).write_bytes(b"fake DER fixture")
                    else:
                        self.assertEqual(argv[0], "/usr/bin/openssl")
                        if failure:
                            raise provision.Refusal("verification fixture refused")

                result = stage / "approval-export.json"
                with patch.object(provision, "execute", side_effect=execute), patch.object(
                    provision.time, "time", return_value=42
                ):
                    if failure:
                        with self.assertRaisesRegex(provision.Refusal, "verification fixture"):
                            provision.output_bundle(options, stage, (["proposal"], provision.sha(b"scope fixture")),
                                                    signer, provision.sha(b"fixture executable"))
                        self.assertFalse(result.exists())
                        continue
                    provision.output_bundle(options, stage, (["proposal"], provision.sha(b"scope fixture")),
                                            signer, provision.sha(b"fixture executable"))
                receipt = json.loads(result.read_text())
                self.assertEqual(receipt["run_id"], options.run)
                self.assertEqual(receipt["signature"]["sha256"], provision.sha(b"fake DER fixture"))
                self.assertEqual(receipt["assignments"], [dict(item, capsule="portable-consent/test-task.json")])


class ProtectedProvision(unittest.TestCase):
    def setUp(self):
        self.stage = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = {"peer_uid": 1000, "host_label": "t2-dev", "issuer": "operator",
                       "ssh_ed25519_fingerprint": "SHA256:" + "A" * 43}
        self.targets = {name: self.stage / name for name in linux.TARGETS}
        self.payload = {name: provision.base64str(f"{name} fixture".encode()) for name in self.targets}
        self.payload.update(ref="a" * 40, signer_sha256="b" * 64,
                            public_key=provision.base64str(b"-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PUBLIC KEY-----\n"))
        self.enterContext(patch.object(linux, "TARGETS", self.targets))
        self.enterContext(patch.object(linux, "BIN", self.targets["verifier"]))
        self.enterContext(patch.object(linux, "STATE", self.stage / "state"))
        self.enterContext(patch.object(linux, "CONFIG", self.stage / "config"))

    def test_existing_replay_path_or_issuer_stops_before_mutation(self):
        linux.STATE.mkdir()
        proof = linux.STATE / "replay_fixture"
        proof.write_bytes(b"state remains")
        verify, accounts = Mock(), Mock()
        with patch.object(linux, "create_accounts", accounts):
            with self.assertRaisesRegex(linux.Refusal, "Existing consent"):
                linux.install(self.config, self.payload, verify)
        self.assertEqual(proof.read_bytes(), b"state remains")
        verify.assert_not_called()
        accounts.assert_not_called()

    def test_existing_runtime_endpoint_fails_before_account_or_systemd_changes(self):
        endpoint = self.stage / linux.SOCKET
        endpoint.symlink_to(self.stage / "unrelated-endpoint")
        with patch.object(linux, "ADDRESS", endpoint), patch.object(linux, "create_accounts") as accounts, \
                patch.object(linux, "systemctl") as system:
            with self.assertRaisesRegex(linux.Refusal, "Existing consent"):
                linux.install(self.config, self.payload, Mock())
            accounts.assert_not_called()
            system.assert_not_called()
        self.assertTrue(endpoint.is_symlink())

    def test_fingerprint_or_uid_mismatch_stops_before_scope_record(self):
        fixed = self.config["ssh_ed25519_fingerprint"]
        with patch.object(linux.os, "geteuid", return_value=0), patch.object(
            linux.socket, "gethostname", return_value="t2-dev"
        ), patch.object(linux, "target_fingerprint", return_value=fixed), patch.dict(
            linux.os.environ, {"SUDO_UID": "1000"}
        ):
            with self.assertRaisesRegex(linux.Refusal, "host key"):
                linux.target_identity("operator", "SHA256:" + "B" * 43, 1000)
            with self.assertRaisesRegex(linux.Refusal, "UID"):
                linux.target_identity("operator", fixed, 1001)
            self.assertEqual(linux.target_identity("operator", fixed, 1000), self.config)

    def test_activation_failure_disables_service_without_deleting_issuer_or_state(self):
        system = Mock()
        peer = SimpleNamespace(pw_name="exact-runtime-account", pw_gid=1000, pw_uid=1000)
        verify = Mock()
        with patch.object(linux, "no_conflicts"), patch.object(linux, "paths_are_protected"), patch.object(
            linux, "create_accounts", return_value=peer
        ), patch.object(linux, "command"), patch.object(linux, "systemctl", system), patch.object(
            linux.pwd, "getpwuid", return_value=peer
        ), patch.object(linux.os, "chown"), patch.object(
            linux, "peer_probe", side_effect=linux.Refusal("activation unconfirmed")
        ):
            with self.assertRaisesRegex(linux.Refusal, "activation unconfirmed"):
                linux.install(self.config, self.payload, verify)
        self.assertEqual([call.args for call in system.mock_calls[-2:]],
                         [("disable", "--now", linux.SOCKET), ("stop", linux.SERVICE)])
        self.assertTrue((linux.CONFIG / "issuer.pem").is_file())
        self.assertTrue(linux.STATE.is_dir())
        verify.assert_called_once()

    def test_received_asset_or_source_ref_mismatch_is_refused(self):
        hashes = {name: linux.sha(f"{name} fixture".encode()) for name in self.targets}
        linux.bind_release(self.payload, self.payload["ref"], hashes)
        with self.assertRaisesRegex(linux.Refusal, "differ"):
            linux.bind_release(self.payload, "b" * 40, hashes)
        with self.assertRaisesRegex(linux.Refusal, "differ"):
            linux.bind_release(dict(self.payload, service=provision.base64str(b"other")),
                               self.payload["ref"], hashes)

    def test_rollback_invalid_release_or_issuer_cannot_stop_broker(self):
        linux.CONFIG.mkdir()
        linux.STATE.mkdir()
        proof = linux.STATE / "replay_fixture"
        proof.write_bytes(b"keep")
        by_path = {
            "settings.json": linux.enc(self.config),
            "release.json": linux.enc({"ref": self.payload["ref"], "public_key_sha256": linux.sha(b"pinned")}),
            "issuer.pem": b"pinned",
        }
        with patch.object(linux, "paths_are_protected"), patch.object(
            linux, "root_file", side_effect=lambda path: by_path[path.name]
        ), patch.object(linux, "disable") as disable:
            with self.assertRaisesRegex(linux.Refusal, "differs"):
                linux.rollback(self.config, "b" * 40)
            with self.assertRaisesRegex(linux.Refusal, "differs"):
                linux.rollback(dict(self.config, issuer="other"), self.payload["ref"])
            disable.assert_not_called()
            linux.rollback(self.config, self.payload["ref"])
            disable.assert_called_once_with()
        self.assertEqual(proof.read_bytes(), b"keep")
