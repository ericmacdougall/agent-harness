"""Focused portable Astra proof tests with generated, disposable P-256 keys."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import t2scan_consent as consent


NOW = 1795350000
ROLES = ("executive-synthesis", "assurance-synthesis", "delivery-synthesis")
DOMAIN = b"Agent Harness T2Scan Astra direct approval v1\x00"
OPENSSL = shutil.which("openssl")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bytes64(data):
    return base64.b64encode(data).decode("ascii")


@unittest.skipUnless(OPENSSL, "OpenSSL required for native signature controls")
class PortableConsent(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.key = self.root / "operator.pem"
        self.public_key = self.root / "issuer.pem"
        self.state = self.root / "state.sqlite3"
        self.keygen(self.public_key, self.key)
        consent.initialize_state(self.state)
        self.clock = NOW
        self.verifier = consent.Verifier(
            issuer="eric-p256-1", audience="t2-dev", peer_uid=501,
            public_key=self.public_key.read_bytes(), state=self.state, clock=lambda: self.clock,
        )
        self.proof = dict(schema="agent-harness.t2scan.astra-direct.v1", issuer="eric-p256-1",
                          audience="t2-dev", provider="codex", model="gpt-6-astra", mode="direct",
                          project_id="prj_project01", run_id="run_original10",
                          created_at=NOW - 1, expires_at=NOW + 300, assignments=[])
        for index, role in enumerate(ROLES):
            work = f"wrk_work{index}"
            scope = [self.proof["project_id"], self.proof["run_id"], work]
            self.proof["assignments"].append({
                "assignment": role, "work_item_id": work,
                "task_key": "t2scan-audit-" + digest(canonical(scope))[:32] + "-astra-direct",
                "packet_sha256": digest(f"packet {index}".encode()),
                "nonce": digest(f"nonce {index}".encode()),
            })

    def keygen(self, public, private, curve="prime256v1"):
        self.openssl("ecparam", "-name", curve, "-genkey", "-noout", "-out", str(private))
        self.openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))

    def openssl(self, *args, data=None):
        return subprocess.run([OPENSSL, *args], input=data, capture_output=True, timeout=5, check=True).stdout

    def request(self, action="check", index=0, *, key=None, payload=None):
        payload = canonical(self.proof) if payload is None else payload
        signature = self.openssl("dgst", "-sha256", "-sign", str(key or self.key), data=DOMAIN + payload)
        scope = {name: self.proof[name] for name in ("project_id", "run_id", "model")}
        scope.update({name: value for name, value in self.proof["assignments"][index].items() if name != "nonce"})
        return dict(action=action, challenge_b64=bytes64(payload), signature_b64=bytes64(signature), **scope)

    def decision(self, request, peer=501):
        return self.verifier.decide(request, peer_uid=peer)

    def test_independent_preview_and_durable_one_use_per_assignment(self):
        self.assertTrue(all(self.decision(self.request(index=index)) for index in range(3)))
        first = self.request("consume")
        self.assertTrue(self.decision(first))
        self.verifier = consent.Verifier(
            issuer="eric-p256-1", audience="t2-dev", peer_uid=501,
            public_key=self.public_key.read_bytes(), state=self.state, clock=lambda: self.clock,
        )
        self.assertFalse(self.decision(first))
        self.assertFalse(self.decision(self.request()))
        self.assertTrue(self.decision(self.request("consume", 1)))
        self.assertTrue(self.decision(self.request("consume", 2)))

    def test_one_concurrent_consume_wins(self):
        request = self.request("consume")
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(self.decision, (request,) * 8)).count(True), 1)

    def test_revocation_between_preview_and_late_consume(self):
        self.assertTrue(self.decision(self.request()))
        revocation = dict(action="revoke", challenge_sha256=digest(canonical(self.proof)))
        self.assertFalse(self.decision(revocation))
        self.assertTrue(self.decision(revocation, peer=0))
        self.assertFalse(self.decision(self.request("consume")))
        self.assertFalse(self.decision(self.request(index=1)))
        self.assertFalse(self.decision(self.request(index=2)))

    def test_unsigned_wrong_issuer_and_mutated_binding_fail(self):
        alternate = self.root / "alternate.pem"
        self.keygen(self.root / "alternate-public.pem", alternate)
        self.assertFalse(self.decision(self.request(key=alternate)))
        request = self.request()
        for name, wrong in (
            ("project_id", "prj_project02"), ("run_id", "run_original11"),
            ("work_item_id", "wrk_work1"), ("task_key", request["task_key"].removesuffix("-direct")),
            ("model", "gpt-6.2-sol"), ("assignment", "assurance-synthesis"),
            ("packet_sha256", "0" * 64), ("signature_b64", bytes64(b"invalid_signature")),
            ("challenge_b64", "%malformed"), ("unbound", True),
        ):
            with self.subTest(name=name):
                self.assertFalse(self.decision(dict(request, **{name: wrong})))
        self.assertFalse(self.decision(request, peer=502))
        self.assertFalse(self.decision(request, peer=0))
        self.assertTrue(self.decision(request))

    def test_even_signed_noncanonical_and_invalid_scopes_fail(self):
        self.assertFalse(self.decision(self.request(payload=canonical(self.proof) + b"\n")))
        duplicate_mode = canonical(self.proof)[:-1] + b',"mode":"direct"}'
        self.assertFalse(self.decision(self.request(payload=duplicate_mode)))
        for name, wrong in (
            ("issuer", "unknown"), ("audience", "other-host"), ("provider", "claude"),
            ("model", "gpt-6.3-astra"), ("mode", "fallback"),
            ("created_at", NOW + 1), ("created_at", True), ("expires_at", NOW),
            ("expires_at", NOW + 901),
        ):
            with self.subTest(name=name):
                original = self.proof[name]
                self.proof[name] = wrong
                self.assertFalse(self.decision(self.request()))
                self.proof[name] = original
        for name, wrong in (
            ("assignment", ROLES[1]), ("assignment", "read-only"),
            ("work_item_id", "wrk_work1"), ("task_key", "t2scan-audit-fake-astra-direct"),
            ("nonce", self.proof["assignments"][1]["nonce"]),
        ):
            with self.subTest(name=name, wrong=wrong):
                original = self.proof["assignments"][0][name]
                self.proof["assignments"][0][name] = wrong
                self.assertFalse(self.decision(self.request(index=1)))
                self.proof["assignments"][0][name] = original
        self.proof["assignments"].reverse()
        self.assertFalse(self.decision(self.request()))
        self.proof["assignments"].pop()
        self.assertFalse(self.decision(self.request()))

    def test_expiration_at_consume_and_missing_or_wrong_curve_state_are_closed(self):
        self.assertTrue(self.decision(self.request()))
        self.clock = self.proof["expires_at"]
        self.assertFalse(self.decision(self.request("consume")))
        self.clock = NOW
        self.state.unlink()
        self.assertFalse(self.decision(self.request()))
        self.assertFalse(self.state.exists())
        larger = self.root / "other-curve.pem"
        self.keygen(larger, self.root / "other-curve-private.pem", "secp384r1")
        with self.assertRaises(ValueError):
            consent.Verifier(issuer="eric-p256-1", audience="t2-dev", peer_uid=501,
                             public_key=larger.read_bytes(), state=self.state)

    def test_frame_receives_one_bounded_record(self):
        expected = {"action": "status"}
        for record, passed in (
            (canonical(expected) + b"\n", True), (b'{}\n{}\n', False),
            (b'{"action": "x", "action": "y"}\n', False),
            (b'{}', False), (b" " * consent.MAX_REQUEST, False),
        ):
            with self.subTest(size=len(record), passed=passed):
                left, right = socket.socketpair()
                with left, right, ThreadPoolExecutor(max_workers=1) as pool:
                    def send():
                        right.settimeout(2)
                        right.sendall(record)
                        right.shutdown(socket.SHUT_WR)

                    sent = pool.submit(send)
                    if passed:
                        self.assertEqual(consent.receive(left), expected)
                    else:
                        with self.assertRaises(ValueError):
                            consent.receive(left)
                    sent.result(timeout=2)

    def test_audience_binds_canonical_ssh_fingerprint_and_execution_uid(self):
        key_blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
        fingerprint = consent.ssh_fingerprint(b"ssh-ed25519 " + base64.b64encode(key_blob) + b" test\n")
        expected = "t2-dev-" + digest(canonical([fingerprint, 501]))[:32]
        self.assertEqual(consent.derive_audience("t2-dev", fingerprint, 501), expected)
        self.assertNotEqual(consent.derive_audience("t2-dev", fingerprint, 502), expected)
        self.assertNotEqual(consent.derive_audience("other", fingerprint, 501), expected)
        with self.assertRaises(ValueError):
            consent.derive_audience("t2-dev", fingerprint + "=", 501)
        with self.assertRaises(ValueError):
            consent.ssh_fingerprint(b"ssh-ed25519 " + base64.b64encode(key_blob[1:]))

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() != 0, "Non-root Linux peer credentials required")
    def test_kernel_uid_and_exact_single_response_on_native_wire(self):
        selected_uid = os.geteuid()
        request = self.request("consume")
        for uid, decision in ((selected_uid + 1, "denied"), (selected_uid, "allowed"), (selected_uid, "denied")):
            verifier = consent.Verifier(
                issuer="eric-p256-1", audience="t2-dev", peer_uid=uid,
                public_key=self.public_key.read_bytes(), state=self.state, clock=lambda: self.clock,
            )
            client, connection = socket.socketpair()

            def serve_one():
                with connection:
                    consent.handle(connection, verifier)

            with client, ThreadPoolExecutor(max_workers=1) as pool:
                client.settimeout(3)
                client.sendall(canonical(request) + b"\n")
                client.shutdown(socket.SHUT_WR)
                server = pool.submit(serve_one)
                with client.makefile("rb") as stream:
                    try:
                        self.assertEqual(stream.read(100), canonical({"decision": decision}) + b"\n")
                    except ConnectionResetError:
                        # Linux may reset when an unauthorized peer is denied before reading its frame.
                        self.assertNotEqual(uid, selected_uid)
                server.result(timeout=3)
