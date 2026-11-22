"""Exercise the real macOS signer parser without invoking key enrollment or Touch ID."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ISSUER = "operator-test"
AUDIENCE = "t2-dev-" + "560e5e0f65e6a62f6e34156047d862a9"
SIGNER = Path(__file__).resolve().parents[1] / "scripts" / "t2scan_astra_operator.swift"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def golden():
    scope = ["prj_FixtureProject", "run_FixtureAudit"]
    assignments = []
    for number, role in enumerate(("assurance-synthesis", "delivery-synthesis", "executive-synthesis")):
        work = "wrk_Fixture" + str(number)
        task = hashlib.sha256(canonical([*scope, work])).hexdigest()[:32]
        assignments.append({
            "assignment": role,
            "work_item_id": work,
            "task_key": f"t2scan-audit-{task}-astra-direct",
            "nonce": hashlib.sha256(f"fixture-nonce-{number}".encode()).hexdigest(),
            "packet_sha256": hashlib.sha256(f"fixture-input-{number}".encode()).hexdigest(),
        })
    now = int(time.time())
    return {
        "schema": "agent-harness.t2scan.astra-direct.v1",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "provider": "codex",
        "model": "gpt-6-astra",
        "mode": "direct",
        "project_id": scope[0],
        "run_id": scope[1],
        "created_at": now - 5,
        "expires_at": now + 300,
        "assignments": assignments,
    }


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"), "requires the macOS Swift SDK")
class OperatorProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="t2scan-operator-test-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "operator"
        subprocess.run(["swiftc", "-parse-as-library", str(SIGNER), "-o", str(cls.binary)], check=True, timeout=60)

    def check(self, payload, expected=2, *, issuer=ISSUER, audience=AUDIENCE):
        challenge = self.directory / "challenge.json"
        challenge.write_bytes(payload)
        result = subprocess.run([self.binary, "check", challenge, issuer, audience],
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, expected)
        self.assertEqual(result.stdout, b"valid challenge\n" if expected == 0 else b"")

    def test_golden_scope(self):
        self.check(canonical(golden()), expected=0)

    def test_rejects_unpinned_identity(self):
        self.check(canonical(golden()), issuer="another-operator")
        self.check(canonical(golden()), audience="another-host")

    def test_wrong_root_fields(self):
        cases = {
            "schema": "agent-harness.t2scan.astra-direct.v2",
            "provider": "claude",
            "model": "gpt-6.2-astra",
            "mode": "fallback",
            "project_id": "prj_OtherProject",
            "run_id": "run_OtherAudit",
            "created_at": int(time.time()) + 90,
            "expires_at": int(time.time()) + 901,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                self.check(canonical({**golden(), field: value}))
        self.check(canonical({**golden(), "expires_at": int(time.time()) - 1}))

    def test_wrong_assignment_scope(self):
        good = golden()
        for field, value in {
            "assignment": "delivery-synthesis",
            "nonce": good["assignments"][1]["nonce"],
            "packet_sha256": "not-a-digest",
            "task_key": good["assignments"][0]["task_key"].removesuffix("-direct"),
            "work_item_id": "wrk_OutOfScope",
        }.items():
            with self.subTest(field=field):
                challenge = copy.deepcopy(good)
                challenge["assignments"][0][field] = value
                self.check(canonical(challenge))
        self.check(canonical({**good, "assignments": good["assignments"][::-1]}))
        self.check(canonical({**good, "assignments": good["assignments"][:2]}))

    def test_noncanonical_or_oversized_input(self):
        good = canonical(golden())
        for payload in (good + b"\n", b'{"mode":"direct",' + good[1:],
                        b'{"extra":"approval",' + good[1:], b"x" * 4097):
            with self.subTest(size=len(payload)):
                self.check(payload)

    def test_non_regular_challenge_input(self):
        target = self.directory / "target.json"
        target.write_bytes(canonical(golden()))
        link = self.directory / "link.json"
        link.symlink_to(target)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(kind=path.name):
                result = subprocess.run([self.binary, "check", path, ISSUER, AUDIENCE],
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
