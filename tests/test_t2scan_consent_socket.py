"""Provisioned socket must match the T2Scan adapter's protected peer contract."""

import configparser
from pathlib import Path
import unittest


SCHEDULERS = Path(__file__).resolve().parents[1] / "harness" / "schedulers"


def unit_section(suffix, section):
    unit = configparser.ConfigParser(interpolation=None)
    path = SCHEDULERS / f"t2scan-astra-consent.{suffix}"
    with path.open(encoding="utf-8") as source:
        unit.read_file(source)
    return unit[section]


class PortableSocketProvisioning(unittest.TestCase):
    def test_socket_uses_root_listener_and_separate_restricted_client_group(self):
        listener = unit_section("socket", "Socket")
        service = unit_section("service", "Service")
        self.assertEqual(listener["ListenStream"], "/run/agent-harness/t2scan-astra-consent.sock")
        self.assertEqual(listener["SocketUser"], "root")
        self.assertEqual(int(listener["DirectoryMode"], 8), 0o755)
        self.assertEqual(int(listener["SocketMode"], 8), 0o660)
        self.assertEqual(listener["SocketGroup"], "agent-harness-consent-client")
        self.assertNotEqual(listener["SocketGroup"], service["User"])
        self.assertNotEqual(listener["SocketGroup"], service["Group"])
