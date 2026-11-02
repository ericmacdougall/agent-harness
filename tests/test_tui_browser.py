"""Contract checks for the opt-in, local-only browser handoff."""

import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


BROWSER = Path(__file__).resolve().parents[1] / "plugins/harness-tui/browser"


class TuiBrowserTests(unittest.TestCase):
    def assert_complete_tap(self, output, module):
        summary = re.search(
            r"(?:^|\n)1\.\.(?P<plan>[0-9]+)\n"
            r"# tests (?P<tests>[0-9]+)\n# suites (?P<suites>[0-9]+)\n"
            r"# pass (?P<passed>[0-9]+)\n# fail (?P<failed>[0-9]+)\n"
            r"# cancelled (?P<cancelled>[0-9]+)\n# skipped (?P<skipped>[0-9]+)\n"
            r"# todo (?P<todo>[0-9]+)\n# duration_ms [0-9]+(?:\.[0-9]+)?\n?\Z",
            output.replace("\r\n", "\n"),
        )
        self.assertIsNotNone(summary, "Node did not emit a complete terminal TAP summary")
        counts = {name: int(value) for name, value in summary.groupdict().items()}
        self.assertGreater(counts["plan"], 0, "Node ran no top-level tests")
        self.assertGreater(counts["tests"], 0, "Node ran no tests")
        self.assertEqual(counts["passed"], counts["tests"])
        for name in ("failed", "cancelled", "skipped", "todo"):
            self.assertEqual(counts[name], 0, name)
        # Node counts an empty file as a passing file-level test. Require a named
        # case, rather than accepting that automatic filename-only fallback.
        names = re.findall(r"^# Subtest: (.+)$", output, flags=re.MULTILINE)
        self.assertEqual(len(names), counts["plan"], "TAP names do not match the final plan")
        self.assertTrue(any(name.strip() != str(module) for name in names), "Node ran no explicit test cases")

    def test_manifest_requests_only_explicit_active_tab_capabilities(self):
        manifest = json.loads((BROWSER / "manifest.json").read_text())
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(set(manifest["permissions"]), {"activeTab", "scripting", "nativeMessaging"})
        for field in ("host_permissions", "content_scripts", "externally_connectable", "background", "web_accessible_resources"):
            self.assertNotIn(field, manifest)
        self.assertIn("connect-src 'none'", manifest["content_security_policy"]["extension_pages"])
        self.assertEqual(manifest["action"]["default_popup"], "popup.html")

    def test_public_key_binds_native_host_extension_identity(self):
        manifest = json.loads((BROWSER / "manifest.json").read_text())
        digest = hashlib.sha256(base64.b64decode(manifest["key"], validate=True)).hexdigest()[:32]
        expected = "".join(chr(ord("a") + int(c, 16)) for c in digest)
        self.assertEqual(expected, "gdpiohlkkniinkfhlbhcjoimlcnhnkgj")
        self.assertEqual((BROWSER / "extension-id.txt").read_text().strip(), expected)

    @unittest.skipUnless(shutil.which("node"), "Node is required for browser adapter unit checks")
    def test_browser_javascript_checks(self):
        module = BROWSER / "tests/capture.test.mjs"
        result = subprocess.run(
            [shutil.which("node"), "--test", "--test-reporter=tap", str(module)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_complete_tap(result.stdout, module)

    @unittest.skipUnless(shutil.which("node"), "Node is required for browser adapter unit checks")
    def test_empty_node_module_fails_evidence_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "empty.test.mjs"
            module.write_text("import test from 'node:test';\n")
            result = subprocess.run(
                [shutil.which("node"), "--test", "--test-reporter=tap", str(module)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stdout)
        with self.assertRaises(AssertionError):
            self.assert_complete_tap(result.stdout, module)


if __name__ == "__main__":
    unittest.main()
