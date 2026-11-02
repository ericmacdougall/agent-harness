"""Contract checks for the opt-in, local-only browser handoff."""

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest


BROWSER = Path(__file__).resolve().parents[1] / "plugins/harness-tui/browser"


class TuiBrowserTests(unittest.TestCase):
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
        result = subprocess.run(
            [shutil.which("node"), "--test", "--test-reporter=tap", str(BROWSER / "tests/capture.test.mjs")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("# fail 0", result.stdout)


if __name__ == "__main__":
    unittest.main()
