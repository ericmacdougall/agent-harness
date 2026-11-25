"""Redactor vs the third gate (PR #316 click-test O1, goodqa#17119).

Contract: every synthetic vendor token in the fixture set that gitleaks flags is REDACTED by pass 1 (the record is
kept, the value is gone, pass 2 and gitleaks are clean on the output), never merely held. Fakes are generated from a
fixed seed (SEED below) at run time, so no token-shaped literal sits in this file. Where the pinned gitleaks binary is
installed, each raw fixture must be flagged by it (so the fixture really exercises the third gate) and the redacted
output must not be; where it is absent the gitleaks half is skipped and says so (TRANSCRIPTS_REQUIRE_GITLEAKS=1 makes
that a failure).
"""
import json
import os
import random
import shutil
import string
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import transcript_redact as tr  # noqa: E402

SEED = 17119
REQUIRE = os.environ.get("TRANSCRIPTS_REQUIRE_GITLEAKS") == "1"
HEX = "0123456789abcdef"
LOWER_ALNUM = string.ascii_lowercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"


def fixtures(seed=SEED):
    """{name: fake token} covering the O1 shapes and the shapes redact.py already had."""
    r = random.Random(seed)

    def pick(alphabet, n):
        return "".join(r.choice(alphabet) for _ in range(n))
    return {
        "twilio": "SK" + pick(HEX, 32),
        "shopify": "shpat_" + pick(HEX, 32),
        "doppler": "dp.pt." + pick(LOWER_ALNUM, 43),
        "square": "sq0atp-" + pick(ALNUM + "-_", 22),
        "databricks": "dapi" + pick(HEX, 32),
        "age": "AGE-SECRET-KEY-1" + pick(BECH32, 58),
        "slack-webhook": "https://hooks.slack.com/services/T" + pick(ALNUM.upper()[:36], 8) + "/B" + pick(
            ALNUM.upper()[:36], 8) + "/" + pick(ALNUM, 24),
        "pypi": "pypi-AgEIcHlwaS5vcmc" + pick(ALNUM + "-_", 60),
        "grafana-sa": "glsa_" + pick(ALNUM, 32) + "_" + pick(HEX, 8),
        "grafana-cloud": "glc_" + pick(ALNUM, 40),
        "linear": "lin_api_" + pick(LOWER_ALNUM, 40),
        "flyio": "fo1_" + pick(ALNUM + "_-", 43),
        "planetscale": "pscale_tkn_" + pick(ALNUM + "_", 43),
        # shapes redact.py already covered: kept here so the contract spans the whole table
        "github-pat": "ghp" + "_" + pick(ALNUM, 36),
        "aws-key": "AKIA" + pick(string.ascii_uppercase + "234567", 16),
        "gitlab": "glpat-" + pick(ALNUM + "-_", 20),
        "slack-bot": "xoxb-" + pick(string.digits, 11) + "-" + pick(string.digits, 12) + "-" + pick(ALNUM, 24),
        "npm": "npm_" + pick(ALNUM, 36),
        "stripe": "sk" + "_live_" + pick(ALNUM, 32),
    }


def record(value):
    return json.dumps({"type": "user", "message": {"role": "user", "content": "note %s end" % value}},
                      separators=(",", ":")).encode()


def gitleaks_bin():
    for c in (shutil.which("gitleaks"), os.path.expanduser("~/.local/bin/gitleaks"), "/opt/homebrew/bin/gitleaks"):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def gitleaks_rules(binary, data):
    r = subprocess.run([binary, "stdin", "--no-banner", "--redact=100", "--report-format", "json", "--report-path",
                        "-", "--exit-code", "0", "--log-level", "error"], input=data, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise AssertionError("gitleaks exit %d" % r.returncode)
    return sorted({f.get("RuleID") for f in json.loads(r.stdout or b"[]") or []})


class RedactorCoversVendorShapes(unittest.TestCase):
    def test_every_fixture_is_redacted_not_held(self):
        for name, value in fixtures().items():
            with self.subTest(shape=name):
                line = record(value)
                self.assertTrue(tr.verify_bytes(line), "pass 2 sees the raw %s fixture" % name)
                out, counts, omitted = tr.redact_line(line, 1)
                self.assertIsNone(omitted, "%s: the record must be redacted, not omitted" % name)
                self.assertNotIn(value.encode(), out)
                self.assertIn(b"[REDACTED:", out)
                self.assertIn(b"end", out, "the rest of the record is kept")
                self.assertEqual(tr.verify_bytes(out), [], name)

    def test_seeds_vary_but_still_redact(self):
        for seed in (1, 2, 3):
            for name, value in fixtures(seed).items():
                with self.subTest(seed=seed, shape=name):
                    out, _, omitted = tr.redact_line(record(value), 1)
                    self.assertIsNone(omitted)
                    self.assertNotIn(value.encode(), out)

    def test_near_misses_are_left_alone(self):
        """Precision guard: ordinary words with the same prefixes stay as they are."""
        for text in ("SKU numbers", "dapi docs", "the age of the key", "shp_files", "lin_api docs", "fo1 note"):
            with self.subTest(text=text):
                out, counts, omitted = tr.redact_line(record(text), 1)
                self.assertIsNone(omitted)
                self.assertNotIn(b"[REDACTED:", out, text)

    def test_contract_against_the_real_scanner(self):
        binary = gitleaks_bin()
        if not binary:
            if REQUIRE:
                self.fail("gitleaks is required on this host but was not found")
            self.skipTest("real gitleaks not installed on this host")
        for name, value in fixtures().items():
            with self.subTest(shape=name):
                line = record(value)
                rules = gitleaks_rules(binary, line)
                self.assertTrue(rules, "%s: the fixture must be one gitleaks flags" % name)
                out, _, omitted = tr.redact_line(line, 1)
                self.assertIsNone(omitted, name)
                self.assertEqual(gitleaks_rules(binary, out), [], "%s (%s) survives redaction" % (name, rules))


if __name__ == "__main__":
    unittest.main()
