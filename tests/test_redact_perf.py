"""Linear-time guard for redact.PATTERNS (GoodQA #16680).

The rclone-token shape (`^\\s*token`) rescanned every line start on a run of newlines, and the first
named-credential shape (`(?:[a-z0-9]+[_-])*` prefix) restarted at every word boundary of a hyphenated run. On
100 KB inputs they took about 52 s and 224 s. Each adversarial 100 KB input must now finish in under 1 s of CPU.
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import redact  # noqa: E402

SIZE = 100_000
ADVERSARIAL = {
    "newline-run": "\n" * SIZE,
    "space-newline-run": " \n" * (SIZE // 2),
    "hyphen-run": "a-" * (SIZE // 2),
    "underscore-hyphen-run": "a_b-" * (SIZE // 4),
    "token-lines": "token\n" * (SIZE // 6),
    "camel-run": "aB" * (SIZE // 2),
}


class PatternsAreLinear(unittest.TestCase):
    def test_each_pattern_on_adversarial_input(self):
        for name, text in ADVERSARIAL.items():
            for kind, pattern in redact.PATTERNS:
                with self.subTest(input=name, kind=kind):
                    start = time.process_time()
                    for _ in pattern.finditer(text):
                        pass
                    self.assertLess(time.process_time() - start, 1.0)

    def test_redact_and_find_on_adversarial_input(self):
        for name, text in ADVERSARIAL.items():
            with self.subTest(input=name):
                start = time.process_time()
                redact.redact(text)
                self.assertLess(time.process_time() - start, 2.0)

    def test_coverage_kept_for_long_and_prefixed_names(self):
        value = "Zq9X" + "w2Lm8Rt4" + "Vb7Np3Kc6"
        for i, text in enumerate(["DB_PASSWORD=" + value, "a_b_c_d_e_f_g_h_i_j_secret=" + value,
                                  "my-app-client-secret: " + value, "token = {\"access\": \"" + value + "\"}",
                                  "  token = {" + value + "}", "x-api-key=" + value, "refresh_token_value=" + value]):
            with self.subTest(case=i):
                self.assertFalse(value in redact.redact(text))


if __name__ == "__main__":
    unittest.main()
