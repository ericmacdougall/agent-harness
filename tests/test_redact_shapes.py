"""Secret shapes Mission Control surfaces that redact.py missed (GoodQA #15585, red-team spec review F5).

Fake values are assembled at runtime so the repository never contains a literal that looks like a live key.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import redact  # noqa: E402

BODY = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"  # 32 mixed characters, not a real key


def fake(prefix: str, body: str = BODY) -> str:
    return "".join([prefix, body])


class NewShapes(unittest.TestCase):
    CASES = {
        "stripe-live-secret": fake("sk" + "_live_"),
        "stripe-test-secret": fake("sk" + "_test_"),
        "stripe-restricted": fake("rk" + "_live_"),
        "stripe-webhook": fake("wh" + "sec_"),
        "huggingface": fake("h" + "f_"),
        "gitlab": fake("gl" + "pat-", BODY[:20]),
        "sendgrid": "S" + "G." + BODY[:22] + "." + BODY + "Ab3dEf6hIj9",
    }

    def test_each_shape_is_redacted_in_prose(self):
        for name, value in self.CASES.items():
            with self.subTest(name=name):
                text = f"the reply said {value} and then stopped"
                out = redact.redact(text)
                self.assertTrue(value not in out, "no full fixture shape may survive")
                self.assertTrue(value[-12:] not in out, "no tail fragment may survive")
                self.assertIn("[REDACTED:", out)

    def test_openssh_private_key_block_is_redacted(self):
        block = ("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + BODY * 3 + "\n-----END OPENSSH " + "PRIVATE KEY-----")
        out = redact.redact("key:\n" + block + "\nend")
        self.assertTrue(BODY not in out, "no private-key-shaped body may survive")

    def test_ordinary_words_are_left_alone(self):
        for text in ("skip_live_tests is a flag", "the hf_ prefix is documented", "SG. is short for sergeant"):
            with self.subTest(text=text):
                self.assertEqual(redact.redact(text), text)

    def test_new_shape_spans_cross_the_shared_chunk_overlap(self):
        body_size = redact.OVERLAP + 128
        shapes = (
            ("stripe", "sk_" + "test_" + "A" * body_size),
            ("stripe-webhook", "whsec_" + "B" * body_size),
            ("huggingface", "hf_" + "C" * body_size),
            ("gitlab", "glpat-" + "D" * body_size),
            ("sendgrid", "SG." + "E" * body_size + "." + "F" * 32),
            ("sendgrid", "SG." + "G" * 24 + "." + "H" * body_size),
        )
        for offset in (redact.MAX_CHUNK - 12, redact.MAX_CHUNK + 7):
            padding = "!" * offset
            for kind, value in shapes:
                with self.subTest(kind=kind, offset=offset, size=len(value)):
                    source = padding + value + "!"
                    self.assertEqual(redact.find(source), [(kind, offset, offset + len(value))])
                    expected = padding + "[REDACTED:" + kind + "]!"
                    self.assertTrue(redact.redact(source) == expected, "the entire span must be replaced")
                    self.assertTrue(redact.redact(expected) == expected, "replacement must be idempotent")

    def test_new_shape_preserves_full_span_when_other_shapes_overlap(self):
        value = "hf_" + "J" * 64
        out = redact.redact("Bearer " + value + "!")
        self.assertTrue(out == "[REDACTED:bearer]!", "the outer span must win")


if __name__ == "__main__":
    unittest.main()
