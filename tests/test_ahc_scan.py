"""ahc_scan: the R5 report scanner (goodqa#16049 spec ahc-m1-v2g7 R5, NEG-21 scan half, harvest idea 4, and the
spec owner's tiering and corpus rulings).

Every secret here is built at run time from a seeded generator and the scanner's own split prefixes; this file
holds no token-shaped literal, and the clean-corpus test checks that (it scans this file too)."""
import base64
import binascii
import json
import random
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import ahc_scan as S  # noqa: E402

SEED = 16049
EXEMPT = ROOT / "tests" / "data" / "ahc_scan_corpus_exempt.json"
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
PREFIX = dict(S.PREFIXES)


def corpus_files(root=ROOT):
    """The repo's own .py and .md files: the tracked ones when git is there, else a walk skipping dot dirs."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "*.py", "*.md"], capture_output=True,
                             check=True).stdout
        return sorted(p for p in out.decode().split("\0") if p)
    except (OSError, subprocess.CalledProcessError):
        return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.suffix in (".py", ".md")
                      and p.is_file() and not any(part.startswith(".") or part in ("node_modules", "__pycache__")
                                                  for part in p.relative_to(root).parts))


def corpus_counts(root=ROOT, files=None):
    """{path: {rule[:prefix]: count}} for every corpus file with at least one finding."""
    counts = {}
    for rel in files if files is not None else corpus_files(root):
        path = Path(root) / rel
        if not path.is_file():
            continue
        findings = S.scan_report(path.read_bytes(), rel)
        if findings:
            counts[rel] = dict(sorted(Counter(f["rule"] + ("" if f["exposure"] else ":prefix")
                                              for f in findings).items()))
    return counts


class Secrets:
    def __init__(self, seed=SEED):
        self.rng = random.Random(seed)

    def body(self, n):
        """n random alphanumerics with every class present (so a body is never hex-only)."""
        while True:
            s = "".join(self.rng.choice(ALNUM) for _ in range(n))
            if n < 3 or (any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)):
                return s

    def token(self, kind, n=36):
        return PREFIX[kind] + self.body(n)

    def jwt(self):
        enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()  # noqa: E731
        return ".".join([enc({"alg": "HS256", "typ": "J" + "WT"}), enc({"sub": self.body(12), "n": 7}),
                         self.body(43)])


class PrefixWindowTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()

    def only(self, text):
        findings = S.scan_report(text.encode())
        self.assertEqual(len(findings), 1, findings)
        return findings[0]

    def test_byte_boundary_pairs_only_the_8_byte_one_is_an_exposure(self):
        for kind in PREFIX:
            with self.subTest(kind=kind):
                seven = self.only("see %s here" % (PREFIX[kind] + self.s.body(7)))
                eight = self.only("see %s here" % (PREFIX[kind] + self.s.body(8)))
                self.assertEqual((seven["rule"], seven["exposure"], seven["severity"]), (kind, False, "block"))
                self.assertEqual((eight["rule"], eight["exposure"], eight["severity"]), (kind, True, "block"))

    def test_a_bare_public_prefix_is_a_block_but_not_an_exposure(self):
        for kind in PREFIX:
            with self.subTest(kind=kind):
                f = self.only("the `%s` prefix" % PREFIX[kind])
                self.assertEqual((f["rule"], f["exposure"]), (kind, False))

    def test_separators_inside_a_value_are_stripped_before_the_window(self):
        b = self.s.body(12)
        split = "-".join(b[i:i + 3] for i in range(0, 12, 3))          # 3 alnum, '-', 3 alnum ...
        f = self.only("value %s%s end" % (PREFIX["github-classic"], split))
        self.assertTrue(f["exposure"], "separators do not hide the 12 alphanumerics")

    def test_the_longest_prefix_names_the_kind(self):
        self.assertEqual(self.only(self.s.token("anthropic"))["rule"], "anthropic")
        self.assertEqual(self.only(self.s.token("openai-project"))["rule"], "openai-project")

    def test_a_prefix_counts_only_at_a_word_boundary(self):
        words = "a risk" + "-based plan, the task" + "-ant-thing and a whisk" + "-proj-x; xghp" + "_y"
        self.assertEqual(S.scan_report(words.encode()), [])

    def test_line_numbers(self):
        text = "one\ntwo\n%s\nfour\n" % self.s.token("github-classic")
        self.assertEqual(self.only(text)["line"], 3)


class EncodingTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()
        self.secret = self.s.token("github-fine-grained", 40)

    def encoded(self, encoding):
        b = self.secret.encode()
        return {"hex": binascii.hexlify(b).decode(), "base64": base64.b64encode(b).decode(),
                "base64-urlsafe": base64.urlsafe_b64encode(b).decode().rstrip("="),
                "url": "".join("%%%02X" % c for c in b)}[encoding]       # every byte percent-encoded

    def test_each_listed_encoding_is_decoded_and_scanned(self):
        for encoding in ("hex", "base64", "base64-urlsafe", "url"):
            with self.subTest(encoding=encoding):
                findings = S.scan_report(("line one\nx = %s\n" % self.encoded(encoding)).encode())
                hits = [f for f in findings if f["rule"] == "github-fine-grained"]
                self.assertTrue(hits, findings)
                self.assertTrue(hits[0]["exposure"])
                self.assertEqual(hits[0]["encoding"], encoding.split("-")[0])
                self.assertEqual(hits[0]["line"], 2)

    def test_url_encoding_of_a_whole_value_with_separators(self):
        value = PREFIX["anthropic"] + "api03-" + self.s.body(20)
        findings = S.scan_report(urllib.parse.quote("key=" + value, safe="").encode())
        self.assertTrue(any(f["rule"] == "anthropic" and f["exposure"] for f in findings), findings)

    def test_jwt_shape(self):
        f = S.scan_report(("Authorization: %s\n" % self.s.jwt()).encode())
        self.assertTrue(any(x["rule"] == "jwt" and x["exposure"] for x in f), f)


class EntropyTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()

    def test_a_long_random_mixed_run_is_an_exposure(self):
        for n in (32, 40, 64):
            with self.subTest(n=n):
                f = S.scan_report(("secret: %s\n" % self.s.body(n)).encode())
                self.assertEqual([(x["rule"], x["exposure"]) for x in f], [("high-entropy", True)])

    def test_a_base64_blob_of_random_bytes_is_an_exposure(self):
        blob = base64.b64encode(bytes(self.s.rng.randrange(256) for _ in range(48))).decode()
        if "+" not in blob:
            blob = blob[:10] + "+" + blob[11:]
        f = S.scan_report(blob.encode())
        self.assertIn(("high-entropy", True), [(x["rule"], x["exposure"]) for x in f])

    def test_ordinary_shapes_are_not_high_entropy(self):
        hexsha = "".join(self.s.rng.choice("0123456789abcdef") for _ in range(64))
        cases = {
            "hex digest": hexsha,
            "upper hex digest": hexsha.upper(),
            "sorted flag table": "0123456789EFGHILPRSTUVWYabchijklnopqrsuvwxyz",
            "alphabet listing": ALNUM,
            "reverse alphabet": ALNUM[::-1],
            "distinct-character flag set": "".join(self.s.rng.sample(ALNUM, 45)),
            "a path": "/Users/someone/Work/Project-2026/src/Module_v2/TestCase9/file.py",
            "NAME=value": "HARNESS_WORKTREE_GATE=off-for-Tests-2026",
            "an identifier": "test_explicit_base_equal_to_head_is_omitted_and_refused_with_base",
            "short random": self.s.body(31),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertEqual(S.scan_report(text.encode()), [])


class TierTests(unittest.TestCase):
    """The spec owner's tiering ruling: prefix-only restricts the outward text; an exposure quarantines."""

    def setUp(self):
        self.s = Secrets()

    def test_clean_report_passes_its_excerpt(self):
        findings = S.scan_report(b"PASS: no findings in harness/hooks/merge_gate.py\n")
        self.assertEqual(S.verdict(findings), {"action": "clean", "incident": False, "exposures": 0, "blocks": 0})
        self.assertEqual(S.outward(findings, "the excerpt"), "the excerpt")

    def test_prefix_only_restricts_to_structured_fields_with_no_incident(self):
        report = "F1 at redact.py:12 the pattern for `%s` misses a case\n" % PREFIX["github-classic"]
        findings = S.scan_report(report.encode(), "reports/r1.md")
        v = S.verdict(findings)
        self.assertEqual((v["action"], v["incident"], v["exposures"], v["blocks"]), ("restrict", False, 0, 1))
        out = S.outward(findings, report)
        self.assertEqual(out, "SCAN-1 reports/r1.md:1 block")
        self.assertNotIn("misses", out, "no excerpt leaves on a prefix-only hit")
        self.assertNotIn(PREFIX["github-classic"], out)

    def test_an_exposure_quarantines_writes_nothing_outward_and_raises_an_incident(self):
        for secret in (self.s.token("anthropic"), self.s.jwt(), self.s.body(40)):
            with self.subTest(kind=secret[:3].isalpha()):
                report = "F1 the reviewer pasted %s by mistake\n" % secret
                findings = S.scan_report(report.encode())
                v = S.verdict(findings)
                self.assertEqual((v["action"], v["incident"]), ("quarantine", True))
                self.assertIsNone(S.outward(findings, report))

    def test_a_prefix_hit_and_an_exposure_together_quarantine(self):
        report = "`%s` and %s\n" % (PREFIX["openai"], self.s.token("github-classic"))
        self.assertEqual(S.verdict(S.scan_report(report.encode()))["action"], "quarantine")

    def test_no_finding_or_rendering_carries_secret_text(self):
        secrets = [self.s.token(k) for k in PREFIX] + [self.s.jwt(), self.s.body(48)]
        report = "\n".join("x %s" % s for s in secrets).encode()
        findings = S.scan_report(report, "r.md")
        dumped = json.dumps(findings) + S.render_structured(findings)
        for secret in secrets:
            body = secret[-8:]
            self.assertNotIn(body, dumped)
        self.assertEqual(set().union(*(f.keys() for f in findings)),
                         {"id", "path", "line", "rule", "encoding", "severity", "exposure"})

    def test_only_bytes_are_scanned(self):
        with self.assertRaises(TypeError):
            S.scan_report("text")


class CleanCorpusTests(unittest.TestCase):
    """The repo's own .py and .md files (spec owner's corpus ruling A): every file not on the exemption list
    yields zero findings, and every listed file yields exactly its listed per-rule counts. A stale entry or a
    changed count fails, so a new credential-shaped literal anywhere in the repo is caught."""

    def test_the_corpus_matches_the_exemption_list_exactly(self):
        exempt = json.loads(EXEMPT.read_text())
        listed = {path: entry["counts"] for path, entry in exempt.items()}
        for path, entry in exempt.items():
            self.assertTrue(entry.get("reason"), "every exemption names its reason: %s" % path)
        actual = corpus_counts()
        unlisted = {p: c for p, c in actual.items() if p not in listed}
        self.assertEqual(unlisted, {}, "files with credential shapes that are not exempted")
        stale = sorted(p for p in listed if p not in actual)
        self.assertEqual(stale, [], "exemptions for files that no longer have findings")
        changed = {p: (listed[p], actual[p]) for p in listed if p in actual and listed[p] != actual[p]}
        self.assertEqual(changed, {}, "per-rule counts changed (listed, actual)")

    def test_the_scanner_and_this_test_are_clean(self):
        for rel in ("harness/hooks/ahc_scan.py", "tests/test_ahc_scan.py"):
            with self.subTest(rel):
                self.assertEqual(S.scan_report((ROOT / rel).read_bytes(), rel), [])

    def test_a_planted_secret_in_an_exempt_file_changes_its_count(self):
        exempt = json.loads(EXEMPT.read_text())
        rel = sorted(exempt)[0]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / rel
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / rel).read_bytes() + ("\n# %s\n" % Secrets(7).token("openai", 40)).encode())
            self.assertNotEqual(corpus_counts(tmp, [rel]).get(rel), exempt[rel]["counts"])


if __name__ == "__main__":
    unittest.main()
