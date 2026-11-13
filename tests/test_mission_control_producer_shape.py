"""The collector against the producer's real output shape (goodqa#15920, Codex receipt F1, F2).

`ah.requirements_view` returns evidence as clipped TEXT (not dicts) and clips the text to 600 characters. These tests
feed its real output, written from real WAL lines in a temporary home, through the Ledger collector."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import ah  # noqa: E402
import collectors as col  # noqa: E402
import events as ev  # noqa: E402

SID = "baab765b-d85c-46b4-b7b9-588eb912c770"
DAY = 86400


def stamp(age):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - age)) + "+00:00"


def real_view(rows):
    """requirements_view over real WAL lines in a temporary home: the producer's own output, parsed as JSON."""
    with tempfile.TemporaryDirectory() as home:
        folder = Path(home) / ".claude" / "wals" / SID
        folder.mkdir(parents=True)
        with open(folder / "main.jsonl", "w") as handle:
            for row in rows:
                handle.write(json.dumps({"event": "requirement", "at": row.pop("at"), **row}, separators=(",", ":")) + "\n")
        return json.loads(json.dumps(ah.requirements_view(Path(home), SID)))


class Runner:
    def __init__(self, view):
        self.view = view

    def run(self, kind, *args, timeout=20.0, limit=0):
        if kind == "ah-requirements":
            return 0, json.dumps(self.view)
        return 0, json.dumps({"goals": [], "generated": ev.iso()}) if kind == "ah-goals" else json.dumps({})


def read(view):
    hub = ev.Hub()
    ledger = col.Ledger(hub, col.Health(hub), Runner(view), lambda: SID)
    ledger.run(time.time())
    return {r["id"]: r for r in hub.snapshots["ledger"]["requirements"]["items"]}, ledger


NON_USER = 'inferred: from queue:x "y" ; queue:x "y" -- z'


class ProducerShape(unittest.TestCase):
    def test_the_producer_really_returns_evidence_as_text_and_clips_the_text(self):
        view = real_view([{"id": "wa", "at": stamp(40 * DAY), "note": "n" * 900, "source": NON_USER, "evidence": ["REALLY_TESTED a: PASS", "deploy b"]}])
        row = view["requirements"][0]
        self.assertIsInstance(row["evidence"], str)
        self.assertEqual(len(row["text"]), 600)

    def test_f1_textual_evidence_guards_an_old_non_user_requirement_and_is_shown(self):
        view = real_view([
            {"id": "wguard", "at": stamp(40 * DAY), "note": "has evidence", "source": NON_USER, "evidence": "REALLY_TESTED a: PASS on the live host"},
            {"id": "wlist", "at": stamp(40 * DAY), "note": "has evidence list", "source": NON_USER, "evidence": ["one", "two"]},
            {"id": "wnone", "at": stamp(40 * DAY), "note": "has none", "source": NON_USER}])
        rows, _ = read(view)
        self.assertEqual(rows["wguard"]["bucket"], "live")
        self.assertEqual(rows["wlist"]["bucket"], "live")
        self.assertIn("REALLY_TESTED a: PASS", rows["wguard"]["evidence_text"])
        self.assertTrue(rows["wguard"]["has_evidence"])
        self.assertEqual((rows["wnone"]["bucket"], rows["wnone"]["rule"]), ("archived", "R4"))  # the guard is real, not blanket

    def test_f2_two_requirements_that_differ_only_after_char_600_stay_live_and_have_distinct_digests(self):
        prefix = "x" * 700
        view = real_view([{"id": "wold", "at": stamp(3 * DAY), "note": prefix + " alpha", "source": NON_USER},
                          {"id": "wnew", "at": stamp(1 * DAY), "note": prefix + " beta", "source": NON_USER}])
        self.assertEqual(view["requirements"][0]["text"], view["requirements"][1]["text"])  # the display text collides
        rows, _ = read(view)
        self.assertEqual((rows["wold"]["bucket"], rows["wnew"]["bucket"]), ("live", "live"))
        self.assertNotEqual(rows["wold"]["digest"], rows["wnew"]["digest"])

    def test_f2_a_real_exact_duplicate_longer_than_600_still_supersedes(self):
        text = "y" * 800
        view = real_view([{"id": "wold", "at": stamp(3 * DAY), "note": text, "source": NON_USER},
                          {"id": "wnew", "at": stamp(1 * DAY), "note": text, "source": NON_USER}])
        rows, _ = read(view)
        self.assertEqual((rows["wold"]["rule"], rows["wnew"]["bucket"]), ("R3", "live"))

    def test_f2_the_digest_changes_when_the_text_changes_after_char_600(self):
        a = real_view([{"id": "wd", "at": stamp(DAY), "note": "z" * 700 + "A", "source": NON_USER}])
        b = real_view([{"id": "wd", "at": stamp(DAY), "note": "z" * 700 + "B", "source": NON_USER}])
        self.assertNotEqual(read(a)[0]["wd"]["digest"], read(b)[0]["wd"]["digest"])

    def test_f2_an_old_producer_without_a_text_hash_never_collapses_clipped_texts(self):
        view = real_view([{"id": "wold", "at": stamp(3 * DAY), "note": "q" * 700 + " a", "source": NON_USER},
                          {"id": "wnew", "at": stamp(DAY), "note": "q" * 700 + " b", "source": NON_USER}])
        for row in view["requirements"]:
            row.pop("text_sha", None)
            row.pop("text_len", None)
        rows, _ = read(view)
        self.assertEqual((rows["wold"]["bucket"], rows["wnew"]["bucket"]), ("live", "live"))  # completeness unknown: R3 refuses


if __name__ == "__main__":
    unittest.main()
