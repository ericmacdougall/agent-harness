"""goodqa#15318: a real user turn or AskUserQuestion answer of fewer than 12 characters ("now", "yes") could never be
cited because every excerpt needed 12+ characters. The excerpt may be shorter only when it is the user's whole turn.
A short fragment of a longer turn stays rejected. Rows are data; transcripts are synthetic."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness" / "hooks"))
import provenance  # noqa: E402

SID = "11111111-2222-3333-4444-555555555556"
SHORT, LONG, ANS = (str(uuid.UUID(int=i)) for i in (41, 42, 43))
ASK_USE = "toolu_ASKSHORT"


class ShortAnswers(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"HOME": tmp.name}); p.start(); self.addCleanup(p.stop)
        os.environ.pop("HARNESS_PROVENANCE_OFFLINE", None)
        proj = Path(tmp.name) / ".claude/projects/-p"; proj.mkdir(parents=True)
        human = {"origin": {"kind": "human"}}

        def turn(uid, text):
            return dict({"type": "user", "uuid": uid, "timestamp": "2026-11-04T10:00:00Z", "sessionId": SID,
                         "message": {"role": "user", "content": text}}, **human)
        rows = [turn(SHORT, "now"), turn(LONG, "do it now, then run the tests"),
                {"type": "assistant", "uuid": str(uuid.uuid4()), "message": {"content": [
                    {"type": "tool_use", "id": ASK_USE, "name": "AskUserQuestion", "input": {}}]}},
                {"type": "user", "uuid": ANS, "timestamp": "2026-11-04T10:05:00Z", "toolUseResult": {"answers": {"q": "now"}},
                 "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": ASK_USE, "content": 'answered "q"="now"'}]}}]
        (proj / (SID + ".jsonl")).write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))

    def test_whole_short_turn_and_short_answer_verify(self):
        self.assertTrue(provenance.resolve('user:%s/%s "now"' % (SID, SHORT))["ok"])
        self.assertTrue(provenance.resolve('answer:%s/%s "now"' % (SID, ANS))["ok"])

    def test_control_short_fragment_of_a_longer_turn_is_rejected(self):
        for src in ('user:%s/%s "now"' % (SID, LONG), 'user:%s/%s "do it"' % (SID, LONG)):
            r = provenance.resolve(src)
            self.assertFalse(r["ok"], r)
        for fluff in ('?', '.', '!!'):  # red-team C5: punctuation proves nothing about an ask
            self.assertFalse(provenance.excerpt_in(fluff, fluff) is None, fluff)
        # a short wrong word never matches a short turn either
        self.assertFalse(provenance.resolve('user:%s/%s "yes"' % (SID, SHORT))["ok"])

    def test_find_user_locates_only_the_whole_short_turn(self):
        found = provenance.find_user(SID, "now")
        self.assertEqual([f["uuid"] for f in found], [SHORT])


if __name__ == "__main__":
    unittest.main()
