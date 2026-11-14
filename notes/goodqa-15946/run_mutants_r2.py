"""Failing-first mutants for the round-2 fixes (goodqa#15946). Run from the repository root.

Each mutant rewrites one source file in place to undo one fix, runs the named tests verbosely, and restores the file
byte for byte (try/finally). A mutant whose tests still pass is reported as SURVIVED.
"""
import subprocess
import sys
from pathlib import Path

MUTANTS = [
    ("F1 source: old ungrounded literal", "harness/hooks/ah_lane.py",
     '"--source", self.register_source(ticket, task, agent),', '"--source", "inferred: ah lane bind by main",',
     ["tests.test_lane_r2.RealTaskRegisterTests.test_real_register_succeeds_with_a_grounded_source_and_a_retry_is_a_duplicate",
      "tests.test_lane_r2.RealTaskRegisterTests.test_bind_through_the_real_register_reaches_holder_bound"]),
    ("F1 bind: refusal swallowed as PARTIAL", "harness/hooks/lane/commands.py",
     "        except lanes.LaneRefusal as error:  # a definite refusal",
     "        except KeyboardInterrupt as error:  # a definite refusal",
     ["tests.test_lane_r2.RealTaskRegisterTests.test_bind_of_a_stream_registered_to_another_holder_is_refused_not_partial"]),
    ("F2: comments never send the persisted id (the pre-fix in-process list is lost on restart)",
     "harness/hooks/lane/commands.py",
     [("cid = ports.ticket.comment(m[\"ticket\"], body, op, attachment_ids=ids)",
       "cid = ports.ticket.comment(m[\"ticket\"], body, op, attachment_ids=[])"),
      ("attachment_ids=[persisted])", "attachment_ids=[])")],
     None, ["tests.test_lane_r2.NewCrashTests"]),
    ("F3: spec_state falls back to ready", "harness/hooks/ah_lane.py",
     'verified, accepted = data.get("spec_verified"), data.get("reviews_accepted")',
     'verified, accepted = bool(data.get("ready")), bool(data.get("ready"))',
     ["tests.test_spec_flow.LaneSpecState"]),
    ("F4: keyed append does not dedupe", "harness/hooks/wal.py",
     "            existing = _find_op_key(fd, unique_key)", "            existing = None",
     ["tests.test_lane_r2.CheckpointExactlyOnceTests", "tests.test_lane_r2.WalNoteOpKeyTests"]),
    ("F4: no per-op lock", "harness/hooks/lane/commands.py",
     "        with store.op_lock(lane_dir, op):  # a concurrent run",
     "        with open(os.devnull):  # a concurrent run",
     ["tests.test_lane_r2.CheckpointExactlyOnceTests.test_two_concurrent_checkpoints_leave_one_note_and_one_comment"]),
]


def run(tests):
    done = subprocess.run([sys.executable, "-m", "unittest", "-v", *tests], capture_output=True, text=True, timeout=900)
    return done.returncode, done.stderr


def main():
    for label, path, old, new, tests in MUTANTS:
        p = Path(path)
        original = p.read_bytes()
        text = original.decode()
        pairs = old if isinstance(old, list) else [(old, new)]
        if any(text.count(a) != 1 for a, _ in pairs):
            print("== %s: anchor not found exactly once; NOT RUN" % label)
            continue
        for a, b in pairs:
            text = text.replace(a, b)
        try:
            p.write_text(text)
            code, out = run(tests)
        finally:
            p.write_bytes(original)
        print("== mutant %s: exit %d -> %s" % (label, code, "KILLED" if code else "SURVIVED"))
        print(out)
    code, out = run([t for m in MUTANTS for t in m[4]])
    print("== restored source: exit %d" % code)
    print(out)


if __name__ == "__main__":
    main()
