"""safe_input.py against the standard hostile inputs (tests/hostile_inputs.py). Each probe runs in a child that is
killed as a process group on timeout, so a regression fails the test instead of eating the machine."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hostile_inputs import HostileInputs, run_capped  # noqa: E402

HOOKS = Path(__file__).resolve().parent.parent / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import safe_input  # noqa: E402

DRIVER = r"""
import json, sys
sys.path.insert(0, %(hooks)r)
import safe_input as si
path = sys.argv[1]
out = {}
def probe(name, fn):
    try:
        value = fn()
        out[name] = ["ok", value if isinstance(value, (int, str, bool, type(None))) else repr(type(value))]
    except si.InputRejected as e:
        out[name] = ["rejected", e.code]
    except ValueError as e:
        out[name] = ["value-error", str(e)[:40]]
def lines():
    return sum(1 for _ in si.iter_jsonl_lines(path, 1 << 20, max_total_bytes=32 << 20, max_seconds=2))
def tail_json():
    return type(si.safe_json_loads(si.read_tail(path, 1 << 20))).__name__
probe("open", lambda: os.close(si.open_regular_file(path)) or 1)
probe("bounded", lambda: len(si.read_bounded(path, 1 << 20)))
probe("tail", lambda: len(si.read_tail(path, 1 << 20)))
probe("lines", lines)
probe("json", tail_json)
print(json.dumps(out))
""" % {"hooks": str(HOOKS)}
DRIVER = "import os\n" + DRIVER


class HostileFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hostile = HostileInputs().__enter__()
        cls.addClassCleanup(cls.hostile.__exit__, None, None, None)

    def probe(self, path):
        code, out, err, seconds, peak = run_capped(["-c", DRIVER, path], timeout=15.0)
        self.assertEqual(code, 0, f"{path}: {err[-300:]}")
        self.assertLess(seconds, 4.0, f"{path} took {seconds:.1f}s")
        self.assertLess(peak, 100 * 1024 * 1024, f"{path}: peak RSS {peak >> 20} MiB")
        return json.loads(out)

    def test_non_regular_files_are_always_rejected(self):
        for path in self.hostile.never_regular():
            result = self.probe(path)
            for name in ("open", "bounded", "tail", "lines", "json"):
                self.assertEqual(result[name][0], "rejected", f"{path}/{name}: {result[name]}")
                self.assertEqual(result[name][1], "file-not-regular", f"{path}/{name}")

    def test_regular_but_hostile_files_stay_bounded(self):
        paths = self.hostile.paths(include_devices=False)
        sparse = self.probe(paths["sparse-5g"])
        self.assertEqual(sparse["open"][0], "ok")
        self.assertEqual(sparse["bounded"], ["rejected", "file-too-large"])
        self.assertEqual(sparse["tail"][0], "ok")  # one megabyte of the hole, not 5 GiB
        deep = self.probe(paths["deep-json"])
        self.assertEqual(deep["json"], ["value-error", "JSON nested too deeply"])
        for label in ("invalid-utf8", "nul-bytes"):
            result = self.probe(paths[label])
            self.assertEqual(result["open"][0], "ok", label)
            self.assertEqual(result["lines"][0], "ok", label)
        huge = self.probe(paths["huge-line"])
        self.assertEqual(huge["lines"], ["ok", 1])  # the 9 MiB line is yielded once as oversized, not buffered
        self.assertEqual(huge["bounded"], ["rejected", "file-too-large"])

    def test_stdin_is_bounded(self):
        code = (f"import sys; sys.path.insert(0, {str(HOOKS)!r}); import safe_input as si\n"
                "try:\n si.read_stdin_bounded(1 << 20); print('READ')\n"
                "except si.InputRejected as e: print('rejected', e.code)\n")
        with open("/dev/zero", "rb") as zero:
            run = subprocess.Popen([sys.executable, "-c", code], stdin=zero, stdout=subprocess.PIPE, start_new_session=True)
            try:
                out, _ = run.communicate(timeout=10)
            finally:
                try:
                    os.killpg(run.pid, 9)
                except OSError:
                    pass
        self.assertEqual(out.decode().strip(), "rejected stdin-too-large")

    def test_json_limits(self):
        with self.assertRaises(ValueError):
            safe_input.safe_json_loads(b"[" * 300 + b"]" * 300)
        with self.assertRaises(ValueError):
            safe_input.safe_json_loads("x" * 100, max_bytes=50)
        self.assertEqual(safe_input.safe_json_loads('{"a":"[[[[[[[[["}'), {"a": "[[[[[[[[["})
        self.assertEqual(safe_input.safe_json_loads(b'{"a":[' + b"[" * 150 + b"]" * 150 + b"]}", max_depth=200)["a"][0] is not None, True)
        with self.assertRaises(ValueError):  # compatible default: safe_json_loads(text, max_depth=100)
            safe_input.safe_json_loads("[" * 101 + "]" * 101)
        self.assertEqual(safe_input.safe_json_loads(bytearray(b"[[1]]")), [[1]])
        import inspect
        self.assertEqual(list(inspect.signature(safe_input.safe_json_loads).parameters)[:2], ["text", "max_depth"])
        self.assertEqual(inspect.signature(safe_input.safe_json_loads).parameters["max_depth"].default, 100)

    def test_allowed_roots_and_toctou_guard(self):
        root = Path(self.hostile.root)
        inside = root / "nul-bytes"
        outside = Path(__file__)
        fd = safe_input.open_regular_file(inside, allowed_roots=[root])
        os.close(fd)
        with self.assertRaises(safe_input.InputRejected) as caught:
            safe_input.open_regular_file(outside, allowed_roots=[root])
        self.assertEqual(caught.exception.code, "file-outside-root")
        link = root / "escape-link"
        if not link.exists():
            os.symlink(outside, link)
        with self.assertRaises(safe_input.InputRejected):
            safe_input.open_regular_file(link, allowed_roots=[root])  # a symlink escaping the root is resolved first


class HooksOnHostilePaths(unittest.TestCase):
    """CLI entry points that take a path must refuse devices and FIFOs quickly."""

    def test_provenance_cli_refuses_non_regular_inputs(self):
        with HostileInputs() as hostile:
            for path in hostile.never_regular():
                for command in ("check-spec", "check-packet"):
                    code, out, err, seconds, peak = run_capped([str(HOOKS / "provenance.py"), command, path], timeout=10.0)
                    self.assertEqual(code, 2, f"{command} {path}: rc={code} {err[-200:]}")
                    self.assertLess(seconds, 2.0, f"{command} {path}")
                    self.assertLess(peak, 100 * 1024 * 1024, f"{command} {path}")


if __name__ == "__main__":
    unittest.main()
