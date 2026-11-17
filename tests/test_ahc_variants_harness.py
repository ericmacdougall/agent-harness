"""AC-15 / NEG-32: the slice 1 (b) variant harness classifies name-only tests, broken imports, errors, timeouts and
no-op controls as unproven or inconclusive, never as killed."""
import importlib.util
import pathlib
import unittest

HARNESS = pathlib.Path(__file__).resolve().parent / "variants" / "ahc_slice1b_variants.py"


def _load():
    spec = importlib.util.spec_from_file_location("ahc_slice1b_variants", str(HARNESS))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VariantHarnessTests(unittest.TestCase):
    def test_slice1b_harness_self_test(self):
        self.assertEqual(_load().self_test(), [])

    def test_slice1b_classify_needs_an_assertion_in_a_mapped_method(self):
        h = _load()
        ids = ["a.B.test_x", "a.B.test_y"]
        self.assertEqual(h.classify({"a.B.test_x": "fail", "a.B.test_y": "pass"}, ids), "killed")
        self.assertEqual(h.classify({"a.B.test_x": "fail", "a.B.test_y": "error"}, ids), "inconclusive")
        self.assertEqual(h.classify({"a.B.test_x": "pass", "a.B.test_y": "pass"}, ids), "survived")
        self.assertEqual(h.classify({"a.B.test_x": "fail"}, ids), "inconclusive", "a mapped method did not run")
        self.assertEqual(h.classify({"a.B.test_x": "skip", "a.B.test_y": "fail"}, ids), "inconclusive")
        self.assertEqual(h.classify("timeout", ids), "inconclusive")

    def test_slice1b_every_entry_names_dotted_methods_and_a_mutation(self):
        h = _load()
        for key, entry in h.ENTRIES.items():
            with self.subTest(key=key):
                self.assertTrue(entry["mutations"], "an entry needs at least one mutation")
                for dotted in entry["tests"]:
                    self.assertRegex(dotted, r"^tests\.test_ahc\w*\.\w+\.test_\w+$")

    def test_slice1b_the_script_entry_point_runs_after_every_entry_is_registered(self):
        """An ENTRIES.update placed after `if __name__ == "__main__"` is seen on import (so the anchor test passes)
        but never by the harness run itself, which exits first: its mutants would be claimed and never run."""
        import ast  # noqa: PLC0415
        tree = ast.parse(HARNESS.read_text(encoding="utf-8"))
        last = tree.body[-1]
        self.assertIsInstance(last, ast.If, "the script entry point is the module's last statement")
        self.assertIn("__main__", ast.dump(last.test))
        self.assertEqual(sum(isinstance(n, ast.If) and "__main__" in ast.dump(n.test) for n in tree.body), 1)

    def test_slice1b_every_mutation_anchor_is_in_its_file_exactly_once(self):
        """A stale anchor stops the whole harness run (SystemExit); catch it in the focused suite instead."""
        h = _load()
        for key, entry in h.ENTRIES.items():
            for name, swaps, rel in entry["mutations"]:
                text = (pathlib.Path(h.ROOT) / rel).read_text(encoding="utf-8")
                for old, _new in swaps:
                    with self.subTest(key=key, mutation=name):
                        self.assertEqual(text.count(old), 1, "anchor %r in %s" % (old[:60], rel))


if __name__ == "__main__":
    unittest.main()
