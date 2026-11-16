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


if __name__ == "__main__":
    unittest.main()
