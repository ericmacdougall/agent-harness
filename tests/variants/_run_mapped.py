"""Child runner for the slice 1 (b) variant harness (AC-15). Not collected by unittest (no test_ prefix).

Usage: python3 -B _run_mapped.py <dotted test id>... ; prints one JSON line last: {"results": {id: outcome}}, where
outcome is "pass", "fail" (an AssertionError, unittest's failure), "error" (anything else, including a load error) or
"skip". AHC_NOOP_TESTS, a comma-separated list of dotted ids, replaces those methods with a no-op before the run (the
harness's control, NEG-32). Each id is loaded by its full dotted name, so only the mapped methods run.
"""
import importlib
import json
import os
import sys
import unittest


def _noop(self):
    return None


def _apply_noops(ids):
    for dotted in ids:
        mod_name, cls_name, meth = dotted.rsplit(".", 2)
        cls = getattr(importlib.import_module(mod_name), cls_name)
        setattr(cls, meth, _noop)


class _Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.outcomes = {}

    def addSuccess(self, test):
        self.outcomes.setdefault(test.id(), "pass")

    def addFailure(self, test, err):
        self.outcomes[test.id()] = "fail"

    def addError(self, test, err):
        self.outcomes[getattr(test, "id", lambda: str(test))()] = "error"

    def addSkip(self, test, reason):
        self.outcomes[test.id()] = "skip"

    def addExpectedFailure(self, test, err):
        self.outcomes[test.id()] = "error"      # an expectedFailure decorator is never evidence

    def addUnexpectedSuccess(self, test):
        self.outcomes[test.id()] = "error"

    def addSubTest(self, test, subtest, err):
        if err is not None:
            failed = issubclass(err[0], test.failureException)
            prior = self.outcomes.get(test.id())
            self.outcomes[test.id()] = "error" if (not failed or prior == "error") else "fail"


def main(ids):
    sys.path.insert(0, os.getcwd())             # load the mapped modules from the repo root, like -m unittest
    noops = [i for i in os.environ.get("AHC_NOOP_TESTS", "").split(",") if i]
    results = {}
    try:
        _apply_noops(noops)
    except Exception as error:                      # a broken import is inconclusive, never a kill
        print(json.dumps({"results": {i: "error" for i in ids}, "load_error": type(error).__name__}))
        return 0
    for dotted in ids:
        try:
            suite = unittest.defaultTestLoader.loadTestsFromName(dotted)
        except Exception as error:
            results[dotted] = "error"
            continue
        result = _Result()
        suite.run(result)
        got = [v for k, v in result.outcomes.items()]
        if result.errors and not got:
            results[dotted] = "error"
        elif not got:
            results[dotted] = "error"               # nothing ran: never evidence
        elif dotted in result.outcomes:
            results[dotted] = result.outcomes[dotted]
        else:                                       # a load failure reports under another id
            results[dotted] = "error"
    print(json.dumps({"results": results}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
