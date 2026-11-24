"""Every control on a guard-file route has a variant that removes it (goodqa#16944, PR 345 review F11: fix the class).

F11 was a gating argument (forced=recorded_guard(row) at --rollback and --resume) whose removal no test noticed. This
test derives, from ah_install.py's own AST, every guard_gate call site, the call itself, each gating argument it
passes (with a value that does not already remove it) and each condition that skips it, and fails when
tests/mutants_guard_install_gate.py has no variant for one of them (GATE_COVERAGE), when a variant does not remove what
it is listed for, or when a variant names no end-to-end test (KILLERS) going through that route's public entry. It
also fails when a guard_gate parameter (keyword-only included) is neither in GATING nor in the runner's NON_GATING
list, which maps the parameters that name the command (host, ref, ticket) to their stamp-key variants. The mutant
runner then proves each named test fails against its variant. This module is not in the runner's SUITES: it
reads the source, so it would fail in every call-site variant's tree and "kill" variants no behaviour test noticed.
"""
import ast
import functools
import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutants_guard_install_gate as mutants  # noqa: E402
import test_guard_install_gate as gate_tests  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / mutants.AI
GATING = ("files", "kind_", "allow_older", "forced", "allow_remote")
REMOVED = {"files": [], "kind_": "install", "allow_older": False, "forced": (), "allow_remote": True}
INSTALL = ("self.install(", "ai.install_files(", "self.refused(", "self.assert_refused_unchanged(")  # Base helpers call install
ENTRY = {"install_files": INSTALL,
         "resume": ("ai.resume(", "self.resume_of("),
         "rollback": ("ai.rollback(", "self.rollback_of("),
         "_run": INSTALL + ("ai.resume(", "self.resume_of(")}


def _value(node):
    try:
        return ast.literal_eval(node)
    except ValueError:
        return node  # not a literal: an expression, which a removal would replace


def _gate_def(tree):
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "guard_gate")


def parameters(source: str) -> list:
    """Every parameter of guard_gate: positional, keyword-only, *args and **kwargs."""
    a = _gate_def(ast.parse(source)).args
    return ([x.arg for x in a.posonlyargs + a.args + a.kwonlyargs] + ([a.vararg.arg] if a.vararg else [])
            + ([a.kwarg.arg] if a.kwarg else []))


@functools.lru_cache(maxsize=64)
def call_sites(source: str) -> tuple:
    """((function, call node, {param: value or expression}, [skip conditions], dead), ...) of every guard_gate call.
    Cached per source text; callers only read the result."""
    tree = ast.parse(source)
    a = _gate_def(tree).args
    params = [x.arg for x in a.posonlyargs + a.args]  # the ones a positional argument can fill
    defaults = dict(zip(params[len(params) - len(a.defaults):], (_value(d) for d in a.defaults)))
    defaults.update({k.arg: _value(d) for k, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
    out = []
    for func in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        parents = {}
        for node in ast.walk(func):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(func):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "guard_gate"):
                continue
            passed = dict(defaults)
            passed.update({params[i]: _value(a) for i, a in enumerate(node.args)})
            passed.update({k.arg: _value(k.value) for k in node.keywords})
            skips, dead, cur = [], False, node
            while cur in parents:
                up = parents[cur]
                if isinstance(up, ast.IfExp) and cur is not up.test:
                    skips.append(ast.unparse(up.test))
                if isinstance(up, ast.If) and cur is not up.test and cur in up.body:
                    skips.append(ast.unparse(up.test))
                    dead = dead or (isinstance(up.test, ast.Constant) and not up.test.value)
                cur = up
            out.append((func.name, node, passed, skips, dead))
    return tuple(out)


def inventory(source: str) -> set:
    """{(function, control)}: what GATE_COVERAGE must cover."""
    keys = set()
    for func, _node, passed, skips, dead in call_sites(source):
        if dead:
            continue
        keys.add((func, "call"))
        for name in GATING:
            value = passed.get(name)
            if isinstance(value, ast.AST) or value != REMOVED[name]:
                keys.add((func, name))
        keys.update((func, "skip: " + s) for s in skips)
    return keys


def removes(source: str, variant, func: str, control: str) -> bool:
    """Does applying VARIANT to SOURCE remove CONTROL at FUNC's guard_gate call?"""
    _name, _rel, old, new = variant
    if source.count(old) != 1:
        return False
    after = [s for s in call_sites(source.replace(old, new)) if s[0] == func]
    live = [s for s in after if not s[4]]
    if control == "call":
        return len(live) < len([s for s in call_sites(source) if s[0] == func and not s[4]])
    return any(not isinstance(s[2].get(control), ast.AST) and s[2].get(control) == REMOVED[control] for s in live)


def problems(source: str, coverage: dict, variants: list, killers: dict) -> list:
    out = []
    by_name = {v[0]: v for v in variants}
    have = inventory(source)
    for key in sorted(have - set(coverage)):
        out.append("no variant for %s at %s()" % (key[1], key[0]))
    for key in sorted(set(coverage) - have):
        out.append("stale coverage entry %s at %s()" % (key[1], key[0]))
    for (func, control), names in sorted(coverage.items()):
        if (func, control) not in have:
            continue
        missing = [n for n in names if n not in by_name]
        if missing or not names:
            out.append("%s at %s(): unknown variant(s) %s" % (control, func, ", ".join(missing) or "(none listed)"))
            continue
        if any(by_name[n][1] == mutants.AI and source.count(by_name[n][2]) != 1 for n in names):
            out.append("%s at %s(): a variant's text no longer occurs exactly once" % (control, func))
        if not control.startswith("skip: ") and not any(by_name[n][1] == mutants.AI and removes(source, by_name[n], func, control)
                                                        for n in names):
            out.append("%s at %s(): no listed variant removes it" % (control, func))
        for n in names:
            tests = killers.get(n) or ()
            if not tests:
                out.append("%s at %s(): variant %r names no end-to-end test" % (control, func, n))
                continue
            texts = []
            for test in tests:
                cls, _, method = test.partition(".")
                fn = getattr(getattr(gate_tests, cls, None), method, None)
                if fn is None:
                    out.append("variant %r: no test %s" % (n, test))
                    continue
                texts.append(inspect.getsource(fn))
            entries = ENTRY.get(func, ())
            if not entries:
                out.append("%s(): no public entry is known for this route (add it to ENTRY)" % func)
            elif texts and not any(e in t for t in texts for e in entries):
                out.append("%s at %s(): no test of variant %r goes through %s" % (control, func, n, " or ".join(entries)))
    return out


def unclassified(source: str, non_gating: dict, variants: list, killers: dict) -> list:
    """Every guard_gate parameter is in GATING (inventoried per call site above) or in NON_GATING, with variants that
    exist, still apply and name an end-to-end test, or with a written reason for having none."""
    out = []
    params = parameters(source)
    by_name = {v[0]: v for v in variants}
    for p in params:
        if p not in GATING and p not in non_gating:
            out.append("guard_gate parameter %s is neither gating nor named non-gating" % p)
    for p in sorted((set(GATING) | set(non_gating)) - set(params)):
        out.append("stale entry %s: guard_gate has no such parameter" % p)
    for p, cover in sorted(non_gating.items()):
        if isinstance(cover, str):
            if not cover.strip():
                out.append("non-gating %s: no variant and no reason" % p)
            continue
        if not cover:
            out.append("non-gating %s: no variant and no reason" % p)
        for n in cover:
            v = by_name.get(n)
            if v is None:
                out.append("non-gating %s: unknown variant %r" % (p, n))
            elif (ROOT / v[1]).read_text().count(v[2]) != 1:
                out.append("non-gating %s: variant %r's text no longer occurs exactly once" % (p, n))
            elif not killers.get(n):
                out.append("non-gating %s: variant %r names no end-to-end test" % (p, n))
    return out


class Coverage(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()

    def test_every_guard_gate_parameter_is_classified(self):
        self.assertEqual(unclassified(self.source, mutants.NON_GATING, mutants.VARIANTS, mutants.KILLERS), [])
        self.assertEqual(set(parameters(self.source)), set(GATING) | set(mutants.NON_GATING))

    def test_an_unclassified_parameter_is_reported(self):
        old = "def guard_gate(host, ref, files, ticket, home, kind_, allow_older=False, forced=(), allow_remote=False):\n"
        self.assertEqual(self.source.count(old), 1)
        for new, name in ((old.replace("):", ", *, skip_receipt=False):"), "skip_receipt"),  # keyword-only
                          (old.replace("allow_remote=False", "allow_remote=False, **extra"), "extra")):
            with self.subTest(name):
                self.assertIn("guard_gate parameter %s is neither gating nor named non-gating" % name,
                              unclassified(self.source.replace(old, new), mutants.NON_GATING, mutants.VARIANTS, mutants.KILLERS))
        non_gating = dict(mutants.NON_GATING, ticket=(), home="")
        found = unclassified(self.source, non_gating, mutants.VARIANTS, mutants.KILLERS)
        self.assertIn("non-gating ticket: no variant and no reason", found)
        self.assertIn("non-gating home: no variant and no reason", found)
        killers = {k: v for k, v in mutants.KILLERS.items() if k != "stamp key ignores the host"}
        self.assertIn("non-gating host: variant 'stamp key ignores the host' names no end-to-end test",
                      unclassified(self.source, mutants.NON_GATING, mutants.VARIANTS, killers))
        self.assertIn("stale entry gone: guard_gate has no such parameter",
                      unclassified(self.source, dict(mutants.NON_GATING, gone=("stamp key ignores the host",)),
                                   mutants.VARIANTS, mutants.KILLERS))

    def test_every_gating_control_has_a_variant_and_an_end_to_end_test(self):
        self.assertEqual(problems(self.source, mutants.GATE_COVERAGE, mutants.VARIANTS, mutants.KILLERS), [])
        self.assertGreaterEqual(len(inventory(self.source)), 20)  # the scan saw the real call sites
        self.assertEqual({f for f, _ in inventory(self.source)}, {"install_files", "resume", "rollback", "_run"})

    def test_every_named_killer_and_variant_exists(self):
        names = {v[0] for v in mutants.VARIANTS}
        self.assertEqual(len(names), len(mutants.VARIANTS))  # unique names
        self.assertEqual(sorted(set(mutants.KILLERS) - names), [])
        for tests in mutants.KILLERS.values():
            for test in tests:
                cls, _, method = test.partition(".")
                self.assertTrue(callable(getattr(getattr(gate_tests, cls, None), method, None)), test)

    # --- failing controls: the check reports what it is meant to catch

    def test_a_new_call_site_with_no_variant_is_reported(self):
        doctored = self.source + ('\n\ndef restore(run_id, ticket, home):\n'
                                  '    return guard_gate("t2-dev", None, ["ah.py"], ticket, home, "rollback", forced=("x",))\n')
        found = problems(doctored, mutants.GATE_COVERAGE, mutants.VARIANTS, mutants.KILLERS)
        self.assertIn("no variant for call at restore()", found)
        self.assertIn("no variant for forced at restore()", found)
        self.assertIn("no variant for kind_ at restore()", found)

    def test_a_new_gating_argument_or_skip_condition_is_reported(self):
        old = 'ticket, home, "rollback", forced=recorded_guard(row),'
        doctored = self.source.replace(old, 'ticket, home, "rollback", row.get("allow_older"), forced=recorded_guard(row),')
        self.assertIn("no variant for allow_older at rollback()",
                      problems(doctored, mutants.GATE_COVERAGE, mutants.VARIANTS, mutants.KILLERS))
        old = "    if not dry_run and gate is None and ref_guard:\n"
        doctored = self.source.replace(old, "    if not dry_run and gate is None and ref_guard and not resume_of:\n")
        found = problems(doctored, mutants.GATE_COVERAGE, mutants.VARIANTS, mutants.KILLERS)
        self.assertIn("no variant for skip: not dry_run and gate is None and ref_guard and (not resume_of) at _run()", found)

    def test_a_variant_that_does_not_remove_its_control_or_names_no_test_is_reported(self):
        variants = [v if v[0] != "rollback ignores the recorded gate" else (v[0], v[1], v[2], v[2].replace("rollback", "rollback "))
                    for v in mutants.VARIANTS]
        coverage = dict(mutants.GATE_COVERAGE)
        coverage[("rollback", "forced")] = ("rollback ignores the recorded gate",)
        self.assertIn("forced at rollback(): no listed variant removes it",
                      problems(self.source, coverage, variants, mutants.KILLERS))
        killers = {k: v for k, v in mutants.KILLERS.items() if k != "resume ignores the recorded gate"}
        self.assertIn("forced at resume(): variant 'resume ignores the recorded gate' names no end-to-end test",
                      problems(self.source, mutants.GATE_COVERAGE, mutants.VARIANTS, killers))
        killers = dict(mutants.KILLERS, **{"rollback ignores the recorded gate": ("Gate.test_a_dry_run_needs_neither",)})
        self.assertIn("forced at rollback(): no test of variant 'rollback ignores the recorded gate' goes through "
                      "ai.rollback( or self.rollback_of(", problems(self.source, mutants.GATE_COVERAGE, mutants.VARIANTS, killers))

    def test_a_removed_call_site_leaves_a_stale_entry(self):
        old = ('    gate = guard_gate(host, row.get("ref"), sorted(row["files"]), ticket, home, "rollback", forced=recorded_guard(row),\n'
               '                      allow_remote=allow_remote)\n')
        self.assertEqual(self.source.count(old), 1)
        found = problems(self.source.replace(old, "    gate = None\n"), mutants.GATE_COVERAGE, mutants.VARIANTS, mutants.KILLERS)
        self.assertIn("stale coverage entry forced at rollback()", found)


if __name__ == "__main__":
    unittest.main()
