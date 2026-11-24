"""Failing-first set for the guard-file exclusion (goodqa#16944, PR #326). Each variant removes one control in a temporary
copy of the tree; tests.test_guard_files must fail against every variant and pass against the real files.

    python3 -B tests/mutants_guard_files.py      exit 0 when every variant is killed and the real tree passes
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPS, INST, GF = "harness/hooks/ah_ops.py", "harness/hooks/ah_install.py", "harness/hooks/guard_files.py"

VARIANTS = [
    ("repair apply not checked (the code before this change)", OPS,
     "    if apply:\n        refuse_guard_changes(ctx, ref, host)\n", ""),
    ("repair ignores host drift", OPS,
     'changed = sorted(n for n in names if mac[n] != expected[n] or remote.get(n) != expected[n])',
     'changed = sorted(n for n in names if mac[n] != expected[n])'),
    ("manifest install not checked (the code before this change)", INST,
     "    if manifest:\n        refuse_guard_files(host, ref, todo, home)\n", ""),
    ("closure not counted", GF, "    return sorted(b for b in bases if is_guard_file(b) or b in closure)",
     "    return sorted(b for b in bases if is_guard_file(b))"),
    ("unreadable manifest fails open", GF, "    if closure is None:\n        return sorted(bases)\n",
     "    if closure is None:\n        closure = set()\n"),
    ("refusal omits the user line", GF, "USER_INSTALL.format(host=host, ref=ref, files=\" --file \".join(files))", "\"ask the user\""),
]


def run(tree: Path) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "unittest", "tests.test_guard_files"], cwd=str(tree),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900).returncode


def main() -> int:
    survivors, missing = [], []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "real"
        for part in ("harness/hooks", "scripts", "tests", "templates"):
            shutil.copytree(ROOT / part, base / part, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy2(ROOT / "install.py", base / "install.py")
        if run(base) != 0:
            print("the real tree fails its own tests; nothing measured")
            return 1
        for number, (name, rel, old, new) in enumerate(VARIANTS):
            tree = Path(tmp) / ("v%02d" % number)
            shutil.copytree(base, tree)
            path = tree / rel
            text = path.read_text()
            if text.count(old) != 1:
                missing.append(name)
                print("NOT APPLIED  %s" % name)
            else:
                path.write_text(text.replace(old, new))
                rc = run(tree)
                print("%-9s %s" % ("killed" if rc else "SURVIVED", name))
                if rc == 0:
                    survivors.append(name)
            shutil.rmtree(tree)
    print("%d variants, survivors: %s, not applied: %s" % (len(VARIANTS), ", ".join(survivors) or "none", ", ".join(missing) or "none"))
    return 1 if survivors or missing else 0


if __name__ == "__main__":
    sys.exit(main())
