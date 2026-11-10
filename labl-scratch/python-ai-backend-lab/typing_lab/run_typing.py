"""Inject 20 realistic bugs, one at a time, into base/gateway.py and ask three detectors:
the team's pytest suite, `mypy --strict`, and pyright (strict).  A bug is "caught" when the detector
fails on the mutant (the base passes all three: asserted first).

python run_typing.py --out ../results/typing.json
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
BASE = HERE / "base"

# (id, class, old text, new text, note)
BUGS = [
    ("B01", "missing-await", "out = await asyncio.wait_for(", "out = asyncio.wait_for(", "forgot await"),
    ("B02", "none-deref", "        if budget is None:\n            raise KeyError(tenant)\n", "", "dropped the unknown-tenant guard"),
    ("B03", "none-deref", "        if provider is None:\n            raise UnknownModel(model)\n", "", "dropped the unknown-model guard"),
    ("B04", "wrong-return-type", "        return list(results)", "        return [r[\"text\"] for r in results]", "fan_out returns strings"),
    ("B05", "typeddict-key", 'out["tokens_in"] + out["tokens_out"]', 'out["tokens_input"] + out["tokens_out"]', "key typo"),
    ("B06", "wrong-arg-type", "provider.complete(messages, max_tokens), self.timeout_s)", "provider.complete(messages, max_tokens), str(self.timeout_s))", "timeout as str"),
    ("B07", "literal-misuse", '{"role": "user", "content": text}', '{"role": "human", "content": text}', "invalid role"),
    ("B08", "missing-arg", "provider.complete(messages, max_tokens)", "provider.complete(messages)", "dropped max_tokens"),
    ("B09", "attr-typo", "budget.remaining() < max_tokens", "budget.remainin() < max_tokens", "method typo"),
    ("B10", "optional-as-str", "    last = last_user_message(messages)\n    if last is None:\n        return \"\"\n    return last.upper()", "    return last_user_message(messages).upper()", "Optional used as str"),
    ("B11", "float-for-int", 'budget.charge(out["tokens_in"] + out["tokens_out"])', 'budget.charge((out["tokens_in"] + out["tokens_out"]) / 2)', "float to int param"),
    ("B12", "wrong-newtype", "self.budgets.get(tenant)", "self.budgets.get(str(tenant))", "plain str used for TenantId key"),
    ("B13", "return-none", "        return out\n\n    async def fan_out", "        return None\n\n    async def fan_out", "call returns None"),
    ("B14", "await-non-awaitable", "results = await asyncio.gather(*[self.call(", "results = await asyncio.gather(*[self.total_cost(", "wrong method in gather"),
    # logic bugs: types cannot see these
    ("L01", "off-by-one", "budget.remaining() < max_tokens", "budget.remaining() <= max_tokens", "boundary"),
    ("L02", "wrong-units", "self.timeout_s)", "self.timeout_s * 1000)", "seconds vs ms"),
    ("L03", "dropped-term", 'budget.charge(out["tokens_in"] + out["tokens_out"])', 'budget.charge(out["tokens_in"])', "bills input only"),
    ("L04", "wrong-price-unit", "tokens / 1000 * price_per_1k", "tokens / 100 * price_per_1k", "per-1k wrong"),
    ("L05", "wrong-role-filter", 'if m["role"] == "user":', 'if m["role"] == "assistant":', "wrong role"),
    ("L06", "swallow-guard", "if budget.remaining() < max_tokens:\n            raise BudgetExceeded(tenant)", "if budget.remaining() < max_tokens:\n            pass", "guard disabled"),
]


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)[-400:]


def detect(d: pathlib.Path):
    py = sys.executable
    t, _ = run([py, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"], d)
    th, _ = run([py, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-k", "call_charges_budget or render_prompt"], d)
    m, mo = run([py, "-m", "mypy", "--strict", "gateway.py"], d)
    pr, po = run([py, "-m", "pyright", "gateway.py"], d)
    return dict(pytest_fail=t != 0, pytest_thin_fail=th != 0, mypy_fail=m != 0, pyright_fail=pr != 0, mypy_msg=mo.strip().splitlines()[-2:] if m else [], pyright_msg=po.strip().splitlines()[-3:] if pr else [])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = []
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / "pyrightconfig.json").write_text('{"typeCheckingMode": "strict", "reportMissingImports": false}')
        shutil.copy(BASE / "test_gateway.py", td)
        base_res = None
        for bid, cls, old, new, note in [("BASE", "none", "", "", "unmodified")] + BUGS:
            src = (BASE / "gateway.py").read_text()
            if bid != "BASE":
                assert src.count(old) == 1, f"{bid}: pattern must match exactly once ({src.count(old)})"
                src = src.replace(old, new)
            (td / "gateway.py").write_text(src)
            r = detect(td)
            r.update(id=bid, cls=cls, note=note)
            print(bid, cls, {k: r[k] for k in ("pytest_fail", "pytest_thin_fail", "mypy_fail", "pyright_fail")}, flush=True)
            if bid == "BASE":
                assert not (r["pytest_fail"] or r["mypy_fail"] or r["pyright_fail"]), f"base must be clean: {r}"
            else:
                out.append(r)
    json.dump(out, open(a.out, "w"), indent=1)
