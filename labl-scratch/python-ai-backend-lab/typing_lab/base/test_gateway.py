"""The ordinary test suite a team would have: happy paths plus the main error branches."""
import asyncio

import pytest

from gateway import Budget, BudgetExceeded, Gateway, TenantId, UnknownModel, render_prompt, user_message

T = TenantId("acme")


class Fake:
    async def complete(self, messages, max_tokens):
        return {"text": "ok", "tokens_in": 10, "tokens_out": 20}


def gw(limit=1000):
    return Gateway({"m": Fake()}, {T: Budget(limit)}, timeout_s=5.0)


def test_call_charges_budget():
    g = gw()
    out = asyncio.run(g.call(T, "m", [user_message("hi")], max_tokens=100))
    assert out["text"] == "ok"
    assert g.budgets[T].used == 30


def test_budget_exceeded():
    with pytest.raises(BudgetExceeded):
        asyncio.run(gw(limit=50).call(T, "m", [user_message("hi")], max_tokens=100))


def test_unknown_model():
    with pytest.raises(UnknownModel):
        asyncio.run(gw().call(T, "nope", [user_message("hi")]))


def test_unknown_tenant():
    with pytest.raises(KeyError):
        asyncio.run(gw().call(TenantId("other"), "m", [user_message("hi")]))


def test_fan_out_returns_completions():
    out = asyncio.run(gw().fan_out(T, "m", ["a", "b", "c"]))
    assert [o["text"] for o in out] == ["ok", "ok", "ok"]


def test_render_prompt():
    assert render_prompt([user_message("hi")]) == "HI"
    assert render_prompt([]) == ""
