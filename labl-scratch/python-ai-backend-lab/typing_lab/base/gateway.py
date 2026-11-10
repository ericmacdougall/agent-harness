"""A small multi-tenant LLM gateway: the kind of module where typing earns its keep."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, NewType, Optional, Protocol, TypedDict

TenantId = NewType("TenantId", str)
Role = Literal["system", "user", "assistant"]


class Message(TypedDict):
    role: Role
    content: str


class Completion(TypedDict):
    text: str
    tokens_in: int
    tokens_out: int


class Provider(Protocol):
    async def complete(self, messages: list[Message], max_tokens: int) -> Completion: ...


class BudgetExceeded(Exception):
    pass


class UnknownModel(Exception):
    pass


@dataclass
class Budget:
    limit_tokens: int
    used: int = 0

    def remaining(self) -> int:
        return self.limit_tokens - self.used

    def charge(self, n: int) -> None:
        self.used += n


def user_message(text: str) -> Message:
    return {"role": "user", "content": text}


def last_user_message(messages: list[Message]) -> Optional[str]:
    for m in reversed(messages):
        if m["role"] == "user":
            return m["content"]
    return None


def render_prompt(messages: list[Message]) -> str:
    last = last_user_message(messages)
    if last is None:
        return ""
    return last.upper()


class Gateway:
    def __init__(self, providers: dict[str, Provider], budgets: dict[TenantId, Budget], timeout_s: float = 30.0) -> None:
        self.providers = providers
        self.budgets = budgets
        self.timeout_s = timeout_s

    def budget_for(self, tenant: TenantId) -> Optional[Budget]:
        return self.budgets.get(tenant)

    async def call(self, tenant: TenantId, model: str, messages: list[Message], max_tokens: int = 256) -> Completion:
        budget = self.budget_for(tenant)
        if budget is None:
            raise KeyError(tenant)
        if budget.remaining() < max_tokens:
            raise BudgetExceeded(tenant)
        provider = self.providers.get(model)
        if provider is None:
            raise UnknownModel(model)
        out = await asyncio.wait_for(provider.complete(messages, max_tokens), self.timeout_s)
        budget.charge(out["tokens_in"] + out["tokens_out"])
        return out

    async def fan_out(self, tenant: TenantId, model: str, prompts: list[str]) -> list[Completion]:
        results = await asyncio.gather(*[self.call(tenant, model, [user_message(p)]) for p in prompts])
        return list(results)

    def total_cost(self, tokens: int, price_per_1k: float) -> float:
        return tokens / 1000 * price_per_1k
