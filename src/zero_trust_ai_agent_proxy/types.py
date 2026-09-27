"""Shared request and decision types for Zero Trust AI Agent Proxy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

type DecisionValue = Literal["allow", "deny"]
type Request = dict[str, Any]


@dataclass(frozen=True, slots=True)
class Decision:
    """Zero Trust AI Agent Proxy authorization decision."""

    decision: DecisionValue
    reason: str
    component: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)
