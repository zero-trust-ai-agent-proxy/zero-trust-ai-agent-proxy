"""Zero Trust Agent Benchmark adapter for Zero Trust AI Agent Proxy."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .defense import ProxyDefense
from .dlp import DLPScanner


def _default_profile() -> dict[str, Any] | None:
    try:
        profile_func = import_module("zero_trust_agent_benchmark.profile").profile
    except Exception:
        return None
    profile_obj = profile_func()
    return dict(profile_obj) if isinstance(profile_obj, dict) else None


class BenchmarkDefense:
    """Adapter with the API expected by zero_trust_agent_benchmark.evaluate."""

    def __init__(self) -> None:
        self.profile = _default_profile()
        self.defense = ProxyDefense(profile=self.profile)

    def reset(self) -> None:
        self.defense.reset()

    def setup(self, profile: dict[str, Any]) -> None:
        self.profile = dict(profile)
        self.defense = ProxyDefense(profile=self.profile)

    def on_trace_start(self, meta: dict[str, Any]) -> None:
        issued = tuple(
            str(secret) for secret in meta.get("issued_secrets", []) if isinstance(secret, str)
        )
        self.defense.dlp = DLPScanner(issued_secrets=issued)

    def decide(self, request: dict[str, Any]) -> dict[str, str]:
        return self.defense.decide(request).as_dict()
