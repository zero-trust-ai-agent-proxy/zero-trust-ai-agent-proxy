"""Zero Trust AI Agent Proxy: Zero Trust AI Proxy."""

from __future__ import annotations

from .defense import ProxyDefense
from .types import Decision

__version__ = "0.1.0"

__all__ = ["Decision", "ProxyDefense", "__version__"]
