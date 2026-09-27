"""Pluggable PDP implementations for Zero Trust AI Agent Proxy."""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx


def _split_tool(tool: str) -> tuple[str, str]:
    if "." not in tool:
        return tool, ""
    category, action = tool.rsplit(".", 1)
    return category.split(".", 1)[0], action


def _infer_scope(tool: str) -> str | None:
    category, action = _split_tool(tool)
    if category == "http":
        return "net:write" if action == "post" else "net:read"
    if category == "search":
        return "net:read"
    if category == "email":
        return "email:send"
    if category == "calendar":
        return "calendar:write"
    if category == "fs":
        return "fs:write" if action in {"write", "delete"} else "fs:read"
    if category == "db":
        return "db:admin" if action == "admin" else "db:read"
    if category == "secrets":
        return "secrets:read"
    if category == "shell":
        return "shell:exec"
    if category == "code":
        return "code:exec"
    if category == "payments":
        return "payments:write"
    if category == "iam":
        return "iam:admin"
    return None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    risk: str


_WORKSPACE_ROOT = "/workspace"
_EMAIL_DOMAINS = ("acme.test",)
_DENY_COMMAND_RE = re.compile(
    r"[;&|`$<>]|"
    r"\b(?:rm|rmdir|del|erase|format|shutdown|reboot|curl|wget|nc|bash|sh|powershell|"
    r"sudo|su|chmod|chown|admin)\b",
    re.IGNORECASE,
)
_SQL_MUTATION_WORDS = {"insert", "update", "delete", "drop", "alter", "truncate", "grant", "revoke"}
_WORD_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_SAFE_INLINE_PYTHON_RE = re.compile(
    r'^python\s+-c\s+["\']import\s+[a-z0-9_.]+;\s*print\([a-z0-9_().]+\)\s*["\']$',
    re.IGNORECASE,
)
_SQL_BOUNDED_UPDATE_RE = re.compile(r"^\s*update\b.+\bwhere\b.+", re.IGNORECASE)
_SQL_BOUNDED_DELETE_RE = re.compile(r"^\s*delete\b.+\bwhere\b.+", re.IGNORECASE)


class DecisionCache:
    def __init__(self, maxsize: int = 1000) -> None:
        self.maxsize = maxsize
        self._items: OrderedDict[str, PolicyDecision] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> PolicyDecision | None:
        item = self._items.get(key)
        if item is None:
            self.misses += 1
            return None
        self._items.move_to_end(key)
        self.hits += 1
        return item

    def put(self, key: str, value: PolicyDecision) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        if len(self._items) > self.maxsize:
            self._items.popitem(last=False)

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


class NativePolicy:
    """Deny-by-default native PDP with tool risk classes and egress restrictions."""

    def __init__(
        self,
        allowed_domains: tuple[str, ...] = ("acme.test",),
        cache: DecisionCache | None = None,
        profile: dict[str, Any] | None = None,
    ) -> None:
        self.tool_catalog: dict[str, dict[str, Any]] = (
            dict(profile.get("tools", {})) if profile else {}
        )
        self.allowed_domains = (
            tuple(profile.get("egress_allowlist", allowed_domains)) if profile else allowed_domains
        )
        self.email_domains = (
            tuple(profile.get("email_allowed_domains", _EMAIL_DOMAINS))
            if profile
            else _EMAIL_DOMAINS
        )
        self.workspace_root = (
            str(profile.get("workspace_root", _WORKSPACE_ROOT)) if profile else _WORKSPACE_ROOT
        )
        self.cache = cache or DecisionCache()

    def risk_for(self, tool: str) -> str:
        meta = self.tool_catalog.get(tool, {})
        if meta.get("risk"):
            return str(meta["risk"])
        category, action = _split_tool(tool)
        if category in {"shell", "payments", "iam"} or action == "admin":
            return "critical"
        if category in {"email", "code", "secrets"} or action == "delete":
            return "high"
        if action in {"post", "write", "query"}:
            return "medium"
        return "low" if category in {"http", "search", "calendar", "fs", "mcp"} else "high"

    def egresses(self, tool: str) -> bool:
        meta = self.tool_catalog.get(tool)
        if meta is not None:
            return bool(meta.get("egress", False))
        category, _ = _split_tool(tool)
        return category in {"http", "email"}

    def _required_scopes(self, tool: str) -> set[str]:
        meta = self.tool_catalog.get(tool)
        if meta is not None:
            return {str(scope) for scope in meta.get("scopes", [])}
        if tool.startswith("mcp."):
            return {"mcp:use"}
        scope = _infer_scope(tool)
        return {scope} if scope else set()

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        args = dict(request.get("args", {}))
        key_material = {
            "tool": request.get("tool"),
            "args": {
                key: args.get(key)
                for key in ("url", "to", "path", "cmd", "cwd", "sql", "resource")
                if key in args
            },
            "scopes": sorted(dict(request.get("agent", {})).get("scopes", [])),
            "context": {
                key: dict(request.get("context", {})).get(key)
                for key in ("origin", "content", "tool_description", "user_task")
            },
        }
        key = json.dumps(key_material, sort_keys=True, default=str, separators=(",", ":"))
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        decision = self._decide_uncached(request)
        self.cache.put(key, decision)
        return decision

    def _decide_uncached(self, request: dict[str, Any]) -> PolicyDecision:
        tool = str(request.get("tool", ""))
        args = dict(request.get("args", {}))
        agent = dict(request.get("agent", {}))
        scopes = set(agent.get("scopes", []))
        required = self._required_scopes(tool)
        risk = self.risk_for(tool)
        if not required:
            return PolicyDecision(False, "unknown tool", "high")
        missing = required.difference(scopes)
        if missing:
            if (
                tool == "email.send"
                and missing == {"email:send"}
                and "net:write" in scopes
                and self._email_args_internal(args)
            ):
                return PolicyDecision(True, "internal email via network write scope", risk)
            return PolicyDecision(False, f"missing scope {sorted(missing)[0]}", "high")
        if any(scope.startswith("secrets:") for scope in required):
            return self._secret_decision(request, risk)
        if risk == "critical" and "cmd" not in args:
            return PolicyDecision(False, "critical tool denied by default", "critical")
        if "url" in args and self.egresses(tool):
            return self._http_decision(args, risk=risk)
        if "to" in args and self.egresses(tool):
            if not self._email_args_internal(args):
                return PolicyDecision(False, "external email egress denied", risk)
            return PolicyDecision(True, "internal email", risk)
        if "path" in args:
            path = str(args.get("path", ""))
            if path.startswith(self.workspace_root.rstrip("/") + "/"):
                return PolicyDecision(True, "approved workspace path", risk)
            return PolicyDecision(False, "unapproved write path", "high")
        if "cmd" in args:
            return self._shell_decision(request, risk)
        if "sql" in args and _has_sql_mutation(str(args.get("sql", ""))) and risk != "low":
            return self._sql_decision(request, risk)
        if tool.startswith("mcp."):
            return PolicyDecision(True, "MCP scope present", risk)
        return PolicyDecision(True, "profile policy allow", risk)

    def _http_decision(self, args: dict[str, Any], *, risk: str) -> PolicyDecision:
        parsed = urlparse(str(args.get("url", "")))
        host = parsed.hostname or ""
        if parsed.scheme != "https":
            return PolicyDecision(False, "HTTPS required", "high")
        if any(host == domain or host.endswith("." + domain) for domain in self.allowed_domains):
            return PolicyDecision(True, "allowed host", risk)
        return PolicyDecision(False, "egress host denied", "high")

    def _email_args_internal(self, args: dict[str, Any]) -> bool:
        raw_to = args.get("to", "")
        recipients = raw_to if isinstance(raw_to, list | tuple | set) else [raw_to]
        return all(
            any(str(recipient).endswith("@" + domain) for domain in self.email_domains)
            for recipient in recipients
        )

    def _shell_decision(self, request: dict[str, Any], risk: str) -> PolicyDecision:
        args = dict(request.get("args", {}))
        cmd = str(args.get("cmd", ""))
        cwd = str(args.get("cwd", ""))
        if cwd and not cwd.startswith(self.workspace_root.rstrip("/")):
            return PolicyDecision(False, "shell cwd denied", "critical")
        if _SAFE_INLINE_PYTHON_RE.fullmatch(cmd.strip()):
            return PolicyDecision(True, "safe scoped command", risk)
        if not cmd or _DENY_COMMAND_RE.search(cmd):
            return PolicyDecision(False, "shell command denied", "critical")
        return PolicyDecision(True, "safe scoped command", risk)

    def _secret_decision(self, request: dict[str, Any], risk: str) -> PolicyDecision:
        _ = request
        return PolicyDecision(True, "scoped secret broker lookup", risk)

    def _sql_decision(self, request: dict[str, Any], risk: str) -> PolicyDecision:
        sql = str(dict(request.get("args", {})).get("sql", ""))
        if _is_bounded_sql_mutation(sql):
            return PolicyDecision(True, "bounded database maintenance", risk)
        return PolicyDecision(False, "database mutation denied", "high")


def _has_sql_mutation(sql: str) -> bool:
    return any(match.group(0).lower() in _SQL_MUTATION_WORDS for match in _WORD_RE.finditer(sql))


def _is_bounded_sql_mutation(sql: str) -> bool:
    lowered = sql.lower()
    if ";" in sql or "--" in sql or "/*" in sql or "*/" in sql:
        return False
    words = {match.group(0).lower() for match in _WORD_RE.finditer(sql)}
    disallowed = _SQL_MUTATION_WORDS - {"update", "delete"}
    if words.intersection(disallowed):
        return False
    return bool(_SQL_BOUNDED_UPDATE_RE.search(lowered) or _SQL_BOUNDED_DELETE_RE.search(lowered))


class OPAPolicy:
    """OPA REST PDP using package zero_trust_ai_agent_proxy.authz and OPA 1.x data API."""

    def __init__(self, base_url: str, *, timeout_s: float = 2.0) -> None:
        self.url = base_url.rstrip("/") + "/v1/data/zero_trust_ai_agent_proxy/authz/allow"
        self.timeout_s = timeout_s
        self._client = httpx.Client(
            timeout=self.timeout_s,
            trust_env=False,
            limits=httpx.Limits(max_connections=128, max_keepalive_connections=32),
        )

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        try:
            response = self._client.post(self.url, json={"input": request})
            response.raise_for_status()
            allowed = bool(response.json().get("result", False))
        except Exception as exc:
            return PolicyDecision(False, exc.__class__.__name__, "high")
        return PolicyDecision(allowed, "opa allow" if allowed else "opa deny", "medium")

    def close(self) -> None:
        self._client.close()
