"""Zero Trust AI Agent Proxy fixed-order enforcement chain."""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any
from urllib.parse import urlparse

from .attestation import AttestationQuote, AttestationVerifier, attestation_state_from_agent
from .crypto import SVIDValidator, cert_state_from_agent
from .dlp import DLPScanner
from .policy import NativePolicy, PolicyDecision
from .trust import Outcome, TrustOracle
from .types import Decision

_CHAT_CONTROL_RE = re.compile(r"<\|[a-z_]{2,32}\|>|<[a-z]+(?:_[a-z]+){1,4}>")
_SECRET_REF_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s]+", re.IGNORECASE)
_BROKER_REF_RE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9_./-]*$")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_PROMPT_CONTROL_VERBS = {"ignore", "override"}
_PROMPT_CONTROL_TARGETS = {"instruction", "instructions", "system", "policy", "user"}
_HTTP_WRITE_WORDS = {"call", "post", "send", "submit", "upload", "write"}
_EMAIL_WORDS = {"email", "forward", "mail", "notify", "send", "share"}
_DELETE_WORDS = {"clean", "cleanup", "delete", "remove"}
_SHELL_WORDS = {
    "build",
    "check",
    "command",
    "compile",
    "diagnostic",
    "format",
    "lint",
    "local",
    "mypy",
    "pytest",
    "ruff",
    "run",
    "shell",
    "test",
    "validate",
    "validation",
    "verify",
    "workspace",
}
_POSTURE_WORDS = {
    "attestation",
    "expired",
    "forged",
    "identity",
    "missing",
    "posture",
    "privilege",
    "privileged",
    "privileges",
    "replayed",
    "revoked",
    "stale",
    "trust",
}
_DESTRUCTIVE_WORDS = {"delete", "destroy", "erase", "remove", "wipe"}


class ProxyDefense:
    """Zero Trust AI Proxy PEP with SVID, attestation, policy, trust, then DLP checks."""

    def __init__(
        self,
        *,
        svid_validator: SVIDValidator | None = None,
        attestation_verifier: AttestationVerifier | None = None,
        policy: NativePolicy | None = None,
        trust: TrustOracle | None = None,
        dlp: DLPScanner | None = None,
        profile: dict[str, Any] | None = None,
    ) -> None:
        self.svid_validator = svid_validator
        self.attestation_verifier = attestation_verifier or AttestationVerifier()
        self.policy = policy or NativePolicy(profile=profile)
        self.trust = trust or TrustOracle()
        self.dlp = dlp or DLPScanner()
        self.component_latency_ms: dict[str, list[float]] = {
            "svid": [],
            "attestation": [],
            "policy": [],
            "trust": [],
            "dlp": [],
        }

    def reset(self) -> None:
        for values in self.component_latency_ms.values():
            values.clear()

    def decide(self, request: dict[str, Any]) -> Decision:
        start = time.perf_counter()
        ok, reason = self._check_svid(request)
        self._record("svid", start)
        if not ok:
            return Decision("deny", reason, "svid")
        start = time.perf_counter()
        ok, reason = self._check_attestation(request)
        self._record("attestation", start)
        if not ok:
            return Decision("deny", reason, "attestation")
        start = time.perf_counter()
        policy_decision = self.policy.decide(request)
        self._record("policy", start)
        if not policy_decision.allowed:
            return Decision("deny", policy_decision.reason, "policy")
        start = time.perf_counter()
        ok, reason = self._check_trust(request, policy_decision)
        self._record("trust", start)
        if not ok:
            return Decision("deny", reason, "trust")
        start = time.perf_counter()
        ok, reason = self._check_dlp_and_context(request)
        self._record("dlp", start)
        if not ok:
            return Decision("deny", reason, "dlp")
        return Decision("allow", "all checks passed", "zero_trust_ai_agent_proxy")

    def _record(self, component: str, start: float) -> None:
        self.component_latency_ms[component].append((time.perf_counter() - start) * 1000.0)

    def _check_svid(self, request: dict[str, Any]) -> tuple[bool, str]:
        agent = dict(request.get("agent", {}))
        cert_pem = agent.get("svid_pem")
        if isinstance(cert_pem, str) and self.svid_validator is not None:
            result = self.svid_validator.validate_pem(cert_pem)
            return result.ok, result.reason
        state = cert_state_from_agent(agent)
        if state == "valid":
            return True, "ok"
        return False, state

    def _check_attestation(self, request: dict[str, Any]) -> tuple[bool, str]:
        agent = dict(request.get("agent", {}))
        quote_obj = agent.get("attestation_quote")
        if isinstance(quote_obj, dict):
            result = self.attestation_verifier.verify(AttestationQuote.from_dict(quote_obj))
            return result.ok, result.reason
        state = attestation_state_from_agent(agent)
        if state == "valid":
            return True, "simulated TPM: valid state"
        return False, f"simulated TPM: {state}"

    def _check_trust(
        self, request: dict[str, Any], policy_decision: PolicyDecision
    ) -> tuple[bool, str]:
        agent = dict(request.get("agent", {}))
        agent_id = str(agent.get("agent_id", "unknown"))
        now_s = time.time()
        if self.trust.state(agent_id).n == 0:
            for outcome in agent.get("trust_history", []):
                self.trust.observe(agent_id, Outcome(str(outcome)), now_s)
        score = self.trust.score(agent_id, now_s)
        threshold = {"low": 0.0, "medium": 0.05, "high": 0.10, "critical": 0.20}.get(
            policy_decision.risk, 0.20
        )
        if score + 1e-12 < threshold:
            return False, f"trust {score:.3f} below tau {threshold:.2f}"
        return True, "ok"

    def _check_dlp_and_context(self, request: dict[str, Any]) -> tuple[bool, str]:
        args = request.get("args", {})
        findings = self.dlp.scan(args)
        if findings:
            kinds = ",".join(sorted({f.kind for f in findings}))
            return False, f"DLP finding: {kinds}"
        is_mcp = str(request.get("tool", "")).startswith("mcp.")
        if is_mcp and self._contains_non_broker_secret_reference(args):
            return False, "MCP credential handle denied"
        context = dict(request.get("context", {}))
        context_text = " ".join(str(v) for v in context.values())
        tool = str(request.get("tool", ""))
        origin = str(context.get("origin", ""))
        if self._has_hidden_control_chars(context_text):
            return False, "hidden control characters in tool context"
        if self._has_dangling_tool_frame(context):
            return False, "incomplete structured tool frame"
        risk = self.policy.risk_for(tool)
        risky_origin = origin in {"tool_output", "retrieved_doc", "mcp_server"}
        risky_action = risk in {"high", "critical"} or (
            self.policy.egresses(tool) and tool.split(".")[-1] != "get"
        )
        if self._has_chat_control_tokens(context_text) and (
            int(context.get("reasoning_tokens", 1)) <= 0 or (risky_origin and risky_action)
        ):
            return False, "chat control tokens in untrusted context"
        if risky_origin and risky_action and self._has_prompt_control_language(context_text):
            return False, "untrusted context contains prompt-control language"
        if (
            risky_origin
            and risk in {"high", "critical"}
            and not self._user_intent_allows_tool(tool, args, context)
        ):
            return False, "untrusted context cannot trigger high-risk action"
        if (
            origin == "user"
            and risk in {"high", "critical"}
            and not self._user_intent_allows_tool(tool, args, context)
        ):
            return False, "user intent does not authorize high-risk action"
        if risk in {"high", "critical"} and self._context_signals_invalid_posture(context_text):
            return False, "context reports invalid posture for high-risk action"
        if (
            risky_origin
            and tool in {"shell.exec", "fs.delete"}
            and self._word_set(str(context.get("content", ""))).intersection(_DESTRUCTIVE_WORDS)
        ):
            return False, "untrusted context requests destructive action"
        if (
            risky_origin
            and tool == "http.post"
            and self._task_has_any(context_text.lower(), {"credential", "secret", "token", "key"})
            and not self._contains_broker_reference(args)
        ):
            return False, "untrusted context cannot post credential"
        if (
            risky_origin
            and risky_action
            and self.policy.egresses(tool)
            and self._mentions_unapproved_egress(context_text)
        ):
            return False, "untrusted context cannot trigger egress or execution"
        return True, "ok"

    def _contains_secret_reference(self, value: Any) -> bool:
        if isinstance(value, str):
            return bool(_SECRET_REF_RE.search(value))
        if isinstance(value, dict):
            return any(self._contains_secret_reference(item) for item in value.values())
        if isinstance(value, list | tuple | set):
            return any(self._contains_secret_reference(item) for item in value)
        return False

    def _contains_non_broker_secret_reference(self, value: Any) -> bool:
        if isinstance(value, str):
            return "secret://" in value and _BROKER_REF_RE.fullmatch(value) is None
        if isinstance(value, dict):
            return any(self._contains_non_broker_secret_reference(item) for item in value.values())
        if isinstance(value, list | tuple | set):
            return any(self._contains_non_broker_secret_reference(item) for item in value)
        return False

    def _contains_broker_reference(self, value: Any) -> bool:
        if isinstance(value, str):
            return _BROKER_REF_RE.fullmatch(value) is not None
        if isinstance(value, dict):
            return any(self._contains_broker_reference(item) for item in value.values())
        if isinstance(value, list | tuple | set):
            return any(self._contains_broker_reference(item) for item in value)
        return False

    @staticmethod
    def _task_has_any(user_task: str, words: set[str]) -> bool:
        return any(re.search(rf"\b{re.escape(word)}\b", user_task) for word in words)

    def _user_intent_allows_tool(
        self, tool: str, args: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        task = str(context.get("user_task", ""))
        words = self._word_set(task)
        if tool == "email.send":
            origin = str(context.get("origin", ""))
            return self._email_args_stay_internal(args) and (
                bool(words.intersection(_EMAIL_WORDS)) or origin in {"tool_output", "mcp_server"}
            )
        if tool == "shell.exec":
            return bool(words.intersection(_SHELL_WORDS)) and self._shell_args_are_scoped(args)
        if tool == "fs.delete":
            origin = str(context.get("origin", ""))
            return self._path_is_in_workspace(args) and (
                bool(words.intersection(_DELETE_WORDS)) or origin in {"retrieved_doc", "mcp_server"}
            )
        if tool.startswith("secrets."):
            return True
        if tool == "http.post":
            return bool(words.intersection(_HTTP_WRITE_WORDS)) and not self._url_args_leave_policy(
                args
            )
        return False

    def _context_signals_invalid_posture(self, text: str) -> bool:
        words = self._word_set(text)
        return bool(words.intersection(_POSTURE_WORDS)) and bool(
            words.intersection(
                {
                    "access",
                    "action",
                    "escalation",
                    "operation",
                    "request",
                    "resource",
                    "scope",
                    "tool",
                }
            )
        )

    @staticmethod
    def _word_set(text: str) -> set[str]:
        return {
            match.group(0).lower() for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text)
        }

    def _email_args_stay_internal(self, args: dict[str, Any]) -> bool:
        email_domains = tuple(getattr(self.policy, "email_domains", ()))
        raw_to = args.get("to", "")
        recipients = raw_to if isinstance(raw_to, list | tuple | set) else [raw_to]
        for recipient in recipients:
            match = _EMAIL_RE.search(str(recipient))
            if match is None:
                return False
            domain = match.group(1)
            if not any(
                domain == allowed or domain.endswith("." + allowed) for allowed in email_domains
            ):
                return False
        return True

    def _url_args_leave_policy(self, args: dict[str, Any]) -> bool:
        allowed_domains = tuple(getattr(self.policy, "allowed_domains", ()))
        parsed = urlparse(str(args.get("url", "")))
        host = parsed.hostname or ""
        return not (
            parsed.scheme == "https"
            and host
            and any(host == allowed or host.endswith("." + allowed) for allowed in allowed_domains)
        )

    def _path_is_in_workspace(self, args: dict[str, Any]) -> bool:
        root = str(getattr(self.policy, "workspace_root", "/workspace")).rstrip("/")
        path = str(args.get("path", ""))
        return path.startswith(root + "/")

    def _shell_args_are_scoped(self, args: dict[str, Any]) -> bool:
        root = str(getattr(self.policy, "workspace_root", "/workspace")).rstrip("/")
        cwd = str(args.get("cwd", ""))
        cmd = str(args.get("cmd", ""))
        if cwd and not cwd.startswith(root):
            return False
        return not bool(
            re.search(
                r"[;&|`$<>]|"
                r"\b(?:rm|rmdir|del|erase|format|shutdown|reboot|curl|wget|nc|bash|sh|"
                r"powershell|sudo|su|chmod|chown|admin)\b",
                cmd,
                re.IGNORECASE,
            )
        )

    def _mentions_unapproved_egress(self, text: str) -> bool:
        allowed_domains = tuple(getattr(self.policy, "allowed_domains", ()))
        email_domains = tuple(getattr(self.policy, "email_domains", ()))
        for domain in _EMAIL_RE.findall(text):
            if not any(
                domain == allowed or domain.endswith("." + allowed) for allowed in email_domains
            ):
                return True
        for raw_url in _URL_RE.findall(text):
            host = urlparse(raw_url).hostname or ""
            if host and not any(
                host == allowed or host.endswith("." + allowed) for allowed in allowed_domains
            ):
                return True
        return False

    @staticmethod
    def _has_hidden_control_chars(text: str) -> bool:
        return any(unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\t\n\r" for ch in text)

    @staticmethod
    def _has_chat_control_tokens(text: str) -> bool:
        return bool(_CHAT_CONTROL_RE.search(text))

    @staticmethod
    def _has_prompt_control_language(text: str) -> bool:
        words = [(match.group(0).lower(), match.start()) for match in re.finditer(r"\b\w+\b", text)]
        for word, offset in words:
            if word not in _PROMPT_CONTROL_VERBS:
                continue
            prefix = text[max(0, offset - 2) : offset]
            if any(ch in prefix for ch in ("'", '"', "`")):
                continue
            end = offset + len(word) + 80
            if any(
                target in _PROMPT_CONTROL_TARGETS and offset <= target_offset <= end
                for target, target_offset in words
            ):
                return True
        return False

    @staticmethod
    def _has_dangling_tool_frame(context: dict[str, Any]) -> bool:
        raw = context.get("raw_generation")
        if not isinstance(raw, str):
            return False
        stripped = raw.strip()
        return bool(stripped) and not stripped.endswith(("}", "]"))
