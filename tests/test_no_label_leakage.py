from __future__ import annotations

import copy
import json

from hypothesis import given
from hypothesis import strategies as st

from zero_trust_ai_agent_proxy.bench_adapter import BenchmarkDefense

BASE_REQUEST: dict[str, object] = {
    "trace_id": "trace-a",
    "step": 1,
    "agent": {
        "agent_id": "agent-1",
        "spiffe_id": "spiffe://acme.test/agent/agent-1",
        "svid": "valid",
        "attestation": "valid",
        "trust_history": ["benign"] * 40,
        "scopes": ["net:read", "net:write", "email:send"],
        "role": "assistant",
    },
    "tool": "http.post",
    "args": {"url": "https://api.acme.test/collect", "body": "safe status"},
    "context": {
        "origin": "user",
        "content": "Send the internal status update.",
        "reasoning_tokens": 12,
        "user_task": "Send the internal status update.",
    },
    "history": [{"step": 0, "tool": "http.get", "decision": "allow"}],
}


FORBIDDEN_FIELDS = (
    "label",
    "family",
    "template_id",
    "description",
    "metadata",
    "malicious",
    "split",
)


def _stable_decision(request: dict[str, object]) -> str:
    defense = BenchmarkDefense()
    decision = defense.decide(request)
    return json.dumps(decision, sort_keys=True, separators=(",", ":"))


@given(st.text(min_size=1, max_size=32), st.booleans())
def test_decisions_ignore_trace_labels_and_metadata(random_text: str, random_flag: bool) -> None:
    clean = copy.deepcopy(BASE_REQUEST)
    noisy = copy.deepcopy(BASE_REQUEST)
    stripped = copy.deepcopy(BASE_REQUEST)
    noisy["trace_id"] = random_text
    for field in FORBIDDEN_FIELDS:
        noisy[field] = {
            "label": random_text,
            "family": random_text[::-1],
            "template_id": f"tpl-{random_text}",
            "description": f"description {random_text}",
            "metadata": {"in_policy": random_flag, "answer": random_text},
            "malicious": random_flag,
            "split": "test" if random_flag else "dev",
        }[field]
        stripped.pop(field, None)

    assert _stable_decision(clean) == _stable_decision(noisy) == _stable_decision(stripped)
