"""Simulated TPM attestation backend.

The implementation intentionally labels itself as simulated TPM: it uses an ECDSA Attestation Key
and TPM2-quote-shaped messages because this development machine has no TPM available.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PCRS = tuple(range(8))


@dataclass(frozen=True, slots=True)
class AttestationQuote:
    agent_id: str
    nonce: str
    timestamp_s: float
    pcrs: dict[int, str]
    signature_b64: str

    def payload(self) -> bytes:
        body = {
            "agent_id": self.agent_id,
            "nonce": self.nonce,
            "pcrs": {str(k): self.pcrs[k] for k in sorted(self.pcrs)},
            "timestamp_s": round(self.timestamp_s, 6),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "nonce": self.nonce,
            "timestamp_s": self.timestamp_s,
            "pcrs": {str(k): v for k, v in self.pcrs.items()},
            "signature_b64": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestationQuote:
        return cls(
            str(data["agent_id"]),
            str(data["nonce"]),
            float(data["timestamp_s"]),
            {int(k): str(v) for k, v in dict(data["pcrs"]).items()},
            str(data["signature_b64"]),
        )


class SimulatedTPMNode:
    """Node-side simulated TPM Attestation Key."""

    label = "simulated TPM: ECDSA AK quote"

    def __init__(self, agent_id: str, pcrs: dict[int, str] | None = None) -> None:
        self.agent_id = agent_id
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.pcrs = pcrs or golden_pcrs(agent_id)

    @property
    def public_key_pem(self) -> str:
        return (
            self._key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def quote(self, nonce: str, *, now_s: float | None = None) -> AttestationQuote:
        ts = time.time() if now_s is None else now_s
        unsigned = AttestationQuote(self.agent_id, nonce, ts, self.pcrs, "")
        digest = quote_digest(unsigned.payload())
        sig = self._key.sign(digest, ec.ECDSA(hashes.SHA256()))
        return AttestationQuote(
            self.agent_id,
            nonce,
            ts,
            dict(self.pcrs),
            base64.b64encode(sig).decode("ascii"),
        )


def quote_digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def golden_pcrs(agent_id: str) -> dict[int, str]:
    return {
        i: hashlib.sha256(f"zero-trust-ai-agent-proxy:{agent_id}:pcr:{i}".encode()).hexdigest()
        for i in PCRS
    }


@dataclass(slots=True)
class CacheEntry:
    expires_s: float
    quote_hash: str


@dataclass(frozen=True, slots=True)
class AttestationResult:
    ok: bool
    reason: str
    label: str = "simulated TPM: ECDSA AK quote"
    cache_hit: bool = False


class AttestationVerifier:
    """Verifier for simulated TPM quotes with replay and revocation protection."""

    def __init__(self, *, max_age_s: float = 60.0, cache_ttl_s: float = 300.0) -> None:
        self.max_age_s = max_age_s
        self.cache_ttl_s = cache_ttl_s
        self._keys: dict[str, ec.EllipticCurvePublicKey] = {}
        self._golden: dict[str, dict[int, str]] = {}
        self._seen_nonces: set[tuple[str, str]] = set()
        self._revoked: set[str] = set()
        self._cache: dict[str, CacheEntry] = {}

    def register(
        self, agent_id: str, public_key_pem: str, pcrs: dict[int, str] | None = None
    ) -> None:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("simulated TPM AK must be ECDSA")
        self._keys[agent_id] = key
        self._golden[agent_id] = pcrs or golden_pcrs(agent_id)
        self._cache.pop(agent_id, None)

    def revoke(self, agent_id: str) -> None:
        self._revoked.add(agent_id)
        self._cache.pop(agent_id, None)

    def verify(self, quote: AttestationQuote, *, now_s: float | None = None) -> AttestationResult:
        ts = time.time() if now_s is None else now_s
        if quote.agent_id in self._revoked:
            return AttestationResult(False, "attestation revoked")
        quote_hash = hashlib.sha256(quote.payload() + quote.signature_b64.encode()).hexdigest()
        if quote.agent_id not in self._keys:
            return AttestationResult(False, "unknown attestation key")
        if ts - quote.timestamp_s > self.max_age_s or quote.timestamp_s - ts > 5.0:
            return AttestationResult(False, "stale quote")
        nonce_key = (quote.agent_id, quote.nonce)
        if nonce_key in self._seen_nonces:
            return AttestationResult(False, "replayed nonce")
        cached = self._cache.get(quote.agent_id)
        if cached and cached.expires_s >= ts and cached.quote_hash == quote_hash:
            return AttestationResult(True, "ok", cache_hit=True)
        if quote.pcrs != self._golden[quote.agent_id]:
            return AttestationResult(False, "PCR mismatch")
        try:
            signature = base64.b64decode(quote.signature_b64.encode("ascii"), validate=True)
            self._keys[quote.agent_id].verify(
                signature, quote_digest(quote.payload()), ec.ECDSA(hashes.SHA256())
            )
        except (InvalidSignature, ValueError):
            return AttestationResult(False, "bad signature")
        self._seen_nonces.add(nonce_key)
        self._cache[quote.agent_id] = CacheEntry(ts + self.cache_ttl_s, quote_hash)
        return AttestationResult(True, "ok")


def attestation_state_from_agent(agent: dict[str, Any]) -> str:
    state = str(agent.get("attestation", "missing"))
    allowed = {"valid", "stale", "pcr_mismatch", "missing", "replayed_nonce", "bad_signature"}
    return state if state in allowed else "missing"
