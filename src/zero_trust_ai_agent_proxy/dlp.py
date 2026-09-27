"""DLP scanners with recursive URL/base64/hex decoding."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    sample: str


AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_RE = re.compile(r"ghp_[A-Za-z0-9_]{30,}")
STRIPE_RE = re.compile(r"sk_live_[A-Za-z0-9]{24,}")
AWS_SEPARATED_RE = re.compile(r"AKIA(?:[0-9A-Z][.\s_-]*){16}", re.IGNORECASE)
GITHUB_SEPARATED_RE = re.compile(r"ghp_(?:[A-Za-z0-9][.\s_-]*){30,}", re.IGNORECASE)
STRIPE_SEPARATED_RE = re.compile(r"sk_live_(?:[A-Za-z0-9][.\s_-]*){24,}", re.IGNORECASE)
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_RE = re.compile(r"\b\+?1?[ -.]?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
B64_RE = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")


def _luhn(candidate: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", candidate)]
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        value = digit * 2 if i % 2 == parity else digit
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _decode_candidates(text: str) -> set[str]:
    seen = {text}
    frontier = [text]
    for _ in range(3):
        nxt: list[str] = []
        for item in frontier:
            url = unquote(item)
            if url not in seen:
                seen.add(url)
                nxt.append(url)
            for match in B64_RE.findall(item):
                padded = match + "=" * ((4 - len(match) % 4) % 4)
                try:
                    decoder = (
                        base64.urlsafe_b64decode
                        if any(ch in match for ch in "-_")
                        else base64.b64decode
                    )
                    decoded = decoder(padded.encode("ascii")).decode("utf-8", errors="ignore")
                except ValueError:
                    continue
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    nxt.append(decoded)
            for match in HEX_RE.findall(item):
                try:
                    decoded = bytes.fromhex(match).decode("utf-8", errors="ignore")
                except ValueError:
                    continue
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    nxt.append(decoded)
        frontier = nxt
        if not frontier:
            break
    return seen


def _walk(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for key, val in value.items():
            out.extend(_walk(key))
            out.extend(_walk(val))
        return out
    if isinstance(value, list | tuple | set):
        out = []
        for item in value:
            out.extend(_walk(item))
        return out
    return [str(value)] if value is not None else []


def _compact(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _issued_secret_forms(secret: str) -> set[str]:
    forms = {secret}
    raw = secret.encode()
    forms.add(base64.b64encode(raw).decode())
    forms.add(base64.urlsafe_b64encode(raw).decode().rstrip("="))
    forms.add(binascii.hexlify(raw).decode())
    forms.add(binascii.hexlify(raw).decode().upper())
    forms.add(quote(secret, safe=""))
    forms.add(quote(secret, safe="").lower())
    forms.add(codecs.encode(secret, "rot13"))
    forms.add(secret[::-1])
    return {form for form in forms if len(form) >= 8}


@dataclass(frozen=True, slots=True)
class DLPScanner:
    """Deny raw credentials and regulated identifiers; allow opaque secret references."""

    issued_secrets: tuple[str, ...] = ()

    def scan(self, value: Any) -> list[Finding]:
        findings: list[Finding] = []
        for raw in _walk(value):
            if raw.startswith("secret://"):
                continue
            for text in _decode_candidates(raw):
                findings.extend(self._scan_issued_secrets(text))
                findings.extend(self._scan_text(text))
        dedup: dict[tuple[str, str], Finding] = {}
        for finding in findings:
            dedup[(finding.kind, finding.sample)] = finding
        return list(dedup.values())

    def _scan_issued_secrets(self, text: str) -> list[Finding]:
        if not self.issued_secrets:
            return []
        compact_text = _compact(text)
        out: list[Finding] = []
        for secret in self.issued_secrets:
            if not secret or secret.startswith("secret://"):
                continue
            encoded_forms = _issued_secret_forms(secret)
            compact_forms = {_compact(form) for form in encoded_forms}
            if any(form in text for form in encoded_forms) or any(
                compact_form and compact_form in compact_text for compact_form in compact_forms
            ):
                out.append(Finding("issued_secret", secret[:24]))
        return out

    def _scan_text(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for kind, regex in [
            ("aws_key_id", AWS_RE),
            ("aws_key_id", AWS_SEPARATED_RE),
            ("github_token", GITHUB_RE),
            ("github_token", GITHUB_SEPARATED_RE),
            ("stripe_live_key", STRIPE_RE),
            ("stripe_live_key", STRIPE_SEPARATED_RE),
            ("private_key", PEM_RE),
            ("jwt", JWT_RE),
            ("ssn", SSN_RE),
            ("phone", PHONE_RE),
        ]:
            for match in regex.findall(text):
                out.append(Finding(kind, match[:24]))
        for match in CARD_RE.findall(text):
            if _luhn(match):
                out.append(Finding("payment_card", match[:24]))
        return out
