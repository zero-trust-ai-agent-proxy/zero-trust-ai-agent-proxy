"""Test CA and X.509-SVID validation for local Zero Trust AI Agent Proxy runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True, slots=True)
class SVID:
    cert_pem: str
    key_pem: str
    serial: int
    spiffe_id: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    reason: str
    spiffe_id: str | None = None
    serial: int | None = None


class TestCA:
    """Small ECDSA P-256 test CA used only by tests and benchmarks."""

    def __init__(self, common_name: str = "Zero Trust AI Agent Proxy local test CA") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(UTC)
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )

    @property
    def bundle_pem(self) -> str:
        return self._cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def mint_svid(
        self,
        spiffe_id: str,
        *,
        ttl: timedelta = timedelta(minutes=5),
        not_before: datetime | None = None,
        backdate: timedelta = timedelta(seconds=10),
    ) -> SVID:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        nbf = not_before or (now - backdate)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id)]))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nbf)
            .not_valid_after(nbf + ttl)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        return SVID(
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            cert.serial_number,
            spiffe_id,
        )


def spiffe_trust_domain(spiffe_id: str) -> str | None:
    parsed = urlparse(spiffe_id)
    if parsed.scheme != "spiffe" or not parsed.netloc or not parsed.path.startswith("/"):
        return None
    return parsed.netloc


class SVIDValidator:
    """Validate a single leaf X.509-SVID against a local trust bundle."""

    def __init__(
        self, bundle_pem: str, trust_domain: str, denylisted_serials: set[int] | None = None
    ) -> None:
        self.bundle = x509.load_pem_x509_certificate(bundle_pem.encode("ascii"))
        self.trust_domain = trust_domain
        self.denylisted_serials = denylisted_serials if denylisted_serials is not None else set()

    def validate_pem(self, cert_pem: str, *, now: datetime | None = None) -> ValidationResult:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        except ValueError:
            return ValidationResult(False, "malformed certificate")
        return self.validate_cert(cert, now=now)

    def validate_cert(
        self, cert: x509.Certificate, *, now: datetime | None = None
    ) -> ValidationResult:
        ts = now or datetime.now(UTC)
        if cert.serial_number in self.denylisted_serials:
            return ValidationResult(False, "serial revoked", serial=cert.serial_number)
        if ts < cert.not_valid_before_utc or ts > cert.not_valid_after_utc:
            return ValidationResult(
                False, "certificate expired or not yet valid", serial=cert.serial_number
            )
        if cert.issuer != self.bundle.subject:
            return ValidationResult(False, "issuer mismatch", serial=cert.serial_number)
        try:
            pub = self.bundle.public_key()
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return ValidationResult(False, "unsupported bundle key", serial=cert.serial_number)
            sig_hash = cert.signature_hash_algorithm
            if sig_hash is None:
                return ValidationResult(False, "missing signature hash", serial=cert.serial_number)
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(sig_hash))
        except InvalidSignature:
            return ValidationResult(False, "bad signature", serial=cert.serial_number)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            return ValidationResult(False, "missing spiffe URI SAN", serial=cert.serial_number)
        if len(uris) != 1:
            return ValidationResult(
                False, "expected exactly one spiffe URI SAN", serial=cert.serial_number
            )
        spiffe_id = uris[0]
        if spiffe_trust_domain(spiffe_id) != self.trust_domain:
            return ValidationResult(False, "trust domain mismatch", spiffe_id, cert.serial_number)
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return ValidationResult(False, "missing key usage", spiffe_id, cert.serial_number)
        if not usage.digital_signature or usage.key_cert_sign:
            return ValidationResult(False, "invalid key usage", spiffe_id, cert.serial_number)
        return ValidationResult(True, "ok", spiffe_id, cert.serial_number)


def cert_state_from_agent(agent: dict[str, Any]) -> str:
    state = str(agent.get("svid", "missing"))
    if state not in {"valid", "expired", "wrong_trust_domain", "missing", "forged", "revoked"}:
        return "missing"
    return state


def is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False
