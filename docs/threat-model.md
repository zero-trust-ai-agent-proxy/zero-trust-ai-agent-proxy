# Threat model (STRIDE)

- Spoofing: X.509 SPIFFE Verifiable Identity Document chain, trust-domain, validity, and denylist checks.
- Tampering: simulated Trusted Platform Module quote signatures and Platform Configuration Register allowlist verification.
- Repudiation: structured benchmark and decision artifacts.
- Information disclosure: data loss prevention scans raw and decoded payloads for secrets and regulated identifiers.
- Denial of service: fail-closed timeouts and small bounded policy cache.
- Elevation of privilege: deny-by-default administrative tools and trust thresholds.