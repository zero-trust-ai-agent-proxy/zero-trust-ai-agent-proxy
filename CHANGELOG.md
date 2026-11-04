# Changelog

## Unreleased - 2026-09-25

- Moved CI, Docker Compose, and benchmark containers to Python 3.15, kept `requires-python >=3.12` with a Python 3.12 floor CI job, moved the TLA+ model check to Java 25 LTS, and updated pinned GitHub Actions to current major versions.
- Decoded mixed-alphabet Base64 explicitly in data loss prevention so detection stays the same on Python 3.15, which deprecates that behavior in `urlsafe_b64decode`.
- Updated integration and benchmark images to Envoy v1.40.2, OPA 1.22.0, and SPIRE 1.15.5, and raised dependency minimums to the tested releases (Starlette 1.10, Uvicorn 0.54, httpx 0.28.1, cryptography 50.0.2, pytest 9.2, mypy 2.4, ruff 0.17).

- Cut benchmark test false positives from 39.4% to 1.8% while blocking all attacks and preserving zero leaks.
- Replaced broad high-entropy data loss prevention with issued-secret matching, recursive common encodings, and structural secret detectors.
- Added intent-aware high-risk gating, scoped secret broker lookups, bounded database maintenance writes, no-label-leakage regression coverage, and benchmark literal guards.
- Renamed internal labels, headers, environment variables, and benchmark adapter names to descriptive public names.
- Renamed labels in result files; measured values unchanged.

## 0.1.0 - 2026-09-25

- Initial local Zero Trust AI Agent Proxy implementation with identity validation, simulated attestation, policy, trust, data loss prevention, Zero Trust Agent Benchmark adapter, TLA+ spec, and benchmark artifacts.