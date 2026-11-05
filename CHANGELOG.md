# Changelog

## Unreleased - 2026-09-25

- Moved CI, Docker Compose, and benchmark containers to Python 3.15, kept `requires-python >=3.12` with a Python 3.12 floor CI job, moved the TLA+ model check to Java 25 LTS, and updated pinned GitHub Actions to current major versions.
- Decoded mixed-alphabet Base64 explicitly in data loss prevention so detection stays the same on Python 3.15, which deprecates that behavior in `urlsafe_b64decode`.
- Updated integration and benchmark images to Envoy v1.40.2, OPA 1.22.0, and SPIRE 1.15.5, and raised dependency minimums to the tested releases (Starlette 1.10, Uvicorn 0.54, httpx 0.28.1, cryptography 50.0.2, pytest 9.2, mypy 2.4, ruff 0.17).
- Removed the `cryptography==46.0.3` pin for Windows on Arm, which carried seven known vulnerabilities. All platforms now require cryptography 50.0.2 or newer; Windows on Arm needs an x64 Python or a source build because upstream no longer publishes `win_arm64` wheels.
- Fixed the Docker integration tests on Linux: Envoy and SPIRE now run as the host user so they can read the 0700 pytest temp directory, SPIRE keeps its state in the bind mount, and failures include the container output.

- Cut benchmark test false positives from 39.4% to 1.8% while blocking all attacks and preserving zero leaks.
- Replaced broad high-entropy data loss prevention with issued-secret matching, recursive common encodings, and structural secret detectors.
- Added intent-aware high-risk gating, scoped secret broker lookups, bounded database maintenance writes, no-label-leakage regression coverage, and benchmark literal guards.
- Renamed internal labels, headers, environment variables, and benchmark adapter names to descriptive public names.
- Renamed labels in result files; measured values unchanged.

## 0.1.0 - 2026-09-25

- Initial local Zero Trust AI Agent Proxy implementation with identity validation, simulated attestation, policy, trust, data loss prevention, Zero Trust Agent Benchmark adapter, TLA+ spec, and benchmark artifacts.