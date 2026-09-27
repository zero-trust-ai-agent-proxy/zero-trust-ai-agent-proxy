#!/usr/bin/env bash
set -euo pipefail
python -m pip install --no-compile --no-cache-dir -q -e ".[dev]"
if [ -n "${BENCHMARK_PATH:-}" ] && [ -f "$BENCHMARK_PATH/pyproject.toml" ]; then python -m pip install --no-compile --no-cache-dir -q -e "$BENCHMARK_PATH"; elif [ -f "../zero-trust-agent-benchmark/pyproject.toml" ]; then python -m pip install --no-compile --no-cache-dir -q -e ../zero-trust-agent-benchmark; fi
ruff check .
ruff format --check .
mypy src
pytest -q --cov=zero_trust_ai_agent_proxy --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh