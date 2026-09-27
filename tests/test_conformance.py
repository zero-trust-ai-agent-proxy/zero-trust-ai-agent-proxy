"""Conformance test: this repo's copy of the reference modules must match golden vectors.

Copy this file to ``tests/test_conformance.py`` and set ``PKG`` to the package name that holds
the vendored ``stats`` (and optionally ``trust``) module. Copy ``golden_vectors.json`` to
``conformance/golden_vectors.json`` unchanged.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

PKG = "zero_trust_ai_agent_proxy"  # e.g. "contextual_trust_policy_engine"

GOLDEN = json.loads(
    (Path(__file__).resolve().parents[1] / "conformance" / "golden_vectors.json").read_text()
)
TOL = GOLDEN["tolerance"]
stats = importlib.import_module(f"{PKG}.stats")


def test_ref_version() -> None:
    assert GOLDEN["ref_version"] == stats.REF_VERSION


@pytest.mark.parametrize("case", GOLDEN["wilson"])
def test_wilson(case: dict) -> None:
    iv = stats.wilson(case["k"], case["n"])
    assert abs(iv.low - case["low"]) < TOL
    assert abs(iv.high - case["high"]) < TOL


@pytest.mark.parametrize("case", GOLDEN["quantile"])
def test_quantile(case: dict) -> None:
    assert abs(stats.quantile(case["values"], case["q"]) - case["value"]) < TOL


def test_mean_t_ci() -> None:
    c = GOLDEN["mean_t_ci"]
    iv = stats.mean_t_ci(c["values"])
    assert abs(iv.point - c["point"]) < TOL
    assert abs(iv.low - c["low"]) < TOL
    assert abs(iv.high - c["high"]) < TOL


def test_bootstrap() -> None:
    c = GOLDEN["bootstrap_quantile_ci"]
    iv = stats.bootstrap_quantile_ci(c["values"], c["q"], resamples=c["resamples"], seed=c["seed"])
    assert abs(iv.low - c["low"]) < TOL
    assert abs(iv.high - c["high"]) < TOL


try:
    trust = importlib.import_module(f"{PKG}.trust")
except ModuleNotFoundError:  # repo does not vendor the trust oracle
    trust = None


@pytest.mark.skipif(trust is None, reason="trust oracle not vendored in this repo")
@pytest.mark.parametrize("case", GOLDEN["trust"])
def test_trust(case: dict) -> None:
    assert trust is not None
    o = trust.TrustOracle()
    for i, s in enumerate(case["outcomes"]):
        o.observe("a", trust.Outcome(s), now_s=float(i))
    last = float(len(case["outcomes"]) - 1)
    assert abs(o.score("a", last) - case["score_now"]) < TOL
    assert abs(o.score("a", last + 7200.0) - case["score_after_2h"]) < TOL
    comps = o.components("a")
    for key, val in case["components"].items():
        assert abs(comps[key] - val) < TOL
