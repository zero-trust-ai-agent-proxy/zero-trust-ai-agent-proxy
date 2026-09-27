"""Hybrid trust oracle using Wilson lower bound plus Dirichlet-EWMA.

COPIED MODULE — source of truth: contextual-trust-policy-engine/contextual-trust-policy-engine
``src/contextual_trust_policy_engine/trust.py`` (ref-v1).
Every copy must pass ``conformance/golden_vectors.json``. Do not edit a copy in isolation.

Model:
  outcomes      K=4: benign, suspicious, malicious, unknown
  x_t           per-outcome score: benign 1.0, unknown 0.5, suspicious 0.25, malicious 0.0
  EWMA          e_t = lam*x_t + (1-lam)*e_{t-1}, lam=0.15, e_0 = 0.5
  Dirichlet     alpha = alpha0 + counts, alpha0 = (1,1,1,1); E[benign] = alpha_b / sum(alpha)
  Wilson LB     lower 95% Wilson bound of benign/n
  score         n < 30  : WilsonLB                           (conservative cold start)
                n >= 30 : 0.4*WilsonLB + 0.6*E[benign]*EWMA
  decay         score * 0.95 ** hours_since_last_observation
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum

from .stats import wilson

__all__ = ["Outcome", "TrustParams", "TrustState", "TrustOracle"]


class Outcome(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


_SCORE = {
    Outcome.BENIGN: 1.0,
    Outcome.UNKNOWN: 0.5,
    Outcome.SUSPICIOUS: 0.25,
    Outcome.MALICIOUS: 0.0,
}
_ORDER = (Outcome.BENIGN, Outcome.SUSPICIOUS, Outcome.MALICIOUS, Outcome.UNKNOWN)


@dataclass(frozen=True, slots=True)
class TrustParams:
    lam: float = 0.15
    w_wilson: float = 0.4
    w_dirichlet: float = 0.6
    cold_start_n: int = 30
    decay_per_hour: float = 0.95
    alpha0: tuple[float, float, float, float] = (1.0, 1.0, 1.0, 1.0)
    ewma0: float = 0.5


@dataclass(slots=True)
class TrustState:
    counts: dict[Outcome, int] = field(default_factory=lambda: {o: 0 for o in _ORDER})
    ewma: float = 0.5
    last_seen_s: float | None = None

    @property
    def n(self) -> int:
        return sum(self.counts.values())


class TrustOracle:
    """Per-agent trust state. Not thread-safe; wrap with a lock if shared."""

    def __init__(self, params: TrustParams | None = None) -> None:
        self.params = params or TrustParams()
        self._agents: dict[str, TrustState] = {}

    def state(self, agent_id: str) -> TrustState:
        st = self._agents.get(agent_id)
        if st is None:
            st = TrustState(ewma=self.params.ewma0)
            self._agents[agent_id] = st
        return st

    def observe(self, agent_id: str, outcome: Outcome | str, now_s: float) -> None:
        o = Outcome(outcome)
        st = self.state(agent_id)
        st.counts[o] += 1
        lam = self.params.lam
        st.ewma = lam * _SCORE[o] + (1 - lam) * st.ewma
        st.last_seen_s = now_s

    def components(self, agent_id: str) -> dict[str, float]:
        st = self.state(agent_id)
        n = st.n
        wl = wilson(st.counts[Outcome.BENIGN], n).low
        alpha = [self.params.alpha0[i] + st.counts[o] for i, o in enumerate(_ORDER)]
        e_benign = alpha[0] / math.fsum(alpha)
        return {"n": float(n), "wilson_lb": wl, "dirichlet_benign": e_benign, "ewma": st.ewma}

    def score(self, agent_id: str, now_s: float) -> float:
        p = self.params
        st = self.state(agent_id)
        c = self.components(agent_id)
        if st.n < p.cold_start_n:
            raw = c["wilson_lb"]
        else:
            raw = p.w_wilson * c["wilson_lb"] + p.w_dirichlet * c["dirichlet_benign"] * c["ewma"]
        if st.last_seen_s is not None and now_s > st.last_seen_s:
            hours = (now_s - st.last_seen_s) / 3600.0
            raw *= p.decay_per_hour**hours
        return max(0.0, min(1.0, raw))
