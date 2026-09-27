"""Reference statistics for Zero Trust AI Agent Proxy.

COPIED MODULE — source of truth: contextual-trust-policy-engine/contextual-trust-policy-engine
``src/contextual_trust_policy_engine/stats.py`` (ref-v1).
Every copy must pass ``conformance/golden_vectors.json``. Do not edit a copy in isolation.

Pure standard library so it can be vendored anywhere.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "REF_VERSION",
    "Interval",
    "wilson",
    "quantile",
    "mean_t_ci",
    "bootstrap_quantile_ci",
]

REF_VERSION = "ref-v1"

# Two-sided Student-t critical values t_{0.975, df} (4 d.p.).
_T975 = {
    1: 12.7062, 2: 4.3027, 3: 3.1824, 4: 2.7764, 5: 2.5706, 6: 2.4469, 7: 2.3646,
    8: 2.3060, 9: 2.2622, 10: 2.2281, 11: 2.2010, 12: 2.1788, 13: 2.1604, 14: 2.1448,
    15: 2.1314, 16: 2.1199, 17: 2.1098, 18: 2.1009, 19: 2.0930, 20: 2.0860, 25: 2.0595,
    30: 2.0423, 40: 2.0211, 50: 2.0086, 60: 2.0003, 80: 1.9901, 99: 1.9842, 100: 1.9840,
    120: 1.9799, 200: 1.9719, 500: 1.9647, 1000: 1.9623,
}

Z95 = 1.959963984540054


@dataclass(frozen=True, slots=True)
class Interval:
    point: float
    low: float
    high: float

    def as_dict(self) -> dict[str, float]:
        return {"point": self.point, "low": self.low, "high": self.high}


def wilson(k: int, n: int, z: float = Z95) -> Interval:
    """Wilson score interval for a binomial proportion k/n.

    Returns point = k/n. For n == 0 returns the uninformative interval [0, 1].
    """
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"invalid k={k}, n={n}")
    if n == 0:
        return Interval(0.0, 0.0, 1.0)
    phat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = phat + z2 / (2 * n)
    delta = z * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))
    low = max(0.0, (centre - delta) / denom)
    high = min(1.0, (centre + delta) / denom)
    if k == n:
        high = 1.0
    if k == 0:
        low = 0.0
    return Interval(phat, low, high)


def quantile(values: Sequence[float], q: float) -> float:
    """Linear-interpolation quantile (NumPy ``method='linear'``, Hyndman-Fan type 7)."""
    if not values:
        raise ValueError("quantile of empty sequence")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be in [0, 1]")
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(xs[lo])
    return float(xs[lo] + (xs[hi] - xs[lo]) * (pos - lo))


def _t975(df: int) -> float:
    if df <= 0:
        raise ValueError("df must be positive")
    if df in _T975:
        return _T975[df]
    keys = sorted(_T975)
    if df > keys[-1]:
        return Z95
    return _T975[max(k for k in keys if k < df)]  # conservative: next-lower df


def mean_t_ci(values: Sequence[float]) -> Interval:
    """Mean with a two-sided 95% Student-t confidence interval."""
    n = len(values)
    if n == 0:
        raise ValueError("mean of empty sequence")
    m = math.fsum(values) / n
    if n == 1:
        return Interval(m, m, m)
    var = math.fsum((x - m) ** 2 for x in values) / (n - 1)
    half = _t975(n - 1) * math.sqrt(var / n)
    return Interval(m, m - half, m + half)


def bootstrap_quantile_ci(
    values: Sequence[float], q: float, *, resamples: int = 2000, seed: int = 0
) -> Interval:
    """Percentile-bootstrap 95% CI for a quantile. Deterministic for a given seed."""
    if not values:
        raise ValueError("empty sequence")
    rng = random.Random(seed)
    n = len(values)
    xs = list(values)
    stats = [quantile([xs[rng.randrange(n)] for _ in range(n)], q) for _ in range(resamples)]
    return Interval(quantile(xs, q), quantile(stats, 0.025), quantile(stats, 0.975))
