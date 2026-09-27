# Claims tested

Current benchmark artifacts are in `results/benchmark-dev` and `results/benchmark-test`. The test split is pinned to sha256 `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b` and was evaluated with `zero_trust_agent_benchmark.evaluate.evaluate`.

## Claim verdicts

| Claim | Measured | Verdict | Notes |
|---|---:|---|---|
| Block 100% of attacks with issued secrets | 100.0% [99.2, 100.0] | Met | 500 of 500 attack traces blocked. |
| Keep false positives at 2% or below | 1.8% [0.9, 3.4] | Met on point estimate | Wilson interval still reaches 3.4%, so the uncertainty is disclosed. |
| Prevent benchmark secret leaks | 0.0% [0.0, 0.4], 0 leaks | Met | Issued-secret and structural detectors blocked leaks. |
| Work without issued secrets | 100.0% block, 1.8% false positives, 0 leaks | Met on this test split | The no-issued-secrets run is recorded separately. |
| Throughput >= 1,100 requests per second per instance | Previous one-worker criterion: 151 requests per second | Not met | This defense-only update did not remeasure socket throughput. |

## Ablation table

| Version | Change | Split used | Block rate | False-positive rate | Leak rate | P95 latency |
|---|---|---|---:|---:|---:|---:|
| Version 1 | Committed baseline | Test | 98.6% [97.1, 99.3] | 39.4% [35.2, 43.7] | 0.0% [0.0, 0.4] | 0.170 ms [0.161, 0.177] |
| Improvement 1 | Replace broad high-entropy blocking with issued-secret and structural matching | Dev | 100.0% [98.5, 100.0] | 4.0% [2.2, 7.2] | 0.0% [0.0, 0.8] | Dev-only |
| Improvement 2 | Add intent-aware high-risk gating, scoped broker lookup, and bounded maintenance writes | Dev | 100.0% [98.5, 100.0] | 2.0% [0.9, 4.6] | 0.0% [0.0, 0.8] | Dev-only |
| Final | Combined controls with scope-compatible internal actions | Test | 100.0% [99.2, 100.0] | 1.8% [0.9, 3.4] | 0.0% [0.0, 0.4] | 0.722 ms [0.639, 0.816] |

Intermediate improvements were selected on the dev split only. The final row is the official test-split result for the committed design.

## Remaining gaps

- The Wilson interval for false positives extends above 2% even though the point estimate is 1.8%.
- Socket throughput still misses the 1,100 requests per second claim from the prior full-system run.
- The Trusted Platform Module path remains simulated rather than a hardware verifier.
