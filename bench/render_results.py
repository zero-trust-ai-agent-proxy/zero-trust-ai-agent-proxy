from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
latest = json.loads((ROOT / "results" / "latest.json").read_text(encoding="utf-8"))
summary_path = Path(latest["summary"])
if not summary_path.is_absolute():
    summary_path = ROOT / summary_path
summary = json.loads(summary_path.read_text(encoding="utf-8"))


def pct(iv: dict[str, float]) -> str:
    return f"{iv['point'] * 100:.1f}% [{iv['low'] * 100:.1f}, {iv['high'] * 100:.1f}]"


def ci_ms(iv: dict[str, float]) -> str:
    return f"{iv['point']:.3f} ms [{iv['low']:.3f}, {iv['high']:.3f}]"


def lat_triplet(cell: dict[str, object]) -> str:
    latency = cell["latency_ms"]
    assert isinstance(latency, dict)
    return (
        f"{latency['p50']:.1f}/{latency['p95_ci']['point']:.1f}/{latency['p99_ci']['point']:.1f} ms"
    )


benchmark = summary["zero_trust_agent_benchmark"]["metrics"]
latency = summary["latency_modes"]
component = summary["component_latency_ms"]
zero_mode = latency["python_mtls_0ms_c1"]
doc_mode = latency["python_mtls_doc_c1"]
envoy_mode = latency.get("envoy_mtls_ext_authz_0ms")
rps_matrix = summary["rps_matrix"]


def rps_line(worker: str) -> str:
    return "/".join(
        f"{rps_matrix[worker][str(concurrency)]['pep']['rps']:.0f}"
        for concurrency in summary["rps_concurrency_sweep"]
    )


rows = [
    (
        "Benchmark headline",
        f"block {pct(benchmark['block_rate'])}; false-positive rate {pct(benchmark['false_positive_rate'])}; leaks {benchmark['leak_count']}",
    ),
    ("P95 direct mock (0 ms tool, c1)", ci_ms(zero_mode["direct_ms"]["p95_ci"])),
    (
        "P95 Python policy enforcement point end-to-end (0 ms tool)",
        ci_ms(summary["python_pep_ms"]["p95_ci"]),
    ),
    ("P95 Python policy enforcement point overhead", ci_ms(summary["overhead_ms"]["p95_ci"])),
    *(
        (
            (
                "P95 Envoy mutual TLS and external authorization overhead",
                ci_ms(envoy_mode["overhead_ms"]["p95_ci"]),
            ),
        )
        if envoy_mode
        else ()
    ),
    ("P95 direct mock (p95≈120 ms tool, c1)", ci_ms(doc_mode["direct_ms"]["p95_ci"])),
    (
        "P95 Python policy enforcement point end-to-end (p95≈120 ms tool, c1)",
        ci_ms(doc_mode["proxy_ms"]["p95_ci"]),
    ),
    (
        "P95 Python policy enforcement point overhead (p95≈120 ms tool, c1)",
        ci_ms(doc_mode["overhead_ms"]["p95_ci"]),
    ),
    (
        "External-load policy enforcement point requests per second workers 1/2/4/8 best",
        "/".join(
            f"{max(cell['pep']['rps'] for cell in rps_matrix[w].values()):.0f}"
            for w in ["1", "2", "4", "8"]
        ),
    ),
    ("SPIFFE Verifiable Identity Document issue p95", ci_ms(component["svid_issue"]["p95_ci"])),
    (
        "SPIFFE Verifiable Identity Document validation p95",
        ci_ms(component["svid_validate"]["p95_ci"]),
    ),
    ("Zero Trust Agent Benchmark false-positive rate", pct(benchmark["false_positive_rate"])),
    ("Zero Trust Agent Benchmark block rate", pct(benchmark["block_rate"])),
    ("Zero Trust Agent Benchmark leaks", str(benchmark["leak_count"])),
]
md = "| Metric | Reference run |\n|---|---|\n" + "\n".join(f"| {a} | {b} |" for a, b in rows) + "\n"
(ROOT / "docs" / "results-table.md").write_text(md, encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")
start = "<!-- results:start -->"
end = "<!-- results:end -->"
if start in readme and end in readme:
    prefix = readme.split(start)[0]
    suffix = readme.split(end, maxsplit=1)[1]
    updated = prefix + start + "\n" + md + end + suffix
    (ROOT / "README.md").write_text(updated, encoding="utf-8")
hypotheses = summary["hypotheses"]
pep_p95 = summary["python_pep_ms"]["p95_ci"]["point"]
overhead_p95 = summary["overhead_ms"]["p95_ci"]["point"]
rps = summary["rps_single_instance"]["point"]
harness_note = summary.get("load_generator_native", "oha")
hypothesis_rows = [
    (
        "Claim 1 — latency target",
        "P95 overhead <= 75 ms and P95 end-to-end <= 195 ms with a 0 ms tool baseline.",
        hypotheses["H1"],
        f"P95 overhead {overhead_p95:.3f} ms; P95 Python policy enforcement point end-to-end {pep_p95:.3f} ms.",
    ),
    (
        "Claim 2 — throughput target",
        ">= 1100 requests per second per instance.",
        hypotheses["H2"],
        f"External {harness_note} load measured one-worker HTTPS over mutual TLS policy enforcement point at {rps:.0f} requests per second; "
        "requests per second at c1/c8/c32/c128 by workers: "
        + "; ".join(f"{w}w={rps_line(w)}" for w in ["1", "2", "4", "8"])
        + ".",
    ),
    (
        "Claim 3 — policy latency",
        "Policy p99 <= 15 ms.",
        hypotheses["H3"],
        f"Policy p99 {component['policy']['p99_ci']['point']:.3f} ms.",
    ),
    (
        "Claim 4 — attestation latency",
        "Simulated Trusted Platform Module attestation verify <= 10 ms.",
        hypotheses["H4"],
        f"Attestation p99 {component['attestation']['p99_ci']['point']:.3f} ms.",
    ),
    (
        "Claim 5 — identity issue latency",
        "SPIFFE Verifiable Identity Document issue <= 15 ms.",
        hypotheses["H5"],
        f"Issue p95 {component['svid_issue']['p95_ci']['point']:.3f} ms; "
        f"validation p95 {component['svid_validate']['p95_ci']['point']:.3f} ms over 100 trials.",
    ),
    (
        "Claim 6 — benchmark safety",
        "Zero Trust Agent Benchmark block rate 100% with 0 leaks.",
        hypotheses["H6"],
        f"Block rate {pct(benchmark['block_rate'])}; leaks {benchmark['leak_count']}; "
        f"false-positive rate {pct(benchmark['false_positive_rate'])}.",
    ),
]
hypothesis_table = "\n".join(
    f"| {identifier} | {criterion} | {verdict} | {evidence} |"
    for identifier, criterion, verdict, evidence in hypothesis_rows
)
bench_rows = [
    (
        "v4 overall",
        pct(benchmark["block_rate"]),
        pct(benchmark["false_positive_rate"]),
        str(benchmark["leak_count"]),
    ),
    (
        "v4 in-policy attacks",
        pct(benchmark["attack_policy_slices"]["in_policy"]["block_rate"]),
        "—",
        str(benchmark["attack_policy_slices"]["in_policy"]["leak_count"]),
    ),
    (
        "v4 out-of-policy attacks",
        pct(benchmark["attack_policy_slices"]["out_of_policy"]["block_rate"]),
        "—",
        str(benchmark["attack_policy_slices"]["out_of_policy"]["leak_count"]),
    ),
]
bench_table = "\n".join(f"| {a} | {b} | {c} | {d} |" for a, b, c, d in bench_rows)
rps_rows = []
for worker in ["1", "2", "4", "8"]:
    for concurrency in summary["rps_concurrency_sweep"]:
        cell = rps_matrix[worker][str(concurrency)]
        rps_rows.append(
            "| "
            + " | ".join(
                [
                    worker,
                    str(concurrency),
                    f"{cell['direct']['rps']:.0f}",
                    lat_triplet(cell["direct"]),
                    f"{cell['pep']['rps']:.0f}",
                    lat_triplet(cell["pep"]),
                ]
            )
            + " |"
        )
rps_table = "\n".join(rps_rows)
linux = summary.get("linux_container_result")
linux_table = ""
linux_latency = ""
if linux and "rps_matrix" in linux:
    linux_rows = []
    for worker in ["1", "2", "4", "8"]:
        for concurrency in linux["rps_concurrency_sweep"]:
            cell = linux["rps_matrix"][worker][str(concurrency)]
            linux_rows.append(
                "| "
                + " | ".join(
                    [
                        worker,
                        str(concurrency),
                        f"{cell['direct']['rps']:.0f}",
                        lat_triplet(cell["direct"]),
                        f"{cell['pep']['rps']:.0f}",
                        lat_triplet(cell["pep"]),
                    ]
                )
                + " |"
            )
    linux_table = "\n".join(linux_rows)
    linux_latency = f"\nHarness ceiling check at c128: {linux.get('harness_ceiling_ok', False)}."
elif linux:
    linux_latency = (
        f"\nLinux container throughput skipped: {linux.get('skipped', 'not available')}."
    )
tlc = summary.get("tlc", {})
dataset_version = summary["zero_trust_agent_benchmark"]["dataset_version"]
dataset_note = (
    f"Dataset `{dataset_version}`, `test.jsonl` sha256 "
    f"`{summary['zero_trust_agent_benchmark']['test_jsonl_sha256']}`."
)
hypothesis_md = f"""# Claims tested

Results are generated from `{latest["summary"]}` by `bench/render_results.py`.

| Claim | Criterion | Verdict | Evidence |
|---|---|---|---|
{hypothesis_table}

## Socket throughput

External `oha` load generator used keep-alive connections. Native rows used {harness_note}; each latency cell is p50/p95/p99.

| Workers | Concurrency | Direct requests per second | Direct p50/p95/p99 | Policy enforcement point requests per second | Policy enforcement point p50/p95/p99 |
|---:|---:|---:|---:|---:|---:|
{rps_table}

### Linux container socket throughput

Linux rows used `oha` from a separate container on the same Docker network as the mock and PEP containers.{linux_latency}

| Workers | Concurrency | Direct requests per second | Direct p50/p95/p99 | Policy enforcement point requests per second | Policy enforcement point p50/p95/p99 |
|---:|---:|---:|---:|---:|---:|
{linux_table}

## Zero Trust Agent Benchmark {dataset_version}

{dataset_note}

An earlier dataset version used shortcuts; v4 replaced it before this run.

| Slice | Block rate | False-positive rate | Leaks |
|---|---:|---:|---:|
{bench_table}

## Latency budget

The p95 budget is measured direct tool p95 plus 75 ms allowed proxy overhead. Direct p95 is {summary["latency_budget_ms"]["direct_tool_p95"]:.3f} ms, so the budget is {summary["latency_budget_ms"]["budget"]:.3f} ms. Through-policy-enforcement-point p95 is {summary["latency_budget_ms"]["measured_p95"]:.3f} ms, leaving {summary["latency_budget_ms"]["margin"]:.3f} ms margin.

## Formal model

TLC checked `{tlc.get("spec", "specs/NoBypass.tla")}` to depth {tlc.get("depth", "n/a")} with {tlc.get("distinct_states", "n/a")} distinct states, {tlc.get("states_generated", "n/a")} generated states, and {tlc.get("violations", "n/a")} invariant violations.
"""
(ROOT / "docs" / "hypotheses.md").write_text(hypothesis_md, encoding="utf-8")
