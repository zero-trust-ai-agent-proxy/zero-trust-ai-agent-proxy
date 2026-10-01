from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata, resources
from pathlib import Path
from typing import Any

import httpx

from zero_trust_ai_agent_proxy.attestation import AttestationVerifier, SimulatedTPMNode
from zero_trust_ai_agent_proxy.bench_adapter import BenchmarkDefense
from zero_trust_ai_agent_proxy.crypto import SVIDValidator, TestCA
from zero_trust_ai_agent_proxy.defense import ProxyDefense
from zero_trust_ai_agent_proxy.dlp import DLPScanner
from zero_trust_ai_agent_proxy.policy import OPAPolicy
from zero_trust_ai_agent_proxy.stats import bootstrap_quantile_ci, mean_t_ci, quantile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".bench-work"
WORKERS = (1, 2, 4, 8)
CONCURRENCIES = (1, 8, 32, 128)
OHA_IMAGE = (
    "ghcr.io/hatoo/oha:1.16.0"
    "@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f"
)


def _request(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_id": "bench",
        "step": 0,
        "agent": {
            "agent_id": "bench-agent",
            "spiffe_id": "spiffe://acme.test/agent/bench-agent",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"] * 40,
            "scopes": ["fs:read", "fs:write", "net:read", "net:write", "email:send", "mcp:use"],
        },
        "tool": tool,
        "args": args,
        "context": {
            "origin": "user",
            "content": "benchmark",
            "reasoning_tokens": 8,
            "user_task": "benchmark",
        },
        "history": [],
    }


def _summ(values: list[float]) -> dict[str, Any]:
    return {
        "mean_ci": mean_t_ci(values).as_dict(),
        "p50": quantile(values, 0.50),
        "p95_ci": bootstrap_quantile_ci(values, 0.95, resamples=500, seed=11).as_dict(),
        "p99_ci": bootstrap_quantile_ci(values, 0.99, resamples=500, seed=13).as_dict(),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cert_files() -> dict[str, Path]:
    ca = TestCA("Zero Trust AI Agent Proxy bench CA")
    server = ca.mint_svid("spiffe://acme.test/server/bench")
    client = ca.mint_svid("spiffe://acme.test/client/bench")
    files = {
        "ca": WORK / "ca.pem",
        "server_cert": WORK / "server.crt",
        "server_key": WORK / "server.key",
        "client_cert": WORK / "client.crt",
        "client_key": WORK / "client.key",
    }
    _write(files["ca"], ca.bundle_pem)
    _write(files["server_cert"], server.cert_pem)
    _write(files["server_key"], server.key_pem)
    _write(files["client_cert"], client.cert_pem)
    _write(files["client_key"], client.key_pem)
    return files


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _uvicorn_cmd(app: str, host: str, port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "uvicorn",
        app,
        "--host",
        host,
        "--port",
        str(port),
        "--no-access-log",
        "--loop",
        "auto",
        "--http",
        "auto",
    ]


async def _wait_url(url: str, *, verify: bool = False, cert: tuple[str, str] | None = None) -> None:
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            async with httpx.AsyncClient(
                verify=verify, cert=cert, timeout=2.0, trust_env=False
            ) as client:
                response = await client.get(url)
            if response.status_code < 500:
                return
        except Exception:
            await asyncio.sleep(0.2)
    raise RuntimeError(f"server did not become ready: {url}")


@contextlib.contextmanager
def _socket_services(workers: int = 1) -> Any:
    files = _cert_files()
    mock_port = _free_port()
    pep_ports = [_free_port() for _ in range(workers)]
    mock = _start(_uvicorn_cmd("zero_trust_ai_agent_proxy.mock_tool:app", "127.0.0.1", mock_port))
    peps = [
        _start(
            [
                *_uvicorn_cmd("zero_trust_ai_agent_proxy.asgi:proxy_app", "127.0.0.1", pep_port),
                "--ssl-keyfile",
                str(files["server_key"]),
                "--ssl-certfile",
                str(files["server_cert"]),
                "--ssl-ca-certs",
                str(files["ca"]),
                "--ssl-cert-reqs",
                "2",
            ],
            env={"AGENT_PROXY_UPSTREAM": f"http://127.0.0.1:{mock_port}"},
        )
        for pep_port in pep_ports
    ]
    try:
        cert = (str(files["client_cert"]), str(files["client_key"]))
        asyncio.run(_wait_url(f"http://127.0.0.1:{mock_port}/healthz"))
        for pep_port in pep_ports:
            asyncio.run(_wait_url(f"https://127.0.0.1:{pep_port}/healthz", cert=cert))
        yield files, mock_port, pep_ports
    finally:
        for proc in [*peps, mock]:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill()


async def _latency_series(
    *,
    direct_url: str,
    pep_url: str,
    cert: tuple[str, str] | None,
    delay_ms: Callable[[int], float],
    trials: int = 100,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    async with httpx.AsyncClient(verify=False, cert=cert, timeout=15.0, trust_env=False) as client:
        for i in range(1, trials + 1):
            delay = delay_ms(i)
            headers = {
                "x-mock-delay-ms": f"{delay:.3f}",
                "x-agent-tool": "http.get",
                "x-agent-url": "https://api.acme.test/docs",
            }
            direct_start = time.perf_counter()
            try:
                direct = await client.get(direct_url, headers={"x-mock-delay-ms": f"{delay:.3f}"})
            except httpx.HTTPError:
                continue
            direct_ms = (time.perf_counter() - direct_start) * 1000.0
            pep_start = time.perf_counter()
            try:
                pep = await client.get(pep_url, headers=headers)
            except httpx.HTTPError:
                continue
            pep_ms = (time.perf_counter() - pep_start) * 1000.0
            rows.append(
                {
                    "trial": i,
                    "timestamp_utc": _now(),
                    "delay_profile_ms": delay,
                    "direct_ms": direct_ms,
                    "proxy_ms": pep_ms,
                    "overhead_ms": pep_ms - direct_ms,
                    "direct_status": direct.status_code,
                    "proxy_status": pep.status_code,
                }
            )
    return rows


async def _latency_series_concurrent(
    *,
    direct_url: str,
    pep_url: str,
    cert: tuple[str, str] | None,
    delay_ms: Callable[[int], float],
    mode: str,
    trials: int = 200,
    concurrency: int = 1,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    next_trial = 0
    lock = asyncio.Lock()
    limits = httpx.Limits(
        max_connections=concurrency * 4, max_keepalive_connections=concurrency * 4
    )
    async with httpx.AsyncClient(
        verify=False, cert=cert, timeout=15.0, trust_env=False, limits=limits
    ) as client:

        async def worker() -> None:
            nonlocal next_trial
            while True:
                async with lock:
                    if next_trial >= trials:
                        return
                    next_trial += 1
                    i = next_trial
                delay = delay_ms(i)
                headers = {
                    "x-mock-delay-ms": f"{delay:.3f}",
                    "x-agent-tool": "http.get",
                    "x-agent-url": "https://api.acme.test/docs",
                }
                direct_start = time.perf_counter()
                try:
                    direct = await client.get(
                        direct_url, headers={"x-mock-delay-ms": f"{delay:.3f}"}
                    )
                except httpx.HTTPError:
                    continue
                direct_ms = (time.perf_counter() - direct_start) * 1000.0
                pep_start = time.perf_counter()
                try:
                    pep = await client.get(pep_url, headers=headers)
                except httpx.HTTPError:
                    continue
                pep_ms = (time.perf_counter() - pep_start) * 1000.0
                rows.append(
                    {
                        "trial": i,
                        "timestamp_utc": _now(),
                        "mode": mode,
                        "concurrency": concurrency,
                        "delay_profile_ms": delay,
                        "direct_ms": direct_ms,
                        "proxy_ms": pep_ms,
                        "overhead_ms": pep_ms - direct_ms,
                        "direct_status": direct.status_code,
                        "proxy_status": pep.status_code,
                    }
                )

        await asyncio.gather(*(worker() for _ in range(concurrency)))
    return sorted(rows, key=lambda item: int(item["trial"]))


async def _load_once(
    urls: list[str],
    *,
    cert: tuple[str, str] | None,
    seconds: float,
    concurrency: int,
    include_agent_headers: bool,
) -> dict[str, Any]:
    count = 0
    errors = 0
    issued = 0
    latencies: list[float] = []
    headers = (
        {"x-agent-tool": "http.get", "x-agent-url": "https://api.acme.test/docs"}
        if include_agent_headers
        else {}
    )
    limits = httpx.Limits(
        max_connections=concurrency * 2, max_keepalive_connections=concurrency * 2
    )

    async def worker(client: httpx.AsyncClient) -> None:
        nonlocal count, errors, issued
        while time.perf_counter() < deadline:
            target = urls[issued % len(urls)]
            issued += 1
            start = time.perf_counter()
            try:
                response = await client.get(target, headers=headers)
            except httpx.HTTPError:
                errors += 1
                continue
            if response.status_code == 200:
                latencies.append((time.perf_counter() - start) * 1000.0)
                count += 1
            else:
                errors += 1

    async with httpx.AsyncClient(
        verify=False, cert=cert, timeout=3.0, trust_env=False, limits=limits
    ) as client:
        # Warm connections so the timed section is keep-alive dominated, not handshake dominated.
        await asyncio.gather(
            *(
                client.get(urls[i % len(urls)], headers=headers)
                for i in range(max(1, min(concurrency, 32)))
            ),
            return_exceptions=True,
        )
        deadline = time.perf_counter() + seconds
        started = time.perf_counter()
        await asyncio.gather(*(worker(client) for _ in range(concurrency)))
        elapsed = time.perf_counter() - started
    return {
        "rps": count / elapsed if elapsed > 0 else 0.0,
        "count": count,
        "errors": errors,
        "elapsed_s": elapsed,
        "latency_ms": _summ(latencies) if latencies else {"count": 0},
    }


def _load_subprocess(
    urls: list[str],
    *,
    cert: tuple[str, str] | None,
    seconds: float,
    concurrency: int,
    include_agent_headers: bool,
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "load",
        "--seconds",
        f"{seconds:.3f}",
        "--concurrency",
        str(concurrency),
    ]
    for url in urls:
        cmd.extend(["--url", url])
    if cert is not None:
        cmd.extend(["--cert", cert[0], "--key", cert[1]])
    if include_agent_headers:
        cmd.append("--agent-headers")
    try:
        output = subprocess.check_output(
            cmd, cwd=ROOT, text=True, timeout=max(30.0, seconds + 20.0)
        )
        return dict(json.loads(output))
    except subprocess.TimeoutExpired:
        return {
            "rps": 0.0,
            "count": 0,
            "errors": 1,
            "elapsed_s": seconds,
            "latency_ms": {"count": 0},
            "timeout": True,
        }


def _load_main(argv: list[str]) -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", action="append", required=True)
    parser.add_argument("--seconds", type=float, default=2.0)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--agent-headers", action="store_true")
    args = parser.parse_args(argv)
    cert = (args.cert, args.key) if args.cert and args.key else None
    result = asyncio.run(
        _load_once(
            args.url,
            cert=cert,
            seconds=args.seconds,
            concurrency=args.concurrency,
            include_agent_headers=args.agent_headers,
        )
    )
    print(json.dumps(result, sort_keys=True))


def _socket_bench() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    rps_matrix: dict[str, dict[str, Any]] = {}
    seconds = float(os.environ.get("PROXY_BENCH_SECONDS", "2.0"))
    load_headers = {"x-agent-tool": "http.get", "x-agent-url": "https://api.acme.test/docs"}
    with _socket_services(workers=1) as (files, mock_port, pep_ports):
        cert = (str(files["client_cert"]), str(files["client_key"]))
        direct_url = f"http://127.0.0.1:{mock_port}/tool"
        pep_url = f"https://127.0.0.1:{pep_ports[0]}/tool"
        zero_rows = asyncio.run(
            _latency_series_concurrent(
                direct_url=direct_url,
                pep_url=pep_url,
                cert=cert,
                delay_ms=lambda _i: 0,
                mode="python_mtls_0ms_c1",
            )
        )
        doc_rows = asyncio.run(
            _latency_series_concurrent(
                direct_url=direct_url,
                pep_url=pep_url,
                cert=cert,
                delay_ms=lambda i: 120.0 if i % 10 == 0 else 20.0,
                mode="python_mtls_doc_c1",
            )
        )
        rows.extend(zero_rows)
        rows.extend(doc_rows)
    for workers in WORKERS:
        with _socket_services(workers=workers) as (files, _mock_port, pep_ports):
            cert_dir = files["client_cert"].parent
            load_host = _load_generator_host()
            direct_url = f"http://{load_host}:{_mock_port}/tool"
            pep_urls = [f"https://{load_host}:{port}/tool" for port in pep_ports]
            worker_key = str(workers)
            rps_matrix[worker_key] = {}
            for concurrency in CONCURRENCIES:
                direct = _run_oha(
                    [direct_url],
                    seconds=seconds,
                    concurrency=concurrency,
                    name=f"native-direct-w{workers}-c{concurrency}",
                )
                pep = _run_oha(
                    pep_urls,
                    seconds=seconds,
                    concurrency=concurrency,
                    headers=load_headers,
                    cert_dir=cert_dir,
                    name=f"native-pep-w{workers}-c{concurrency}",
                )
                rps_matrix[worker_key][str(concurrency)] = {"direct": direct, "pep": pep}
    h2_ceiling_ok = all(
        rps_matrix[worker][str(max(CONCURRENCIES))]["direct"]["rps"]
        > rps_matrix[worker][str(max(CONCURRENCIES))]["pep"]["rps"]
        for worker in rps_matrix
    )
    rps_by_workers = {
        worker: max(item["pep"]["rps"] for item in by_concurrency.values())
        for worker, by_concurrency in rps_matrix.items()
    }
    return {
        "rps_by_workers": rps_by_workers,
        "rps_matrix": rps_matrix,
        "concurrency_sweep": list(CONCURRENCIES),
        "load_seconds": seconds,
        "load_generator": "oha",
        "load_generator_native": _load_generator_mode(),
        "harness_ceiling_ok": h2_ceiling_ok,
    }, rows


def _linux_oha_bench() -> dict[str, Any]:
    if os.environ.get("SKIP_LINUX_OHA") == "1":
        return {"skipped": "SKIP_LINUX_OHA=1"}
    if not _docker_available():
        return {"skipped": "docker unavailable"}
    seconds = float(os.environ.get("PROXY_BENCH_SECONDS", "2.0"))
    files = _cert_files()
    cert_dir = files["client_cert"].parent
    run_name = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    network = f"proxy-oha-{run_name}"
    subprocess.run(
        ["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.run(
        ["docker", "network", "create", network],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    rps_matrix: dict[str, dict[str, Any]] = {}
    load_headers = {"x-agent-tool": "http.get", "x-agent-url": "https://api.acme.test/docs"}
    try:
        for workers in WORKERS:
            worker_key = str(workers)
            mock_name = f"proxy-mock-{run_name}-{workers}"
            pep_name = f"proxy-pep-{run_name}-{workers}"
            mock_port = _free_port()
            pep_port = _free_port()
            _docker_server(
                name=mock_name,
                network=network,
                app="zero_trust_ai_agent_proxy.mock_tool:app",
                port=18080,
                host_port=mock_port,
                workers=1,
            )
            _docker_server(
                name=pep_name,
                network=network,
                app="zero_trust_ai_agent_proxy.asgi:proxy_app",
                port=18443,
                host_port=pep_port,
                workers=workers,
                env={"AGENT_PROXY_UPSTREAM": f"http://{mock_name}:18080"},
                cert_dir=cert_dir,
                extra=[
                    "--ssl-keyfile",
                    "/certs/server.key",
                    "--ssl-certfile",
                    "/certs/server.crt",
                    "--ssl-ca-certs",
                    "/certs/ca.pem",
                    "--ssl-cert-reqs",
                    "2",
                ],
            )
            try:
                asyncio.run(_wait_url(f"http://127.0.0.1:{mock_port}/healthz"))
                asyncio.run(
                    _wait_url(
                        f"https://127.0.0.1:{pep_port}/healthz",
                        cert=(str(files["client_cert"]), str(files["client_key"])),
                    )
                )
                _run_oha(
                    [f"http://{mock_name}:18080/tool"],
                    seconds=1.0,
                    concurrency=8,
                    network=network,
                    name=f"linux-warm-direct-w{workers}",
                )
                _run_oha(
                    [f"https://{pep_name}:18443/tool"],
                    seconds=1.0,
                    concurrency=8,
                    headers=load_headers,
                    cert_dir=cert_dir,
                    network=network,
                    name=f"linux-warm-pep-w{workers}",
                )
                rps_matrix[worker_key] = {}
                for concurrency in CONCURRENCIES:
                    direct = _run_oha(
                        [f"http://{mock_name}:18080/tool"],
                        seconds=seconds,
                        concurrency=concurrency,
                        network=network,
                        name=f"linux-direct-w{workers}-c{concurrency}",
                    )
                    pep = _run_oha(
                        [f"https://{pep_name}:18443/tool"],
                        seconds=seconds,
                        concurrency=concurrency,
                        headers=load_headers,
                        cert_dir=cert_dir,
                        network=network,
                        name=f"linux-pep-w{workers}-c{concurrency}",
                    )
                    rps_matrix[worker_key][str(concurrency)] = {"direct": direct, "pep": pep}
            finally:
                subprocess.run(
                    ["docker", "rm", "-f", pep_name, mock_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        h2_ceiling_ok = all(
            rps_matrix[worker][str(max(CONCURRENCIES))]["direct"]["rps"]
            > rps_matrix[worker][str(max(CONCURRENCIES))]["pep"]["rps"]
            for worker in rps_matrix
        )
        return {
            "rps_matrix": rps_matrix,
            "rps_concurrency_sweep": list(CONCURRENCIES),
            "rps_load_seconds": seconds,
            "load_generator": "oha",
            "network": "docker user-defined bridge",
            "harness_ceiling_ok": h2_ceiling_ok,
        }
    finally:
        subprocess.run(
            ["docker", "network", "rm", network],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _envoy_config(files: dict[str, Path], *, authz_port: int, upstream_port: int) -> Path:
    config = f"""
static_resources:
  listeners:
  - name: listener_https
    address:
      socket_address: {{ address: 0.0.0.0, port_value: 10000 }}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain: {{ filename: "/certs/server.crt" }}
              private_key: {{ filename: "/certs/server.key" }}
            validation_context:
              trusted_ca: {{ filename: "/certs/ca.pem" }}
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          forward_client_cert_details: ALWAYS_FORWARD_ONLY
          set_current_client_cert_details:
            uri: true
            dns: true
          route_config:
            name: local_route
            virtual_hosts:
            - name: local
              domains: ["*"]
              routes:
              - match: {{ prefix: "/" }}
                route: {{ cluster: mock_tool }}
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              with_request_body:
                max_request_bytes: 8192
                allow_partial_message: true
              http_service:
                server_uri:
                  uri: http://host.docker.internal:{authz_port}
                  cluster: agent_proxy_authz
                  timeout: 2s
                path_prefix: /envoy/authz
                authorization_request:
                  allowed_headers:
                    patterns:
                    - exact: x-agent-tool
                    - exact: x-agent-url
                    - exact: x-agent-origin
                    - exact: x-agent-context
                    - exact: x-forwarded-client-cert
                    - exact: x-mock-delay-ms
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: agent_proxy_authz
    connect_timeout: 1s
    type: LOGICAL_DNS
    load_assignment:
      cluster_name: agent_proxy_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: {{ address: host.docker.internal, port_value: {authz_port} }}
  - name: mock_tool
    connect_timeout: 1s
    type: LOGICAL_DNS
    load_assignment:
      cluster_name: mock_tool
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: {{ address: host.docker.internal, port_value: {upstream_port} }}
"""
    path = WORK / "envoy.yaml"
    _write(path, config)
    _ = files
    return path


def _docker_available() -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ).returncode
            == 0
        )
    except FileNotFoundError:
        return False


def _point(value: float) -> dict[str, float]:
    return {"point": value, "low": value, "high": value}


def _empty_load(reason: str) -> dict[str, Any]:
    return {
        "rps": 0.0,
        "count": 0,
        "errors": 1,
        "elapsed_s": 0.0,
        "latency_ms": {"count": 0, "p50": 0.0, "p95_ci": _point(0.0), "p99_ci": _point(0.0)},
        "error": reason,
        "generator": "oha",
    }


def _oha_available() -> str | None:
    native = shutil.which("oha")
    if native:
        return native
    if _docker_available():
        subprocess.run(
            ["docker", "pull", OHA_IMAGE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return "docker"
    return None


def _load_generator_host() -> str:
    # Servers bind to 127.0.0.1. Docker Desktop forwards host.docker.internal to the host's
    # loopback, but on Linux the container must share the host network to reach it.
    if shutil.which("oha") or sys.platform.startswith("linux"):
        return "127.0.0.1"
    return "host.docker.internal"


def _load_generator_mode() -> str:
    if shutil.which("oha"):
        return "native oha"
    if sys.platform.startswith("linux"):
        return "oha container on host network"
    return "oha container to host"


def _write_urls(name: str, urls: list[str]) -> tuple[Path, str]:
    path = WORK / f"{name}.urls"
    _write(path, "\n".join(urls) + "\n")
    return path, f"/work/{path.name}"


def _oha_result(raw: dict[str, Any], *, seconds: float) -> dict[str, Any]:
    metrics = dict(raw.get("metrics", {}))
    latency = dict(metrics.get("latency_ms", {}))
    status_counts = {str(k): int(v) for k, v in dict(raw.get("statusCodeDistribution", {})).items()}
    count = sum(status_counts.values())
    errors = sum(int(v) for v in dict(raw.get("errorDistribution", {})).values())
    if count == 0 or latency.get("p50") is None:
        raise RuntimeError(
            "oha recorded no successful responses; errors: "
            f"{dict(raw.get('errorDistribution', {}))}"
        )
    p50 = float(latency.get("p50", 0.0))
    p95 = float(latency.get("p95", 0.0))
    p99 = float(latency.get("p99", 0.0))
    return {
        "rps": float(
            metrics.get("requests_per_sec", raw.get("summary", {}).get("requestsPerSec", 0.0))
        ),
        "count": count,
        "errors": errors,
        "elapsed_s": float(raw.get("summary", {}).get("total", seconds)),
        "latency_ms": {
            "count": count,
            "p50": p50,
            "p95_ci": _point(p95),
            "p99_ci": _point(p99),
        },
        "success_rate": float(
            metrics.get("success_rate", raw.get("summary", {}).get("successRate", 0.0))
        ),
        "status_codes": status_counts,
        "generator": "oha",
    }


def _run_oha(
    urls: list[str],
    *,
    seconds: float,
    concurrency: int,
    headers: dict[str, str] | None = None,
    cert_dir: Path | None = None,
    network: str | None = None,
    name: str,
) -> dict[str, Any]:
    runner = _oha_available()
    if runner is None:
        return _empty_load("oha unavailable")
    url_file, container_url_file = _write_urls(name, urls)
    oha_args = [
        "-z",
        f"{seconds:.0f}s",
        "-c",
        str(concurrency),
        "--no-tui",
        "--output-format",
        "json",
        "--urls-from-file",
    ]
    for key, value in (headers or {}).items():
        oha_args.extend(["-H", f"{key}: {value}"])
    if cert_dir is not None:
        oha_args.extend(
            [
                "--cert",
                "/certs/client.crt",
                "--key",
                "/certs/client.key",
                "--insecure",
            ]
        )
    if runner == "docker":
        cmd = ["docker", "run", "--rm"]
        if network is None and sys.platform.startswith("linux"):
            cmd.extend(["--network", "host"])
        elif network is None and sys.platform != "win32":
            cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
        if network is not None:
            cmd.extend(["--network", network])
        cmd.extend(["-v", f"{WORK.resolve()}:/work:ro"])
        if cert_dir is not None:
            cmd.extend(["-v", f"{cert_dir.resolve()}:/certs:ro"])
        cmd.extend([OHA_IMAGE, *oha_args, container_url_file])
    else:
        cmd = [runner, *oha_args, str(url_file)]
        if cert_dir is not None:
            cmd.extend(
                [
                    "--cert",
                    str(cert_dir / "client.crt"),
                    "--key",
                    str(cert_dir / "client.key"),
                    "--insecure",
                ]
            )
    try:
        output = subprocess.check_output(
            cmd, cwd=ROOT, text=True, timeout=max(60.0, seconds + 45.0)
        )
        return _oha_result(json.loads(output), seconds=seconds)
    except (subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return _empty_load(exc.__class__.__name__)


def _server_container_command(
    app: str, port: int, workers: int, extra: list[str] | None = None
) -> str:
    install = "python -m pip install --no-compile --no-cache-dir -q -e /work"
    command = [
        "exec",
        "python",
        "-m",
        "uvicorn",
        app,
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
        "--workers",
        str(workers),
        "--no-access-log",
        "--loop",
        "auto",
        "--http",
        "auto",
        *(extra or []),
    ]
    return install + " && " + " ".join(command)


def _docker_server(
    *,
    name: str,
    network: str,
    app: str,
    port: int,
    host_port: int,
    workers: int,
    env: dict[str, str] | None = None,
    cert_dir: Path | None = None,
    extra: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        "-p",
        f"{host_port}:{port}",
        "-v",
        f"{ROOT.resolve()}:/work",
        "-w",
        "/work",
    ]
    if cert_dir is not None:
        cmd.extend(["-v", f"{cert_dir.resolve()}:/certs:ro"])
    for key, value in (env or {}).items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.extend(
        ["python:3.12-slim", "bash", "-lc", _server_container_command(app, port, workers, extra)]
    )
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)


def _envoy_bench() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if os.environ.get("SKIP_ENVOY") == "1":
        return {"skipped": "SKIP_ENVOY=1"}, []
    if not _docker_available():
        return {"skipped": "docker unavailable"}, []
    files = _cert_files()
    authz_port = _free_port()
    upstream_port = _free_port()
    envoy_port = _free_port()
    config = _envoy_config(files, authz_port=authz_port, upstream_port=upstream_port)
    mock = _start(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "zero_trust_ai_agent_proxy.mock_tool:app",
            "--host",
            "0.0.0.0",
            "--port",
            str(upstream_port),
        ]
    )
    authz = _start(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "zero_trust_ai_agent_proxy.asgi:app",
            "--host",
            "0.0.0.0",
            "--port",
            str(authz_port),
        ]
    )
    container = f"proxy-bench-envoy-{envoy_port}"
    subprocess.run(
        ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container,
        *(["--add-host", "host.docker.internal:host-gateway"] if sys.platform != "win32" else []),
        "-p",
        f"{envoy_port}:10000",
        "-v",
        f"{config.parent.resolve()}:/config:ro",
        "-v",
        f"{files['ca'].parent.resolve()}:/certs:ro",
        "envoyproxy/envoy:v1.36.2",
        "envoy",
        "-c",
        "/config/envoy.yaml",
    ]
    envoy = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    try:
        cert = (str(files["client_cert"]), str(files["client_key"]))
        asyncio.run(_wait_url(f"http://127.0.0.1:{authz_port}/healthz"))
        asyncio.run(_wait_url(f"http://127.0.0.1:{upstream_port}/healthz"))
        asyncio.run(_wait_url(f"https://127.0.0.1:{envoy_port}/tool", cert=cert))
        rows = asyncio.run(
            _latency_series(
                direct_url=f"http://127.0.0.1:{upstream_port}/tool",
                pep_url=f"https://127.0.0.1:{envoy_port}/tool",
                cert=cert,
                delay_ms=lambda _i: 0,
                trials=100,
            )
        )
        for row in rows:
            row["mode"] = "envoy_mtls_ext_authz_0ms"
        return {"status": "ok"}, rows
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        for proc in (authz, mock, envoy):
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill()


def _component_bench() -> dict[str, Any]:
    ca = TestCA()
    issue_ms = []
    validate_ms = []
    validator = SVIDValidator(ca.bundle_pem, "acme.test")
    for i in range(100):
        start = time.perf_counter()
        svid = ca.mint_svid(f"spiffe://acme.test/agent/issue-{i}")
        issue_ms.append((time.perf_counter() - start) * 1000.0)
        start = time.perf_counter()
        assert validator.validate_pem(svid.cert_pem).ok
        validate_ms.append((time.perf_counter() - start) * 1000.0)

    attest_cold = []
    for i in range(100):
        start = time.perf_counter()
        cold_node = SimulatedTPMNode(f"cold-{i}")
        cold_verifier = AttestationVerifier()
        cold_verifier.register(f"cold-{i}", cold_node.public_key_pem)
        assert cold_verifier.verify(cold_node.quote(f"nonce-cold-{i}")).ok
        attest_cold.append((time.perf_counter() - start) * 1000.0)

    node = SimulatedTPMNode("bench-agent")
    verifier = AttestationVerifier()
    verifier.register("bench-agent", node.public_key_pem)
    attest = []
    for i in range(100):
        quote = node.quote(f"nonce-{i}")
        start = time.perf_counter()
        assert verifier.verify(quote).ok
        attest.append((time.perf_counter() - start) * 1000.0)

    defense = ProxyDefense()
    for _ in range(100):
        defense.decide(_request("http.get", {"url": "https://api.acme.test/docs"}))
    dlp = DLPScanner()
    dlp_ms = []
    for _ in range(100):
        start = time.perf_counter()
        dlp.scan({"body": "public benchmark payload"})
        dlp_ms.append((time.perf_counter() - start) * 1000.0)
    return {
        "svid_issue": _summ(issue_ms),
        "svid_validate": _summ(validate_ms),
        "attestation_cold": _summ(attest_cold),
        "attestation_warm": _summ(attest),
        "policy_opa": _opa_component_bench(),
        "dlp": _summ(dlp_ms),
        **{k: _summ(v) for k, v in defense.component_latency_ms.items() if v},
    }


def _opa_component_bench() -> dict[str, Any]:
    if not _docker_available():
        return {"skipped": "docker unavailable"}
    port = _free_port()
    policy = WORK / "bench-policy.rego"
    _write(
        policy,
        """
package zero_trust_ai_agent_proxy.authz

default allow := false

allow if {
  input.tool == "http.get"
  startswith(input.args.url, "https://api.acme.test/")
}
""",
    )
    container = f"proxy-bench-opa-{port}"
    subprocess.run(
        ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    proc = subprocess.Popen(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            container,
            "-p",
            f"{port}:8181",
            "-v",
            f"{policy.resolve()}:/policy.rego:ro",
            "openpolicyagent/opa:1.10.1-static",
            "run",
            "--server",
            "--addr",
            "0.0.0.0:8181",
            "/policy.rego",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        asyncio.run(_wait_url(f"http://127.0.0.1:{port}/health", verify=False))
        opa = OPAPolicy(f"http://127.0.0.1:{port}", timeout_s=2.0)
        values = []
        request = {"tool": "http.get", "args": {"url": "https://api.acme.test/docs"}}
        try:
            for _ in range(100):
                start = time.perf_counter()
                assert opa.decide(request).allowed
                values.append((time.perf_counter() - start) * 1000.0)
        finally:
            opa.close()
        return _summ(values)
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()


TEST_SPLIT_SHA256 = "d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b"


def _benchmark() -> dict[str, Any]:
    benchmark_root = Path(
        os.environ.get("BENCHMARK_PATH", str(ROOT.parent / "zero-trust-agent-benchmark"))
    )
    benchmark_src = benchmark_root / "src"
    if benchmark_src.exists():
        sys.path.insert(0, str(benchmark_src))
    from zero_trust_agent_benchmark import evaluate, load_traces
    from zero_trust_agent_benchmark.profile import profile

    with contextlib.ExitStack() as stack:
        traces_dir = benchmark_root / "traces"
        if not (traces_dir / "test.jsonl").exists():
            # Without a sibling checkout (as on CI), use the traces shipped in the installed package.
            packaged = resources.files("zero_trust_agent_benchmark").joinpath("_data", "traces")
            traces_dir = stack.enter_context(resources.as_file(packaged))
        test_path = traces_dir / "test.jsonl"
        test_sha256 = hashlib.sha256(test_path.read_bytes()).hexdigest()
        if test_sha256 != TEST_SPLIT_SHA256:
            raise RuntimeError(
                f"benchmark test split sha256 {test_sha256} does not match {TEST_SPLIT_SHA256}"
            )
        data = evaluate(BenchmarkDefense(), load_traces("test", traces_dir)).to_dict()
    data["dataset_version"] = str(profile().get("dataset_version", "unknown"))
    data["test_jsonl_sha256"] = test_sha256
    return data


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:
        return "uncommitted"


def _mode_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_mode: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_mode.setdefault(str(row["mode"]), []).append(row)
    return {
        mode: {
            "direct_ms": _summ([float(r["direct_ms"]) for r in items]),
            "proxy_ms": _summ([float(r["proxy_ms"]) for r in items]),
            "overhead_ms": _summ([float(r["overhead_ms"]) for r in items]),
        }
        for mode, items in sorted(by_mode.items())
    }


def _write_artifacts(out: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    logs = out / "per-trial-logs"
    logs.mkdir(parents=True, exist_ok=True)
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for idx, row in enumerate(rows, 1):
        (logs / f"trial-{idx:03d}.json").write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    env = {
        "python": sys.version,
        "platform": platform.platform().replace("-microsoft-standard", "-standard"),
        "processor": platform.processor(),
        "git_sha": _git_sha(),
        "packages": {},
        "docker_images": [
            "python:3.12-slim",
            "openpolicyagent/opa:1.10.1-static",
            "envoyproxy/envoy:v1.36.2",
            "ghcr.io/spiffe/spire-server:1.13.3",
            "ghcr.io/spiffe/spire-agent:1.13.3",
        ],
    }
    for name in ["zero_trust_ai_agent_proxy", "cryptography", "httpx", "starlette", "uvicorn"]:
        with contextlib.suppress(metadata.PackageNotFoundError):
            env["packages"][name] = metadata.version(name)
    (out / "env.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "manifest.sha256":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rel = path.relative_to(out).as_posix()
            manifest.append(f"{digest}  {rel}")
    (out / "manifest.sha256").write_text("\n".join(manifest) + "\n", encoding="utf-8")


def main() -> None:
    WORK.mkdir(exist_ok=True)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-local")
    out = ROOT / "results" / run_id
    socket_meta, socket_rows = _socket_bench()
    linux_oha = _linux_oha_bench()
    envoy_meta, envoy_rows = _envoy_bench()
    rows = socket_rows + envoy_rows
    component = _component_bench()
    benchmark = _benchmark()
    mode_summary = _mode_summary(rows)
    pep = mode_summary["python_mtls_0ms_c1"]["proxy_ms"]
    overhead = mode_summary["python_mtls_0ms_c1"]["overhead_ms"]
    doc_mode = mode_summary["python_mtls_doc_c1"]
    doc_budget = doc_mode["direct_ms"]["p95_ci"]["point"] + 75.0
    svid_issue_p95 = component["svid_issue"]["p95_ci"]["point"]
    rps_single = max(cell["pep"]["rps"] for cell in socket_meta["rps_matrix"]["1"].values())
    summary = {
        "run_id": run_id,
        "trials": len(rows),
        "latency_modes": mode_summary,
        "python_pep_ms": pep,
        "overhead_ms": overhead,
        "component_latency_ms": component,
        "rps_by_workers": socket_meta["rps_by_workers"],
        "rps_matrix": socket_meta["rps_matrix"],
        "rps_concurrency_sweep": socket_meta["concurrency_sweep"],
        "rps_load_seconds": socket_meta["load_seconds"],
        "load_generator": socket_meta["load_generator"],
        "load_generator_native": socket_meta["load_generator_native"],
        "harness_ceiling_ok": socket_meta["harness_ceiling_ok"],
        "rps_single_instance": {
            "point": rps_single,
            "note": "best one-worker HTTPS over mutual TLS Python proxy result from the external load sweep",
        },
        "envoy": envoy_meta,
        "linux_container_result": linux_oha,
        "zero_trust_agent_benchmark": benchmark,
        "latency_budget_ms": {
            "direct_tool_p95": doc_mode["direct_ms"]["p95_ci"]["point"],
            "overhead_allowance": 75.0,
            "budget": doc_budget,
            "measured_p95": doc_mode["proxy_ms"]["p95_ci"]["point"],
            "margin": doc_budget - doc_mode["proxy_ms"]["p95_ci"]["point"],
        },
        "hypotheses": {
            "H1": "PASS"
            if overhead["p95_ci"]["point"] <= 75 and pep["p95_ci"]["point"] <= 195
            else "FAIL",
            "H2": "PASS"
            if rps_single >= 1100
            and socket_meta.get("harness_ceiling_ok")
            and linux_oha.get("harness_ceiling_ok")
            else "FAIL",
            "H3": "PASS" if component["policy"]["p99_ci"]["point"] <= 15 else "FAIL",
            "H4": "PASS" if component["attestation"]["p99_ci"]["point"] <= 10 else "FAIL",
            "H5": "PASS" if svid_issue_p95 <= 15 else "FAIL",
            "H6": "PASS"
            if benchmark["metrics"]["block_rate"]["point"] == 1.0
            and benchmark["metrics"]["leak_count"] == 0
            else "FAIL",
        },
    }
    _write_artifacts(out, rows, summary)
    (ROOT / "results" / "latest.json").write_text(
        json.dumps({"run_id": run_id, "summary": f"results/{run_id}/summary.json"}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(out)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "load":
        _load_main(sys.argv[2:])
    else:
        main()
