from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from zero_trust_ai_agent_proxy.attestation import AttestationVerifier, SimulatedTPMNode
from zero_trust_ai_agent_proxy.crypto import SVIDValidator, TestCA
from zero_trust_ai_agent_proxy.policy import OPAPolicy

pytestmark = pytest.mark.integration


def _need_integration() -> None:
    if os.environ.get("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("set RUN_INTEGRATION_TESTS=1 to run Docker-backed integration checks")
    if shutil.which("docker") is None:
        pytest.skip("docker CLI unavailable on this host")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


async def _wait_url(
    url: str, *, cert: tuple[str, str] | None = None, timeout_seconds: float = 90
) -> None:
    deadline = time.time() + timeout_seconds
    last_error = "no response"
    while time.time() < deadline:
        try:
            async with httpx.AsyncClient(
                verify=False, cert=cert, timeout=2.0, trust_env=False
            ) as client:
                response = await client.get(url)
            if response.status_code < 500:
                return
            last_error = f"HTTP {response.status_code}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(0.2)
    raise AssertionError(f"service did not become ready: {url}; last error: {last_error}")


@contextlib.contextmanager
def _host_uvicorn(app: str, port: int, *, env: dict[str, str] | None = None) -> object:
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app, "--host", "0.0.0.0", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **(env or {})},
        text=True,
    )
    try:
        yield proc
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()


def _envoy_config(work: Path, authz_port: int, upstream_port: int) -> Path:
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
    path = work / "envoy.yaml"
    _write(path, config)
    return path


def _certs(work: Path) -> tuple[TestCA, dict[str, Path]]:
    ca = TestCA("Zero Trust AI Agent Proxy integration CA")
    server = ca.mint_svid("spiffe://acme.test/server/envoy")
    client = ca.mint_svid("spiffe://acme.test/client/integration")
    files = {
        "ca": work / "ca.pem",
        "server_cert": work / "server.crt",
        "server_key": work / "server.key",
        "client_cert": work / "client.crt",
        "client_key": work / "client.key",
    }
    _write(files["ca"], ca.bundle_pem)
    _write(files["server_cert"], server.cert_pem)
    _write(files["server_key"], server.key_pem)
    _write(files["client_cert"], client.cert_pem)
    _write(files["client_key"], client.key_pem)
    return ca, files


def test_envoy_mtls_ext_authz_allows_and_denies(tmp_path: Path) -> None:
    _need_integration()
    envoy_port = _free_port()
    authz_port = _free_port()
    upstream_port = _free_port()
    _, files = _certs(tmp_path)
    _envoy_config(tmp_path, authz_port, upstream_port)
    container = f"proxy-it-envoy-{envoy_port}"
    with (
        _host_uvicorn("zero_trust_ai_agent_proxy.mock_tool:app", upstream_port),
        _host_uvicorn("zero_trust_ai_agent_proxy.asgi:app", authz_port),
    ):
        asyncio.run(_wait_url(f"http://127.0.0.1:{upstream_port}/healthz"))
        asyncio.run(_wait_url(f"http://127.0.0.1:{authz_port}/healthz"))
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
                *(
                    ["--add-host", "host.docker.internal:host-gateway"]
                    if sys.platform != "win32"
                    else []
                ),
                "-p",
                f"{envoy_port}:10000",
                "-v",
                f"{tmp_path.resolve()}:/config:ro",
                "-v",
                f"{tmp_path.resolve()}:/certs:ro",
                "envoyproxy/envoy:v1.36.2",
                "envoy",
                "-c",
                "/config/envoy.yaml",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            cert = (str(files["client_cert"]), str(files["client_key"]))
            url = f"https://127.0.0.1:{envoy_port}/tool"
            asyncio.run(_wait_url(url, cert=cert))
            with httpx.Client(verify=False, cert=cert, timeout=10.0, trust_env=False) as client:
                allowed = client.post(
                    url,
                    headers={
                        "x-agent-tool": "http.get",
                        "x-agent-url": "https://api.acme.test/docs",
                    },
                    content="allow body reaches ext_authz",
                )
                denied = client.post(
                    url,
                    headers={
                        "x-agent-tool": "shell.exec",
                        "x-agent-url": "https://api.acme.test/docs",
                    },
                    content="deny body reaches ext_authz",
                )
            assert allowed.status_code == 200
            assert denied.status_code == 403
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.terminate()


def test_opa_policy_container_allows_and_denies(tmp_path: Path) -> None:
    _need_integration()
    policy = tmp_path / "policy.rego"
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
    port = _free_port()
    container = f"proxy-it-opa-{port}"
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
        asyncio.run(_wait_url(f"http://127.0.0.1:{port}/health"))
        opa = OPAPolicy(f"http://127.0.0.1:{port}")
        assert opa.decide(
            {"tool": "http.get", "args": {"url": "https://api.acme.test/docs"}}
        ).allowed
        assert not opa.decide(
            {"tool": "http.get", "args": {"url": "https://evil.example/"}}
        ).allowed
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        proc.terminate()


def test_spire_server_minted_x509_svid_validates(tmp_path: Path) -> None:
    _need_integration()
    config = tmp_path / "server.conf"
    _write(
        config,
        """
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  socket_path = "/run/spire/sockets/api.sock"
  trust_domain = "acme.test"
  data_dir = "/run/spire/data"
  log_level = "ERROR"
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/run/spire/data/datastore.sqlite3"
    }
  }
  KeyManager "disk" {
    plugin_data {
      keys_path = "/run/spire/data/keys.json"
    }
  }
  NodeAttestor "join_token" {
    plugin_data {}
  }
}
""",
    )
    container = f"proxy-it-spire-{_free_port()}"
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
            "-v",
            f"{tmp_path.resolve()}:/config:ro",
            "-v",
            f"{tmp_path.resolve()}:/out",
            "ghcr.io/spiffe/spire-server:1.13.3",
            "-config",
            "/config/server.conf",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "/opt/spire/bin/spire-server",
                    "healthcheck",
                    "-socketPath",
                    "/run/spire/sockets/api.sock",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("SPIRE server did not become healthy")
        subprocess.run(
            [
                "docker",
                "exec",
                container,
                "/opt/spire/bin/spire-server",
                "x509",
                "mint",
                "-socketPath",
                "/run/spire/sockets/api.sock",
                "-spiffeID",
                "spiffe://acme.test/workload/integration",
                "-write",
                "/out",
            ],
            check=True,
        )
        bundle = (tmp_path / "bundle.pem").read_text(encoding="utf-8")
        cert = (tmp_path / "svid.pem").read_text(encoding="utf-8")
        result = SVIDValidator(bundle, "acme.test").validate_pem(cert)
        assert result.ok
        assert result.spiffe_id == "spiffe://acme.test/workload/integration"
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        proc.terminate()


def test_simulated_tpm_integration_cache() -> None:
    _need_integration()
    node = SimulatedTPMNode("agent-int")
    verifier = AttestationVerifier()
    verifier.register("agent-int", node.public_key_pem)
    quote = node.quote("nonce-int")
    assert verifier.verify(quote).ok
