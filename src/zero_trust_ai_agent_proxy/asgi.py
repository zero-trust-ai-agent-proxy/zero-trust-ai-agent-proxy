"""ASGI service exposing POST /v1/decide for Envoy ext_authz or direct use."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .defense import ProxyDefense


def _default_agent() -> dict[str, Any]:
    return {
        "agent_id": "envoy-agent",
        "spiffe_id": "spiffe://acme.test/agent/envoy-agent",
        "svid": "valid",
        "attestation": "valid",
        "trust_history": ["benign"] * 40,
        "scopes": [
            "fs:read",
            "fs:write",
            "net:read",
            "net:write",
            "email:send",
            "calendar:write",
            "db:read",
            "mcp:use",
        ],
    }


def _headers_to_request(headers: dict[str, str], body: str = "") -> dict[str, Any]:
    tool = headers.get("x-agent-tool", "http.get")
    target_url = headers.get("x-agent-url", "https://api.acme.test/docs")
    args: dict[str, Any] = {"url": target_url}
    if body:
        args["body"] = body
    return {
        "trace_id": headers.get("x-request-id", "envoy"),
        "step": 0,
        "agent": _default_agent(),
        "tool": tool,
        "args": args,
        "context": {
            "origin": headers.get("x-agent-origin", "user"),
            "content": headers.get("x-agent-context", "envoy request"),
            "reasoning_tokens": 8,
            "user_task": "envoy request",
        },
        "history": [],
    }


def create_app(defense: ProxyDefense | None = None) -> Starlette:
    pep = defense or ProxyDefense()

    async def decide(request: Request) -> JSONResponse:
        try:
            body: dict[str, Any] = await request.json()
        except Exception:
            return JSONResponse(
                {"decision": "deny", "reason": "bad json", "component": "request"}, status_code=400
            )
        decision = pep.decide(body)
        return JSONResponse(decision.as_dict())

    async def envoy_authz(request: Request) -> Response:
        body = (await request.body()).decode("utf-8", errors="ignore")
        proxy_request = _headers_to_request(
            {k.lower(): v for k, v in request.headers.items()}, body
        )
        decision = pep.decide(proxy_request)
        status_code = 200 if decision.decision == "allow" else 403
        return JSONResponse(decision.as_dict(), status_code=status_code)

    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/v1/decide", decide, methods=["POST"]),
            Route("/envoy/authz", envoy_authz, methods=["GET", "POST"]),
            Route("/envoy/authz/{path:path}", envoy_authz, methods=["GET", "POST"]),
        ]
    )


app = create_app()


def _upstream_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=10.0,
        trust_env=False,
        limits=httpx.Limits(max_connections=1024, max_keepalive_connections=256),
    )


def create_proxy_app(
    defense: ProxyDefense | None = None, upstream: str = "http://127.0.0.1:18203"
) -> Starlette:
    pep = defense or ProxyDefense()
    upstream = upstream.rstrip("/")
    client: httpx.AsyncClient | None = None

    async def proxy(request: Request) -> Response:
        nonlocal client
        if client is None:
            client = _upstream_client()
        body_bytes = await request.body()
        body = body_bytes.decode("utf-8", errors="ignore")
        headers = {k.lower(): v for k, v in request.headers.items()}
        proxy_request = _headers_to_request(headers, body)
        decision = pep.decide(proxy_request)
        if decision.decision != "allow":
            return JSONResponse(decision.as_dict(), status_code=403)
        upstream_response = await client.request(
            request.method,
            upstream + request.url.path,
            content=body_bytes,
            headers={"x-mock-delay-ms": headers.get("x-mock-delay-ms", "0")},
        )
        return Response(
            upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
        )

    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def close_client() -> None:
        if client is not None:
            await client.aclose()

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        nonlocal client
        client = _upstream_client()
        try:
            yield
        finally:
            await close_client()

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/{path:path}", proxy, methods=["GET", "POST"]),
        ],
        lifespan=lifespan,
    )


proxy_app = create_proxy_app(
    upstream=os.environ.get("AGENT_PROXY_UPSTREAM", "http://127.0.0.1:18203")
)
