"""Small ASGI mock tool used by integration and socket benchmarks."""

from __future__ import annotations

import asyncio

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


async def handle(request: Request) -> JSONResponse:
    delay_ms = float(request.headers.get("x-mock-delay-ms", "0") or "0")
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)
    body = (await request.body()).decode("utf-8", errors="ignore")
    return JSONResponse({"ok": True, "path": request.url.path, "body_len": len(body)})


async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = Starlette(
    routes=[
        Route("/healthz", healthz),
        Route("/{path:path}", handle, methods=["GET", "POST"]),
    ]
)
