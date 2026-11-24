"""The HTTP surface. Read-only, and refused unless the gate says otherwise."""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from keep import api, security
from keep.collectors.action1 import Action1Collector
from keep.collectors.unifi import UnifiCollector
from keep.identity import Gate, localapi_whois
from keep.inventory import build
from keep.page import inventory_page, locked_page, security_page
from keep.runner import Runner

log = logging.getLogger("keep.web")
DEFAULT_INTERVAL_SECONDS = 900.0
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_SECURITY_HEADER_PAIRS = tuple(
    (name.lower().encode("latin-1"), value.encode("latin-1"))
    for name, value in SECURITY_HEADERS.items()
)
_SECURITY_HEADER_KEYS = frozenset(name for name, _ in _SECURITY_HEADER_PAIRS)
GZIP_MINIMUM_SIZE = 500


class _SecurityHeadersMiddleware:
    """Pure ASGI security-header wrapper without BaseHTTPMiddleware overhead."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", ())
                    if name.lower() not in _SECURITY_HEADER_KEYS
                ]
                headers.extend(_SECURITY_HEADER_PAIRS)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app(gate: Gate, runner: Runner, *, security_db: Path | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(GZipMiddleware, minimum_size=GZIP_MINIMUM_SIZE)
    app.add_middleware(_SecurityHeadersMiddleware)

    @app.get("/livez")
    def livez() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/readyz")
    def readyz() -> PlainTextResponse:
        alive = runner.thread.is_alive()
        return PlainTextResponse("ok" if alive else "collector stopped", 200 if alive else 503)

    def who(request: Request):
        return gate.check(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            request.headers.get("x-keep-proxy-token"),
        )

    def refused(reason: str) -> JSONResponse:
        log.info("refused reason=%s", reason)
        return JSONResponse({"error": "not allowed", "reason": reason}, 403)

    def security_data() -> security.Security | None:
        records, _ = runner.snapshot()
        try:
            return security.load(security_db, records, datetime.now(UTC))
        except sqlite3.Error:
            log.warning("Security database unavailable")
            return None

    @app.get("/api/v1/devices")
    def api_devices(request: Request) -> JSONResponse:
        verdict = who(request)
        if verdict.identity is None:
            return refused(verdict.reason)
        records, _ = runner.snapshot()
        return JSONResponse(api.devices(build(records, datetime.now(UTC))))

    @app.get("/api/v1/sources")
    def api_sources(request: Request) -> JSONResponse:
        verdict = who(request)
        if verdict.identity is None:
            return refused(verdict.reason)
        records, _ = runner.snapshot()
        return JSONResponse(api.sources(records))

    @app.get("/api/v1/security")
    def api_security(request: Request) -> JSONResponse:
        verdict = who(request)
        if verdict.identity is None:
            return refused(verdict.reason)
        data = security_data()
        if data is None:
            return JSONResponse({"error": "Security database unavailable"}, 503)
        return JSONResponse(jsonable_encoder(data))

    @app.get("/security", response_class=HTMLResponse)
    def security_index(request: Request) -> HTMLResponse:
        verdict = who(request)
        if verdict.identity is None:
            log.info("refused reason=%s", verdict.reason)
            return HTMLResponse(
                locked_page(verdict.reason, gate.missing, [], datetime.now(UTC)), 403
            )
        data = security_data()
        return HTMLResponse(security_page(data), 503 if data is None else 200)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        now = datetime.now(UTC)
        records, failures = runner.snapshot()
        verdict = who(request)
        if verdict.identity is None:
            log.info("refused reason=%s", verdict.reason)
            return HTMLResponse(locked_page(verdict.reason, gate.missing, records, now), 403)
        return HTMLResponse(
            inventory_page(build(records, now), records, failures, verdict.identity, now)
        )

    return app


def _words(name: str) -> list[str]:
    return os.environ.get(name, "").replace(",", " ").split()


def from_env() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    env = os.environ.get
    gate = Gate(
        proxy_token=env("KEEP_PROXY_TOKEN", ""),
        trusted_proxies=_words("KEEP_TRUSTED_PROXY_CIDRS"),
        allowed_logins=set(_words("KEEP_ALLOWED_LOGINS")),
        allowed_nodes=set(_words("KEEP_ALLOWED_NODES")),
        whois=localapi_whois(env("KEEP_TAILSCALED_SOCKET", "/var/run/tailscale/tailscaled.sock")),
    )
    collectors = [
        Action1Collector(
            env("KEEP_ACTION1_BASE_URL"),
            env("KEEP_ACTION1_CLIENT_ID"),
            env("KEEP_ACTION1_CLIENT_SECRET"),
        ),
        UnifiCollector(
            env("KEEP_UNIFI_BASE_URL"),
            env("KEEP_UNIFI_API_KEY"),
            env("KEEP_UNIFI_CERT_PEM"),
            env("KEEP_UNIFI_SITE") or "default",
        ),
    ]
    interval = float(env("KEEP_COLLECT_INTERVAL_SECONDS") or DEFAULT_INTERVAL_SECONDS)
    runner = Runner(collectors, interval)
    runner.start()
    security_path = env("KEEP_SECURITY_DB")
    return create_app(gate, runner, security_db=Path(security_path) if security_path else None)
