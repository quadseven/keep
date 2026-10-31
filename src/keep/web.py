"""The HTTP surface. Read-only, and refused unless the gate says otherwise."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from keep.collectors.action1 import Action1Collector
from keep.collectors.unifi import UnifiCollector
from keep.identity import Gate, localapi_whois
from keep.inventory import build
from keep.page import inventory_page, locked_page
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


def create_app(gate: Gate, runner: Runner) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def harden(request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/livez")
    def livez() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/readyz")
    def readyz() -> PlainTextResponse:
        alive = runner.thread.is_alive()
        return PlainTextResponse("ok" if alive else "collector stopped", 200 if alive else 503)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        now = datetime.now(UTC)
        records, failures = runner.snapshot()
        verdict = gate.check(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            request.headers.get("x-keep-proxy-token"),
        )
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
    return create_app(gate, runner)
