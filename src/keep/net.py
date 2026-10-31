"""The one way Keep reads a network API.

Every call has a connect timeout and a hard total deadline, TLS is mandatory
and always verified, and redirects are not followed. Failures become
SourceError with a fixed reason, so a reason can never carry a URL, an address
or a credential.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from keep.model import SourceError

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
TOTAL_TIMEOUT = 30.0
MAX_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    connect_timeout: float = CONNECT_TIMEOUT
    read_timeout: float = READ_TIMEOUT
    total_timeout: float = TOTAL_TIMEOUT
    max_bytes: int = MAX_BYTES


def _context(trust_pem: str | None) -> ssl.SSLContext:
    if not trust_pem:
        return ssl.create_default_context()
    # A self-signed console leaf cannot chain to a CA and carries no usable
    # name, so that one exact certificate becomes the only trust anchor. The
    # chain is still verified, including expiry.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=trust_pem)
    context.verify_flags = ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


@contextmanager
def _verified_socket(
    parts: SplitResult, trust_pem: str | None, limits: Limits, expired: threading.Event
) -> Iterator[ssl.SSLSocket]:
    """A TLS socket past verification, closed by force at the total deadline."""
    raw = socket.create_connection(
        (parts.hostname, parts.port or 443), timeout=limits.connect_timeout
    )
    raw.settimeout(limits.read_timeout)
    tls = _context(trust_pem).wrap_socket(
        raw, server_hostname=parts.hostname, do_handshake_on_connect=False
    )

    def expire() -> None:
        expired.set()
        try:
            # The plain socket call: SSLSocket.shutdown drops its TLS state
            # while another thread may still be reading through it.
            socket.socket.shutdown(tls, socket.SHUT_RDWR)
        except OSError:
            pass  # The peer already closed; the reader fails either way.

    timer = threading.Timer(limits.total_timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        tls.do_handshake()
        yield tls
    finally:
        timer.cancel()
        tls.close()


def _read_body(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := response.read1(65536):
        size += len(chunk)
        if size > max_bytes:
            raise SourceError("response too large")
        chunks.append(chunk)
    if response.length not in (None, 0):
        raise SourceError("response truncated")
    return b"".join(chunks)


def _exchange(
    tls: ssl.SSLSocket,
    parts: SplitResult,
    headers: dict[str, str] | None,
    body: bytes | None,
    max_bytes: int,
) -> bytes:
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443)
    connection.sock = tls
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    method = "POST" if body is not None else "GET"
    connection.request(method, target, body=body, headers=headers or {})
    response = connection.getresponse()
    if response.status in (401, 403):
        raise SourceError(f"auth refused (HTTP {response.status})")
    if response.status != 200:
        raise SourceError(f"unexpected HTTP {response.status}")
    return _read_body(response, max_bytes)


def _reason(error: Exception) -> str:
    """The fixed, displayable reason for a failed exchange."""
    if isinstance(error, TimeoutError):
        return "timed out"
    if isinstance(error, ssl.SSLError):
        return "TLS error"
    if isinstance(error, http.client.HTTPException):
        return "bad HTTP response"
    return "connection failed"


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    trust_pem: str | None = None,
    limits: Limits = Limits(),  # noqa: B008 - frozen, shared safely
) -> Any:
    """GET, or POST when body is given, and return the parsed JSON document.

    Only a 200 counts. With trust_pem, that certificate is the only one
    accepted; without it, the system trust store and hostname checks apply.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SourceError("refused: not an https URL")
    expired = threading.Event()
    try:
        with _verified_socket(parts, trust_pem, limits, expired) as tls:
            data = _exchange(tls, parts, headers, body, limits.max_bytes)
    except SourceError:
        raise
    except (OSError, http.client.HTTPException) as error:
        raise SourceError("timed out" if expired.is_set() else _reason(error)) from error
    if expired.is_set():
        raise SourceError("timed out")
    try:
        return json.loads(data)
    except ValueError as error:
        raise SourceError("malformed JSON") from error
