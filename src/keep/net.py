"""The one way Keep reads a network API.

Every call has a connect timeout and a hard total deadline, TLS is mandatory,
and a pinned certificate is checked before any credential is written to the
socket. Failures become SourceError with a fixed reason, so a reason can never
carry a URL, an address or a credential.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import socket
import ssl
import threading
from typing import Any
from urllib.parse import urlsplit

from keep.model import SourceError

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
TOTAL_TIMEOUT = 30.0
MAX_BYTES = 32 * 1024 * 1024


def _context(pin_sha256: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if pin_sha256:
        # The fingerprint check in _connect replaces chain and name checks: a
        # self-signed console leaf cannot chain to any CA.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _check_pin(tls: ssl.SSLSocket, pin_sha256: str) -> None:
    der = tls.getpeercert(binary_form=True)
    actual = hashlib.sha256(der or b"").hexdigest()
    if not hmac.compare_digest(actual, pin_sha256.replace(":", "").strip().lower()):
        raise SourceError("certificate pin mismatch")


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    pin_sha256: str | None = None,
    connect_timeout: float = CONNECT_TIMEOUT,
    read_timeout: float = READ_TIMEOUT,
    total_timeout: float = TOTAL_TIMEOUT,
    max_bytes: int = MAX_BYTES,
) -> Any:
    """GET, or POST when body is given, and return the parsed JSON document.

    Only a 200 counts. Redirects are not followed, so a credential never
    travels to a host the caller did not name.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SourceError("refused: not an https URL")
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    expired = threading.Event()
    timer: threading.Timer | None = None
    tls: ssl.SSLSocket | None = None

    try:
        raw = socket.create_connection((parts.hostname, parts.port or 443), timeout=connect_timeout)
        raw.settimeout(read_timeout)
        tls = _context(pin_sha256).wrap_socket(
            raw, server_hostname=parts.hostname, do_handshake_on_connect=False
        )

        def expire(sock: ssl.SSLSocket = tls) -> None:
            expired.set()
            try:
                # The plain socket call: SSLSocket.shutdown drops its TLS state
                # while another thread may still be reading through it.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass  # The peer already closed; the reader fails either way.

        timer = threading.Timer(total_timeout, expire)
        timer.daemon = True
        timer.start()

        tls.do_handshake()
        if pin_sha256:
            _check_pin(tls, pin_sha256)

        connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443)
        connection.sock = tls
        connection.request(
            "POST" if body is not None else "GET", target, body=body, headers=headers or {}
        )
        response = connection.getresponse()
        if response.status in (401, 403):
            raise SourceError(f"auth refused (HTTP {response.status})")
        if response.status != 200:
            raise SourceError(f"unexpected HTTP {response.status}")

        chunks: list[bytes] = []
        size = 0
        while chunk := response.read1(65536):
            size += len(chunk)
            if size > max_bytes:
                raise SourceError("response too large")
            chunks.append(chunk)
        if expired.is_set():
            raise SourceError("timed out")
        if response.length not in (None, 0):
            raise SourceError("response truncated")
        return json.loads(b"".join(chunks))
    except SourceError:
        raise
    except json.JSONDecodeError as error:
        raise SourceError("malformed JSON") from error
    except UnicodeDecodeError as error:
        raise SourceError("malformed JSON") from error
    except TimeoutError as error:
        raise SourceError("timed out") from error
    except ssl.SSLError as error:
        if expired.is_set():
            raise SourceError("timed out") from error
        raise SourceError("TLS error") from error
    except http.client.HTTPException as error:
        if expired.is_set():
            raise SourceError("timed out") from error
        raise SourceError("bad HTTP response") from error
    except OSError as error:
        if expired.is_set():
            raise SourceError("timed out") from error
        raise SourceError("connection failed") from error
    finally:
        if timer is not None:
            timer.cancel()
        if tls is not None:
            tls.close()
