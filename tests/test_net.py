import json
import socket
import ssl
import threading
import time

import pytest
import trustme

from keep.model import SourceError
from keep.net import Limits, fetch_json


class Server:
    """One local TLS listener that records what it received."""

    def __init__(self, reply=None, stall=False):
        self.ca = trustme.CA()
        cert = self.ca.issue_cert("keep.test")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert.configure_cert(context)
        self.pem = cert.cert_chain_pems[0].bytes().decode()
        self.received = b""
        self.reply = reply
        self.stall = stall
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.context = context
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        raw, _ = self.listener.accept()
        try:
            tls = self.context.wrap_socket(raw, server_side=True)
            self.received = tls.recv(65536)
            if self.stall:
                while True:
                    tls.sendall(b"X-Slow: 1\r\n" if self.received else b"")
                    time.sleep(0.05)
            tls.sendall(self.reply)
            tls.close()
        except OSError:
            pass

    @property
    def url(self):
        return f"https://127.0.0.1:{self.port}/api?x=1"


def http(status, body):
    return (f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body


def test_the_trusted_certificate_reads_json():
    server = Server(http(200, json.dumps({"ok": 1}).encode()))
    assert fetch_json(server.url, trust_pem=server.pem) == {"ok": 1}


def test_any_other_certificate_never_gets_the_credential():
    server = Server(http(200, b"{}"))
    other = Server(http(200, b"{}"))
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, headers={"X-API-KEY": "TEST-KEY"}, trust_pem=other.pem)
    assert caught.value.reason == "TLS error"
    server.thread.join(2)
    assert b"TEST-KEY" not in server.received


def test_an_unverified_certificate_is_refused_without_a_trust_pem():
    server = Server(http(200, b"{}"))
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, headers={"X-API-KEY": "TEST-KEY"})
    assert caught.value.reason == "TLS error"
    assert b"TEST-KEY" not in server.received


def test_plain_http_is_refused():
    with pytest.raises(SourceError) as caught:
        fetch_json("http://192.0.2.1/api", headers={"X-API-KEY": "TEST-KEY"})
    assert caught.value.reason == "refused: not an https URL"


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "auth refused (HTTP 401)"),
        (403, "auth refused (HTTP 403)"),
        (302, "unexpected HTTP 302"),
        (500, "unexpected HTTP 500"),
    ],
)
def test_only_a_200_counts(status, reason):
    server = Server(http(status, b"{}"))
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, trust_pem=server.pem)
    assert caught.value.reason == reason


def test_a_bad_payload_is_a_failure():
    server = Server(http(200, b"<html>not json"))
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, trust_pem=server.pem)
    assert caught.value.reason == "malformed JSON"


def test_a_truncated_body_is_a_failure():
    server = Server(b"HTTP/1.1 200 X\r\nContent-Length: 100\r\n\r\n{}")
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, trust_pem=server.pem)
    assert caught.value.reason in ("response truncated", "bad HTTP response")


def test_an_oversized_body_is_a_failure():
    server = Server(http(200, b"[" + b"1," * 1000 + b"1]"))
    with pytest.raises(SourceError) as caught:
        fetch_json(server.url, trust_pem=server.pem, limits=Limits(max_bytes=100))
    assert caught.value.reason == "response too large"


def test_a_server_that_drips_forever_hits_the_total_deadline():
    server = Server(stall=True)
    started = time.monotonic()
    with pytest.raises(SourceError) as caught:
        fetch_json(
            server.url, trust_pem=server.pem, limits=Limits(read_timeout=5, total_timeout=0.4)
        )
    assert caught.value.reason in ("timed out", "bad HTTP response")
    assert time.monotonic() - started < 3


def test_a_silent_server_times_out():
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    with pytest.raises(SourceError) as caught:
        fetch_json(f"https://127.0.0.1:{port}/", limits=Limits(read_timeout=0.2, total_timeout=1))
    assert caught.value.reason == "timed out"
    listener.close()


def test_a_refused_connection_is_a_failure():
    probe = socket.create_server(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(SourceError) as caught:
        fetch_json(f"https://127.0.0.1:{port}/")
    assert caught.value.reason == "connection failed"
