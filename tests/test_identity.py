import json
import socket
import threading

import pytest

from fixtures import TAILNET_CLIENT, TEST_TAILNET
from keep.identity import Gate, Who, localapi_whois

PROXY = "192.0.2.0/31"
PEER = "192.0.2.1"
CLIENT = TAILNET_CLIENT
TOKEN = "TEST-PROXY-TOKEN"


OPERATOR = Who("operator@example.com", "TEST-NODE-1")


def gate(who=OPERATOR, **over):
    fields = dict(
        proxy_token=TOKEN,
        trusted_proxies=[PROXY],
        allowed_logins={"Operator@example.com"},
        allowed_nodes={"TEST-NODE-2"},
        whois=lambda _: who,
        tailnet=TEST_TAILNET,
    )
    fields.update(over)
    return Gate(**fields)


def test_an_allowed_login_gets_in():
    verdict = gate().check(PEER, CLIENT, TOKEN)
    assert verdict.identity == "operator@example.com" and verdict.reason == "ok"


def test_an_allowed_tagged_node_gets_in():
    verdict = gate(Who(None, "TEST-NODE-2", tagged=True)).check(PEER, CLIENT, TOKEN)
    assert verdict.identity == "node:TEST-NODE-2"


@pytest.mark.parametrize(
    "peer,forwarded,token,reason",
    [
        ("203.0.113.9", CLIENT, TOKEN, "untrusted_peer"),
        (None, CLIENT, TOKEN, "untrusted_peer"),
        (PEER, CLIENT, "wrong", "bad_proxy_token"),
        (PEER, CLIENT, None, "bad_proxy_token"),
        (PEER, None, TOKEN, "no_client"),
        (
            PEER,
            f"{CLIENT}, {CLIENT}",
            TOKEN,
            "no_client",
        ),
        (PEER, "not-an-address", TOKEN, "no_client"),
        (PEER, "203.0.113.9", TOKEN, "not_tailnet"),
    ],
)
def test_a_bad_request_is_refused_before_whois(peer, forwarded, token, reason):
    def never(_):
        raise AssertionError("whois must not run")

    verdict = gate(whois=never).check(peer, forwarded, token)
    assert verdict.identity is None and verdict.reason == reason


@pytest.mark.parametrize(
    "who,reason",
    [
        (None, "unknown_identity"),
        (Who("stranger@example.com", "TEST-NODE-3"), "not_allowed"),
        (Who(None, "TEST-NODE-3"), "not_allowed"),
        (Who(None, "TEST-NODE-3", tagged=True), "tagged_device"),
    ],
)
def test_an_unknown_or_unlisted_identity_is_refused(who, reason):
    verdict = gate(who).check(PEER, CLIENT, TOKEN)
    assert verdict.identity is None and verdict.reason == reason


@pytest.mark.parametrize(
    "over,named",
    [
        ({"proxy_token": ""}, "KEEP_PROXY_TOKEN"),
        ({"trusted_proxies": []}, "KEEP_TRUSTED_PROXY_CIDRS"),
        ({"allowed_logins": set(), "allowed_nodes": set()}, "KEEP_ALLOWED_LOGINS or"),
    ],
)
def test_incomplete_sign_in_config_locks_everyone_out(over, named):
    locked = gate(**over)
    verdict = locked.check(PEER, CLIENT, TOKEN if over.get("proxy_token") != "" else "")
    assert verdict.identity is None and verdict.reason == "not_configured"
    assert any(item.startswith(named) for item in locked.missing)


def serve_whois(path, status, body):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def run():
        connection, _ = listener.accept()
        connection.recv(65536)
        connection.sendall(
            f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
        )
        connection.close()

    threading.Thread(target=run, daemon=True).start()


def short(tmp_path_factory):
    return tmp_path_factory.mktemp("w", numbered=True) / "s"


def test_whois_reads_a_login(tmp_path_factory):
    path = short(tmp_path_factory)
    serve_whois(
        path,
        200,
        json.dumps(
            {"Node": {"StableID": "TEST-NODE-1"}, "UserProfile": {"LoginName": "o@example.com"}}
        ).encode(),
    )
    assert localapi_whois(str(path))(CLIENT) == Who("o@example.com", "TEST-NODE-1")


def test_whois_marks_a_tagged_node(tmp_path_factory):
    path = short(tmp_path_factory)
    serve_whois(
        path,
        200,
        json.dumps(
            {
                "Node": {"StableID": "TEST-NODE-1", "Tags": ["tag:x"]},
                "UserProfile": {"LoginName": "o@example.com"},
            }
        ).encode(),
    )
    assert localapi_whois(str(path))(CLIENT) == Who(None, "TEST-NODE-1", tagged=True)


@pytest.mark.parametrize(
    "status,body", [(404, b"{}"), (200, b"not json"), (200, b"{}"), (200, b"[]")]
)
def test_whois_failure_is_no_identity(tmp_path_factory, status, body):
    path = short(tmp_path_factory)
    serve_whois(path, status, body)
    assert localapi_whois(str(path))(CLIENT) is None


def test_a_missing_socket_is_no_identity(tmp_path):
    assert localapi_whois(str(tmp_path / "gone"))(CLIENT) is None
