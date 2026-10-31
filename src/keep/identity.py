"""Who is asking: the tailnet login behind a request, or no one.

A proxy on the tailnet edge sets X-Forwarded-For to the client's tailnet
address and sends a shared secret. The header is believed only with that
secret and only from a trusted proxy address; the address alone is forgeable
by anything sharing the proxy's network namespace. The client address is then
resolved by the node's tailscaled LocalAPI. Everything else is refused.
"""

from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import logging
import socket
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger("keep.identity")

TAILNET = (
    ipaddress.ip_network("100.64.0.0/10"),  # leak-guard-allow: reserved range, not a host
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)
WHOIS_TIMEOUT = 3.0
MAX_WHOIS_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Who:
    login: str | None
    node: str | None
    tagged: bool = False


@dataclass(frozen=True)
class Verdict:
    identity: str | None
    reason: str


def _ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


class Gate:
    def __init__(
        self,
        proxy_token: str,
        trusted_proxies: list[str],
        allowed_logins: set[str],
        allowed_nodes: set[str],
        whois: Callable[[str], Who | None],
    ):
        self.token = proxy_token.encode()
        self.trusted = [ipaddress.ip_network(cidr) for cidr in trusted_proxies]
        self.allowed_logins = {login.lower() for login in allowed_logins}
        self.allowed_nodes = set(allowed_nodes)
        self.whois = whois

    @property
    def missing(self) -> list[str]:
        """The sign-in settings still absent. Any one of them locks the site."""
        gaps = []
        if not self.token:
            gaps.append("KEEP_PROXY_TOKEN")
        if not self.trusted:
            gaps.append("KEEP_TRUSTED_PROXY_CIDRS")
        if not self.allowed_logins and not self.allowed_nodes:
            gaps.append("KEEP_ALLOWED_LOGINS or KEEP_ALLOWED_NODES")
        return gaps

    def check(self, peer: str | None, forwarded: str | None, token: str | None) -> Verdict:
        if self.missing:
            return Verdict(None, "not_configured")
        peer_ip = _ip(peer)
        if peer_ip is None or not any(peer_ip in network for network in self.trusted):
            return Verdict(None, "untrusted_peer")
        if not hmac.compare_digest((token or "").encode(), self.token):
            return Verdict(None, "bad_proxy_token")
        client = _ip(forwarded)
        if client is None:
            return Verdict(None, "no_client")
        if not any(client in network for network in TAILNET):
            return Verdict(None, "not_tailnet")
        who = self.whois(str(client))
        if who is None:
            return Verdict(None, "unknown_identity")
        if who.node and who.node in self.allowed_nodes:
            return Verdict(f"node:{who.node}", "ok")
        if who.tagged:
            return Verdict(None, "tagged_device")
        if not who.login or who.login.lower() not in self.allowed_logins:
            return Verdict(None, "not_allowed")
        return Verdict(who.login, "ok")


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("local-tailscaled.sock", timeout=WHOIS_TIMEOUT)
        self.path_to_socket = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(WHOIS_TIMEOUT)
        self.sock.connect(self.path_to_socket)


def localapi_whois(socket_path: str) -> Callable[[str], Who | None]:
    """A whois(ip) over tailscaled's LocalAPI socket. Any failure is None."""

    def lookup(ip: str) -> Who | None:
        address = f"[{ip}]:1" if ":" in ip else f"{ip}:1"
        connection = _UnixConnection(socket_path)
        try:
            connection.request("GET", f"/localapi/v0/whois?addr={address}")
            response = connection.getresponse()
            if response.status != 200:
                return None
            body = json.loads(response.read(MAX_WHOIS_BYTES))
            node = body.get("Node") or {}
            stable_id = node.get("StableID") or None
            if node.get("Tags"):
                return Who(login=None, node=stable_id, tagged=True)
            login = (body.get("UserProfile") or {}).get("LoginName") or None
            if login is None and stable_id is None:
                return None
            return Who(login=login, node=stable_id)
        except (OSError, ValueError, AttributeError, http.client.HTTPException) as error:
            log.error("whois_failed error=%s", type(error).__name__)
            return None
        finally:
            connection.close()

    return lookup
