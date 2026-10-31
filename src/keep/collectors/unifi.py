"""UniFi Network: adopted network devices and the clients connected now."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from keep.collectors import Fetch
from keep.collectors.parse import mac, serial, text
from keep.model import Kind, Observation, SourceError
from keep.net import fetch_json

STATE_DISCONNECTED = 0
STATE_CONNECTED = 1


def _data(document: Any, what: str) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise SourceError(f"malformed payload: {what}")
    meta = document.get("meta")
    if not isinstance(meta, dict) or meta.get("rc") != "ok":
        raise SourceError(f"source reported an error: {what}")
    data = document.get("data")
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise SourceError(f"malformed payload: {what}")
    return data


def _mac(item: dict[str, Any], what: str) -> str:
    address = mac(item.get("mac"))
    if address is None:
        raise SourceError(f"malformed payload: {what} mac")
    return address


def _epoch(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return datetime.fromtimestamp(value, UTC)


class UnifiCollector:
    name = "UniFi"

    def __init__(
        self,
        base_url: str | None,
        api_key: str | None,
        cert_pem: str | None = None,
        site: str = "default",
        fetch: Fetch = fetch_json,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.cert_pem = cert_pem or None
        self.site = site
        self.fetch = fetch

    def missing(self) -> list[str]:
        needed = {"KEEP_UNIFI_BASE_URL": self.base_url, "KEEP_UNIFI_API_KEY": self.api_key}
        return [key for key, value in needed.items() if not value]

    def _get(self, path: str, what: str) -> list[dict[str, Any]]:
        site = quote(self.site, safe="")
        return _data(
            self.fetch(
                f"{self.base_url}/proxy/network/api/s/{site}/{path}",
                headers={"X-API-KEY": self.api_key, "Accept": "application/json"},
                trust_pem=self.cert_pem,
            ),
            what,
        )

    def _device(self, item: dict[str, Any], now: datetime) -> Observation:
        address = _mac(item, "device")
        state = item.get("state")
        online = {STATE_CONNECTED: True, STATE_DISCONNECTED: False}.get(state)
        upgradable = item.get("upgradable")
        version = text(item.get("version"))
        model = text(item.get("model"))
        return Observation(
            source=self.name,
            ref=address,
            observed_at=now,
            kind=Kind.NETWORK_DEVICE,
            name=text(item.get("name")) or model or address,
            detail=" ".join(part for part in (model, version) if part) or None,
            serial=serial(item.get("serial")),
            macs=(address,),
            online=online,
            last_seen=_epoch(item.get("last_seen")),
            firmware_pending=upgradable if isinstance(upgradable, bool) else None,
            firmware_target=text(item.get("upgrade_to_firmware")),
            link=self.base_url,
        )

    def _client(self, item: dict[str, Any], now: datetime) -> Observation:
        address = _mac(item, "client")
        return Observation(
            source=self.name,
            ref=address,
            observed_at=now,
            kind=Kind.CLIENT,
            name=text(item.get("name")) or text(item.get("hostname")) or address,
            detail="wired" if item.get("is_wired") is True else "wireless",
            macs=(address,),
            online=True,
            last_seen=_epoch(item.get("last_seen")),
        )

    def collect(self) -> list[Observation]:
        now = datetime.now(UTC)
        devices = self._get("stat/device", "devices")
        clients = self._get("stat/sta", "clients")
        return [self._device(item, now) for item in devices] + [
            self._client(item, now) for item in clients
        ]
