"""Action1: managed endpoints with update, vulnerability and reboot state."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlencode

from keep.collectors import Fetch
from keep.collectors.parse import count, mac, required, serial, text
from keep.model import Kind, Observation, SourceError
from keep.net import fetch_json

PAGE_SIZE = 100
MAX_PAGES = 100
LAST_SEEN_FORMAT = "%Y-%m-%d_%H-%M-%S"


def _items(document: Any, what: str) -> list[dict[str, Any]]:
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise SourceError(f"malformed payload: {what}")
    return items


def _yes_no(value: Any) -> bool | None:
    return {"yes": True, "no": False}.get((text(value) or "").lower())


def _online(value: Any) -> bool | None:
    return {"connected": True, "disconnected": False}.get((text(value) or "").lower())


def _last_seen(value: Any) -> datetime | None:
    raw = text(value)
    if raw is None:
        return None
    try:
        return datetime.strptime(raw, LAST_SEEN_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _pair(value: Any, field: str) -> tuple[int | None, int | None]:
    if value is None:
        return None, None
    if not isinstance(value, dict):
        raise SourceError(f"malformed payload: {field}")
    return count(value.get("critical"), field), count(value.get("other"), field)


class Action1Collector:
    name = "Action1"

    def __init__(
        self,
        base_url: str | None,
        client_id: str | None,
        client_secret: str | None,
        fetch: Fetch = fetch_json,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.fetch = fetch

    def missing(self) -> list[str]:
        needed = {
            "KEEP_ACTION1_BASE_URL": self.base_url,
            "KEEP_ACTION1_CLIENT_ID": self.client_id,
            "KEEP_ACTION1_CLIENT_SECRET": self.client_secret,
        }
        return [key for key, value in needed.items() if not value]

    def _token(self) -> str:
        document = self.fetch(
            f"{self.base_url}/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode(
                {"client_id": self.client_id, "client_secret": self.client_secret}
            ).encode(),
        )
        token = text(document.get("access_token")) if isinstance(document, dict) else None
        if token is None:
            raise SourceError("malformed payload: token")
        return token

    def _endpoints(self, organization: str, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Every endpoint, or SourceError: a short list would hide devices."""
        collected: list[dict[str, Any]] = []
        url: str | None = (
            f"{self.base_url}/endpoints/managed/{quote(organization, safe='')}"
            f"?fields=*&limit={PAGE_SIZE}"
        )
        total = None
        for _ in range(MAX_PAGES):
            document = self.fetch(url, headers=headers)
            collected.extend(_items(document, "endpoints"))
            total = document.get("total_items")
            url = text(document.get("next_page"))
            if url is None:
                break
            if not url.startswith(f"{self.base_url}/"):
                # The bearer token only ever goes back to the configured API.
                raise SourceError("malformed payload: next_page")
        else:
            raise SourceError("too many pages")
        try:
            expected = int(total)
        except (TypeError, ValueError) as error:
            raise SourceError("malformed payload: total_items") from error
        if len(collected) != expected:
            raise SourceError("partial response")
        return collected

    def _observation(self, item: dict[str, Any], now: datetime) -> Observation:
        updates = _pair(item.get("missing_updates"), "missing_updates")
        vulns = _pair(item.get("vulnerabilities"), "vulnerabilities")
        address = mac(item.get("MAC"))
        return Observation(
            source=self.name,
            ref=required(item, "id"),
            observed_at=now,
            kind=Kind.COMPUTER,
            name=text(item.get("name")) or text(item.get("device_name")) or required(item, "id"),
            detail=text(item.get("OS")) or text(item.get("platform")),
            serial=serial(item.get("serial")),
            macs=(address,) if address else (),
            online=_online(item.get("status")),
            last_seen=_last_seen(item.get("last_seen")),
            updates_critical=updates[0],
            updates_other=updates[1],
            vulns_critical=vulns[0],
            vulns_other=vulns[1],
            reboot_required=_yes_no(item.get("reboot_required")),
            link=self.base_url.split("/api/", 1)[0],
        )

    def collect(self) -> list[Observation]:
        headers = {"Authorization": f"Bearer {self._token()}"}
        now = datetime.now(UTC)
        observations: list[Observation] = []
        for organization in _items(
            self.fetch(f"{self.base_url}/organizations", headers=headers), "organizations"
        ):
            endpoints = self._endpoints(required(organization, "id"), headers)
            observations.extend(self._observation(item, now) for item in endpoints)
        return observations
