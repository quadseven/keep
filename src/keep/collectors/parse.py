"""Field readers shared by collectors. A missing value stays None."""

from __future__ import annotations

import re
from typing import Any

from keep.model import SourceError

_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")
ALL_ZERO_MAC = ":".join(["00"] * 6)
_NOT_A_SERIAL = {
    "",
    "0",
    "none",
    "n/a",
    "na",
    "unknown",
    "default string",
    "to be filled by o.e.m.",
    "system serial number",
}


def text(value: Any) -> str | None:
    """A non-empty stripped string, or None."""
    if not isinstance(value, str):
        return None
    return value.strip() or None


def mac(value: Any) -> str | None:
    """A lowercase colon-separated MAC, or None when it cannot identify a device."""
    raw = text(value)
    if raw is None or not _MAC.match(raw.lower()):
        return None
    normalized = raw.lower().replace("-", ":")
    return None if normalized == ALL_ZERO_MAC else normalized


def serial(value: Any) -> str | None:
    """A serial worth joining on. Vendor placeholders would merge strangers."""
    raw = text(value)
    if raw is None or raw.lower() in _NOT_A_SERIAL:
        return None
    return raw


def count(value: Any, field: str) -> int | None:
    """A non-negative count. Absent is unknown; a wrong type is a bad payload."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SourceError(f"malformed payload: {field}")
    return value


def required(item: dict[str, Any], key: str) -> str:
    """A required string field. Without it the response is not trustworthy."""
    value = text(item.get(key))
    if value is None:
        raise SourceError(f"malformed payload: {key}")
    return value
