"""The JSON surface: the same readings the page shows, for agents.

Read-only. Unknown values stay null, never zero, and a failed source is
reported failed with its reason, never healthy.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from keep.inventory import Device, View
from keep.model import Observation, SourceRecord

SEVERITY_NAMES = {1: "low", 2: "medium", 3: "high", 4: "critical"}
# Page order: what needs attention first, then what cannot be called, then
# what is healthy, then clients seen on the network only.
STATUS_ORDER = ("attention", "unknown", "healthy", "client")


def _when(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _reading(o: Observation) -> dict[str, Any]:
    return {
        "source": o.source,
        "kind": o.kind.value,
        "name": o.name,
        "detail": o.detail,
        "observed_at": _when(o.observed_at),
        "online": o.online,
        "last_seen": _when(o.last_seen),
        "updates_critical": o.updates_critical,
        "updates_other": o.updates_other,
        "vulns_critical": o.vulns_critical,
        "vulns_other": o.vulns_other,
        "reboot_required": o.reboot_required,
        "firmware_pending": o.firmware_pending,
        "firmware_target": o.firmware_target,
        "link": o.link,
    }


def _device(device: Device, status: str) -> dict[str, Any]:
    return {
        "name": device.name,
        "status": status,
        "worst": SEVERITY_NAMES[int(device.worst)] if device.findings else None,
        "kinds": sorted(kind.value for kind in device.kinds),
        "sources": device.sources,
        "findings": [
            {
                "severity": SEVERITY_NAMES[int(f.severity)],
                "kind": f.kind,
                "summary": f.summary,
                "link": f.link,
            }
            for f in device.findings
        ],
        "unknown": list(device.gaps),
        "readings": [_reading(o) for o in device.observations],
    }


def devices(view: View) -> dict[str, Any]:
    buckets = {
        "attention": view.attention,
        "unknown": view.unknown,
        "healthy": view.healthy,
        "client": view.clients,
    }
    return {
        "devices": [
            _device(device, status) for status in STATUS_ORDER for device in buckets[status]
        ]
    }


def sources(records: list[SourceRecord]) -> dict[str, Any]:
    return {
        "sources": [
            {
                "name": r.name,
                "state": r.state.value,
                "reason": r.reason,
                "last_attempt": _when(r.last_attempt),
                "last_success": _when(r.last_success),
                # No successful read means the count is unknown, not zero.
                "records": len(r.observations) if r.last_success else None,
            }
            for r in records
        ]
    }
