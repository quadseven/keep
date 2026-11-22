"""The first screen: what needs attention, worst first. Every value is escaped."""

from __future__ import annotations

from datetime import datetime
from html import escape

from keep.inventory import Device, Severity, View
from keep.model import Kind, SourceFailure, SourceRecord, SourceState
from keep.security import Control, DeviceReading, DeviceSecurity, Person, Security

SEVERITY_LABELS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}

NOT_COLLECTED = (
    "Not collected yet: antivirus, Proxmox, Kubernetes, SSH hosts, image SBOM matching. "
    "A device here has been checked only for what its listed sources report."
)
MEMORY_NOTE = "Device readings live in memory, so a restart clears them."

CSS = """
:root{color-scheme:light dark;--bg:#f6f5f2;--panel:#fff;--ink:#1d1f21;--mute:#62676d;--line:#dfddd7;
--crit:#b3261e;--high:#b4530a;--med:#7a6200;--low:#3f6b8c;--ok:#2f6f46}
@media(prefers-color-scheme:dark){:root{--bg:#141517;--panel:#1c1e21;--ink:#e8e7e3;--mute:#9a9fa6;
--line:#2e3136;--crit:#ff8a80;--high:#ffb26b;--med:#e3cc6a;--low:#8fc1e3;--ok:#86d3a0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,sans-serif}
main{max-width:880px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;margin:0}h2{font-size:15px;margin:28px 0 8px}
.sub,.note{color:var(--mute);font-size:13px}.note{margin:8px 0 0}
.src{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px;margin-top:14px}
.src div,.dev{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.state{font-weight:600}.ok{color:var(--ok)}.bad{color:var(--crit)}.wait{color:var(--med)}
.locked{border:1px solid var(--crit);border-radius:8px;padding:12px;margin-top:14px;background:var(--panel)}
.dev{margin-bottom:8px}.top{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.name{font-weight:600;overflow-wrap:anywhere}.meta{color:var(--mute);font-size:13px}
ul{margin:6px 0 0;padding:0;list-style:none}li{padding:1px 0}
.pill{font-size:12px;font-weight:600;min-width:58px;display:inline-block}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:8px}
summary{cursor:pointer;font-weight:600}a{color:inherit}
"""


def _age(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "never"
    seconds = max(0, int((now - moment).total_seconds()))
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{seconds // 60} minutes ago"
    if seconds < 129600:
        return f"{seconds // 3600} hours ago"
    return f"{seconds // 86400} days ago"


def _source(record: SourceRecord, now: datetime) -> str:
    style = {SourceState.OK: "ok", SourceState.PENDING: "wait"}.get(record.state, "bad")
    devices = len(record.observations)
    parts = [
        f"<div><b>{escape(record.name)}</b> "
        f'<span class="state {style}">{escape(record.state.value)}</span>'
    ]
    if record.reason:
        parts.append(f'<div class="meta">{escape(record.reason)}</div>')
    if record.last_success:
        parts.append(
            f'<div class="meta">{devices} records, read {_age(record.last_success, now)}</div>'
        )
    else:
        parts.append('<div class="meta">No successful read yet, so nothing is known here</div>')
    parts.append("</div>")
    return "".join(parts)


def _sources(records: list[SourceRecord], now: datetime) -> str:
    return '<section class="src">' + "".join(_source(r, now) for r in records) + "</section>"


def _device(device: Device) -> str:
    kinds = ", ".join(sorted(kind.value for kind in device.kinds if kind is not Kind.CLIENT))
    meta = " | ".join(part for part in (kinds, device.detail, ", ".join(device.sources)) if part)
    rows = []
    for finding in device.findings:
        label = SEVERITY_LABELS[finding.severity]
        summary = escape(finding.summary)
        if finding.link and finding.link.startswith("https://"):
            summary = f'<a href="{escape(finding.link)}" rel="noreferrer">{summary}</a>'
        rows.append(f'<li><span class="pill {label}">{label}</span>{summary}</li>')
    rows.extend(f'<li class="meta">Unknown: {escape(gap)}</li>' for gap in device.gaps)
    body = f"<ul>{''.join(rows)}</ul>" if rows else ""
    return (
        f'<article class="dev"><div class="top"><span class="name">{escape(device.name)}</span>'
        f'<span class="meta">{escape(meta)}</span></div>{body}</article>'
    )


def _folded(title: str, devices: list[Device]) -> str:
    if not devices:
        return ""
    return (
        f"<details><summary>{escape(title)}: {len(devices)}</summary>"
        + "".join(_device(device) for device in devices)
        + "</details>"
    )


def _shell(body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Keep</title><style>{CSS}</style></head><body><main>{body}</main></body></html>"
    )


def inventory_page(
    view: View,
    records: list[SourceRecord],
    failures: list[SourceFailure],
    identity: str,
    now: datetime,
) -> str:
    known = any(record.last_success for record in records)
    parts = [
        "<h1>Keep</h1>",
        f'<div class="sub">Signed in as {escape(identity)}</div>',
        '<p><a href="/security">Security</a></p>',
        _sources(records, now),
        "<h2>Needs attention, worst first</h2>",
    ]
    if view.attention:
        parts.extend(_device(device) for device in view.attention)
    elif known:
        parts.append('<p class="sub">Nothing flagged by the sources read so far.</p>')
    else:
        parts.append('<p class="sub">No source has been read yet, so this list says nothing.</p>')
    parts.append(_folded("Unknown, not enough data to call", view.unknown))
    parts.append(_folded("Healthy", view.healthy))
    parts.append(_folded("Other network clients, seen on the network only", view.clients))
    if failures:
        rows = "".join(
            f"<li>{_age(f.at, now)}: {escape(f.source)}, {escape(f.reason)}</li>"
            for f in reversed(failures[-20:])
        )
        parts.append(
            f"<details><summary>Recent source failures: {len(failures)}</summary>"
            f"<ul>{rows}</ul></details>"
        )
    parts.append(f'<p class="note">{escape(NOT_COLLECTED)} {escape(MEMORY_NOTE)}</p>')
    return _shell("".join(parts))


def _known(value: str | int | bool | None) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return escape(str(value))


def _control(control: Control) -> str:
    checked = (
        f"checked {escape(control.checked_on)}" if control.checked_on else "check date unknown"
    )
    return f"<li>{escape(control.label)}: {escape(control.status.capitalize())} ({checked})</li>"


def _device_reading(reading: DeviceReading) -> str:
    source = escape(reading.source)
    state = escape(reading.source_state.value)
    observed = reading.observed_at.isoformat()
    parts = [f'<li><span class="meta">{source} ({state}), read {observed}</span><ul>']
    if reading.kind is Kind.COMPUTER:
        parts.extend(
            (
                f"<li>Critical patches pending: {_known(reading.updates_critical)}</li>",
                f"<li>Other patches pending: {_known(reading.updates_other)}</li>",
            )
        )
    elif reading.kind is Kind.NETWORK_DEVICE:
        parts.append(f"<li>Firmware update pending: {_known(reading.firmware_pending)}</li>")
    else:
        parts.append("<li>Patch status: Unknown</li>")
    return "".join(parts) + "</ul></li>"


def _device_security(device: DeviceSecurity) -> str:
    readings = "".join(_device_reading(reading) for reading in device.readings)
    return (
        f'<li><span class="name">{escape(device.name)}</span><ul>'
        f"{readings or '<li>No device reading available.</li>'}"
        f"<li>Antivirus: {_known(device.av_status)}</li>"
        f"<li>OS support: {_known(device.os_support)}</li></ul></li>"
    )


def _posture(person: Person) -> str:
    breach = person.breach
    latest = "None reported" if breach.count == 0 else _known(breach.latest_breach_on)
    return (
        f'<article class="dev"><h2>{escape(person.name)}</h2>'
        "<h3>Breach exposure</h3><ul>"
        f"<li>Breach count: {_known(breach.count)}</li>"
        f"<li>Most recent breach: {latest}</li>"
        f"<li>Passwords involved: {_known(breach.passwords_involved)}</li>"
        f"<li>Last checked: {_known(breach.checked_on)}</li></ul>"
        "<h3>Protective controls</h3><ul>"
        + "".join(_control(control) for control in person.controls)
        + "</ul><h3>Device security, worst first</h3>"
        + (
            "<ul>" + "".join(_device_security(device) for device in person.devices) + "</ul>"
            if person.devices
            else '<p class="sub">No devices linked.</p>'
        )
        + "</article>"
    )


def security_page(data: Security | None) -> str:
    header = '<p><a href="/">Devices</a></p><h1>Security</h1>'
    if data is None:
        return _shell(header + '<p class="locked">Security database unavailable.</p>')
    if not data.configured:
        return _shell(header + '<p class="sub">Security database is not configured.</p>')
    if not data.people:
        return _shell(header + '<p class="sub">No people recorded.</p>')
    return _shell(header + "".join(_posture(person) for person in data.people))


def locked_page(reason: str, missing: list[str], records: list[SourceRecord], now: datetime) -> str:
    """Shown to anyone refused. Source health only, never a device."""
    if missing:
        message = "Sign-in is not set up, so no device data is shown. Missing: " + ", ".join(
            missing
        )
    else:
        message = f"This identity is not allowed to see device data ({reason})."
    return _shell(
        "<h1>Keep</h1>"
        f'<div class="locked">{escape(message)}</div>'
        "<h2>Sources</h2>" + _sources(records, now)
    )
