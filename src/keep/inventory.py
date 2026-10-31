"""Turns observations into devices and findings.

Records join by serial, then machine ID, then MAC. A hostname is only a label.
A device is healthy only when every signal it should have was read
successfully; anything less lands in the unknown bucket.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

from keep.model import Kind, Observation, SourceRecord, SourceState


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    severity: Severity
    kind: str
    summary: str
    link: str | None = None


@dataclass
class Device:
    name: str
    kinds: set[Kind]
    observations: list[Observation]
    findings: list[Finding] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def worst(self) -> Severity:
        return max((finding.severity for finding in self.findings), default=Severity.LOW)

    @property
    def sources(self) -> list[str]:
        return sorted({observation.source for observation in self.observations})

    @property
    def detail(self) -> str | None:
        return next((o.detail for o in self.observations if o.detail), None)

    @property
    def sort_key(self) -> tuple[int, int, str]:
        vulns = sum(o.vulns_critical or 0 for o in self.observations)
        return (-int(self.worst), -vulns, self.name.lower())


@dataclass
class View:
    attention: list[Device]
    unknown: list[Device]
    healthy: list[Device]
    clients: list[Device]


class _Groups:
    """Union-find that refuses to merge two different serials."""

    def __init__(self, observations: list[Observation]):
        self.parent = list(range(len(observations)))
        self.serials = [{o.serial} if o.serial else set() for o in observations]

    def find(self, index: int) -> int:
        while self.parent[index] != index:
            self.parent[index] = self.parent[self.parent[index]]
            index = self.parent[index]
        return index

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a == b or (self.serials[a] and self.serials[b] and self.serials[a] != self.serials[b]):
            return
        self.parent[b] = a
        self.serials[a] |= self.serials[b]


def _join(observations: list[Observation]) -> list[list[Observation]]:
    groups = _Groups(observations)
    for keys_of in (
        lambda o: [o.serial] if o.serial else [],
        lambda o: [o.machine_id] if o.machine_id else [],
        lambda o: list(o.macs),
    ):
        first_seen: dict[str, int] = {}
        for index, observation in enumerate(observations):
            for key in keys_of(observation):
                groups.union(first_seen.setdefault(key, index), index)
    joined: dict[int, list[Observation]] = {}
    for index, observation in enumerate(observations):
        joined.setdefault(groups.find(index), []).append(observation)
    return list(joined.values())


def _ago(moment: datetime, now: datetime) -> str:
    days = (now - moment).days
    if days >= 1:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return "today"


def _findings(observation: Observation, now: datetime) -> list[Finding]:
    o = observation
    found: list[Finding] = []
    if o.vulns_critical:
        found.append(
            Finding(
                Severity.CRITICAL,
                "vulnerability",
                f"{o.vulns_critical} critical vulnerabilities",
                o.link,
            )
        )
    if o.vulns_other:
        found.append(
            Finding(
                Severity.MEDIUM, "vulnerability", f"{o.vulns_other} other vulnerabilities", o.link
            )
        )
    if o.online is False:
        when = f", last seen {_ago(o.last_seen, now)}" if o.last_seen else ""
        found.append(Finding(Severity.HIGH, "offline", f"Offline{when}", o.link))
    if o.updates_critical:
        found.append(
            Finding(
                Severity.HIGH, "updates", f"{o.updates_critical} critical updates missing", o.link
            )
        )
    if o.updates_other:
        found.append(
            Finding(Severity.MEDIUM, "updates", f"{o.updates_other} other updates missing", o.link)
        )
    if o.firmware_pending:
        target = f": {o.firmware_target}" if o.firmware_target else ""
        found.append(
            Finding(Severity.MEDIUM, "firmware", f"Firmware update available{target}", o.link)
        )
    if o.reboot_required:
        found.append(Finding(Severity.LOW, "reboot", "Reboot required", o.link))
    return found


def _gaps(observation: Observation, record: SourceRecord) -> list[str]:
    o = observation
    gaps: list[str] = []
    if record.state is not SourceState.OK:
        gaps.append(f"{o.source} reading is stale: {record.reason or 'not read'}")
    if o.online is None:
        gaps.append(f"{o.source} did not report online state")
    if o.kind is Kind.COMPUTER:
        for label, value in (
            ("critical updates", o.updates_critical),
            ("other updates", o.updates_other),
            ("critical vulnerabilities", o.vulns_critical),
            ("other vulnerabilities", o.vulns_other),
            ("reboot state", o.reboot_required),
        ):
            if value is None:
                gaps.append(f"{o.source} did not report {label}")
    if o.kind is Kind.NETWORK_DEVICE and o.firmware_pending is None:
        gaps.append(f"{o.source} did not report firmware state")
    return gaps


def build(records: Iterable[SourceRecord], now: datetime) -> View:
    records = list(records)
    by_source = {record.name: record for record in records}
    observations = [o for record in records for o in record.observations]
    view = View(attention=[], unknown=[], healthy=[], clients=[])
    for group in _join(observations):
        kinds = {o.kind for o in group}
        managed = sorted(group, key=lambda o: o.kind is Kind.CLIENT)
        device = Device(name=managed[0].name, kinds=kinds, observations=group)
        for observation in group:
            device.findings.extend(_findings(observation, now))
            device.gaps.extend(_gaps(observation, by_source[observation.source]))
        device.findings.sort(key=lambda finding: -int(finding.severity))
        if kinds == {Kind.CLIENT}:
            view.clients.append(device)
        elif device.findings:
            view.attention.append(device)
        elif device.gaps:
            view.unknown.append(device)
        else:
            view.healthy.append(device)
    for bucket in (view.attention, view.unknown, view.healthy, view.clients):
        bucket.sort(key=lambda device: device.sort_key)
    return view
