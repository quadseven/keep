"""Keep's nouns. An unknown value is None, never zero."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class SourceError(Exception):
    """A source could not be read. The reason is safe to display and log."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SourceState(Enum):
    PENDING = "pending"
    OK = "ok"
    FAILED = "failed"
    NOT_CONFIGURED = "not configured"


class Kind(Enum):
    COMPUTER = "computer"
    NETWORK_DEVICE = "network device"
    CLIENT = "network client"


@dataclass(frozen=True)
class Observation:
    """One reading of one device from one source at one time."""

    source: str
    ref: str
    observed_at: datetime
    kind: Kind
    name: str
    detail: str | None = None
    serial: str | None = None
    machine_id: str | None = None
    macs: tuple[str, ...] = ()
    online: bool | None = None
    last_seen: datetime | None = None
    updates_critical: int | None = None
    updates_other: int | None = None
    vulns_critical: int | None = None
    vulns_other: int | None = None
    reboot_required: bool | None = None
    firmware_pending: bool | None = None
    firmware_target: str | None = None
    link: str | None = None


@dataclass
class SourceRecord:
    """What Keep knows about a source right now."""

    name: str
    state: SourceState = SourceState.PENDING
    reason: str | None = None
    last_attempt: datetime | None = None
    last_success: datetime | None = None
    observations: list[Observation] = field(default_factory=list)


@dataclass(frozen=True)
class SourceFailure:
    """One failed read. A later success does not remove it."""

    source: str
    at: datetime
    reason: str
