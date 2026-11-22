"""Read operator-verified Security records from the household database."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime
from itertools import chain
from pathlib import Path

from keep.inventory import View, build
from keep.model import Kind, Observation, SourceRecord, SourceState

CONTROLS = (
    ("equifax_freeze", "Equifax credit freeze"),
    ("experian_freeze", "Experian credit freeze"),
    ("transunion_freeze", "TransUnion credit freeze"),
    ("irs_ip_pin", "IRS Identity Protection PIN"),
    ("ssa_lock", "SSA account lock"),
    ("e_verify_self_lock", "E-Verify Self Lock"),
    ("email_mfa", "Primary email passkey or 2FA"),
    ("watchtower_review", "Password manager Watchtower review"),
)


@dataclass(frozen=True)
class Breach:
    count: int | None
    latest_breach_name: str | None
    latest_breach_on: str | None
    passwords_involved: bool | None
    checked_on: str | None


@dataclass(frozen=True)
class Control:
    key: str
    label: str
    status: str = "unknown"
    checked_on: str | None = None


@dataclass(frozen=True)
class DeviceReading:
    source: str
    source_state: SourceState
    kind: Kind
    observed_at: datetime
    updates_critical: int | None
    updates_other: int | None
    firmware_pending: bool | None


@dataclass(frozen=True)
class DeviceSecurity:
    name: str
    readings: list[DeviceReading] = field(default_factory=list)
    # Neither collector currently reports these signals.
    av_status: str | None = None
    os_support: str | None = None


@dataclass(frozen=True)
class CryptoAccount:
    service: str
    controls: list[Control]


@dataclass(frozen=True)
class Person:
    name: str
    breach: Breach
    controls: list[Control]
    devices: list[DeviceSecurity]
    crypto_accounts: list[CryptoAccount]


@dataclass(frozen=True)
class Incident:
    id: int
    kind: str
    service: str | None
    title: str
    severity: str
    action: str
    reported_on: str
    state: str
    state_checked_on: str
    affected_people: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Security:
    configured: bool
    people: list[Person] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)


type DeviceKey = tuple[str, str]


def _reading(observation: Observation, state: SourceState) -> DeviceReading:
    patches = state is SourceState.OK and observation.kind is Kind.COMPUTER
    firmware = state is SourceState.OK and observation.kind is Kind.NETWORK_DEVICE
    return DeviceReading(
        source=observation.source,
        source_state=state,
        kind=observation.kind,
        observed_at=observation.observed_at,
        updates_critical=observation.updates_critical if patches else None,
        updates_other=observation.updates_other if patches else None,
        firmware_pending=observation.firmware_pending if firmware else None,
    )


def _devices(
    owners: dict[DeviceKey, str], view: View, states: dict[str, SourceState]
) -> list[DeviceSecurity]:
    result: list[DeviceSecurity] = []
    seen: set[DeviceKey] = set()
    for device in chain(view.attention, view.unknown, view.healthy, view.clients):
        matched = {(item.source, item.ref) for item in device.observations} & owners.keys()
        if matched:
            seen.update(matched)
            readings = [_reading(item, states[item.source]) for item in device.observations]
            result.append(DeviceSecurity(device.name, readings))
    result.extend(DeviceSecurity(label) for key, label in owners.items() if key not in seen)
    return result


def _person(
    row: sqlite3.Row,
    saved: dict[str, tuple[str, str | None]],
    devices: list[DeviceSecurity],
    crypto_accounts: list[CryptoAccount],
) -> Person:
    passwords = row["passwords_involved"]
    return Person(
        name=row["name"],
        breach=Breach(
            row["breach_count"],
            row["latest_breach_name"],
            row["latest_breach_on"],
            None if passwords is None else bool(passwords),
            row["breach_checked_on"],
        ),
        controls=[
            Control(key, label, *saved.get(key, ("unknown", None))) for key, label in CONTROLS
        ],
        devices=devices,
        crypto_accounts=crypto_accounts,
    )


def _crypto_accounts(db: sqlite3.Connection) -> dict[int, list[CryptoAccount]]:
    accounts = defaultdict(list)
    for row in db.execute("""
        SELECT c.person_id, s.name, c.mfa_status, c.mfa_checked_on,
               c.withdrawal_status, c.withdrawal_checked_on
        FROM crypto_accounts c
        JOIN service_accounts a USING (person_id, service_id)
        JOIN services s ON s.id = c.service_id
        ORDER BY s.name
    """):
        accounts[row["person_id"]].append(
            CryptoAccount(
                row["name"],
                [
                    Control("mfa", "Passkey or 2FA", row["mfa_status"], row["mfa_checked_on"]),
                    Control(
                        "withdrawal",
                        "Withdrawal controls",
                        row["withdrawal_status"],
                        row["withdrawal_checked_on"],
                    ),
                ],
            )
        )
    return accounts


def _incidents(db: sqlite3.Connection) -> list[Incident]:
    rows = db.execute("""
        SELECT i.id, i.kind, s.name AS service, i.title, i.severity, i.action,
               i.reported_on, i.state, i.state_checked_on, p.name AS affected
        FROM incidents i
        LEFT JOIN services s ON s.id = i.service_id
        LEFT JOIN service_accounts a ON i.kind = 'vendor' AND a.service_id = i.service_id
        JOIN people p ON p.id = coalesce(i.person_id, a.person_id)
        ORDER BY CASE i.state WHEN 'open' THEN 0 WHEN 'done' THEN 1 ELSE 2 END,
                 CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                 WHEN 'medium' THEN 2 ELSE 3 END,
                 i.reported_on DESC, i.id DESC, p.id
    """)
    incidents: dict[int, Incident] = {}
    for row in rows:
        key = row["id"]
        if key not in incidents:
            details = dict(row)
            del details["affected"]
            incidents[key] = Incident(**details)
        incidents[key].affected_people.append(row["affected"])
    return list(incidents.values())


def load(path: Path | None, records: list[SourceRecord], now: datetime) -> Security:
    if path is None:
        return Security(configured=False)

    view = build(records, now)
    states = {record.name: record.state for record in records}
    with closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        saved: dict[int, dict[str, tuple[str, str | None]]] = {}
        for row in db.execute("SELECT person_id, control, status, checked_on FROM controls"):
            saved.setdefault(row["person_id"], {})[row["control"]] = (
                row["status"],
                row["checked_on"],
            )
        owners: dict[int, dict[DeviceKey, str]] = {}
        for row in db.execute("""
            SELECT person_id, source, source_ref, label FROM device_owners
            ORDER BY label, source, source_ref
        """):
            owners.setdefault(row["person_id"], {})[row["source"], row["source_ref"]] = row["label"]
        accounts = _crypto_accounts(db)
        people = [
            _person(
                row,
                saved.get(row["id"], {}),
                _devices(owners.get(row["id"], {}), view, states),
                accounts.get(row["id"], []),
            )
            for row in db.execute("""
                SELECT id, name, breach_count, latest_breach_name, latest_breach_on,
                       passwords_involved, breach_checked_on FROM people ORDER BY id
            """)
        ]
        incidents = _incidents(db)
    return Security(configured=True, people=people, incidents=incidents)
