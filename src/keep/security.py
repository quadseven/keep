"""Read operator-verified Security records from the household database."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

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
class Person:
    name: str
    breach: Breach
    controls: list[Control]


@dataclass(frozen=True)
class Security:
    configured: bool
    people: list[Person] = field(default_factory=list)


def _person(row: sqlite3.Row, saved: dict[str, tuple[str, str | None]]) -> Person:
    passwords = row["passwords_involved"]
    return Person(
        name=row["name"],
        breach=Breach(
            row["breach_count"],
            row["latest_breach_on"],
            None if passwords is None else bool(passwords),
            row["breach_checked_on"],
        ),
        controls=[
            Control(key, label, *saved.get(key, ("unknown", None))) for key, label in CONTROLS
        ],
    )


def load(path: Path | None) -> Security:
    if path is None:
        return Security(configured=False)

    with closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        saved: dict[int, dict[str, tuple[str, str | None]]] = {}
        for row in db.execute("SELECT person_id, control, status, checked_on FROM controls"):
            saved.setdefault(row["person_id"], {})[row["control"]] = (
                row["status"],
                row["checked_on"],
            )
        people = [
            _person(row, saved.get(row["id"], {}))
            for row in db.execute("""
                SELECT id, name, breach_count, latest_breach_on, passwords_involved,
                       breach_checked_on FROM people ORDER BY id
            """)
        ]
    return Security(configured=True, people=people)
