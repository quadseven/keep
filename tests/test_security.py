import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from test_web import HEADERS, client

SCHEMA = Path(__file__).resolve().parents[1] / "src/keep/security.sql"


@pytest.fixture
def security_db(tmp_path):
    path = tmp_path / "security.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        db.executescript(SCHEMA.read_text(encoding="ascii"))
        db.executescript("""
            INSERT INTO people (id, name) VALUES (1, 'TEST-ADULT <b>'), (2, 'TEST-SECOND');
            UPDATE people SET breach_count = 2, latest_breach_on = '2026-01-01',
                passwords_involved = 1, breach_checked_on = '2026-01-02' WHERE id = 1;
            INSERT INTO controls (person_id, control, status, checked_on)
                VALUES (1, 'equifax_freeze', 'in place', '2026-01-03');
        """)
    return path


def test_security_is_linked_and_read_only():
    web = client([])
    assert 'href="/security"' in web.get("/", headers=HEADERS).text
    assert "Security database is not configured" in web.get("/security", headers=HEADERS).text
    assert web.get("/api/v1/security", headers=HEADERS).json() == {
        "configured": False,
        "people": [],
    }
    for path in ("/security", "/api/v1/security"):
        assert web.post(path, headers=HEADERS).status_code == 405


def test_security_shows_dated_verified_posture_and_unknowns(security_db):
    web = client([], security_db=security_db)
    response = web.get("/api/v1/security", headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload["configured"] is True
    adult, second = payload["people"]
    assert adult["breach"] == {
        "count": 2,
        "latest_breach_on": "2026-01-01",
        "passwords_involved": True,
        "checked_on": "2026-01-02",
    }
    assert second["breach"] == dict.fromkeys(adult["breach"])
    assert [control["label"] for control in adult["controls"]] == [
        "Equifax credit freeze",
        "Experian credit freeze",
        "TransUnion credit freeze",
        "IRS Identity Protection PIN",
        "SSA account lock",
        "E-Verify Self Lock",
        "Primary email passkey or 2FA",
        "Password manager Watchtower review",
    ]
    assert adult["controls"][0]["status"] == "in place"
    assert adult["controls"][0]["checked_on"] == "2026-01-03"
    assert adult["controls"][1]["status"] == "unknown"
    assert adult["controls"][1]["checked_on"] is None

    page = web.get("/security", headers=HEADERS)
    assert page.status_code == 200 and page.headers["cache-control"] == "no-store"
    assert "TEST-ADULT &lt;b&gt;" in page.text and "TEST-ADULT <b>" not in page.text
    assert "TEST-SECOND" in page.text
    assert "Breach count: 2" in page.text and "Passwords involved: Yes" in page.text
    assert "Last checked: 2026-01-02" in page.text
    assert "Equifax credit freeze: In place (checked 2026-01-03)" in page.text
    assert "Experian credit freeze: Unknown (check date unknown)" in page.text
    assert "Breach count: Unknown" in page.text


def test_security_refuses_unauthenticated_requests_before_reading_database(tmp_path):
    path = tmp_path / "missing.sqlite3"
    web = client([], security_db=path)
    for route in ("/security", "/api/v1/security"):
        assert web.get(route).status_code == 403
        response = web.get(route, headers=HEADERS)
        assert response.status_code == 503
        assert "Security database unavailable" in response.text
        assert path.name not in response.text
    assert not path.exists()


def test_a_claimed_control_or_breach_status_requires_a_valid_date(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE people SET breach_count = 0 WHERE id = 2")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE controls SET checked_on = '2026-02-30'")
