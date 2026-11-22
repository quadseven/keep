import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from fixtures import mac
from keep.model import Kind, SourceRecord, SourceState
from test_web import HEADERS, NOW, client, obs, ok_record

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
        "incidents": [],
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
    assert adult["devices"] == []

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


def test_devices_reuse_worst_first_inventory_and_show_current_signals(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        db.executescript("""
            INSERT INTO device_owners (person_id, source, source_ref, label) VALUES
                (1, 'Action1', 'TEST-ENDPOINT-1', 'TEST-LABEL-1'),
                (1, 'UniFi', '00:00:5e:00:53:01', 'TEST-LABEL-1'),
                (1, 'UniFi', '00:00:5e:00:53:02', 'TEST-LABEL-2'),
                (1, 'Action1', 'TEST-ENDPOINT-4', 'TEST-UNREAD'),
                (2, 'Action1', 'TEST-ENDPOINT-3', 'TEST-LABEL-3');
        """)
    worst = obs(
        "TEST-WORST <i>",
        ref="TEST-ENDPOINT-1",
        macs=(mac(1),),
        updates_critical=4,
        updates_other=None,
    )
    other = obs("TEST-OTHER", ref="TEST-ENDPOINT-3", vulns_critical=0)
    network = SourceRecord(
        "UniFi",
        SourceState.OK,
        observations=[
            obs("TEST-JOINED", source="UniFi", kind=Kind.CLIENT, ref=mac(1), macs=(mac(1),)),
            obs(
                "TEST-SWITCH",
                source="UniFi",
                kind=Kind.NETWORK_DEVICE,
                ref=mac(2),
                macs=(mac(2),),
                firmware_pending=True,
                vulns_critical=None,
            ),
        ],
    )
    web = client([network, ok_record(other, worst)], security_db=security_db)
    adult, second = web.get("/api/v1/security", headers=HEADERS).json()["people"]
    assert [item["name"] for item in adult["devices"]] == [
        "TEST-WORST <i>",
        "TEST-SWITCH",
        "TEST-UNREAD",
    ]
    assert [item["name"] for item in second["devices"]] == ["TEST-OTHER"]
    device = adult["devices"][0]
    assert device["av_status"] is None and device["os_support"] is None
    readings = {item["source"]: item for item in device["readings"]}
    assert readings["Action1"]["updates_critical"] == 4
    assert readings["Action1"]["updates_other"] is None
    assert readings["Action1"]["observed_at"] == NOW.isoformat()
    assert adult["devices"][1]["readings"][0]["firmware_pending"] is True
    assert adult["devices"][2]["readings"] == []
    page = web.get("/security", headers=HEADERS).text
    assert (
        page.index("TEST-WORST &lt;i&gt;") < page.index("TEST-SWITCH") < page.index("TEST-UNREAD")
    )
    assert "Critical patches pending: 4" in page
    assert "Other patches pending: Unknown" in page
    assert "Firmware update pending: Yes" in page
    assert "Antivirus: Unknown" in page and "OS support: Unknown" in page
    assert "No device reading available" in page


def test_failed_source_never_reports_old_patch_or_firmware_values_as_current(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        db.executescript("""
            INSERT INTO device_owners (person_id, source, source_ref, label) VALUES
                (1, 'Action1', 'TEST-ENDPOINT', 'TEST-STALE');
        """)
    stale = SourceRecord(
        "Action1",
        SourceState.FAILED,
        reason="timed out",
        last_success=NOW,
        observations=[obs("TEST-STALE", ref="TEST-ENDPOINT", updates_critical=0, updates_other=5)],
    )
    web = client([stale], security_db=security_db)
    reading = web.get("/api/v1/security", headers=HEADERS).json()["people"][0]["devices"][0][
        "readings"
    ][0]
    assert reading["source_state"] == "failed"
    assert reading["updates_critical"] is None and reading["updates_other"] is None
    page = web.get("/security", headers=HEADERS).text
    assert "Critical patches pending: Unknown" in page
    assert "Action1 (failed)" in page


def test_incident_feed_matches_services_and_keeps_dated_states(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        db.executescript("""
            PRAGMA foreign_keys = ON;
            INSERT INTO services (id, name) VALUES
                (1, 'TEST-SERVICE'), (2, 'TEST-UNUSED');
            INSERT INTO service_accounts (person_id, service_id) VALUES (1, 1), (2, 1);
            INSERT INTO incidents (id, kind, service_id, person_id, title, severity, action,
                                   reported_on, state, state_checked_on) VALUES
                (1, 'vendor', 1, NULL, 'TEST-VENDOR', 'high', 'Update <version>',
                 '2026-02-01', 'open', '2026-02-01'),
                (2, 'breach', 1, 1, 'TEST-BREACH', 'critical', 'Review account sign-ins',
                 '2026-02-02', 'done', '2026-02-03'),
                (3, 'vendor', 1, NULL, 'TEST-DISMISSED', 'low', 'Review notice',
                 '2026-02-02', 'dismissed', '2026-02-03'),
                (4, 'vendor', 2, NULL, 'TEST-UNMATCHED', 'critical', 'Review notice',
                 '2026-02-02', 'open', '2026-02-02'),
                (5, 'breach', NULL, 2, 'TEST-OTHER-BREACH', 'low', 'Review notice',
                 '2026-02-01', 'dismissed', '2026-02-02');
        """)
    web = client([], security_db=security_db)
    feed = web.get("/api/v1/security", headers=HEADERS).json()["incidents"]
    assert [item["title"] for item in feed] == [
        "TEST-VENDOR",
        "TEST-BREACH",
        "TEST-DISMISSED",
        "TEST-OTHER-BREACH",
    ]
    assert feed[0] == {
        "id": 1,
        "kind": "vendor",
        "service": "TEST-SERVICE",
        "title": "TEST-VENDOR",
        "severity": "high",
        "action": "Update <version>",
        "reported_on": "2026-02-01",
        "state": "open",
        "state_checked_on": "2026-02-01",
        "affected_people": ["TEST-ADULT <b>", "TEST-SECOND"],
    }
    assert feed[1]["affected_people"] == ["TEST-ADULT <b>"]
    assert feed[1]["state"] == "done" and feed[1]["state_checked_on"] == "2026-02-03"
    assert feed[2]["state"] == "dismissed"
    assert feed[3]["service"] is None and feed[3]["affected_people"] == ["TEST-SECOND"]
    page = web.get("/security", headers=HEADERS).text
    assert "TEST-VENDOR" in page and "Action: Update &lt;version&gt;" in page
    assert "TEST-UNMATCHED" not in page
    assert "Affected: TEST-ADULT &lt;b&gt;, TEST-SECOND" in page
    assert "State: Done (checked 2026-02-03)" in page
    assert "State: Dismissed (checked 2026-02-03)" in page

    with closing(sqlite3.connect(security_db)) as db, db:
        db.execute(
            "UPDATE incidents SET state = 'done', state_checked_on = '2026-02-04' WHERE id=1"
        )
    feed = web.get("/api/v1/security", headers=HEADERS).json()["incidents"]
    vendor = next(item for item in feed if item["id"] == 1)
    assert vendor["state"] == "done" and vendor["state_checked_on"] == "2026-02-04"
