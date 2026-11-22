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


@pytest.mark.parametrize("path", ["/security", "/api/v1/security"])
def test_security_responses_are_not_cached(security_db, path):
    response = client([], security_db=security_db).get(path, headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


def test_security_api_shows_dated_verified_posture_and_unknowns(security_db):
    web = client([], security_db=security_db)
    response = web.get("/api/v1/security", headers=HEADERS)
    payload = response.json()
    assert payload["configured"] is True
    adult, second = payload["people"]
    assert adult["breach"] == {
        "count": 2,
        "latest_breach_name": None,
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
    assert [(control["status"], control["checked_on"]) for control in adult["controls"][:2]] == [
        ("in place", "2026-01-03"),
        ("unknown", None),
    ]
    assert adult["devices"] == []


def test_security_page_shows_dated_verified_posture_and_unknowns(security_db):
    page = client([], security_db=security_db).get("/security", headers=HEADERS).text
    assert "TEST-ADULT &lt;b&gt;" in page and "TEST-ADULT <b>" not in page
    assert "TEST-SECOND" in page
    assert "Breach count: 2" in page and "Passwords involved: Yes" in page
    assert "Last checked: 2026-01-02" in page
    assert "Equifax credit freeze: In place (checked 2026-01-03)" in page
    assert "Experian credit freeze: Unknown (check date unknown)" in page
    assert "Breach count: Unknown" in page


def test_breach_summary_names_the_latest_notice_and_preserves_confirmed_zero(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        db.executescript("""
            UPDATE people SET latest_breach_name = 'TEST-BREACH <b>' WHERE id = 1;
            UPDATE people SET breach_count = 0, passwords_involved = 0,
                breach_checked_on = '2026-01-04' WHERE id = 2;
        """)
    web = client([], security_db=security_db)
    adult, second = web.get("/api/v1/security", headers=HEADERS).json()["people"]
    assert adult["breach"]["latest_breach_name"] == "TEST-BREACH <b>"
    assert second["breach"]["count"] == 0 and second["breach"]["passwords_involved"] is False
    page = web.get("/security", headers=HEADERS).text
    assert "Most recent breach: TEST-BREACH &lt;b&gt; (2026-01-01)" in page
    assert "Most recent breach: None reported" in page
    assert "Passwords involved: No" in page


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


@pytest.fixture
def security_with_devices(security_db):
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
    return client([network, ok_record(other, worst)], security_db=security_db)


def test_security_api_groups_devices_by_owner_in_worst_first_order(security_with_devices):
    adult, second = security_with_devices.get("/api/v1/security", headers=HEADERS).json()["people"]
    assert [item["name"] for item in adult["devices"]] == [
        "TEST-WORST <i>",
        "TEST-SWITCH",
        "TEST-UNREAD",
    ]
    assert [item["name"] for item in second["devices"]] == ["TEST-OTHER"]


def test_security_api_shows_current_device_readings(security_with_devices):
    adult, _ = security_with_devices.get("/api/v1/security", headers=HEADERS).json()["people"]
    device = adult["devices"][0]
    assert device["av_status"] is None and device["os_support"] is None
    readings = {item["source"]: item for item in device["readings"]}
    assert readings["Action1"]["updates_critical"] == 4
    assert readings["Action1"]["updates_other"] is None
    assert readings["Action1"]["observed_at"] == NOW.isoformat()
    assert adult["devices"][1]["readings"][0]["firmware_pending"] is True
    assert adult["devices"][2]["readings"] == []


def test_security_page_shows_device_readings_in_worst_first_order(security_with_devices):
    page = security_with_devices.get("/security", headers=HEADERS).text
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


@pytest.fixture
def security_with_incidents(security_db):
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
    return security_db


def test_incident_feed_matches_services_and_keeps_dated_states(security_with_incidents):
    web = client([], security_db=security_with_incidents)
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


def test_security_page_shows_matching_incidents_and_dated_states(security_with_incidents):
    web = client([], security_db=security_with_incidents)
    page = web.get("/security", headers=HEADERS).text
    assert "TEST-VENDOR" in page and "Action: Update &lt;version&gt;" in page
    assert "TEST-UNMATCHED" not in page
    assert "Affected: TEST-ADULT &lt;b&gt;, TEST-SECOND" in page
    assert "State: Done (checked 2026-02-03)" in page
    assert "State: Dismissed (checked 2026-02-03)" in page


def test_incident_feed_reads_updated_state_from_database(security_with_incidents):
    web = client([], security_db=security_with_incidents)
    feed = web.get("/api/v1/security", headers=HEADERS).json()["incidents"]
    assert feed[0]["state"] == "open"
    with closing(sqlite3.connect(security_with_incidents)) as db, db:
        db.execute(
            "UPDATE incidents SET state = 'done', state_checked_on = '2026-02-04' WHERE id=1"
        )
    feed = web.get("/api/v1/security", headers=HEADERS).json()["incidents"]
    vendor = next(item for item in feed if item["id"] == 1)
    assert vendor["state"] == "done" and vendor["state_checked_on"] == "2026-02-04"


@pytest.fixture
def security_with_custodial_accounts(security_db):
    with closing(sqlite3.connect(security_db)) as db:
        db.executescript("""
            PRAGMA foreign_keys = ON;
            INSERT INTO services (id, name) VALUES
                (1, 'TEST-CUSTODY <b>'), (2, 'TEST-OTHER-CUSTODY'), (3, 'TEST-REGULAR');
            INSERT INTO service_accounts (person_id, service_id) VALUES
                (1, 1), (1, 3), (2, 2);
            INSERT INTO crypto_accounts (person_id, service_id, mfa_status, mfa_checked_on,
                                         withdrawal_status, withdrawal_checked_on) VALUES
                (1, 1, 'in place', '2026-01-04', 'not offered', '2026-01-05');
            INSERT INTO crypto_accounts (person_id, service_id) VALUES (2, 2);
        """)
    return security_db


def test_claimed_withdrawal_controls_require_a_check_date(security_with_custodial_accounts):
    with closing(sqlite3.connect(security_with_custodial_accounts)) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "UPDATE crypto_accounts SET withdrawal_status = 'in place' WHERE person_id=2"
            )


def test_custodial_account_controls_show_verified_and_unknown_states(
    security_with_custodial_accounts,
):
    web = client([], security_db=security_with_custodial_accounts)
    adult, second = web.get("/api/v1/security", headers=HEADERS).json()["people"]
    assert [account["service"] for account in adult["crypto_accounts"]] == ["TEST-CUSTODY <b>"]
    assert adult["crypto_accounts"][0]["controls"] == [
        {"key": "mfa", "label": "Passkey or 2FA", "status": "in place", "checked_on": "2026-01-04"},
        {
            "key": "withdrawal",
            "label": "Withdrawal controls",
            "status": "not offered",
            "checked_on": "2026-01-05",
        },
    ]
    assert [account["service"] for account in second["crypto_accounts"]] == ["TEST-OTHER-CUSTODY"]
    controls = second["crypto_accounts"][0]["controls"]
    assert [(control["status"], control["checked_on"]) for control in controls] == [
        ("unknown", None),
        ("unknown", None),
    ]


def test_security_page_shows_custodial_control_states(security_with_custodial_accounts):
    web = client([], security_db=security_with_custodial_accounts)
    page = web.get("/security", headers=HEADERS).text
    assert "TEST-CUSTODY &lt;b&gt;" in page and "TEST-REGULAR" not in page
    assert "Passkey or 2FA: In place (checked 2026-01-04)" in page
    assert "Withdrawal controls: Not offered (checked 2026-01-05)" in page
    assert "Withdrawal controls: Unknown (check date unknown)" in page


def test_security_routes_keep_household_data_behind_sign_in(security_db):
    web = client([], security_db=security_db)
    for route in ("/security", "/api/v1/security"):
        response = web.get(route)
        assert response.status_code == 403
        assert "TEST-ADULT" not in response.text
