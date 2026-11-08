from datetime import UTC, datetime

from keep.model import Kind, SourceRecord, SourceState
from test_web import HEADERS, NOW, client, obs, ok_record


def test_devices_come_back_worst_first_in_page_order():
    worst = obs("TEST-WORST", ref="1", serial="TEST-SERIAL-0001", vulns_critical=9)
    milder = obs("TEST-MILDER", ref="2", serial="TEST-SERIAL-0002", vulns_critical=1)
    healthy = obs("TEST-HEALTHY", ref="3", serial="TEST-SERIAL-0003", vulns_critical=0)
    response = client([ok_record(healthy, milder, worst)]).get("/api/v1/devices", headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    devices = response.json()["devices"]
    assert [d["name"] for d in devices] == ["TEST-WORST", "TEST-MILDER", "TEST-HEALTHY"]
    assert [d["status"] for d in devices] == ["attention", "attention", "healthy"]
    assert devices[0]["worst"] == "critical"
    assert devices[0]["readings"][0]["vulns_critical"] == 9
    assert devices[2]["worst"] is None and devices[2]["findings"] == []


def test_unknown_counts_are_null_never_zero():
    unread = obs(
        "TEST-UNKNOWN",
        vulns_critical=None,
        vulns_other=None,
        updates_critical=None,
        updates_other=None,
    )
    devices = client([ok_record(unread)]).get("/api/v1/devices", headers=HEADERS).json()["devices"]
    reading = devices[0]["readings"][0]
    for key in ("vulns_critical", "vulns_other", "updates_critical", "updates_other"):
        assert reading[key] is None
    assert devices[0]["status"] == "unknown"
    assert any("did not report critical vulnerabilities" in gap for gap in devices[0]["unknown"])


def test_a_failed_source_never_makes_its_devices_healthy():
    stale = SourceRecord(
        "Action1",
        SourceState.FAILED,
        reason="timed out",
        last_success=NOW,
        observations=[obs("TEST-STALE", vulns_critical=0)],
    )
    web = client([stale])
    devices = web.get("/api/v1/devices", headers=HEADERS).json()["devices"]
    assert devices[0]["status"] == "unknown"
    assert any("stale: timed out" in gap for gap in devices[0]["unknown"])
    source = web.get("/api/v1/sources", headers=HEADERS).json()["sources"][0]
    assert source["state"] == "failed" and source["reason"] == "timed out"


def test_sources_match_the_page_panel():
    records = [
        ok_record(obs("TEST-DEVICE")),
        SourceRecord("UniFi", SourceState.NOT_CONFIGURED, reason="missing KEEP_UNIFI_API_KEY"),
    ]
    sources = client(records).get("/api/v1/sources", headers=HEADERS).json()["sources"]
    assert sources[0] == {
        "name": "Action1",
        "state": "ok",
        "reason": None,
        "last_attempt": None,
        "last_success": NOW.isoformat(),
        "records": 1,
    }
    assert sources[1]["state"] == "not configured"
    assert sources[1]["reason"] == "missing KEEP_UNIFI_API_KEY"
    assert sources[1]["records"] is None and sources[1]["last_success"] is None


def test_a_client_only_device_is_listed_last():
    seen = obs("TEST-CLIENT", source="Action1", kind=Kind.CLIENT, vulns_critical=None)
    flagged = obs("TEST-FLAGGED", ref="2", serial="TEST-SERIAL-0009")
    devices = client([ok_record(seen, flagged)]).get("/api/v1/devices", headers=HEADERS)
    assert [d["status"] for d in devices.json()["devices"]] == ["attention", "client"]


def test_the_api_refuses_whoever_the_page_refuses():
    web = client([ok_record(obs("TEST-DEVICE"))])
    for path in ("/api/v1/devices", "/api/v1/sources"):
        response = web.get(path, headers={})
        assert response.status_code == 403
        assert "TEST-DEVICE" not in response.text
        assert response.json()["error"] == "not allowed"


def test_the_api_has_no_write_routes():
    web = client([])
    for path in ("/api/v1/devices", "/api/v1/sources"):
        assert web.post(path, headers=HEADERS).status_code == 405


def test_timestamps_are_iso_strings():
    moment = datetime(2026, 1, 1, 12, tzinfo=UTC)
    reading = obs("TEST-DEVICE", last_seen=moment)
    devices = client([ok_record(reading)]).get("/api/v1/devices", headers=HEADERS).json()
    assert devices["devices"][0]["readings"][0]["last_seen"] == moment.isoformat()
