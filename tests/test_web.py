from datetime import UTC, datetime

from fastapi.testclient import TestClient

from fixtures import TAILNET_CLIENT
from keep.identity import Gate, Who
from keep.model import Kind, Observation, SourceRecord, SourceState
from keep.web import create_app

TOKEN = "TEST-PROXY-TOKEN"
NOW = datetime(2026, 1, 2, tzinfo=UTC)
HEADERS = {
    "X-Forwarded-For": TAILNET_CLIENT,
    "X-Keep-Proxy-Token": TOKEN,
}


class FakeRunner:
    class thread:
        @staticmethod
        def is_alive():
            return True

    def __init__(self, records):
        self.records = records

    def snapshot(self):
        return self.records, []


def obs(name="<b>host</b>", **over):
    fields = dict(
        source="Action1",
        ref="1",
        observed_at=NOW,
        kind=Kind.COMPUTER,
        name=name,
        online=True,
        updates_critical=0,
        updates_other=0,
        vulns_critical=5,
        vulns_other=0,
        reboot_required=False,
        link="https://action1.example.com",
    )
    fields.update(over)
    return Observation(**fields)


def client(records, token=TOKEN):
    who = Who("operator@example.com", "TEST-NODE-1")
    gate = Gate(token, ["127.0.0.1/32"], {"operator@example.com"}, set(), lambda _: who)
    app = create_app(gate, FakeRunner(records))
    return TestClient(app, client=("127.0.0.1", 5000))


def ok_record(*observations):
    return SourceRecord(
        "Action1", SourceState.OK, last_success=NOW, observations=list(observations)
    )


def test_a_signed_in_operator_sees_escaped_findings():
    response = client([ok_record(obs())]).get("/", headers=HEADERS)
    assert response.status_code == 200
    assert "5 critical vulnerabilities" in response.text
    assert "&lt;b&gt;host&lt;/b&gt;" in response.text and "<b>host</b>" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_a_refused_visitor_gets_no_device_data():
    response = client([ok_record(obs("TEST-DEVICE"))]).get("/", headers={})
    assert response.status_code == 403
    assert "TEST-DEVICE" not in response.text and "vulnerabilities" not in response.text


def test_a_missing_token_names_it_and_still_shows_source_health():
    response = client([ok_record(obs("TEST-DEVICE"))], token="").get("/", headers=HEADERS)
    assert response.status_code == 403
    assert "KEEP_PROXY_TOKEN" in response.text and "1 records" in response.text
    assert "TEST-DEVICE" not in response.text


def test_an_unread_source_is_labeled_and_the_list_claims_nothing():
    record = SourceRecord("UniFi", SourceState.NOT_CONFIGURED, reason="missing KEEP_UNIFI_API_KEY")
    text = client([record]).get("/", headers=HEADERS).text
    assert "not configured" in text and "KEEP_UNIFI_API_KEY" in text
    assert "No source has been read yet" in text
    assert "Healthy" not in text


def test_health_endpoints_need_no_sign_in():
    web = client([])
    assert web.get("/livez").text == "ok" and web.get("/readyz").status_code == 200


def test_there_are_no_write_routes_or_docs():
    web = client([])
    assert web.post("/", headers=HEADERS).status_code == 405
    assert web.get("/docs").status_code == 404 and web.get("/openapi.json").status_code == 404
