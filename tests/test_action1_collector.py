import pytest

from fixtures import mac
from keep.collectors.action1 import Action1Collector
from keep.model import Kind, SourceError

BASE = "https://action1.example.com/api/3.0"


def endpoint(**over):
    item = {
        "id": "TEST-ENDPOINT-0001",
        "name": "host-1.example",
        "OS": "Test OS 1",
        "status": "Connected",
        "last_seen": "2026-01-02_03-04-05",
        "MAC": mac(1).upper(),
        "serial": "TEST-SERIAL-0001",
        "reboot_required": "No",
        "missing_updates": {"critical": 1, "other": 2},
        "vulnerabilities": {"critical": 3, "other": 4},
    }
    item.update(over)
    return item


class FakeApi:
    def __init__(self, pages=None, total=None, organizations=None, token=None):
        self.pages = pages if pages is not None else [([endpoint()], None)]
        self.total = total
        self.organizations = organizations or {"items": [{"id": "TEST-ORG-0001"}]}
        self.token = token or {"access_token": "TEST-TOKEN"}
        self.seen = []
        self.page = 0

    def __call__(self, url, headers=None, body=None, **_):
        self.seen.append((url, headers))
        if url.endswith("/oauth2/token"):
            assert body
            return self.token
        if url.endswith("/organizations"):
            return self.organizations
        items, next_page = self.pages[self.page]
        self.page += 1
        total = self.total if self.total is not None else sum(len(p[0]) for p in self.pages)
        return {"items": items, "next_page": next_page, "total_items": str(total)}


def collector(api):
    return Action1Collector(BASE, "TEST-ID", "TEST-SECRET", fetch=api)


def test_it_reads_an_endpoint():
    [o] = collector(FakeApi()).collect()
    assert o.kind is Kind.COMPUTER
    assert o.serial == "TEST-SERIAL-0001"
    assert o.macs == (mac(0x01),)
    assert (o.updates_critical, o.updates_other, o.vulns_critical, o.vulns_other) == (1, 2, 3, 4)
    assert o.online is True and o.reboot_required is False
    assert o.last_seen.year == 2026


def test_it_keeps_only_the_fields_it_uses():
    [o] = collector(FakeApi(pages=[([endpoint(user="TEST-USER")], None)])).collect()
    assert "TEST-USER" not in repr(o)


def test_missing_counts_stay_unknown_and_never_become_zero():
    item = endpoint()
    del item["missing_updates"], item["vulnerabilities"]
    [o] = collector(FakeApi(pages=[([item], None)])).collect()
    assert o.updates_critical is None and o.vulns_critical is None and o.vulns_other is None


def test_it_follows_pages():
    second = f"{BASE}/endpoints/managed/TEST-ORG-0001?page=2"
    api = FakeApi(pages=[([endpoint()], second), ([endpoint(id="TEST-ENDPOINT-0002")], None)])
    assert len(collector(api).collect()) == 2


def test_a_short_list_is_a_failure_not_fewer_devices():
    with pytest.raises(SourceError, match="partial response"):
        collector(FakeApi(total=2)).collect()


def test_a_next_page_on_another_host_never_gets_the_token():
    api = FakeApi(pages=[([endpoint()], "https://evil.example.net/x"), ([], None)])
    with pytest.raises(SourceError, match="next_page"):
        collector(api).collect()
    assert not any("evil" in url for url, _ in api.seen)


@pytest.mark.parametrize(
    "item",
    [
        {"name": "no-id"},
        endpoint(missing_updates={"critical": "many"}),
        endpoint(vulnerabilities="none"),
        endpoint(missing_updates={"critical": -1}),
    ],
)
def test_a_bad_endpoint_fails_the_source(item):
    with pytest.raises(SourceError, match="malformed payload"):
        collector(FakeApi(pages=[([item], None)])).collect()


@pytest.mark.parametrize("document", [{}, [], {"items": "x"}, {"items": ["x"]}])
def test_a_bad_organization_list_fails_the_source(document):
    api = FakeApi()
    api.organizations = document
    with pytest.raises(SourceError, match="malformed payload"):
        collector(api).collect()


def test_a_token_response_without_a_token_fails_the_source():
    with pytest.raises(SourceError, match="malformed payload: token"):
        collector(FakeApi(token={"nope": 1})).collect()


def test_a_transport_failure_propagates():
    def down(*_, **__):
        raise SourceError("timed out")

    with pytest.raises(SourceError, match="timed out"):
        collector(down).collect()


def test_missing_config_is_named():
    assert Action1Collector(BASE, None, "").missing() == [
        "KEEP_ACTION1_CLIENT_ID",
        "KEEP_ACTION1_CLIENT_SECRET",
    ]
