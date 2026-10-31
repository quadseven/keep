import pytest

from fixtures import mac
from keep.collectors.unifi import UnifiCollector
from keep.model import Kind, SourceError

BASE = "https://198.51.100.1"


def device(**over):
    item = {
        "mac": mac(0x10),
        "name": "switch-1",
        "model": "TEST",
        "version": "1.2.3",
        "serial": "TEST-SERIAL-0010",
        "state": 1,
        "upgradable": False,
        "last_seen": 1700000000,
    }
    item.update(over)
    return item


def client(**over):
    item = {"mac": mac(0x20), "hostname": "client-1.example", "is_wired": True}
    item.update(over)
    return item


def api(devices=None, clients=None, rc="ok"):
    calls = []

    def fetch(url, headers=None, trust_pem=None):
        calls.append((url, headers, trust_pem))
        rows = devices if url.endswith("stat/device") else clients
        return {"meta": {"rc": rc}, "data": rows if rows is not None else []}

    fetch.calls = calls
    return fetch


def collector(fetch):
    return UnifiCollector(BASE, "TEST-KEY", "TEST-PEM", fetch=fetch)


def test_it_reads_devices_and_clients_through_the_trusted_cert():
    fetch = api([device()], [client()])
    d, c = collector(fetch).collect()
    assert d.kind is Kind.NETWORK_DEVICE and d.online is True and d.firmware_pending is False
    assert c.kind is Kind.CLIENT and c.name == "client-1.example" and c.detail == "wired"
    assert all(pem == "TEST-PEM" for _, _, pem in fetch.calls)


def test_a_disconnected_device_is_offline():
    [d] = collector(api([device(state=0)])).collect()
    assert d.online is False


def test_an_unrecognized_state_stays_unknown():
    [d] = collector(api([device(state=5)])).collect()
    assert d.online is None


def test_a_missing_upgrade_flag_stays_unknown():
    item = device()
    del item["upgradable"]
    [d] = collector(api([item])).collect()
    assert d.firmware_pending is None


def test_a_console_error_fails_the_source():
    with pytest.raises(SourceError, match="source reported an error"):
        collector(api(rc="error")).collect()


@pytest.mark.parametrize(
    "document",
    [None, [], {"meta": {"rc": "ok"}}, {"meta": {"rc": "ok"}, "data": ["x"]}, {"data": []}],
)
def test_a_bad_payload_fails_the_source(document):
    with pytest.raises(SourceError):
        collector(lambda *_, **__: document).collect()


def test_a_device_without_a_mac_fails_the_source():
    with pytest.raises(SourceError, match="device mac"):
        collector(api([device(mac="")])).collect()


def test_a_transport_failure_propagates():
    def down(*_, **__):
        raise SourceError("connection failed")

    with pytest.raises(SourceError, match="connection failed"):
        collector(down).collect()


def test_missing_config_is_named():
    assert UnifiCollector(None, None).missing() == ["KEEP_UNIFI_BASE_URL", "KEEP_UNIFI_API_KEY"]
