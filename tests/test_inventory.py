from datetime import UTC, datetime, timedelta

from fixtures import mac
from keep.inventory import Severity, build
from keep.model import Kind, Observation, SourceRecord, SourceState

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def computer(name="host-1", **over):
    fields = dict(
        source="Action1",
        ref=name,
        observed_at=NOW,
        kind=Kind.COMPUTER,
        name=name,
        online=True,
        updates_critical=0,
        updates_other=0,
        vulns_critical=0,
        vulns_other=0,
        reboot_required=False,
    )
    fields.update(over)
    return Observation(**fields)


def network(name="switch-1", **over):
    fields = dict(
        source="UniFi",
        ref=name,
        observed_at=NOW,
        kind=Kind.NETWORK_DEVICE,
        name=name,
        online=True,
        firmware_pending=False,
    )
    fields.update(over)
    return Observation(**fields)


def client(address, name="client-1"):
    return Observation(
        source="UniFi",
        ref=mac,
        observed_at=NOW,
        kind=Kind.CLIENT,
        name=name,
        macs=(address,),
        online=True,
    )


def record(name, *observations, state=SourceState.OK, reason=None):
    return SourceRecord(name=name, state=state, reason=reason, observations=list(observations))


def test_a_fully_read_clean_device_is_healthy():
    view = build([record("Action1", computer()), record("UniFi", network())], NOW)
    assert [d.name for d in view.healthy] == ["host-1", "switch-1"]
    assert not view.attention and not view.unknown


def test_unknown_counts_are_never_healthy():
    view = build([record("Action1", computer(updates_critical=None, vulns_other=None))], NOW)
    assert not view.healthy
    assert len(view.unknown) == 1
    assert "did not report critical updates" in view.unknown[0].gaps[0]


def test_a_failed_source_makes_its_clean_devices_unknown():
    failed = record("Action1", computer(), state=SourceState.FAILED, reason="timed out")
    view = build([failed], NOW)
    assert not view.healthy
    assert "stale: timed out" in view.unknown[0].gaps[0]


def test_a_finding_from_a_stale_reading_stays_visible():
    failed = record("Action1", computer(vulns_critical=2), state=SourceState.FAILED, reason="x")
    view = build([failed], NOW)
    assert view.attention[0].gaps


def test_worst_comes_first():
    view = build(
        [
            record(
                "Action1",
                computer("a-low", reboot_required=True),
                computer("b-offline", online=False, last_seen=NOW - timedelta(days=9)),
                computer("c-few", vulns_critical=1),
                computer("d-many", vulns_critical=40),
            )
        ],
        NOW,
    )
    assert [d.name for d in view.attention] == ["d-many", "c-few", "b-offline", "a-low"]
    assert view.attention[0].worst is Severity.CRITICAL
    assert "9 days ago" in view.attention[2].findings[0].summary


def test_a_pending_firmware_update_is_a_finding():
    view = build([record("UniFi", network(firmware_pending=True, firmware_target="9.9.9"))], NOW)
    assert "9.9.9" in view.attention[0].findings[0].summary


def test_records_join_by_mac_and_the_hostname_is_ignored():
    shared = mac(0x01)
    view = build(
        [
            record("Action1", computer("host-1", macs=(shared,))),
            record("UniFi", client(shared, "other-name")),
        ],
        NOW,
    )
    assert len(view.healthy) == 1
    assert view.healthy[0].sources == ["Action1", "UniFi"]
    assert view.healthy[0].name == "host-1"
    assert not view.clients


def test_the_same_hostname_does_not_join():
    view = build([record("Action1", computer("same")), record("UniFi", network("same"))], NOW)
    assert len(view.healthy) == 2


def test_a_serial_outranks_a_shared_mac():
    shared = mac(0x01)
    view = build(
        [
            record(
                "Action1",
                computer("a", serial="TEST-SERIAL-0001", macs=(shared,)),
                computer("b", serial="TEST-SERIAL-0002", macs=(shared,)),
            )
        ],
        NOW,
    )
    assert len(view.healthy) == 2


def test_a_serial_joins_across_different_macs():
    view = build(
        [
            record("Action1", computer("a", serial="TEST-SERIAL-0001", macs=(mac(0x01),))),
            record("UniFi", network("b", serial="TEST-SERIAL-0001", macs=(mac(0x02),))),
        ],
        NOW,
    )
    assert len(view.healthy) == 1


def test_an_unjoined_client_is_never_called_healthy():
    view = build([record("UniFi", client(mac(0x30)))], NOW)
    assert len(view.clients) == 1 and not view.healthy


def test_no_data_gives_an_empty_view():
    view = build([record("Action1", state=SourceState.NOT_CONFIGURED)], NOW)
    assert not (view.attention or view.unknown or view.healthy or view.clients)
