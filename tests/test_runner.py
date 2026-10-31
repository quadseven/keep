from keep.model import SourceError, SourceState
from keep.runner import Runner


class Fake:
    name = "Fake"

    def __init__(self, results, missing=()):
        self.results = list(results)
        self.needed = list(missing)

    def missing(self):
        return self.needed

    def collect(self):
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_an_unconfigured_source_is_named_and_not_called():
    runner = Runner([Fake([], missing=["KEEP_X"])], 60)
    runner.collect_once()
    [record], failures = runner.snapshot()
    assert record.state is SourceState.NOT_CONFIGURED and "KEEP_X" in record.reason
    assert not failures


def test_a_failure_is_recorded_with_its_reason():
    runner = Runner([Fake([SourceError("timed out")])], 60)
    runner.collect_once()
    [record], failures = runner.snapshot()
    assert record.state is SourceState.FAILED and record.reason == "timed out"
    assert failures[0].source == "Fake" and failures[0].reason == "timed out"


def test_a_crash_is_a_failure_and_never_leaks_its_message():
    runner = Runner([Fake([ValueError("TEST-SECRET in message")])], 60)
    runner.collect_once()
    [record], _ = runner.snapshot()
    assert record.state is SourceState.FAILED and record.reason == "collector error: ValueError"


def test_a_failure_keeps_the_last_good_reading():
    runner = Runner([Fake([["reading"], SourceError("timed out")])], 60)
    runner.collect_once()
    runner.collect_once()
    [record], _ = runner.snapshot()
    assert record.state is SourceState.FAILED and record.observations == ["reading"]
    assert record.last_success is not None


def test_a_later_success_does_not_erase_a_failure():
    runner = Runner([Fake([SourceError("timed out"), ["reading"]])], 60)
    runner.collect_once()
    runner.collect_once()
    [record], failures = runner.snapshot()
    assert record.state is SourceState.OK and record.reason is None
    assert len(failures) == 1


def test_one_bad_source_does_not_stop_the_next():
    good = Fake([["reading"]])
    good.name = "Good"
    runner = Runner([Fake([RuntimeError("boom")]), good], 60)
    runner.collect_once()
    records, _ = runner.snapshot()
    assert records[1].state is SourceState.OK
