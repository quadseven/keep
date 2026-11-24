"""Runs the collectors and holds the latest reading of each source.

The reading lives in memory. A failed read keeps the last good observations,
which inventory marks stale, and records the failure.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from datetime import UTC, datetime

from keep.collectors import Collector
from keep.model import SourceError, SourceFailure, SourceRecord, SourceState

log = logging.getLogger("keep.runner")
FAILURES_KEPT = 200


class Runner:
    def __init__(self, collectors: Sequence[Collector], interval_seconds: float):
        self.collectors = list(collectors)
        self.interval = interval_seconds
        self.lock = threading.Lock()
        self.records = {c.name: SourceRecord(name=c.name) for c in self.collectors}
        self.failures: deque[SourceFailure] = deque(maxlen=FAILURES_KEPT)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="keep-runner", daemon=True)

    def snapshot(self) -> tuple[list[SourceRecord], list[SourceFailure]]:
        with self.lock:
            return [copy(record) for record in self.records.values()], list(self.failures)

    def _fail(self, collector: Collector, now: datetime, reason: str) -> None:
        log.warning("source_failed source=%s reason=%s", collector.name, reason)
        with self.lock:
            record = self.records[collector.name]
            record.state = SourceState.FAILED
            record.reason = reason
            record.last_attempt = now
            self.failures.append(SourceFailure(collector.name, now, reason))

    def _collect_one(self, collector: Collector) -> None:
        now = datetime.now(UTC)
        missing = collector.missing()
        if missing:
            with self.lock:
                record = self.records[collector.name]
                record.state = SourceState.NOT_CONFIGURED
                record.reason = "missing " + ", ".join(missing)
                record.last_attempt = now
            return
        try:
            observations = collector.collect()
        except SourceError as error:
            self._fail(collector, now, error.reason)
            return
        except Exception as error:  # noqa: BLE001 - one source must not stop the others
            log.exception("source_crashed source=%s", collector.name)
            self._fail(collector, now, f"collector error: {type(error).__name__}")
            return
        with self.lock:
            record = self.records[collector.name]
            record.state = SourceState.OK
            record.reason = None
            record.last_attempt = now
            record.last_success = now
            record.observations = observations
        log.info("source_ok source=%s observations=%d", collector.name, len(observations))

    def collect_once(self) -> None:
        if len(self.collectors) <= 1:
            for collector in self.collectors:
                self._collect_one(collector)
            return
        with ThreadPoolExecutor(
            max_workers=len(self.collectors), thread_name_prefix="keep-collect"
        ) as pool:
            futures = [pool.submit(self._collect_one, collector) for collector in self.collectors]
            for future in futures:
                future.result()

    def _loop(self) -> None:
        while not self.stop.is_set():
            self.collect_once()
            self.stop.wait(self.interval)

    def start(self) -> None:
        self.thread.start()
