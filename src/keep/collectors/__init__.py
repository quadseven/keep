"""Collectors read one source and return observations, or raise SourceError."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from keep.model import Observation

Fetch = Callable[..., Any]


class Collector(Protocol):
    name: str

    def missing(self) -> list[str]:
        """The config keys this collector still needs. Empty means ready."""
        ...

    def collect(self) -> list[Observation]:
        """Everything the source holds, or SourceError. Never a partial list."""
        ...
