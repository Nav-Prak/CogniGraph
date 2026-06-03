from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Protocol

from cognigraph.trace.models import TraceLog


class TraceLoadError(ValueError):
    pass


class TraceAdapter(Protocol):
    format_name: ClassVar[str]

    def load(self, path: Path) -> TraceLog:
        ...
