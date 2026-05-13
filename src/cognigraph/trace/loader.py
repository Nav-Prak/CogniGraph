from __future__ import annotations

import json
from pathlib import Path

from cognigraph.trace.models import TraceLog


def load_trace(path: Path) -> TraceLog:
    with open(path) as f:
        raw = json.load(f)
    return TraceLog(**raw)
