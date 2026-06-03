from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from cognigraph.trace.adapters.base import TraceLoadError
from cognigraph.trace.models import TraceLog


class InternalJsonTraceAdapter:
    format_name = "internal-json"

    def load(self, path: Path) -> TraceLog:
        try:
            with open(path) as f:
                raw = json.load(f)
        except OSError as e:
            raise TraceLoadError(f"Could not read trace file: {e}") from e
        except json.JSONDecodeError as e:
            raise TraceLoadError(f"Invalid JSON trace file: {e}") from e

        try:
            return TraceLog.model_validate(raw)
        except ValidationError as e:
            raise TraceLoadError(f"Invalid CogniGraph trace: {e}") from e
