from __future__ import annotations

from pydantic import BaseModel, Field

from cognigraph.schemas.enums import RuntimeEdgeType


class TraceEvent(BaseModel, frozen=True):
    timestamp: str
    source_id: str
    target_id: str
    edge_type: RuntimeEdgeType
    metadata: dict[str, str] = Field(default_factory=dict)


class TraceLog(BaseModel, frozen=True):
    trace_id: str
    events: list[TraceEvent]
