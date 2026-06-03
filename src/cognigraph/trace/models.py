from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cognigraph.schemas.enums import NodeType, RuntimeEdgeType

TRACE_SCHEMA = "cognigraph.trace.v1"


class TraceSource(BaseModel, frozen=True):
    type: str
    name: str | None = None
    version: str | None = None


class TraceNodeRef(BaseModel, frozen=True):
    id: str
    type: NodeType | None = None
    name: str | None = None


class TraceEvent(BaseModel, frozen=True):
    id: str | None = None
    timestamp: str
    source_id: str
    target_id: str
    source_ref: TraceNodeRef | None = None
    target_ref: TraceNodeRef | None = None
    edge_type: RuntimeEdgeType
    status: str | None = None
    duration_ms: float | None = None
    origin: dict[str, str] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _derive_ids_from_refs(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        values = dict(data)
        for side in ("source", "target"):
            id_key = f"{side}_id"
            ref_key = f"{side}_ref"
            ref = values.get(ref_key)
            if values.get(id_key) or not isinstance(ref, dict):
                continue
            ref_id = ref.get("id")
            if ref_id:
                values[id_key] = ref_id
        return values


class TraceLog(BaseModel, frozen=True):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: Literal["cognigraph.trace.v1"] = Field(
        default=TRACE_SCHEMA,
        alias="schema",
    )
    trace_id: str
    session_id: str | None = None
    source: TraceSource | None = None
    events: list[TraceEvent]
