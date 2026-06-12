from datetime import date
from enum import IntEnum

from pydantic import BaseModel


class FindingSeverity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class Finding(BaseModel, frozen=True):
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    path: list[str]
    entities: dict[str, str]
    recommended_control: str
    mitigated_by: str | None = None


class FindingGroup(BaseModel, frozen=True):
    rule_id: str
    title: str
    target: str
    severity: FindingSeverity
    findings: list[Finding]
    suppressed: bool = False
    suppression_reason: str | None = None
    mitigated_by: str | None = None


class Suppression(BaseModel, frozen=True):
    rule_id: str
    target: str
    reason: str
    expires: date | None = None
