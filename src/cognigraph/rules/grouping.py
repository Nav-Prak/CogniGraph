from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from cognigraph.schemas.findings import Finding, FindingGroup, Suppression


class SuppressionError(Exception):
    pass


# Which entity field(s) identify a group's target, per rule. Findings that
# share a target differ only in the path taken to reach it.
_GROUP_TARGET_KEYS: dict[str, tuple[str, ...]] = {
    "R001": ("capability",),
    "R002": ("resource",),
    "R003": ("capability_a", "capability_b"),
    "R004": ("mcp_server",),
    "R005": ("capability",),
}


def group_target(finding: Finding) -> str:
    keys = _GROUP_TARGET_KEYS.get(finding.rule_id)
    if keys is None:
        return finding.path[-1] if finding.path else finding.rule_id
    return "+".join(finding.entities[key] for key in keys)


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        key = (finding.rule_id, group_target(finding))
        grouped.setdefault(key, []).append(finding)

    groups = [
        FindingGroup(
            rule_id=rule_id,
            title=members[0].title,
            target=target,
            severity=max(f.severity for f in members),
            findings=members,
        )
        for (rule_id, target), members in grouped.items()
    ]
    groups.sort(key=lambda g: (g.rule_id, g.target))
    return groups


class _SuppressionsFile(BaseModel, frozen=True):
    suppressions: list[Suppression] = Field(default_factory=list)


def load_suppressions(path: Path) -> list[Suppression]:
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except OSError as e:
        raise SuppressionError(f"Could not read suppressions file: {e}") from e
    except yaml.YAMLError as e:
        raise SuppressionError(f"Invalid YAML in suppressions file: {e}") from e
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise SuppressionError(
            f"Expected a mapping with a 'suppressions' list in '{path}'"
        )
    try:
        return _SuppressionsFile(**raw).suppressions
    except ValidationError as e:
        raise SuppressionError(f"Invalid suppressions file: {e}") from e


def apply_suppressions(
    groups: list[FindingGroup],
    suppressions: list[Suppression],
    *,
    today: date | None = None,
) -> list[FindingGroup]:
    """Mark matching groups suppressed.

    A suppression that matches nothing, or has expired, is an error: stale
    entries hide drift between the suppression file and the actual findings.
    """
    today = today or date.today()
    by_key = {(g.rule_id, g.target): i for i, g in enumerate(groups)}
    result = list(groups)
    for suppression in suppressions:
        if suppression.expires is not None and suppression.expires < today:
            raise SuppressionError(
                f"Suppression for {suppression.rule_id}/{suppression.target} "
                f"expired on {suppression.expires.isoformat()}; remove it or "
                "re-review the accepted risk"
            )
        index = by_key.get((suppression.rule_id, suppression.target))
        if index is None:
            raise SuppressionError(
                f"Suppression for {suppression.rule_id}/{suppression.target} "
                "matches no finding group; remove the stale entry"
            )
        result[index] = result[index].model_copy(
            update={"suppressed": True, "suppression_reason": suppression.reason}
        )
    return result


def active_groups(groups: list[FindingGroup]) -> list[FindingGroup]:
    return [g for g in groups if not g.suppressed]


def suppressed_groups(groups: list[FindingGroup]) -> list[FindingGroup]:
    return [g for g in groups if g.suppressed]
