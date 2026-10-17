"""Shared helpers for ATT&CK direct_llm mapping."""

from __future__ import annotations

from typing import Any, Optional

from wap.mapping.attck_meta import NON_COVERAGE_STEP_TYPES
from wap.models.schemas import MappingStatus, TechniqueMapping, TechniqueRef


def coerce_unit_interval(value: Any) -> float | None:
    """Parse a 0..1 float; None if missing/invalid. Preserves 0.0 (unlike `or`)."""
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        x = float(value)
    except (TypeError, ValueError):
        return None
    if x != x:  # NaN
        return None
    return max(0.0, min(1.0, x))


def format_technique_catalog_block(
    technique_ids: list[str], catalog: dict[str, TechniqueRef]
) -> str:
    """Format a catalog slice for the direct_llm prompt."""
    lines = []
    for tid in technique_ids:
        t = catalog.get(tid)
        if not t:
            lines.append(f"- {tid} | (unknown) |")
            continue
        name = t.technique_name_zh or t.technique_name or ""
        en = t.technique_name or ""
        desc = (t.description or "").strip().replace("\n", " ")
        if len(desc) > 280:
            desc = desc[:277] + "..."
        tactic = t.tactic_en or (t.tactic or "").split()[0] if t.tactic else ""
        lines.append(f"- {tid} | {en} | {name} | tactic={tactic} | def={desc}")
    return "\n".join(lines)


def chain_skip_reason(meta: Any) -> Optional[dict[str, str]]:
    """If writeup should skip mapping due to unresolved chain, return summary fields."""
    if meta is None:
        return None
    keys = meta.keys()
    chain_source = (
        (meta["attack_chain_source"] if "attack_chain_source" in keys else "") or ""
    )
    coverage_status = (
        (meta["coverage_status"] if "coverage_status" in keys else "") or ""
    )
    if chain_source == "unresolved" or coverage_status == "insufficient_evidence":
        return {
            "attack_chain_source": chain_source or "unresolved",
            "coverage_status": "insufficient_evidence",
        }
    return None


def select_steps_for_map(all_steps: list) -> tuple[list, list, list, Optional[str]]:
    """
    Return (steps_to_map, selected, pending, error).

    error is set when chain must be run first (no selected, only pending).
    Prefer selected attack-chain steps; else fall back to all steps (legacy).
    """
    selected = [
        s
        for s in all_steps
        if (s["chain_status"] if "chain_status" in s.keys() else "pending") == "selected"
    ]
    pending = [
        s
        for s in all_steps
        if (s["chain_status"] if "chain_status" in s.keys() else "pending") == "pending"
    ]
    if not selected and pending:
        return [], selected, pending, "run `chain` before `map` (no selected attack-chain steps)"
    steps = selected if selected else all_steps
    return steps, selected, pending, None


def is_non_coverage_step(step_dict: dict[str, Any]) -> bool:
    step_type = step_dict.get("step_type") or "other"
    return step_type in NON_COVERAGE_STEP_TYPES


def non_coverage_mapping(
    *,
    writeup_id: str,
    step_dict: dict[str, Any],
    mapping_method: str,
) -> TechniqueMapping:
    import json
    import uuid

    step_type = step_dict.get("step_type") or "other"
    return TechniqueMapping(
        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
        step_id=step_dict["step_id"],
        writeup_id=writeup_id,
        mapping_status=MappingStatus.unmatched,
        mapping_type="non_attack_step",
        mapping_reason=(
            f"行为类别={step_type}：准备/观察/数据处理步骤默认不计入 ATT&CK 覆盖"
            "（分类字段，不是用 step_type 映射技术）。"
        ),
        evidence=step_dict.get("evidence") or "",
        evidence_location=step_dict.get("evidence_location") or "",
        mapping_role="sole",
        behavior_observed=str(step_dict.get("action") or ""),
        evidence_directness="direct",
        candidates_json="[]",
        ensemble_json=json.dumps(
            {"skip": "non_coverage_step_type", "step_type": step_type},
            ensure_ascii=False,
        ),
        mapping_method=mapping_method,
    )


def normalize_roles(step_maps: list[TechniqueMapping]) -> None:
    primaries = [x for x in step_maps if x.mapping_role == "primary"]
    if len(primaries) > 1:
        for extra in primaries[1:]:
            extra.mapping_role = "secondary"
    if len(step_maps) == 1:
        step_maps[0].mapping_role = "sole"
    elif step_maps and not any(x.mapping_role == "primary" for x in step_maps):
        retained = next(
            (x for x in step_maps if x.mapping_status == MappingStatus.retained),
            step_maps[0],
        )
        retained.mapping_role = "primary"
        for x in step_maps:
            if x is not retained and x.mapping_role == "sole":
                x.mapping_role = "secondary"


def mapping_stats(mappings: list[TechniqueMapping]) -> dict[str, int]:
    return {
        "mappings": len(mappings),
        "retained": sum(
            1 for m in mappings if m.mapping_status == MappingStatus.retained
        ),
        "excluded": sum(
            1 for m in mappings if m.mapping_status == MappingStatus.excluded
        ),
        "unmatched": sum(
            1 for m in mappings if m.mapping_status == MappingStatus.unmatched
        ),
        "pending_review": sum(
            1 for m in mappings if m.mapping_status == MappingStatus.pending_review
        ),
    }
