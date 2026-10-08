from __future__ import annotations

"""Stage-2 code-side verification gates (Precision). LLM proposals still pass here."""

from dataclasses import dataclass

from wap.mapping.rules import demote_retained
from wap.models.schemas import MappingStatus


@dataclass
class VerifyResult:
    status: MappingStatus
    reason: str
    definition_match: bool
    required_conditions_met: bool
    evidence_directness: str


def verify_candidate(
    *,
    technique_id: str | None,
    proposed_status: MappingStatus,
    reason: str,
    evidence: str,
    supporting: str,
    step_type: str,
    action: str,
    evidence_directness: str = "direct",
    definition_match: bool = True,
    required_conditions_met: bool = True,
    counterevidence: str = "",
) -> VerifyResult:
    """
    Decision order: definition/conditions/evidence → status → (confidence is separate).
    Never promote unmatched/excluded to retained.
    """
    status = proposed_status
    if status == MappingStatus.retained:
        if evidence_directness == "inferred":
            status = MappingStatus.excluded
            reason = (reason + "；" if reason else "") + "[验证] inferred 证据不足以 retained。"
        if not definition_match or not required_conditions_met:
            status = MappingStatus.excluded
            reason = (reason + "；" if reason else "") + "[验证] 定义匹配或必要条件未满足。"
        # Counterevidence with strong negation words → exclude if model still retained
        ce = (counterevidence or "").strip()
        if ce and ce not in ("无", "none", "n/a", "无反证") and status == MappingStatus.retained:
            if any(
                k in ce.lower()
                for k in (
                    "不足以",
                    "不是",
                    "并非",
                    "only single",
                    "own session",
                    "自身",
                    "单次",
                    "正常登录",
                )
            ):
                status = MappingStatus.excluded
                reason = (reason + "；" if reason else "") + f"[验证] 反证成立：{ce[:80]}"

        status, reason = demote_retained(
            technique_id=technique_id,
            status=status,
            reason=reason,
            evidence=evidence,
            supporting=supporting,
            step_type=step_type,
            action=action,
        )

    req_met = status == MappingStatus.retained
    def_match = status == MappingStatus.retained and definition_match
    return VerifyResult(
        status=status,
        reason=reason,
        definition_match=def_match,
        required_conditions_met=req_met,
        evidence_directness=evidence_directness
        if evidence_directness in ("direct", "indirect", "inferred")
        else "direct",
    )
