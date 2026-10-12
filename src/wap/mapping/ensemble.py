"""Multi-model ATT&CK mapping: candidates → model A/B → model C on conflict.

Code owns orchestration, structural validation, and persistence payloads.
Models own semantic support/reject/insufficient judgments.
Technique-specific regex gates are intentionally NOT applied here.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from wap.models.schemas import MappingStatus, TechniqueMapping, TechniqueRef
from wap.utils.llm import LLMClient

STANCES = frozenset({"support", "reject", "insufficient"})


class JsonChatClient(Protocol):
    model: str
    role: Optional[str]

    @property
    def available(self) -> bool: ...

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict[str, Any]: ...


@dataclass
class ModelJudgment:
    stance: str  # support|reject|insufficient
    evidence_quote: str = ""
    reason: str = ""
    uncertainty: float = 0.0
    raw_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stance": self.stance,
            "evidence_quote": self.evidence_quote,
            "reason": self.reason,
            "uncertainty": self.uncertainty,
            "raw_error": self.raw_error,
        }


@dataclass
class TechniqueVoteResult:
    technique_id: str
    final_status: MappingStatus
    vote: str
    reason: str
    evidence: str
    supporting_behavior: str
    judgments: dict[str, ModelJudgment] = field(default_factory=dict)
    used_model_c: bool = False


def normalize_stance(value: Any) -> str:
    s = str(value or "").strip().lower()
    aliases = {
        "supported": "support",
        "supports": "support",
        "yes": "support",
        "retain": "support",
        "retained": "support",
        "rejected": "reject",
        "no": "reject",
        "exclude": "reject",
        "excluded": "reject",
        "unknown": "insufficient",
        "unsure": "insufficient",
        "abstain": "insufficient",
        "evidence_insufficient": "insufficient",
    }
    s = aliases.get(s, s)
    return s if s in STANCES else "insufficient"


def _coerce_unit_interval(value: Any) -> float | None:
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


def parse_model_uncertainty(item: dict[str, Any]) -> float:
    """
    Uncertainty in [0,1]: 0 = sure, 1 = unsure.

    Prefer explicit `uncertainty`. If only legacy `confidence` is present, treat it as
    certainty (higher = more sure) and convert: uncertainty = 1 - confidence.
    Never use `x or y` so that uncertainty=0.0 is kept.
    """
    if "uncertainty" in item:
        u = _coerce_unit_interval(item.get("uncertainty"))
        if u is not None:
            return u
    if "confidence" in item:
        c = _coerce_unit_interval(item.get("confidence"))
        if c is not None:
            return round(1.0 - c, 6)
    return 0.0


def decide_vote(
    stance_a: str,
    stance_b: str,
    stance_c: Optional[str] = None,
) -> tuple[MappingStatus, str, bool]:
    """
    Returns (final_status, vote_label, needs_or_used_c).

    If stance_c is None and C is required, returns pending_review with needs_c=True
    so the caller can invoke model C.
    """
    a, b = normalize_stance(stance_a), normalize_stance(stance_b)
    if a == "support" and b == "support":
        return MappingStatus.retained, "agree_support", False
    if a == "reject" and b == "reject":
        return MappingStatus.excluded, "agree_reject", False

    # Conflict or any insufficient → model C
    if stance_c is None:
        return MappingStatus.pending_review, "needs_model_c", True

    c = normalize_stance(stance_c)
    if c == "support":
        return MappingStatus.retained, "c_support", True
    if c == "reject":
        return MappingStatus.excluded, "c_reject", True
    return MappingStatus.pending_review, "c_insufficient", True


def parse_judgments_payload(
    data: dict[str, Any] | None,
    candidate_ids: list[str],
    *,
    error: str = "",
) -> dict[str, ModelJudgment]:
    """Map technique_id → judgment; illegal ids dropped; missing → insufficient."""
    out: dict[str, ModelJudgment] = {}
    allowed = set(candidate_ids)
    raw_list = []
    if isinstance(data, dict):
        raw_list = data.get("judgments") or data.get("verifications") or []
    if not isinstance(raw_list, list):
        raw_list = []

    for item in raw_list:
        if not isinstance(item, dict):
            continue
        tid = item.get("technique_id")
        if not isinstance(tid, str):
            continue
        tid = tid.strip()
        if tid not in allowed:
            continue
        out[tid] = ModelJudgment(
            stance=normalize_stance(item.get("stance") or item.get("mapping_status")),
            evidence_quote=str(item.get("evidence_quote") or item.get("mapping_evidence") or "")[
                :500
            ],
            reason=str(item.get("reason") or item.get("mapping_reason") or "")[:500],
            uncertainty=parse_model_uncertainty(item),
        )

    for tid in candidate_ids:
        if tid not in out:
            out[tid] = ModelJudgment(
                stance="insufficient",
                reason=error or "模型未返回该候选的判断",
                raw_error=error,
            )
    return out


def format_candidate_block(candidate_ids: list[str], catalog: dict[str, TechniqueRef]) -> str:
    lines = []
    for tid in candidate_ids:
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


def build_step_user_prompt(
    *,
    candidate_block: str,
    step: dict[str, Any],
    step_index: int,
    step_total: int,
) -> str:
    return (
        "Judge EACH candidate for THIS step only. "
        "stances: support | reject | insufficient.\n"
        "Do NOT invent ids outside CANDIDATES.\n\n"
        f"CANDIDATES:\n{candidate_block}\n\n"
        f"STEP ({step_index}/{step_total}):\n"
        f"action={step.get('action') or ''}\n"
        f"step_type={step.get('step_type') or ''}\n"
        f"phase={step.get('phase') or ''}\n"
        f"target={step.get('target') or ''}\n"
        f"input={step.get('input') or ''}\n"
        f"output={step.get('output') or ''}\n"
        f"purpose={step.get('purpose') or ''}\n"
        f"evidence_type={step.get('evidence_type') or ''}\n"
        f"evidence={step.get('evidence') or ''}\n"
    )


class EnsembleMapper:
    def __init__(
        self,
        *,
        system_prompt: str,
        client_a: JsonChatClient,
        client_b: JsonChatClient,
        client_c: JsonChatClient,
        strategy_version: str = "vote_v1",
        prompt_version: str = "ensemble_v1",
        max_retained_per_step: int = 2,
    ):
        self.system = system_prompt
        self.client_a = client_a
        self.client_b = client_b
        self.client_c = client_c
        self.strategy_version = strategy_version
        self.prompt_version = prompt_version
        self.max_retained_per_step = max_retained_per_step

    @classmethod
    def from_model_cfg(
        cls,
        model_cfg: dict[str, Any],
        system_prompt: str,
        *,
        client_a: Optional[JsonChatClient] = None,
        client_b: Optional[JsonChatClient] = None,
        client_c: Optional[JsonChatClient] = None,
    ) -> "EnsembleMapper":
        ens = model_cfg.get("ensemble") or {}
        return cls(
            system_prompt=system_prompt,
            client_a=client_a or LLMClient.for_ensemble_role(model_cfg, "model_a"),
            client_b=client_b or LLMClient.for_ensemble_role(model_cfg, "model_b"),
            client_c=client_c or LLMClient.for_ensemble_role(model_cfg, "model_c"),
            strategy_version=str(ens.get("strategy_version") or "vote_v1"),
            prompt_version=str(ens.get("prompt_version") or "ensemble_v1"),
            max_retained_per_step=int(ens.get("max_retained_per_step") or 2),
        )

    def _call_model(
        self, client: JsonChatClient, user: str, candidate_ids: list[str]
    ) -> dict[str, ModelJudgment]:
        if not getattr(client, "available", True):
            return parse_judgments_payload(
                None, candidate_ids, error="LLM client not configured / unavailable"
            )
        try:
            data = client.chat_json(self.system, user)
            return parse_judgments_payload(data, candidate_ids)
        except Exception as e:
            return parse_judgments_payload(None, candidate_ids, error=str(e))

    def vote_candidates(
        self,
        *,
        candidate_ids: list[str],
        catalog: dict[str, TechniqueRef],
        step: dict[str, Any],
        step_index: int = 1,
        step_total: int = 1,
    ) -> list[TechniqueVoteResult]:
        if not candidate_ids:
            return []

        block = format_candidate_block(candidate_ids, catalog)
        user = build_step_user_prompt(
            candidate_block=block,
            step=step,
            step_index=step_index,
            step_total=step_total,
        )

        ja = self._call_model(self.client_a, user, candidate_ids)
        jb = self._call_model(self.client_b, user, candidate_ids)

        need_c_ids: list[str] = []
        prelim: dict[str, tuple[MappingStatus, str, bool]] = {}
        for tid in candidate_ids:
            status, vote, need_c = decide_vote(ja[tid].stance, jb[tid].stance, None)
            prelim[tid] = (status, vote, need_c)
            if need_c:
                need_c_ids.append(tid)

        jc: dict[str, ModelJudgment] = {}
        if need_c_ids:
            # Same evidence/candidates; do NOT reveal A/B stances
            jc = self._call_model(self.client_c, user, need_c_ids)

        results: list[TechniqueVoteResult] = []
        for tid in candidate_ids:
            status, vote, need_c = prelim[tid]
            used_c = False
            judgments = {
                "model_a": ja[tid],
                "model_b": jb[tid],
            }
            if need_c:
                used_c = True
                j_c = jc.get(tid) or ModelJudgment(
                    stance="insufficient", reason="模型 C 未返回判断"
                )
                judgments["model_c"] = j_c
                status, vote, _ = decide_vote(
                    ja[tid].stance, jb[tid].stance, j_c.stance
                )

            # Structural: yellow catalog techniques never count as retained
            tref = catalog.get(tid)
            reason_parts = [
                f"[投票:{vote}]",
                f"A={ja[tid].stance}",
                f"B={jb[tid].stance}",
            ]
            if used_c:
                reason_parts.append(f"C={judgments['model_c'].stance}")
            reason_parts.append(ja[tid].reason or jb[tid].reason or "")
            reason = "；".join(p for p in reason_parts if p)

            if tref is not None and not tref.retained:
                if status == MappingStatus.retained:
                    status = MappingStatus.excluded
                    reason += "；黄标排除项，不可计入 coverage。"
                    vote = f"{vote}+yellow_excluded"

            evidence = (
                (judgments.get("model_c") or ja[tid]).evidence_quote
                or ja[tid].evidence_quote
                or jb[tid].evidence_quote
                or str(step.get("evidence") or "")
            )
            supporting = ja[tid].reason or jb[tid].reason or ""

            results.append(
                TechniqueVoteResult(
                    technique_id=tid,
                    final_status=status,
                    vote=vote,
                    reason=reason,
                    evidence=evidence,
                    supporting_behavior=supporting,
                    judgments=judgments,
                    used_model_c=used_c,
                )
            )
        return results

    def to_mappings(
        self,
        *,
        vote_results: list[TechniqueVoteResult],
        candidate_ids: list[str],
        catalog: dict[str, TechniqueRef],
        step: dict[str, Any],
        writeup_id: str,
    ) -> list[TechniqueMapping]:
        model_meta = {
            "model_a": {
                "role": "model_a",
                "model": getattr(self.client_a, "model", ""),
            },
            "model_b": {
                "role": "model_b",
                "model": getattr(self.client_b, "model", ""),
            },
            "model_c": {
                "role": "model_c",
                "model": getattr(self.client_c, "model", ""),
            },
        }
        # Cap retained per step (structural)
        retained_order = [
            r for r in vote_results if r.final_status == MappingStatus.retained
        ]
        demote_ids = {
            r.technique_id for r in retained_order[self.max_retained_per_step :]
        }

        out: list[TechniqueMapping] = []
        for r in vote_results:
            status = r.final_status
            reason = r.reason
            vote = r.vote
            if r.technique_id in demote_ids:
                status = MappingStatus.excluded
                vote = f"{vote}+cap_excluded"
                reason += (
                    f"；[结构] 同一步 retained 超过 {self.max_retained_per_step} 条，"
                    "额外项降为 excluded。"
                )

            tref = catalog.get(r.technique_id)
            ensemble_payload = {
                "strategy_version": self.strategy_version,
                "prompt_version": self.prompt_version,
                "candidates": list(candidate_ids),
                "models": model_meta,
                "technique_id": r.technique_id,
                "judgments": {k: v.to_dict() for k, v in r.judgments.items()},
                "vote": vote,
                "final_status": status.value,
                "used_model_c": r.used_model_c,
            }
            out.append(
                TechniqueMapping(
                    mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                    step_id=str(step.get("step_id") or ""),
                    writeup_id=writeup_id,
                    technique_id=r.technique_id,
                    technique_name=tref.technique_name if tref else None,
                    tactic=tref.tactic if tref else None,
                    mapping_status=status,
                    mapping_type="behavior",
                    mapping_reason=reason,
                    evidence=r.evidence or str(step.get("evidence") or ""),
                    evidence_location=str(step.get("evidence_location") or ""),
                    mapping_role="sole",
                    supporting_behavior=r.supporting_behavior,
                    behavior_observed=str(step.get("action") or ""),
                    definition_match=status == MappingStatus.retained,
                    required_conditions_met=status == MappingStatus.retained,
                    evidence_directness="direct",
                    mapping_evidence=r.evidence,
                    counterevidence="",
                    ensemble_json=json.dumps(ensemble_payload, ensure_ascii=False),
                    candidates_json=json.dumps(candidate_ids, ensure_ascii=False),
                )
            )
        return out
