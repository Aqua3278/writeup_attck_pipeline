from __future__ import annotations

"""Re-apply evidence gates on stored mappings without calling the LLM."""

from typing import Optional

from wap.db.store import Store
from wap.mapping.rules import demote_retained
from wap.models.schemas import MappingStatus, TechniqueMapping
from wap.utils.config import load_yaml


class RefilterService:
    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])

    def refilter_writeup(self, writeup_id: str) -> dict:
        steps = {
            r["step_id"]: dict(r) for r in self.store.get_steps(writeup_id)
        }
        out: list[TechniqueMapping] = []
        demoted = 0
        for row in self.store.get_mappings(writeup_id):
            m = dict(row)
            step = steps.get(m["step_id"], {})
            status = MappingStatus(m["mapping_status"])
            new_status, new_reason = demote_retained(
                technique_id=m.get("technique_id"),
                status=status,
                reason=m.get("mapping_reason") or "",
                evidence=m.get("evidence") or "",
                supporting=m.get("supporting_behavior") or "",
                step_type=step.get("step_type") or "other",
                action=step.get("action") or "",
            )
            if status == MappingStatus.retained and new_status != MappingStatus.retained:
                demoted += 1
            out.append(
                TechniqueMapping(
                    mapping_id=m["mapping_id"],
                    step_id=m["step_id"],
                    writeup_id=writeup_id,
                    technique_id=m.get("technique_id"),
                    technique_name=m.get("technique_name"),
                    tactic=m.get("tactic"),
                    mapping_status=new_status,
                    mapping_type=m.get("mapping_type") or "behavior",
                    mapping_reason=new_reason,
                    evidence=m.get("evidence") or "",
                    evidence_location=m.get("evidence_location") or "",
                    confidence=float(m.get("confidence") or 0.0),
                    review_status=m.get("review_status") or "open",
                    mapping_role=m.get("mapping_role") or "sole",
                    supporting_behavior=m.get("supporting_behavior") or "",
                    behavior_observed=m.get("behavior_observed") or "",
                    definition_match=bool(m.get("definition_match")),
                    required_conditions_met=(
                        new_status == MappingStatus.retained
                    ),
                    evidence_directness=m.get("evidence_directness") or "direct",
                    mapping_evidence=m.get("mapping_evidence") or m.get("evidence") or "",
                    counterevidence=m.get("counterevidence") or "",
                )
            )
        self.store.replace_mappings(writeup_id, out)
        return {
            "writeup_id": writeup_id,
            "mappings": len(out),
            "demoted_from_retained": demoted,
            "retained": sum(1 for x in out if x.mapping_status == MappingStatus.retained),
            "excluded": sum(1 for x in out if x.mapping_status == MappingStatus.excluded),
            "unmatched": sum(1 for x in out if x.mapping_status == MappingStatus.unmatched),
        }
