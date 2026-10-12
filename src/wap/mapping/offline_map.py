from __future__ import annotations

import uuid
from typing import Optional

from wap.analyze.offline_extract import CMD_PATTERNS
from wap.db.store import Store
from wap.models.schemas import MappingStatus, TechniqueMapping
from wap.utils.config import load_yaml


class OfflineMappingService:
    """Keyword/heuristic mapper for smoke tests without LLM."""

    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])

    def map_writeup(self, writeup_id: str) -> dict:
        catalog = self.store.get_catalog_by_id()
        if not catalog:
            from wap.mapping.service import MappingService

            MappingService(self.cfg).load_catalog()
            catalog = self.store.get_catalog_by_id()
        meta = next(
            (r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id),
            None,
        )
        if meta is not None:
            keys = meta.keys()
            src = (meta["attack_chain_source"] if "attack_chain_source" in keys else "") or ""
            cov = (meta["coverage_status"] if "coverage_status" in keys else "") or ""
            if src == "unresolved" or cov == "insufficient_evidence":
                self.store.replace_mappings(writeup_id, [])
                return {
                    "writeup_id": writeup_id,
                    "mappings": 0,
                    "mode": "offline",
                    "coverage_status": "insufficient_evidence",
                }

        all_steps = self.store.get_steps(writeup_id)
        selected = [
            s
            for s in all_steps
            if (s["chain_status"] if "chain_status" in s.keys() else "pending")
            == "selected"
        ]
        steps = selected if selected else all_steps
        mappings: list[TechniqueMapping] = []
        for step in steps:
            text = f"{step['action']} {step['input']} {step['evidence']}"
            hit = None
            for pat, _action, tid in CMD_PATTERNS:
                import re

                if re.search(pat, text, re.I):
                    hit = tid
                    break
            if hit and hit in catalog:
                t = catalog[hit]
                st = MappingStatus.retained if t.retained else MappingStatus.excluded
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        technique_id=t.technique_id,
                        technique_name=t.technique_name,
                        tactic=t.tactic,
                        mapping_status=st,
                        mapping_type="heuristic",
                        mapping_reason="offline keyword heuristic (replace with LLM map)",
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                        review_status="open",
                    )
                )
            else:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_type="heuristic",
                        mapping_reason="no heuristic match",
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                    )
                )
        self.store.replace_mappings(writeup_id, mappings)
        return {"writeup_id": writeup_id, "mappings": len(mappings), "mode": "offline"}