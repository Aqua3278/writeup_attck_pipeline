from __future__ import annotations

import uuid
from typing import Optional

from wap.db.store import Store
from wap.mapping.attck_catalog import catalog_summary, load_attck_workbook
from wap.mapping.attck_meta import (
    NON_COVERAGE_STEP_TYPES,
    default_metadata_path,
    enrich_ref,
    export_metadata_json,
)
from wap.mapping.candidates import generate_candidates
from wap.mapping.verify import verify_candidate
from wap.models.schemas import MappingStatus, TechniqueMapping
from wap.utils.config import ROOT, load_yaml, resolve_path
from wap.utils.llm import LLMClient


class MappingService:
    """
    Two-stage ATT&CK mapping:
      Stage-1 candidates (code, high recall) → Stage-2 LLM verify (high precision)
      → code gates (required conditions) → retained/excluded/unmatched
    Coverage only counts retained. Precision > recall.
    """

    def __init__(self, pipeline_cfg: Optional[dict] = None, model_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.model_cfg = model_cfg or load_yaml("configs/model.yaml")
        self.store = Store(self.cfg["db_path"])
        self.llm = LLMClient(self.model_cfg)
        ver = (self.model_cfg.get("prompt_versions") or {}).get(
            "technique_map", "verify_v2"
        )
        path = ROOT / "prompts" / f"technique_{ver}.txt"
        if not path.exists():
            path = ROOT / "prompts" / f"technique_map_{ver}.txt"
        if not path.exists():
            path = ROOT / "prompts" / "technique_verify_v2.txt"
        self.system = path.read_text(encoding="utf-8")

    def load_catalog(self) -> dict:
        path = resolve_path(self.cfg["attck_workbook"])
        techs = load_attck_workbook(
            path,
            sheet=self.cfg.get("attck_sheet", "Sheet1"),
            excluded_rgb_suffix=self.cfg.get("attck_excluded_fill_rgb_suffix", "FFFF00"),
        )
        for t in techs:
            enrich_ref(t)
        self.store.replace_catalog(techs, str(path))
        export_metadata_json(techs, default_metadata_path())
        return catalog_summary(techs)

    def _catalog_lines(self, ids: list[str], catalog: dict) -> str:
        lines = []
        for tid in ids:
            t = catalog.get(tid)
            if not t:
                continue
            tactic = t.tactic_en or (t.tactic or "").split()[0]
            zh = t.technique_name_zh or t.technique_name
            lines.append(f"- {tid} | {t.technique_name} | {zh} | {tactic}")
        return "\n".join(lines)

    def map_writeup(self, writeup_id: str) -> dict:
        catalog = self.store.get_catalog_by_id()
        if not catalog:
            self.load_catalog()
            catalog = self.store.get_catalog_by_id()
        retained_ids = [tid for tid, t in catalog.items() if t.retained]

        meta = next(
            (r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id),
            None,
        )
        chain_source = ""
        coverage_status = ""
        if meta is not None:
            keys = meta.keys()
            chain_source = (
                (meta["attack_chain_source"] if "attack_chain_source" in keys else "")
                or ""
            )
            coverage_status = (
                (meta["coverage_status"] if "coverage_status" in keys else "") or ""
            )

        # Unresolved / insufficient evidence → no ATT&CK coverage
        if chain_source == "unresolved" or coverage_status == "insufficient_evidence":
            self.store.replace_mappings(writeup_id, [])
            return {
                "writeup_id": writeup_id,
                "mappings": 0,
                "retained": 0,
                "excluded": 0,
                "unmatched": 0,
                "pending_review": 0,
                "attack_chain_source": chain_source or "unresolved",
                "coverage_status": "insufficient_evidence",
                "pipeline": "chain-unresolved→skip-map",
            }

        all_steps = self.store.get_steps(writeup_id)
        selected = [
            s
            for s in all_steps
            if (s["chain_status"] if "chain_status" in s.keys() else "pending")
            == "selected"
        ]
        # Require chain resolution: if none selected and any pending, refuse to map all behaviors
        pending = [
            s
            for s in all_steps
            if (s["chain_status"] if "chain_status" in s.keys() else "pending")
            == "pending"
        ]
        if not selected and pending:
            return {
                "writeup_id": writeup_id,
                "mappings": 0,
                "retained": 0,
                "error": "run `chain` before `map` (no selected attack-chain steps)",
                "attack_chain_source": chain_source or "",
                "coverage_status": coverage_status or "pending",
                "pipeline": "awaiting-chain",
            }
        steps = selected if selected else all_steps
        mappings: list[TechniqueMapping] = []
        # Prior *selected* chain steps only — supplement semantics for Stage-1 recall
        prior_selected: list[dict] = []

        def _remember_prior(st) -> None:
            cs = (st["chain_status"] if "chain_status" in st.keys() else "pending") or "pending"
            # Only successful-path steps become context (when mapping selected list, all qualify)
            if cs == "selected" or (bool(selected) and cs != "excluded"):
                prior_selected.append(
                    {
                        "action": str(st["action"] or ""),
                        "evidence": str(st["evidence"] or ""),
                        "sequence": int(st["sequence"] or 0),
                    }
                )

        for i, step in enumerate(steps, 1):
            step_type = (step["step_type"] if "step_type" in step.keys() else None) or "other"
            if step_type in NON_COVERAGE_STEP_TYPES:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_type="non_attack_step",
                        mapping_reason=(
                            f"行为类别={step_type}：准备/观察/数据处理步骤默认不计入 ATT&CK 覆盖"
                            "（分类字段，不是用 step_type 映射技术）。"
                        ),
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                        confidence=1.0,
                        mapping_role="sole",
                        behavior_observed=str(step["action"] or ""),
                        evidence_directness="direct",
                    )
                )
                _remember_prior(step)
                continue

            # Stage-1: candidates (high recall; prior selected steps as context)
            cands = generate_candidates(
                action=str(step["action"] or ""),
                evidence=str(step["evidence"] or ""),
                catalog_ids=retained_ids,
                max_candidates=8,
                prior_selected_steps=prior_selected,
            )
            if not cands:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_reason="Stage-1 无候选技术；证据不足以提出 ATT&CK 候选。",
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                        confidence=0.0,
                        behavior_observed=str(step["action"] or ""),
                    )
                )
                _remember_prior(step)
                continue

            cand_block = self._catalog_lines(cands, catalog)
            user = (
                "Stage-2 VERIFY. Candidates are HYPOTHESES TO FALSIFY, not answers to accept.\n"
                "Evidence → behavior → definition → required conditions → status.\n"
                "Precision > recall. Prefer unmatched over wrong retained.\n"
                "Do NOT invent ids outside CANDIDATES. Do NOT retain because it is a candidate.\n"
                "step_type/phase/tool-name/keyword/later outcomes are NEVER sufficient alone.\n\n"
                f"CANDIDATE HYPOTHESES (falsify by default):\n{cand_block}\n\n"
                f"STEP ({i}/{len(steps)}):\n"
                f"action={step['action']}\n"
                f"step_type={step_type}\n"
                f"phase={step['phase'] if 'phase' in step.keys() else ''}\n"
                f"target={step['target']}\n"
                f"input={step['input']}\n"
                f"output={step['output']}\n"
                f"purpose={step['purpose']}\n"
                f"evidence_type={step['evidence_type']}\n"
                f"evidence={step['evidence']}\n"
            )
            try:
                data = self.llm.chat_json(self.system, user)
            except Exception as e:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.pending_review,
                        mapping_reason=f"Stage-2 LLM verify failed: {e}",
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                        confidence=0.0,
                    )
                )
                _remember_prior(step)
                continue

            raw = data.get("verifications") or data.get("mappings") or []
            # Keep only candidates; cap retained later
            step_maps: list[TechniqueMapping] = []
            for m in raw:
                tid = m.get("technique_id")
                if isinstance(tid, str):
                    tid = tid.strip()
                if tid and tid not in cands:
                    # reject hallucinated ids outside stage-1 set
                    continue
                step_maps.append(self._finalize_verification(m, step, writeup_id, catalog))

            # At most 2 retained; demote extras to excluded
            retained_list = [x for x in step_maps if x.mapping_status == MappingStatus.retained]
            if len(retained_list) > 2:
                for extra in retained_list[2:]:
                    extra.mapping_status = MappingStatus.excluded
                    extra.mapping_reason = (
                        (extra.mapping_reason or "")
                        + "；[验证] 同一步 retained 超过 2 条，额外项降为 excluded。"
                    )
                    extra.required_conditions_met = False

            if not step_maps:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_reason="Stage-2 未确认任何候选技术。",
                        evidence=step["evidence"] or "",
                        evidence_location=step["evidence_location"] or "",
                        confidence=0.0,
                        behavior_observed=str(step["action"] or ""),
                    )
                )
            else:
                self._normalize_roles(step_maps)
                mappings.extend(step_maps)

            _remember_prior(step)

        self.store.replace_mappings(writeup_id, mappings)
        retained_techs = sorted(
            {
                m.technique_id
                for m in mappings
                if m.mapping_status == MappingStatus.retained and m.technique_id
            }
        )
        return {
            "writeup_id": writeup_id,
            "mappings": len(mappings),
            "retained": sum(1 for m in mappings if m.mapping_status == MappingStatus.retained),
            "excluded": sum(1 for m in mappings if m.mapping_status == MappingStatus.excluded),
            "unmatched": sum(1 for m in mappings if m.mapping_status == MappingStatus.unmatched),
            "pending_review": sum(
                1 for m in mappings if m.mapping_status == MappingStatus.pending_review
            ),
            "attack_chain_source": chain_source or "",
            "coverage_status": coverage_status or "ok",
            "raw_step_count": len(all_steps),
            "attack_chain_step_count": len(steps),
            "retained_techniques": retained_techs,
            "coverage": retained_techs,
            "pipeline": "chain→candidate→verify→gates",
        }

    @staticmethod
    def _normalize_roles(step_maps: list[TechniqueMapping]) -> None:
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

    def _finalize_verification(
        self, m: dict, step, writeup_id: str, catalog: dict
    ) -> TechniqueMapping:
        tid = m.get("technique_id") or None
        if isinstance(tid, str):
            tid = tid.strip() or None
        model_status = str(m.get("mapping_status") or "unmatched").lower()
        try:
            proposed = MappingStatus(model_status)
        except ValueError:
            proposed = MappingStatus.pending_review

        reason = str(m.get("mapping_reason") or "")
        supporting = str(m.get("supporting_behavior") or m.get("behavior_observed") or "")
        map_ev = str(m.get("mapping_evidence") or m.get("evidence") or step["evidence"] or "")
        behavior = str(m.get("behavior_observed") or step["action"] or "")
        directness = str(m.get("evidence_directness") or "direct").lower()
        counter = str(m.get("counterevidence") or "")
        def_match = bool(m.get("definition_match", True))
        req_met = bool(m.get("required_conditions_met", True))
        role = str(m.get("mapping_role") or "sole").lower()
        if role not in ("primary", "secondary", "sole"):
            role = "sole"

        tname = None
        tactic = None
        if not tid:
            proposed = MappingStatus.unmatched
        elif tid not in catalog:
            proposed = MappingStatus.pending_review
            tname = m.get("technique_name")
            tactic = m.get("tactic")
        else:
            tref = catalog[tid]
            tname = tref.technique_name
            tactic = tref.tactic
            if not tref.retained:
                proposed = MappingStatus.excluded
                reason = (reason + "；" if reason else "") + "黄标排除项，不可计入 coverage。"

        step_type = (step["step_type"] if "step_type" in step.keys() else None) or "other"
        vr = verify_candidate(
            technique_id=tid,
            proposed_status=proposed,
            reason=reason,
            evidence=map_ev,
            supporting=supporting,
            step_type=step_type,
            action=str(step["action"] or ""),
            evidence_directness=directness,
            definition_match=def_match,
            required_conditions_met=req_met,
            counterevidence=counter,
        )

        return TechniqueMapping(
            mapping_id=f"map_{uuid.uuid4().hex[:10]}",
            step_id=step["step_id"],
            writeup_id=writeup_id,
            technique_id=tid,
            technique_name=tname,
            tactic=tactic,
            mapping_status=vr.status,
            mapping_type="behavior",
            mapping_reason=vr.reason,
            evidence=map_ev,
            evidence_location=step["evidence_location"] or "",
            confidence=float(m.get("confidence") or 0.0),
            mapping_role=role,
            supporting_behavior=supporting,
            behavior_observed=behavior,
            definition_match=vr.definition_match,
            required_conditions_met=vr.required_conditions_met,
            evidence_directness=vr.evidence_directness,
            mapping_evidence=map_ev,
            counterevidence=counter,
        )

    def map_all(self, source_id: Optional[str] = None) -> list[dict]:
        out = []
        for w in self.store.list_writeups(source_id):
            steps = self.store.get_steps(w["writeup_id"])
            if not steps:
                continue
            try:
                out.append(self.map_writeup(w["writeup_id"]))
            except Exception as e:
                out.append({"writeup_id": w["writeup_id"], "error": str(e)})
        return out
