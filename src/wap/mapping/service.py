from __future__ import annotations

import json
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
from wap.mapping.ensemble import EnsembleMapper
from wap.models.schemas import MappingStatus, TechniqueMapping
from wap.utils.config import ROOT, load_yaml, resolve_path


class MappingService:
    """
    ATT&CK mapping pipeline:
      Stage-1 candidates (code, high recall; never decides retained)
      → multi-model vote (A/B, C on conflict/insufficient)
      → structural checks only (catalog id, yellow fill, max retained/step)

    Coverage counts retained only. Precision > recall.
    """

    def __init__(self, pipeline_cfg: Optional[dict] = None, model_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.model_cfg = model_cfg or load_yaml("configs/model.yaml")
        self.store = Store(self.cfg["db_path"])
        self.system = self._load_system_prompt()
        self.ensemble = EnsembleMapper.from_model_cfg(self.model_cfg, self.system)

    def _load_system_prompt(self) -> str:
        ver = (self.model_cfg.get("prompt_versions") or {}).get(
            "technique_map", "ensemble_v1"
        )
        ens = self.model_cfg.get("ensemble") or {}
        ver = ens.get("prompt_version") or ver
        candidates = [
            ROOT / "prompts" / f"technique_{ver}.txt",
            ROOT / "prompts" / "technique_ensemble_v1.txt",
        ]
        for path in candidates:
            if path.exists():
                return path.read_text(encoding="utf-8")
        raise FileNotFoundError("no technique mapping prompt found under prompts/")

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

    def map_writeup(self, writeup_id: str) -> dict:
        catalog = self.store.get_catalog_by_id()
        if not catalog:
            self.load_catalog()
            catalog = self.store.get_catalog_by_id()
        # Candidates drawn from catalog ids that may count toward coverage;
        # yellow rows still exist in catalog for structural demotion if present.
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
        prior_selected: list[dict] = []

        def _remember_prior(st) -> None:
            cs = (st["chain_status"] if "chain_status" in st.keys() else "pending") or "pending"
            if cs == "selected" or (bool(selected) and cs != "excluded"):
                prior_selected.append(
                    {
                        "action": str(st["action"] or ""),
                        "evidence": str(st["evidence"] or ""),
                        "purpose": str(st["purpose"] or "") if "purpose" in st.keys() else "",
                        "sequence": int(st["sequence"] or 0),
                    }
                )

        for i, step in enumerate(steps, 1):
            step_dict = {k: step[k] for k in step.keys()}
            step_type = step_dict.get("step_type") or "other"
            if step_type in NON_COVERAGE_STEP_TYPES:
                mappings.append(
                    TechniqueMapping(
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
                    )
                )
                _remember_prior(step)
                continue

            cands = generate_candidates(
                action=str(step_dict.get("action") or ""),
                evidence=str(step_dict.get("evidence") or ""),
                purpose=str(step_dict.get("purpose") or ""),
                catalog_ids=retained_ids,
                max_candidates=10,
                prior_selected_steps=prior_selected,
            )
            if not cands:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step_dict["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_reason=(
                            "候选筛选未生成任何技术假设，因此未进入多模型判断；"
                            "这不表示模型已认定该步骤不符合任何 ATT&CK 技术条件。"
                        ),
                        evidence=step_dict.get("evidence") or "",
                        evidence_location=step_dict.get("evidence_location") or "",
                        behavior_observed=str(step_dict.get("action") or ""),
                        candidates_json="[]",
                        ensemble_json=json.dumps(
                            {
                                "strategy_version": self.ensemble.strategy_version,
                                "prompt_version": self.ensemble.prompt_version,
                                "candidates": [],
                                "skip": "empty_candidates",
                                "note": "no model vote",
                            },
                            ensure_ascii=False,
                        ),
                    )
                )
                _remember_prior(step)
                continue

            try:
                votes = self.ensemble.vote_candidates(
                    candidate_ids=cands,
                    catalog=catalog,
                    step=step_dict,
                    step_index=i,
                    step_total=len(steps),
                )
                step_maps = self.ensemble.to_mappings(
                    vote_results=votes,
                    candidate_ids=cands,
                    catalog=catalog,
                    step=step_dict,
                    writeup_id=writeup_id,
                )
            except Exception as e:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step_dict["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.pending_review,
                        mapping_reason=f"多模型映射失败: {e}",
                        evidence=step_dict.get("evidence") or "",
                        evidence_location=step_dict.get("evidence_location") or "",
                        candidates_json=json.dumps(cands, ensure_ascii=False),
                        ensemble_json=json.dumps(
                            {"error": str(e), "candidates": cands},
                            ensure_ascii=False,
                        ),
                    )
                )
                _remember_prior(step)
                continue

            if not step_maps:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step_dict["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.unmatched,
                        mapping_reason="多模型投票未产生任何候选技术结果。",
                        evidence=step_dict.get("evidence") or "",
                        evidence_location=step_dict.get("evidence_location") or "",
                        behavior_observed=str(step_dict.get("action") or ""),
                        candidates_json=json.dumps(cands, ensure_ascii=False),
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
            "pipeline": "chain→candidates→ensemble_vote(A/B/C)",
            "ensemble": {
                "strategy_version": self.ensemble.strategy_version,
                "prompt_version": self.ensemble.prompt_version,
                "model_a": getattr(self.ensemble.client_a, "model", ""),
                "model_b": getattr(self.ensemble.client_b, "model", ""),
                "model_c": getattr(self.ensemble.client_c, "model", ""),
            },
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
