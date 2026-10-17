"""Direct LLM ATT&CK mapping: full retained catalog, no vector candidates, no A/B/C vote.

Catalog is scanned in batches only to fit context limits; every retained technique
is shown to the model exactly once per step (partition, not retrieval filtering).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from wap.db.store import Store
from wap.mapping.attck_catalog import catalog_summary, load_attck_workbook
from wap.mapping.attck_meta import (
    default_metadata_path,
    enrich_ref,
    export_metadata_json,
)
from wap.mapping.common import (
    chain_skip_reason,
    is_non_coverage_step,
    mapping_stats,
    non_coverage_mapping,
    normalize_roles,
    select_steps_for_map,
)
from wap.mapping.common import coerce_unit_interval, format_technique_catalog_block
from wap.mapping.methods import METHOD_DIRECT_LLM
from wap.models.schemas import MappingStatus, TechniqueMapping, TechniqueRef
from wap.utils.config import ROOT, load_yaml, resolve_path
from wap.utils.llm import LLMClient


class JsonChatClient(Protocol):
    model: str

    @property
    def available(self) -> bool: ...

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict[str, Any]: ...


@dataclass
class DirectHit:
    technique_id: str
    kind: str  # supported | uncertain
    evidence_quote: str = ""
    definition_link: str = ""
    reason: str = ""
    uncertainty: float = 0.0
    batch_index: int = 0


@dataclass
class DirectStepResult:
    hits: list[DirectHit] = field(default_factory=list)
    batch_count: int = 0
    errors: list[str] = field(default_factory=list)
    raw_batches: list[dict[str, Any]] = field(default_factory=list)


def _parse_uncertainty(item: dict[str, Any]) -> float:
    u = coerce_unit_interval(item.get("uncertainty"))
    return 0.0 if u is None else u


def parse_direct_payload(
    data: dict[str, Any] | None,
    allowed_ids: set[str],
    *,
    batch_index: int = 0,
    error: str = "",
) -> tuple[list[DirectHit], str]:
    """Parse open-ended supported/uncertain lists; drop illegal ids."""
    hits: list[DirectHit] = []
    if error:
        return hits, error
    if not isinstance(data, dict):
        return hits, "model returned non-object JSON"

    def _consume(key: str, kind: str) -> None:
        raw = data.get(key)
        if raw is None and key == "supported":
            # tolerate alternate keys
            raw = data.get("mappings") or data.get("techniques") or []
        if not isinstance(raw, list):
            return
        for item in raw:
            if not isinstance(item, dict):
                continue
            tid = item.get("technique_id")
            if not isinstance(tid, str):
                continue
            tid = tid.strip()
            if tid not in allowed_ids:
                continue
            hits.append(
                DirectHit(
                    technique_id=tid,
                    kind=kind,
                    evidence_quote=str(
                        item.get("evidence_quote") or item.get("mapping_evidence") or ""
                    )[:500],
                    definition_link=str(item.get("definition_link") or "")[:500],
                    reason=str(item.get("reason") or item.get("mapping_reason") or "")[
                        :500
                    ],
                    uncertainty=_parse_uncertainty(item),
                    batch_index=batch_index,
                )
            )

    _consume("supported", "supported")
    _consume("uncertain", "uncertain")
    return hits, ""


def chunk_ids(ids: list[str], batch_size: int) -> list[list[str]]:
    if batch_size <= 0:
        return [list(ids)]
    return [ids[i : i + batch_size] for i in range(0, len(ids), batch_size)]


def build_direct_user_prompt(
    *,
    catalog_block: str,
    step: dict[str, Any],
    step_index: int,
    step_total: int,
    batch_index: int,
    batch_total: int,
) -> str:
    return (
        "请根据以下攻击步骤的实际行为和证据，参照本批提供的 MITRE ATT&CK 技术定义，"
        "识别其中有充分证据支持的技术映射。"
        "请逐项核对行为证据与技术定义；不要根据工具名称、关键词重合、攻击意图或后续结果"
        "推断未被证实的行为。"
        "如果没有任何技术得到充分支持，请返回空的 supported 与 uncertain。"
        "只使用本批目录中的 technique_id。\n\n"
        f"CATALOG_BATCH ({batch_index}/{batch_total}):\n{catalog_block}\n\n"
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


class DirectLlmMapper:
    def __init__(
        self,
        *,
        system_prompt: str,
        client: JsonChatClient,
        prompt_version: str = "direct_llm_v1",
        batch_size: int = 40,
    ):
        self.system = system_prompt
        self.client = client
        self.prompt_version = prompt_version
        self.batch_size = batch_size

    @classmethod
    def from_model_cfg(
        cls,
        model_cfg: dict[str, Any],
        system_prompt: str,
        *,
        client: Optional[JsonChatClient] = None,
    ) -> "DirectLlmMapper":
        cfg = model_cfg.get("direct_llm") or {}
        return cls(
            system_prompt=system_prompt,
            client=client or LLMClient(model_cfg),
            prompt_version=str(cfg.get("prompt_version") or "direct_llm_v1"),
            batch_size=int(cfg.get("batch_size") or 40),
        )

    def map_step(
        self,
        *,
        retained_ids: list[str],
        catalog: dict[str, TechniqueRef],
        step: dict[str, Any],
        step_index: int = 1,
        step_total: int = 1,
    ) -> DirectStepResult:
        batches = chunk_ids(list(retained_ids), self.batch_size)
        result = DirectStepResult(batch_count=len(batches))
        if not batches:
            return result

        seen_supported: set[str] = set()
        seen_uncertain: set[str] = set()

        for bi, batch in enumerate(batches, 1):
            allowed = set(batch)
            block = format_technique_catalog_block(batch, catalog)
            user = build_direct_user_prompt(
                catalog_block=block,
                step=step,
                step_index=step_index,
                step_total=step_total,
                batch_index=bi,
                batch_total=len(batches),
            )
            err = ""
            data: dict[str, Any] | None = None
            if not getattr(self.client, "available", True):
                err = "LLM client not configured / unavailable"
            else:
                try:
                    data = self.client.chat_json(self.system, user)
                except Exception as e:
                    err = str(e)
                    result.errors.append(f"batch {bi}/{len(batches)}: {e}")

            hits, parse_err = parse_direct_payload(
                data, allowed, batch_index=bi, error=err
            )
            if parse_err and not err:
                result.errors.append(f"batch {bi}/{len(batches)}: {parse_err}")

            result.raw_batches.append(
                {
                    "batch_index": bi,
                    "batch_total": len(batches),
                    "technique_ids": list(batch),
                    "error": err or parse_err or "",
                    "hit_count": len(hits),
                }
            )

            for h in hits:
                if h.kind == "supported":
                    if h.technique_id in seen_supported:
                        continue
                    # prefer supported over uncertain
                    seen_uncertain.discard(h.technique_id)
                    seen_supported.add(h.technique_id)
                    result.hits.append(h)
                else:
                    if h.technique_id in seen_supported or h.technique_id in seen_uncertain:
                        continue
                    seen_uncertain.add(h.technique_id)
                    result.hits.append(h)

        return result

    def to_mappings(
        self,
        *,
        step_result: DirectStepResult,
        catalog: dict[str, TechniqueRef],
        step: dict[str, Any],
        writeup_id: str,
        retained_ids: list[str],
    ) -> list[TechniqueMapping]:
        allowed = set(retained_ids)
        supported = [h for h in step_result.hits if h.kind == "supported"]
        uncertain = [h for h in step_result.hits if h.kind == "uncertain"]

        out: list[TechniqueMapping] = []
        model_name = getattr(self.client, "model", "")

        def _audit(extra: dict[str, Any]) -> str:
            payload = {
                "method": METHOD_DIRECT_LLM,
                "prompt_version": self.prompt_version,
                "batch_size": self.batch_size,
                "batch_count": step_result.batch_count,
                "model": model_name,
                "catalog_size": len(retained_ids),
                "batches": step_result.raw_batches,
                "errors": step_result.errors,
                **extra,
            }
            return json.dumps(payload, ensure_ascii=False)

        if step_result.errors and not supported and not uncertain:
            out.append(
                TechniqueMapping(
                    mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                    step_id=str(step.get("step_id") or ""),
                    writeup_id=writeup_id,
                    mapping_status=MappingStatus.pending_review,
                    mapping_type="behavior",
                    mapping_reason="direct_llm 映射失败: " + "; ".join(step_result.errors)[:400],
                    evidence=str(step.get("evidence") or ""),
                    evidence_location=str(step.get("evidence_location") or ""),
                    behavior_observed=str(step.get("action") or ""),
                    candidates_json="[]",
                    ensemble_json=_audit({"final_status": "pending_review"}),
                    mapping_method=METHOD_DIRECT_LLM,
                )
            )
            return out

        for h in supported:
            if h.technique_id not in allowed:
                continue
            tref = catalog.get(h.technique_id)
            status = MappingStatus.retained
            reason = h.reason
            if h.definition_link:
                reason = f"{reason}；对应定义：{h.definition_link}".strip("；")
            if tref is not None and not tref.retained:
                status = MappingStatus.excluded
                reason += "；黄标排除项，不可计入 coverage。"
            out.append(
                TechniqueMapping(
                    mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                    step_id=str(step.get("step_id") or ""),
                    writeup_id=writeup_id,
                    technique_id=h.technique_id,
                    technique_name=tref.technique_name if tref else None,
                    tactic=tref.tactic if tref else None,
                    mapping_status=status,
                    mapping_type="behavior",
                    mapping_reason=reason or "direct_llm supported",
                    evidence=h.evidence_quote or str(step.get("evidence") or ""),
                    evidence_location=str(step.get("evidence_location") or ""),
                    mapping_role="sole",
                    supporting_behavior=h.definition_link or h.reason,
                    behavior_observed=str(step.get("action") or ""),
                    definition_match=status == MappingStatus.retained,
                    required_conditions_met=status == MappingStatus.retained,
                    evidence_directness="direct",
                    mapping_evidence=h.evidence_quote,
                    counterevidence="",
                    candidates_json="[]",
                    ensemble_json=_audit(
                        {
                            "technique_id": h.technique_id,
                            "kind": "supported",
                            "uncertainty": h.uncertainty,
                            "batch_index": h.batch_index,
                            "final_status": status.value,
                        }
                    ),
                    mapping_method=METHOD_DIRECT_LLM,
                )
            )

        for h in uncertain:
            if h.technique_id not in allowed:
                continue
            if any(m.technique_id == h.technique_id for m in out):
                continue
            tref = catalog.get(h.technique_id)
            out.append(
                TechniqueMapping(
                    mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                    step_id=str(step.get("step_id") or ""),
                    writeup_id=writeup_id,
                    technique_id=h.technique_id,
                    technique_name=tref.technique_name if tref else None,
                    tactic=tref.tactic if tref else None,
                    mapping_status=MappingStatus.pending_review,
                    mapping_type="behavior",
                    mapping_reason=h.reason or "证据不足，待复核",
                    evidence=h.evidence_quote or str(step.get("evidence") or ""),
                    evidence_location=str(step.get("evidence_location") or ""),
                    mapping_role="secondary",
                    supporting_behavior=h.reason,
                    behavior_observed=str(step.get("action") or ""),
                    candidates_json="[]",
                    ensemble_json=_audit(
                        {
                            "technique_id": h.technique_id,
                            "kind": "uncertain",
                            "uncertainty": h.uncertainty,
                            "final_status": "pending_review",
                        }
                    ),
                    mapping_method=METHOD_DIRECT_LLM,
                )
            )

        if not out:
            out.append(
                TechniqueMapping(
                    mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                    step_id=str(step.get("step_id") or ""),
                    writeup_id=writeup_id,
                    mapping_status=MappingStatus.unmatched,
                    mapping_type="behavior",
                    mapping_reason=(
                        "direct_llm 未识别出任何有充分证据支持的 ATT&CK 技术"
                        "（已扫描全部 retained 目录）。"
                    ),
                    evidence=str(step.get("evidence") or ""),
                    evidence_location=str(step.get("evidence_location") or ""),
                    behavior_observed=str(step.get("action") or ""),
                    candidates_json="[]",
                    ensemble_json=_audit({"final_status": "unmatched"}),
                    mapping_method=METHOD_DIRECT_LLM,
                )
            )

        normalize_roles([m for m in out if m.mapping_status == MappingStatus.retained] or out)
        # Re-normalize across all retained+others for role consistency
        retained_maps = [m for m in out if m.mapping_status == MappingStatus.retained]
        if retained_maps:
            normalize_roles(retained_maps)
        return out


class DirectMappingService:
    """Map writeups with direct_llm."""

    def __init__(
        self, pipeline_cfg: Optional[dict] = None, model_cfg: Optional[dict] = None
    ):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.model_cfg = model_cfg or load_yaml("configs/model.yaml")
        self.store = Store(self.cfg["db_path"])
        self.system = self._load_system_prompt()
        self.mapper = DirectLlmMapper.from_model_cfg(self.model_cfg, self.system)

    def _load_system_prompt(self) -> str:
        cfg = self.model_cfg.get("direct_llm") or {}
        ver = cfg.get("prompt_version") or "direct_llm_v1"
        candidates = [
            ROOT / "prompts" / f"technique_{ver}.txt",
            ROOT / "prompts" / "technique_direct_llm_v1.txt",
        ]
        for path in candidates:
            if path.exists():
                return path.read_text(encoding="utf-8")
        raise FileNotFoundError("no technique_direct_llm prompt found under prompts/")

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
        retained_ids = sorted(tid for tid, t in catalog.items() if t.retained)

        meta = next(
            (r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id),
            None,
        )
        skip = chain_skip_reason(meta)
        if skip:
            self.store.replace_mappings(
                writeup_id, [], method=METHOD_DIRECT_LLM
            )
            return {
                "writeup_id": writeup_id,
                "mapping_method": METHOD_DIRECT_LLM,
                "mappings": 0,
                "retained": 0,
                "excluded": 0,
                "unmatched": 0,
                "pending_review": 0,
                "attack_chain_source": skip["attack_chain_source"],
                "coverage_status": skip["coverage_status"],
                "pipeline": "chain-unresolved→skip-map",
            }

        all_steps = self.store.get_steps(writeup_id)
        steps, _selected, _pending, err = select_steps_for_map(all_steps)
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
        if err:
            return {
                "writeup_id": writeup_id,
                "mapping_method": METHOD_DIRECT_LLM,
                "mappings": 0,
                "retained": 0,
                "error": err,
                "attack_chain_source": chain_source,
                "coverage_status": coverage_status or "pending",
                "pipeline": "awaiting-chain",
            }

        mappings: list[TechniqueMapping] = []
        for i, step in enumerate(steps, 1):
            step_dict = {k: step[k] for k in step.keys()}
            if is_non_coverage_step(step_dict):
                mappings.append(
                    non_coverage_mapping(
                        writeup_id=writeup_id,
                        step_dict=step_dict,
                        mapping_method=METHOD_DIRECT_LLM,
                    )
                )
                continue

            try:
                step_result = self.mapper.map_step(
                    retained_ids=retained_ids,
                    catalog=catalog,
                    step=step_dict,
                    step_index=i,
                    step_total=len(steps),
                )
                step_maps = self.mapper.to_mappings(
                    step_result=step_result,
                    catalog=catalog,
                    step=step_dict,
                    writeup_id=writeup_id,
                    retained_ids=retained_ids,
                )
            except Exception as e:
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map_{uuid.uuid4().hex[:10]}",
                        step_id=step_dict["step_id"],
                        writeup_id=writeup_id,
                        mapping_status=MappingStatus.pending_review,
                        mapping_reason=f"direct_llm 映射失败: {e}",
                        evidence=step_dict.get("evidence") or "",
                        evidence_location=step_dict.get("evidence_location") or "",
                        candidates_json="[]",
                        ensemble_json=json.dumps(
                            {"method": METHOD_DIRECT_LLM, "error": str(e)},
                            ensure_ascii=False,
                        ),
                        mapping_method=METHOD_DIRECT_LLM,
                    )
                )
                continue

            mappings.extend(step_maps)

        self.store.replace_mappings(
            writeup_id, mappings, method=METHOD_DIRECT_LLM
        )
        stats = mapping_stats(mappings)
        retained_techs = sorted(
            {
                m.technique_id
                for m in mappings
                if m.mapping_status == MappingStatus.retained and m.technique_id
            }
        )
        return {
            "writeup_id": writeup_id,
            "mapping_method": METHOD_DIRECT_LLM,
            **stats,
            "attack_chain_source": chain_source or "",
            "coverage_status": coverage_status or "ok",
            "raw_step_count": len(all_steps),
            "attack_chain_step_count": len(steps),
            "retained_techniques": retained_techs,
            "coverage": retained_techs,
            "pipeline": "chain→direct_llm(full_catalog_batches)",
            "direct_llm": {
                "prompt_version": self.mapper.prompt_version,
                "batch_size": self.mapper.batch_size,
                "catalog_retained": len(retained_ids),
                "model": getattr(self.mapper.client, "model", ""),
            },
        }

    def map_all(self, source_id: Optional[str] = None) -> list[dict]:
        out = []
        for w in self.store.list_writeups(source_id):
            steps = self.store.get_steps(w["writeup_id"])
            if not steps:
                continue
            try:
                out.append(self.map_writeup(w["writeup_id"]))
            except Exception as e:
                out.append(
                    {
                        "writeup_id": w["writeup_id"],
                        "mapping_method": METHOD_DIRECT_LLM,
                        "error": str(e),
                    }
                )
        return out
