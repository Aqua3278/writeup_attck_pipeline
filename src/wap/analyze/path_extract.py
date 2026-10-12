from __future__ import annotations

import re
import uuid
from typing import Optional

from wap.analyze.step_merge import merge_behavioral_steps
from wap.db.store import Store
from wap.mapping.attck_meta import VALID_PHASES, VALID_STEP_TYPES
from wap.models.schemas import AttackStep, EvidenceType, PathEdge
from wap.utils.config import ROOT, load_yaml, resolve_path
from wap.utils.llm import LLMClient, chunk_text

_TOOL_SETUP = re.compile(
    r"\b(git\s+clone|pip\s+install|npm\s+install|go\s+build|python\s+-m\s+venv|"
    r"virtualenv|mkdir|chmod|wget\s+https?://|curl\s+-O)\b",
    re.I,
)
_DATA_PROC = re.compile(
    r"\b(csv|json|jq|base64\s+-d|xxd|hexdump|pretty.?print|convert)\b",
    re.I,
)


def _normalize_step_type(raw: str, action: str, evidence: str) -> str:
    st = (raw or "other").strip().lower()
    if st not in VALID_STEP_TYPES:
        st = "other"
    blob = f"{action}\n{evidence}"
    if st in ("other", "attack") and _TOOL_SETUP.search(blob):
        return "tool_setup"
    if st in ("other", "attack") and _DATA_PROC.search(blob) and not re.search(
        r"\b(exploit|spray|nmap|smb|rce|shell)\b", blob, re.I
    ):
        return "data_processing"
    return st


def _normalize_phase(raw: str, step_type: str) -> str:
    phase = (raw or "其他").strip()
    if phase not in VALID_PHASES:
        phase = "其他"
    if step_type in ("tool_setup", "data_processing", "validation") and phase == "其他":
        return "其他"
    # soft defaults when phase missing
    defaults = {
        "reconnaissance": "侦察",
        "discovery": "发现",
        "credential_access": "账户/凭据获取",
        "exploitation": "初始访问",
        "execution": "执行",
        "persistence": "持久化",
        "defense_evasion": "防御规避",
        "lateral_movement": "横向移动",
        "collection": "收集",
    }
    if phase == "其他" and step_type in defaults:
        return defaults[step_type]
    return phase


class PathExtractService:
    def __init__(self, pipeline_cfg: Optional[dict] = None, model_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.model_cfg = model_cfg or load_yaml("configs/model.yaml")
        self.store = Store(self.cfg["db_path"])
        self.llm = LLMClient(self.model_cfg)
        ver = (self.model_cfg.get("prompt_versions") or {}).get("path_extract", "v2")
        path = ROOT / "prompts" / f"path_extract_{ver}.txt"
        if not path.exists():
            path = ROOT / "prompts" / "path_extract_v2.txt"
        self.system = path.read_text(encoding="utf-8")

    def analyze_writeup(self, writeup_id: str) -> dict:
        rows = [r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id]
        if not rows:
            raise KeyError(writeup_id)
        w = rows[0]
        path = resolve_path(w["parsed_content_path"])
        if not path.exists():
            raise FileNotFoundError(path)
        text = path.read_text(encoding="utf-8")
        chunk_cfg = self.model_cfg.get("chunking") or {}
        chunks = chunk_text(
            text,
            max_chars=int(chunk_cfg.get("max_chars_per_chunk", 3500)),
            overlap=int(chunk_cfg.get("overlap_chars", 200)),
            max_chunks=int(chunk_cfg.get("max_chunks_per_writeup", 40)),
        )
        all_steps: list[AttackStep] = []
        all_edges: list[PathEdge] = []
        seq_base = 0
        chunk_errors: list[dict] = []
        max_steps = int(chunk_cfg.get("max_steps_per_chunk", 6))
        for chunk_id, chunk in chunks:
            if len(chunk) > 2000:
                chunk = chunk[:2000]
            try:
                data = self.llm.chat_json(
                    self.system,
                    (
                        f"writeup_id={writeup_id}\nchunk_id={chunk_id}\n"
                        f"max_steps={max_steps}\n\nCHUNK:\n{chunk}"
                    ),
                )
            except Exception as e:
                chunk_errors.append({"chunk_id": chunk_id, "error": str(e)})
                continue
            local_id_map: dict[int, str] = {}
            for s in (data.get("steps") or [])[:max_steps]:
                et = str(s.get("evidence_type", "unknown"))
                try:
                    et_enum = EvidenceType(et)
                except ValueError:
                    et_enum = EvidenceType.unknown
                if et_enum == EvidenceType.mentioned:
                    continue
                action = str(s.get("action") or "").strip()
                evidence = str(s.get("evidence") or "")
                if not action and not evidence:
                    continue
                step_type = _normalize_step_type(
                    str(s.get("step_type") or "other"), action, evidence
                )
                phase = _normalize_phase(str(s.get("phase") or "其他"), step_type)
                seq = seq_base + int(s.get("sequence") or 1)
                step_id = f"{writeup_id}_s{seq:04d}_{uuid.uuid4().hex[:6]}"
                local_seq = int(s.get("sequence") or 1)
                local_id_map[local_seq] = step_id
                all_steps.append(
                    AttackStep(
                        step_id=step_id,
                        writeup_id=writeup_id,
                        sequence=seq,
                        action=action or evidence[:80],
                        target=s.get("target"),
                        input=s.get("input"),
                        output=s.get("output"),
                        purpose=s.get("purpose"),
                        prerequisite=s.get("prerequisite"),
                        evidence=evidence,
                        evidence_location=f"{chunk_id}:{s.get('evidence_location', '')}",
                        evidence_type=et_enum,
                        inference=bool(s.get("inference") or et_enum == EvidenceType.inferred),
                        chunk_id=chunk_id,
                        step_type=step_type,
                        phase=phase,
                    )
                )
            for e in data.get("edges") or []:
                fs = local_id_map.get(int(e.get("from_sequence") or 0))
                ts = local_id_map.get(int(e.get("to_sequence") or 0))
                if fs and ts:
                    all_edges.append(
                        PathEdge(
                            from_step_id=fs,
                            to_step_id=ts,
                            relation=str(e.get("relation") or "sequence"),
                        )
                    )
            seq_base = max([s.sequence for s in all_steps], default=seq_base)

        deduped: list[AttackStep] = []
        seen_actions: set[str] = set()
        for s in sorted(all_steps, key=lambda x: x.sequence):
            key = f"{s.action}|{s.target}|{s.evidence[:80]}"
            if key in seen_actions:
                continue
            seen_actions.add(key)
            deduped.append(s)
        for i, s in enumerate(deduped, 1):
            s.sequence = i

        # Merge consecutive request-level HTTP probes into behavioral units
        before_merge = len(deduped)
        deduped = merge_behavioral_steps(deduped)

        self.store.replace_steps(writeup_id, deduped, all_edges)
        return {
            "writeup_id": writeup_id,
            "chunks": len(chunks),
            "steps": len(deduped),
            "steps_before_merge": before_merge,
            "edges": len(all_edges),
            "chunk_errors": chunk_errors,
            "by_step_type": _count_types(deduped),
        }

    def analyze_all(self, source_id: Optional[str] = None) -> list[dict]:
        out = []
        for w in self.store.list_writeups(source_id):
            if w["parse_status"] != "success":
                continue
            try:
                out.append(self.analyze_writeup(w["writeup_id"]))
            except Exception as e:
                out.append({"writeup_id": w["writeup_id"], "error": str(e)})
        return out


def _count_types(steps: list[AttackStep]) -> dict[str, int]:
    from collections import Counter

    return dict(Counter(s.step_type for s in steps))
