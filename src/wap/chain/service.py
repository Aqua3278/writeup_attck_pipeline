from __future__ import annotations

"""
Attack Chain Source Resolver + extract / recover.

Separates "is this step on the successful path?" from ATT&CK mapping.
No benchmark-specific if/else — content-driven via resolve_chain_source.
"""

import json
import re
import uuid
from typing import Any, Optional

from wap.chain.resolver import merge_task_corpus, resolve_chain_source
from wap.db.store import Store
from wap.models.schemas import AttackStep, EvidenceType, PathEdge
from wap.utils.config import ROOT, load_yaml, resolve_path
from wap.utils.llm import LLMClient

_FAILED = re.compile(
    r"(?i)\b(ruled\s+out|failed|unsuccessful|dead\s*end|abandoned|"
    r"no\s+longer\s+pursued|排除|失败|走不通|放弃)\b"
)


class ChainService:
    def __init__(
        self,
        pipeline_cfg: Optional[dict] = None,
        model_cfg: Optional[dict] = None,
        *,
        offline: bool = False,
    ):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.model_cfg = model_cfg or load_yaml("configs/model.yaml")
        self.store = Store(self.cfg["db_path"])
        self.offline = offline
        self.llm = None if offline else LLMClient(self.model_cfg)
        vers = self.model_cfg.get("prompt_versions") or {}
        ex = ROOT / "prompts" / f"chain_extract_{vers.get('chain_extract', 'v1')}.txt"
        rc = ROOT / "prompts" / f"chain_recover_{vers.get('chain_recover', 'v1')}.txt"
        if not ex.exists():
            ex = ROOT / "prompts" / "chain_extract_v1.txt"
        if not rc.exists():
            rc = ROOT / "prompts" / "chain_recover_v1.txt"
        self.extract_system = ex.read_text(encoding="utf-8")
        self.recover_system = rc.read_text(encoding="utf-8")

    def _load_text(self, writeup_row) -> str:
        path = writeup_row["parsed_content_path"]
        if not path:
            return ""
        p = resolve_path(path)
        if not p.exists():
            return ""
        return p.read_text(encoding="utf-8")

    def _task_corpus(self, writeup_id: str, primary_row) -> tuple[str, list[str]]:
        primary = self._load_text(primary_row)
        sibling_texts: list[str] = []
        for sib in self.store.list_sibling_writeups(writeup_id):
            t = self._load_text(sib)
            if t.strip():
                sibling_texts.append(t)
        return merge_task_corpus(primary, sibling_texts), sibling_texts

    def resolve_writeup(self, writeup_id: str) -> dict:
        rows = [r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id]
        if not rows:
            raise KeyError(writeup_id)
        w = rows[0]
        corpus, _siblings = self._task_corpus(writeup_id, w)
        decision = resolve_chain_source(corpus)

        if decision.source == "unresolved":
            self._mark_unresolved(writeup_id, decision.notes)
            return {
                "writeup_id": writeup_id,
                "attack_chain_source": "unresolved",
                "coverage_status": "insufficient_evidence",
                "raw_step_count": len(self.store.get_steps(writeup_id)),
                "attack_chain_step_count": 0,
                "paths": [],
                "notes": decision.notes,
            }

        if decision.source in (
            "explicit_full_chain",
            "explicit_success_narrative",
        ):
            return self._extract_from_section(
                writeup_id, w, decision.source, decision.section_text, decision.notes
            )

        # recovered_from_trace
        return self._recover_from_trace(
            writeup_id, decision.section_text or corpus, decision.notes
        )

    def resolve_all(self, source_id: Optional[str] = None) -> list[dict]:
        out = []
        for w in self.store.list_writeups(source_id):
            if w["parse_status"] != "success":
                continue
            try:
                out.append(self.resolve_writeup(w["writeup_id"]))
            except Exception as e:
                out.append({"writeup_id": w["writeup_id"], "error": str(e)})
        return out

    def _mark_unresolved(self, writeup_id: str, notes: str) -> None:
        self.store.update_writeup_chain(
            writeup_id,
            attack_chain_source="unresolved",
            coverage_status="insufficient_evidence",
            chain_paths_json="[]",
            chain_notes=notes,
        )
        for s in self.store.get_steps(writeup_id):
            self.store.update_step_chain(
                s["step_id"],
                chain_status="excluded",
                chain_reason="attack_chain_source=unresolved; not used for coverage",
                path_id="",
            )
        # Clear prior ATT&CK mappings so coverage cannot stale-count
        self.store.replace_mappings(writeup_id, [])

    def _extract_from_section(
        self,
        writeup_id: str,
        writeup_row,
        source: str,
        section_text: str,
        notes: str,
    ) -> dict:
        existing = self.store.get_steps(writeup_id)
        raw_count = len(existing)
        max_steps = 24

        if self.offline or self.llm is None:
            paths_data = self._offline_extract(section_text, max_steps)
        else:
            try:
                data = self.llm.chat_json(
                    self.extract_system,
                    (
                        f"writeup_id={writeup_id}\nmax_steps={max_steps}\n"
                        f"source={source}\n\nSECTION:\n{section_text[:12000]}"
                    ),
                )
            except Exception as e:
                self._mark_unresolved(writeup_id, f"chain extract LLM failed: {e}")
                return {
                    "writeup_id": writeup_id,
                    "attack_chain_source": "unresolved",
                    "coverage_status": "insufficient_evidence",
                    "raw_step_count": raw_count,
                    "attack_chain_step_count": 0,
                    "error": str(e),
                }
            paths_data = data

        steps, edges, path_meta = self._paths_to_steps(
            writeup_id, paths_data, existing_for_enrich=existing
        )
        selected = [s for s in steps if s.chain_status == "selected"]
        if not selected:
            self._mark_unresolved(
                writeup_id, notes + "; extract produced no selected steps"
            )
            return {
                "writeup_id": writeup_id,
                "attack_chain_source": "unresolved",
                "coverage_status": "insufficient_evidence",
                "raw_step_count": raw_count,
                "attack_chain_step_count": 0,
                "paths": path_meta,
                "notes": notes,
            }

        self.store.replace_steps(writeup_id, steps, edges)
        self.store.update_writeup_chain(
            writeup_id,
            attack_chain_source=source,
            coverage_status="ok",
            chain_paths_json=json.dumps(path_meta, ensure_ascii=False),
            chain_notes=notes,
        )
        return {
            "writeup_id": writeup_id,
            "attack_chain_source": source,
            "coverage_status": "ok",
            "raw_step_count": raw_count,
            "attack_chain_step_count": len(selected),
            "paths": path_meta,
            "header_notes": notes,
        }

    def _recover_from_trace(
        self, writeup_id: str, corpus: str, notes: str
    ) -> dict:
        existing = list(self.store.get_steps(writeup_id))
        raw_count = len(existing)
        if raw_count == 0:
            self._mark_unresolved(
                writeup_id, notes + "; no analyzed steps for recovery"
            )
            return {
                "writeup_id": writeup_id,
                "attack_chain_source": "unresolved",
                "coverage_status": "insufficient_evidence",
                "raw_step_count": 0,
                "attack_chain_step_count": 0,
                "notes": notes,
            }

        if self.offline or self.llm is None:
            data = self._offline_recover(existing)
        else:
            cand_lines = []
            for s in existing:
                cand_lines.append(
                    f"seq={s['sequence']}\taction={s['action']}\t"
                    f"type={s['step_type'] if 'step_type' in s.keys() else ''}\t"
                    f"evidence={(s['evidence'] or '')[:240]}"
                )
            try:
                data = self.llm.chat_json(
                    self.recover_system,
                    (
                        f"writeup_id={writeup_id}\n"
                        f"OBJECTIVE/TRACE CONTEXT (truncated):\n{corpus[:6000]}\n\n"
                        f"CANDIDATE_STEPS:\n" + "\n".join(cand_lines)
                    ),
                )
            except Exception as e:
                self._mark_unresolved(writeup_id, f"chain recover LLM failed: {e}")
                return {
                    "writeup_id": writeup_id,
                    "attack_chain_source": "unresolved",
                    "coverage_status": "insufficient_evidence",
                    "raw_step_count": raw_count,
                    "attack_chain_step_count": 0,
                    "error": str(e),
                }

        if data.get("unresolved") is True or not (data.get("paths") or []):
            self._mark_unresolved(
                writeup_id, notes + "; recovery returned unresolved/empty"
            )
            return {
                "writeup_id": writeup_id,
                "attack_chain_source": "unresolved",
                "coverage_status": "insufficient_evidence",
                "raw_step_count": raw_count,
                "attack_chain_step_count": 0,
                "notes": notes,
            }

        by_seq = {int(s["sequence"]): s for s in existing}
        selected_count = 0
        path_meta: list[dict[str, Any]] = []
        # default: exclude all, then select from recovery
        for s in existing:
            self.store.update_step_chain(
                s["step_id"],
                chain_status="excluded",
                chain_reason="not selected by attack-chain recovery",
                path_id="",
            )

        for p in data.get("paths") or []:
            pid = str(p.get("path_id") or "path1")
            path_meta.append(
                {
                    "path_id": pid,
                    "summary": p.get("summary") or "",
                    "step_sequences": [],
                }
            )
            for st in p.get("steps") or []:
                seq = int(st.get("source_sequence") or 0)
                row = by_seq.get(seq)
                if not row:
                    continue
                status = str(st.get("chain_status") or "unknown").lower()
                if status not in ("selected", "excluded", "unknown"):
                    status = "unknown"
                # unknown → excluded for coverage safety
                if status == "unknown":
                    status = "excluded"
                deps = st.get("depends_on_sequences") or []
                self.store.update_step_chain(
                    row["step_id"],
                    chain_status=status,
                    chain_reason=str(st.get("chain_reason") or ""),
                    path_id=pid if status == "selected" else "",
                    depends_on_json=json.dumps(deps, ensure_ascii=False),
                )
                if status == "selected":
                    selected_count += 1
                    path_meta[-1]["step_sequences"].append(seq)

        if selected_count == 0:
            self._mark_unresolved(
                writeup_id, notes + "; recovery selected zero steps"
            )
            return {
                "writeup_id": writeup_id,
                "attack_chain_source": "unresolved",
                "coverage_status": "insufficient_evidence",
                "raw_step_count": raw_count,
                "attack_chain_step_count": 0,
                "paths": path_meta,
            }

        self.store.update_writeup_chain(
            writeup_id,
            attack_chain_source="recovered_from_trace",
            coverage_status="ok",
            chain_paths_json=json.dumps(path_meta, ensure_ascii=False),
            chain_notes=notes,
        )
        return {
            "writeup_id": writeup_id,
            "attack_chain_source": "recovered_from_trace",
            "coverage_status": "ok",
            "raw_step_count": raw_count,
            "attack_chain_step_count": selected_count,
            "paths": path_meta,
            "notes": notes,
        }

    def _paths_to_steps(
        self,
        writeup_id: str,
        data: dict,
        existing_for_enrich: Optional[list] = None,
    ) -> tuple[list[AttackStep], list[PathEdge], list[dict]]:
        steps: list[AttackStep] = []
        edges: list[PathEdge] = []
        path_meta: list[dict[str, Any]] = []
        seq = 0
        prev_selected_id: Optional[str] = None

        for p in data.get("paths") or []:
            pid = str(p.get("path_id") or f"path{len(path_meta)+1}")
            path_meta.append(
                {
                    "path_id": pid,
                    "summary": p.get("summary") or "",
                    "step_sequences": [],
                }
            )
            prev_selected_id = None
            for st in p.get("steps") or []:
                status = str(st.get("chain_status") or "selected").lower()
                if status not in ("selected", "excluded"):
                    status = "selected"
                action = str(st.get("action") or "").strip()
                evidence = str(st.get("evidence") or "").strip()
                if not action and not evidence:
                    continue
                # Enrich evidence from prior analyze steps when quote is thin
                if existing_for_enrich and len(evidence) < 40:
                    evidence = self._enrich_evidence(
                        action, evidence, existing_for_enrich
                    )
                seq += 1
                step_id = f"{writeup_id}_c{seq:04d}_{uuid.uuid4().hex[:6]}"
                et = EvidenceType.direct
                step = AttackStep(
                    step_id=step_id,
                    writeup_id=writeup_id,
                    sequence=seq,
                    action=action or evidence[:80],
                    target=st.get("target"),
                    input=st.get("input"),
                    output=st.get("output"),
                    purpose=st.get("purpose") or st.get("chain_reason"),
                    prerequisite=st.get("prerequisite"),
                    evidence=evidence or action,
                    evidence_location=f"chain:{pid}:seq{seq}",
                    evidence_type=et,
                    inference=False,
                    confidence=float(st.get("confidence") or 0.7),
                    chunk_id="chain_extract",
                    step_type=str(st.get("step_type") or "other"),
                    phase=str(st.get("phase") or "其他"),
                    chain_status=status,
                    chain_reason=str(st.get("chain_reason") or ""),
                    path_id=pid if status == "selected" else "",
                    depends_on_json="[]",
                )
                steps.append(step)
                if status == "selected":
                    path_meta[-1]["step_sequences"].append(seq)
                    if prev_selected_id:
                        edges.append(
                            PathEdge(
                                from_step_id=prev_selected_id,
                                to_step_id=step_id,
                                relation="chain",
                            )
                        )
                    prev_selected_id = step_id
        return steps, edges, path_meta

    @staticmethod
    def _enrich_evidence(action: str, evidence: str, existing: list) -> str:
        key = (action or "")[:40].lower()
        for s in existing:
            blob = f"{s['action'] or ''} {s['evidence'] or ''}".lower()
            if key and key in blob and (s["evidence"] or ""):
                return str(s["evidence"])[:500]
        return evidence

    def _offline_extract(self, section_text: str, max_steps: int) -> dict:
        """Heuristic extract when LLM unavailable (smoke / CI)."""
        lines = [
            ln.strip(" -*\t")
            for ln in section_text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        steps = []
        seq = 0
        for ln in lines:
            if len(ln) < 12:
                continue
            seq += 1
            failed = bool(_FAILED.search(ln))
            steps.append(
                {
                    "sequence": seq,
                    "action": ln[:120],
                    "step_type": "other",
                    "phase": "其他",
                    "evidence": ln[:400],
                    "chain_status": "excluded" if failed else "selected",
                    "chain_reason": "offline: failed-branch keyword"
                    if failed
                    else "offline: narrative line",
                    "confidence": 0.4,
                }
            )
            if seq >= max_steps:
                break
        return {
            "objective": "",
            "paths": [{"path_id": "path1", "summary": "offline extract", "steps": steps}],
        }

    def _offline_recover(self, existing: list) -> dict:
        steps_out = []
        for s in existing:
            blob = f"{s['action'] or ''}\n{s['evidence'] or ''}"
            failed = bool(_FAILED.search(blob))
            steps_out.append(
                {
                    "source_sequence": int(s["sequence"]),
                    "chain_status": "excluded" if failed else "selected",
                    "chain_reason": "offline: failed keyword"
                    if failed
                    else "offline: keep pending causal filter",
                    "depends_on_sequences": [],
                    "confidence": 0.35,
                }
            )
        return {
            "unresolved": False,
            "objective": "",
            "paths": [
                {"path_id": "path1", "summary": "offline recover", "steps": steps_out}
            ],
        }
