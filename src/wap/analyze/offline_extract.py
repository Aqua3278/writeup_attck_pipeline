from __future__ import annotations

import re
import uuid
from typing import Optional

from wap.db.store import Store
from wap.models.schemas import AttackStep, EvidenceType, PathEdge
from wap.utils.config import load_yaml, resolve_path

# Lightweight offline extractor for smoke tests when LLM is unavailable.
CMD_PATTERNS = [
    (r"nmap[^\n]*", "network scan with nmap", "T1046"),
    (r"GetNPUsers\.py[^\n]*", "AS-REP roasting with GetNPUsers", "T1558"),
    (r"hashcat[^\n]*|john[^\n]*", "offline password cracking", "T1110"),
    (r"smbclient[^\n]*|smbmap[^\n]*", "SMB share access", "T1021"),
    (r"evil-winrm[^\n]*|psexec|wmiexec", "remote execution / lateral auth", "T1021"),
    (r"certipy[^\n]*|certify\.exe", "ADCS abuse tooling", "T1649"),
]


class OfflinePathExtractService:
    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])

    def analyze_writeup(self, writeup_id: str) -> dict:
        rows = [r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id]
        if not rows:
            raise KeyError(writeup_id)
        text = resolve_path(rows[0]["parsed_content_path"]).read_text(encoding="utf-8")
        steps: list[AttackStep] = []
        edges: list[PathEdge] = []
        seq = 0
        for pat, action, _hint in CMD_PATTERNS:
            for m in re.finditer(pat, text, re.I):
                seq += 1
                sid = f"{writeup_id}_off_{seq:03d}_{uuid.uuid4().hex[:4]}"
                evidence = m.group(0).strip()[:240]
                steps.append(
                    AttackStep(
                        step_id=sid,
                        writeup_id=writeup_id,
                        sequence=seq,
                        action=action,
                        target=None,
                        input=evidence,
                        output=None,
                        purpose="offline heuristic extraction (no LLM)",
                        prerequisite=None,
                        evidence=evidence,
                        evidence_location=f"offline_regex:{m.start()}",
                        evidence_type=EvidenceType.direct,
                        inference=False,
                        chunk_id="offline",
                        step_type="reconnaissance",
                        phase="侦察",
                    )
                )
        for i in range(len(steps) - 1):
            edges.append(
                PathEdge(
                    from_step_id=steps[i].step_id,
                    to_step_id=steps[i + 1].step_id,
                    relation="sequence",
                )
            )
        self.store.replace_steps(writeup_id, steps, edges)
        return {"writeup_id": writeup_id, "steps": len(steps), "mode": "offline"}