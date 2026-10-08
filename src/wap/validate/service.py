from __future__ import annotations

import re
import uuid
from collections import Counter
from typing import Optional

from wap.db.store import Store
from wap.mapping.attck_meta import NON_COVERAGE_STEP_TYPES
from wap.mapping.rules import WEAK_REASON
from wap.models.schemas import ValidationIssue
from wap.utils.config import load_yaml, resolve_path

_HTTP_ONLY_ACTION = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/",
    re.I,
)
_OVERCLAIM = re.compile(
    r"(成功利用|成功越权|其他用户|管理员权限|获得.?shell|IDR\s*成功|"
    r"successfully\s+exploited|other\s+user.?s?\s+(order|data))",
    re.I,
)


class ValidateService:
    """End-to-end consistency checks: Step / Evidence / Mapping / Coverage rules."""

    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])

    def validate_writeup(self, writeup_id: str) -> list[ValidationIssue]:
        catalog = self.store.get_catalog_by_id()
        rows = [r for r in self.store.list_writeups() if r["writeup_id"] == writeup_id]
        issues: list[ValidationIssue] = []
        if not rows:
            return issues
        w = rows[0]
        body = ""
        if w["parsed_content_path"]:
            p = resolve_path(w["parsed_content_path"])
            if p.exists():
                body = p.read_text(encoding="utf-8")

        steps = self.store.get_steps(writeup_id)
        seqs = [s["sequence"] for s in steps]
        if seqs != sorted(seqs):
            issues.append(
                ValidationIssue(
                    issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                    writeup_id=writeup_id,
                    severity="warning",
                    code="step_order",
                    message="attack step sequence is not sorted",
                )
            )

        step_by_id = {s["step_id"]: s for s in steps}
        http_only = 0
        for s in steps:
            if not (s["action"] or "").strip():
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        step_id=s["step_id"],
                        severity="error",
                        code="empty_step",
                        message="empty step action",
                    )
                )
            if _HTTP_ONLY_ACTION.match((s["action"] or "").strip()):
                http_only += 1
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        step_id=s["step_id"],
                        severity="warning",
                        code="request_level_step",
                        message="action looks like a single HTTP log line; prefer behavioral units",
                    )
                )
            if s["evidence_type"] == "inferred" and not s["inference"]:
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        step_id=s["step_id"],
                        severity="warning",
                        code="inference_unmarked",
                        message="inferred evidence_type without inference=true",
                    )
                )
            if s["evidence"] and body and s["evidence"][:40] not in body:
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        step_id=s["step_id"],
                        severity="info",
                        code="evidence_not_found_verbatim",
                        message="evidence quote not found verbatim in parsed body",
                        details={"evidence": s["evidence"][:200]},
                    )
                )
            # action overclaims vs thin evidence
            ev = s["evidence"] or ""
            if _OVERCLAIM.search(s["action"] or "") and not _OVERCLAIM.search(ev):
                if not re.search(r"(other\s+user|越权|管理员|shell|RCE)", ev, re.I):
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            step_id=s["step_id"],
                            severity="warning",
                            code="action_exceeds_evidence",
                            message="action claims exploit/success beyond evidence text",
                        )
                    )

        if http_only >= 5:
            issues.append(
                ValidationIssue(
                    issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                    writeup_id=writeup_id,
                    severity="warning",
                    code="http_log_shredding",
                    message=f"{http_only} steps look like HTTP log shredding",
                )
            )

        chain_source = (
            w["attack_chain_source"] if "attack_chain_source" in w.keys() else None
        ) or ""
        coverage_status = (
            w["coverage_status"] if "coverage_status" in w.keys() else None
        ) or ""
        if chain_source == "unresolved" or coverage_status == "insufficient_evidence":
            maps = self.store.get_mappings(writeup_id)
            if any(m["mapping_status"] == "retained" for m in maps):
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        severity="error",
                        code="coverage_despite_unresolved_chain",
                        message="unresolved attack chain must not retain ATT&CK coverage",
                    )
                )

        retained_per_step: Counter[str] = Counter()
        for m in self.store.get_mappings(writeup_id):
            tid = m["technique_id"]
            status = m["mapping_status"]
            step = step_by_id.get(m["step_id"])
            step_type = (
                step["step_type"] if step and "step_type" in step.keys() else None
            ) or "other"
            chain_st = (
                step["chain_status"] if step and "chain_status" in step.keys() else None
            ) or "pending"

            if status == "retained":
                retained_per_step[m["step_id"]] += 1
                if chain_st not in ("selected", "pending"):
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            mapping_id=m["mapping_id"],
                            step_id=m["step_id"],
                            severity="error",
                            code="retained_off_attack_chain",
                            message=f"retained mapping on chain_status={chain_st}",
                        )
                    )

            if tid and tid in catalog:
                t = catalog[tid]
                if m["technique_name"] and m["technique_name"] != t.technique_name:
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            mapping_id=m["mapping_id"],
                            severity="error",
                            code="name_mismatch",
                            message="technique_name disagrees with Excel catalog metadata",
                        )
                    )
                if status == "retained" and not t.retained:
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            mapping_id=m["mapping_id"],
                            severity="error",
                            code="excluded_counted_as_retained",
                            message="yellow/excluded catalog technique marked retained",
                        )
                    )
            elif tid and tid not in catalog:
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        mapping_id=m["mapping_id"],
                        severity="warning",
                        code="unknown_technique_id",
                        message=f"technique_id {tid} not in catalog",
                    )
                )

            if status != "unmatched" and not (m["evidence"] or "").strip():
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        mapping_id=m["mapping_id"],
                        severity="error",
                        code="missing_evidence",
                        message="mapping lacks evidence",
                    )
                )

            if status == "retained" and WEAK_REASON.search(m["mapping_reason"] or ""):
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        mapping_id=m["mapping_id"],
                        severity="error",
                        code="weak_reason_retained",
                        message="retained uses speculative / keyword / circular reason",
                    )
                )

            if status == "retained" and step_type in NON_COVERAGE_STEP_TYPES:
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        mapping_id=m["mapping_id"],
                        step_id=m["step_id"],
                        severity="error",
                        code="non_attack_step_retained",
                        message=f"step_type={step_type} must not retain for coverage",
                    )
                )

            if status == "retained":
                req = m["required_conditions_met"] if "required_conditions_met" in m.keys() else 1
                if not req:
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            mapping_id=m["mapping_id"],
                            severity="error",
                            code="required_conditions_false",
                            message="retained but required_conditions_met=false",
                        )
                    )
                directness = (
                    m["evidence_directness"]
                    if "evidence_directness" in m.keys()
                    else "direct"
                )
                if directness == "inferred":
                    issues.append(
                        ValidationIssue(
                            issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                            writeup_id=writeup_id,
                            mapping_id=m["mapping_id"],
                            severity="error",
                            code="inferred_retained",
                            message="retained with inferred evidence_directness",
                        )
                    )

        for sid, n in retained_per_step.items():
            if n > 2:
                issues.append(
                    ValidationIssue(
                        issue_id=f"iss_{uuid.uuid4().hex[:8]}",
                        writeup_id=writeup_id,
                        step_id=sid,
                        severity="warning",
                        code="over_mapping",
                        message=f"step has {n} retained techniques (prefer ≤2)",
                    )
                )

        self.store.save_issues(issues)
        return issues

    def validate_all(self, source_id: Optional[str] = None) -> list[ValidationIssue]:
        all_issues: list[ValidationIssue] = []
        for w in self.store.list_writeups(source_id):
            all_issues.extend(self.validate_writeup(w["writeup_id"]))
        return all_issues
