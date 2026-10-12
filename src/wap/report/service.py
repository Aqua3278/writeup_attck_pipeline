from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from wap.db.store import Store
from wap.mapping.attck_meta import (
    display_technique,
    technique_zh,
    tactic_zh,
)
from wap.utils.config import load_yaml, resolve_path

_STATUS_ZH = {
    "retained": "保留",
    "excluded": "排除",
    "unmatched": "未匹配",
    "pending_review": "待审",
}
_ROLE_ZH = {
    "primary": "主要",
    "secondary": "辅助",
    "sole": "唯一",
}


def _one_line(text: str, max_len: int = 160) -> str:
    s = re.sub(r"\s+", " ", (text or "").strip())
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _format_ensemble_block(m: dict) -> list[str]:
    """Render multi-model vote audit from ensemble_json / candidates_json."""
    raw = (m.get("ensemble_json") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [f"投票审计：（无法解析 ensemble_json）"]
    if not isinstance(data, dict):
        return []
    lines: list[str] = []
    if data.get("skip") == "empty_candidates":
        lines.append("投票：未进入模型（候选为空）")
        return lines
    if data.get("skip") == "non_coverage_step_type":
        return lines
    cands = data.get("candidates")
    if cands is None:
        try:
            cands = json.loads(m.get("candidates_json") or "[]")
        except json.JSONDecodeError:
            cands = []
    if cands:
        lines.append(f"候选集：{', '.join(str(x) for x in cands)}")
    models = data.get("models") or {}
    judgments = data.get("judgments") or {}
    for role in ("model_a", "model_b", "model_c"):
        j = judgments.get(role)
        if not j:
            continue
        mid = (models.get(role) or {}).get("model") or role
        stance = j.get("stance") or "?"
        reason = _one_line(str(j.get("reason") or ""), 120)
        lines.append(f"模型{role[-1].upper()}（{mid}）：{stance}" + (f"；{reason}" if reason else ""))
    vote = data.get("vote")
    if vote:
        lines.append(f"投票结果：{vote}")
    return lines


def _md_evidence_block(text: str, max_len: int = 900) -> list[str]:
    """Render evidence as a safe fenced block (no nested ``` breakage)."""
    s = (text or "").strip()
    # Drop noisy HTML wrappers from RedAmon/session dumps
    s = re.sub(r"</?details[^>]*>", "", s, flags=re.I)
    s = re.sub(r"</?summary[^>]*>", "", s, flags=re.I)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    # Neutralize markdown fences / headings that break the report
    s = s.replace("```", "'''")
    # Avoid accidental markdown headings inside evidence
    s = re.sub(r"(?m)^(#{1,6}\s)", lambda m: "＃" + m.group(0).lstrip("#"), s)
    return ["```text", s, "```", ""]


class ReportService:
    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])
        self.out = resolve_path(self.cfg["exports_dir"])
        self.out.mkdir(parents=True, exist_ok=True)

    def export_writeup(self, writeup_id: str) -> Path:
        wdir = self.out / "writeups" / writeup_id
        wdir.mkdir(parents=True, exist_ok=True)
        steps = [dict(r) for r in self.store.get_steps(writeup_id)]
        maps = [dict(r) for r in self.store.get_mappings(writeup_id)]
        for row in steps + maps:
            row.pop("confidence", None)
        meta = next(
            (dict(r) for r in self.store.list_writeups() if r["writeup_id"] == writeup_id),
            {},
        )
        catalog = self.store.get_catalog_by_id()
        steps_by_id = {s["step_id"]: s for s in steps}

        retained = [m for m in maps if m["mapping_status"] == "retained"]
        excluded = [m for m in maps if m["mapping_status"] == "excluded"]
        unmatched = [m for m in maps if m["mapping_status"] == "unmatched"]
        pending_all = [m for m in maps if m["mapping_status"] == "pending_review"]
        retained_unique = {m["technique_id"] for m in retained if m["technique_id"]}
        # Pending only if not already retained elsewhere in this writeup
        pending = [
            m
            for m in pending_all
            if (not m.get("technique_id")) or (m["technique_id"] not in retained_unique)
        ]
        pending_unique = {m["technique_id"] for m in pending if m["technique_id"]}
        pending_no_tid = [m for m in pending if not m.get("technique_id")]
        pending_steps_by_tid: dict[str, list[int]] = defaultdict(list)
        for m in pending:
            tid = m.get("technique_id")
            if not tid:
                continue
            st = steps_by_id.get(m.get("step_id") or "", {})
            try:
                seq = int(st.get("sequence") or 0)
            except (TypeError, ValueError):
                seq = 0
            if seq and seq not in pending_steps_by_tid[tid]:
                pending_steps_by_tid[tid].append(seq)
        for tid in pending_steps_by_tid:
            pending_steps_by_tid[tid].sort()

        (wdir / "attack_path.json").write_text(
            json.dumps(steps, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        chain_summary = {
            "benchmark": meta.get("benchmark_name") or meta.get("source_id") or "",
            "task": meta.get("task_name") or "",
            "attack_chain_source": meta.get("attack_chain_source") or "",
            "coverage_status": meta.get("coverage_status") or "",
            "raw_step_count": len(steps),
            "attack_chain_step_count": sum(
                1 for s in steps if (s.get("chain_status") or "") == "selected"
            ),
            "chain_paths_json": meta.get("chain_paths_json") or "[]",
            "chain_notes": meta.get("chain_notes") or "",
            "retained_techniques": sorted(retained_unique),
            "pending_review_techniques": sorted(pending_unique),
            "pending_review_by_step": {
                tid: pending_steps_by_tid[tid] for tid in sorted(pending_unique)
            },
            "pending_review_without_technique": len(pending_no_tid),
            "pending_review_suppressed_already_retained": sum(
                1
                for m in pending_all
                if m.get("technique_id") and m["technique_id"] in retained_unique
            ),
        }
        (wdir / "attack_chain.json").write_text(
            json.dumps(chain_summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (wdir / "technique_mapping.json").write_text(
            json.dumps(maps, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self._write_csv(wdir / "attack_path.csv", steps)
        self._write_csv(wdir / "technique_mapping.csv", maps)

        maps_by_step: dict[str, list[dict]] = defaultdict(list)
        for m in maps:
            maps_by_step[m["step_id"]].append(m)

        title = meta.get("title") or writeup_id
        task = meta.get("task_name") or ""
        source = meta.get("source_name") or meta.get("source_id") or ""

        md: list[str] = [
            f"# {title}",
            "",
            "## 概要",
            "",
            f"- **writeup_id**: `{writeup_id}`",
            f"- **source**: {source}",
        ]
        if task:
            md.append(f"- **task**: {task}")
        if meta.get("canonical_url"):
            md.append(f"- **url**: {meta['canonical_url']}")
        chain_src = meta.get("attack_chain_source") or ""
        cov_status = meta.get("coverage_status") or ""
        selected_steps = [
            s for s in steps if (s.get("chain_status") or "pending") == "selected"
        ]
        if chain_src:
            md.append(f"- **attack_chain_source**: `{chain_src}`")
        if cov_status:
            md.append(f"- **coverage_status**: `{cov_status}`")
        md.extend(
            [
                f"- **步骤数（raw）**: {len(steps)}",
                f"- **成功攻击链步骤数**: {len(selected_steps)}",
                (
                    f"- **映射条数**: {len(maps)}（保留 {len(retained)} / 排除 {len(excluded)}"
                    f" / 未匹配 {len(unmatched)} / 待审原始 {len(pending_all)}）"
                ),
                f"- **覆盖技术数（去重 retained）**: {len(retained_unique)}",
                f"- **coverage**: {', '.join(sorted(retained_unique)) if retained_unique else '（无）'}",
                (
                    f"- **pending_review（未在 retained 出现）**: "
                    + (
                        ", ".join(
                            f"{tid}（Step {', '.join(str(s) for s in pending_steps_by_tid[tid])}）"
                            for tid in sorted(pending_unique)
                        )
                        if pending_unique
                        else "（无）"
                    )
                    + (
                        f"；另有 {len(pending_no_tid)} 条无 technique_id"
                        if pending_no_tid
                        else ""
                    )
                ),
                "",
                "## 攻击路径概览",
                "",
            ]
        )
        # Phase chain: first-seen order among successful-path steps
        chain_phases: list[str] = []
        seen_ph: set[str] = set()
        phase_src = selected_steps or steps
        for s in phase_src:
            st = s.get("step_type") or "other"
            if st in ("tool_setup", "data_processing", "validation"):
                continue
            if selected_steps and (s.get("chain_status") or "") != "selected":
                continue
            ph = s.get("phase") or "其他"
            if ph == "其他" or ph in seen_ph:
                continue
            seen_ph.add(ph)
            chain_phases.append(ph)
        if chain_phases:
            md.append(" → ".join(chain_phases))
        else:
            md.append("（无可展示的攻击阶段）")
        md.extend(["", "## 攻击路径（成功链 Step 与 ATT&CK 绑定）", ""])
        if cov_status == "insufficient_evidence":
            md.append("> coverage_status=insufficient_evidence：未生成 ATT&CK Coverage。")
            md.append("")

        # Prefer selected chain steps; list by sequence (phase is a label only)
        report_steps = sorted(
            selected_steps or steps,
            key=lambda s: int(s.get("sequence") or 0),
        )

        for s in report_steps:
            st = s.get("step_type") or "other"
            phase = s.get("phase") or "其他"
            md.append(f"### Step {s['sequence']}｜{s['action']}")
            md.append("")
            md.append(f"- **phase**: {phase}")
            md.append(f"- **step_type**: `{st}`")
            if s.get("chain_status"):
                md.append(f"- **chain_status**: `{s.get('chain_status')}`")
            if s.get("path_id"):
                md.append(f"- **path_id**: `{s.get('path_id')}`")
            if s.get("chain_reason"):
                md.append(f"- **chain_reason**: {_one_line(s.get('chain_reason') or '', 200)}")
            md.append(f"- **证据类型**: {s.get('evidence_type')}")
            if s.get("target"):
                md.append(f"- **目标**: {s['target']}")
            md.append("- **证据**:")
            md.append("")
            md.extend(_md_evidence_block(s.get("evidence") or ""))
            step_maps = maps_by_step.get(s["step_id"], [])
            if not step_maps:
                md.append("- **ATT&CK**: （本步无映射记录）")
                md.append("")
                md.append("---")
                md.append("")
                continue
            md.append("- **ATT&CK**:")
            md.append("")
            for m in sorted(
                step_maps,
                key=lambda x: (
                    0
                    if x.get("mapping_role") == "primary"
                    else 1
                    if x.get("mapping_role") == "sole"
                    else 2
                ),
            ):
                tid = m.get("technique_id")
                if tid:
                    label = display_technique(
                        tid,
                        m.get("technique_name") or "",
                        (catalog[tid].technique_name_zh if tid in catalog else ""),
                    )
                else:
                    label = "（无技术）"
                st_zh = _STATUS_ZH.get(
                    m.get("mapping_status") or "", m.get("mapping_status")
                )
                role = _ROLE_ZH.get(
                    m.get("mapping_role") or "sole", m.get("mapping_role")
                )
                md.append(f"**{label}**｜{st_zh}（{role}）")
                md.append("")
                behavior = (m.get("supporting_behavior") or "").strip()
                reason = (m.get("mapping_reason") or "").strip()
                if behavior:
                    md.append(f"行为依据：{_one_line(behavior)}")
                if "[最终裁决]" in reason and "[模型原始判断]" in reason:
                    model_part, _, verdict_part = reason.partition("[最终裁决]")
                    model_part = model_part.replace("[模型原始判断]", "").strip()
                    verdict_part = verdict_part.strip().lstrip("；")
                    if model_part:
                        md.append(f"模型原始判断：{_one_line(model_part)}")
                    md.append(f"最终裁决：{_one_line(verdict_part)}")
                elif "；[自动降级]" in reason:
                    # Legacy demotion format from older runs
                    base, _, note = reason.partition("；[自动降级]")
                    if base.strip():
                        md.append(f"模型原始判断：{_one_line(base)}")
                    md.append(
                        f"最终裁决：excluded；{_one_line(note.lstrip('；'))}"
                    )
                elif reason:
                    md.append(f"映射理由：{_one_line(reason)}")
                ens_lines = _format_ensemble_block(m)
                md.extend(ens_lines)
                md.append("")
            md.append("---")
            md.append("")

        # Coverage section
        md.extend(["## ATT&CK 覆盖（仅 retained，本 writeup 去重）", ""])
        if not retained_unique:
            md.append("（无 retained 技术）")
        else:
            by_tactic: dict[str, list[str]] = defaultdict(list)
            for tid in sorted(retained_unique):
                tref = catalog.get(tid)
                tac = tactic_zh(tref.tactic) if tref else "其他"
                by_tactic[tac].append(
                    display_technique(
                        tid,
                        tref.technique_name if tref else "",
                        tref.technique_name_zh if tref else "",
                    )
                )
            for tac, items in by_tactic.items():
                md.append(f"### {tac}")
                for item in items:
                    md.append(f"- {item}")
                md.append("")

        # Pending review: only techniques not already retained; include step pointers
        md.extend(
            [
                "## 待审（pending_review，且未出现在 retained；不计入 coverage）",
                "",
            ]
        )
        if not pending_unique and not pending_no_tid:
            md.append("（无额外待审项；已在 retained 中的 pending 已省略）")
        else:
            if pending_unique:
                by_tactic_p: dict[str, list[tuple[str, str]]] = defaultdict(list)
                for tid in sorted(pending_unique):
                    tref = catalog.get(tid)
                    tac = tactic_zh(tref.tactic) if tref else "其他"
                    label = display_technique(
                        tid,
                        tref.technique_name if tref else "",
                        tref.technique_name_zh if tref else "",
                    )
                    seqs = pending_steps_by_tid.get(tid) or []
                    step_hint = (
                        "Step " + ", ".join(str(s) for s in seqs) if seqs else "Step ?"
                    )
                    by_tactic_p[tac].append((label, step_hint))
                for tac, items in by_tactic_p.items():
                    md.append(f"### {tac}")
                    for label, step_hint in items:
                        md.append(f"- {label} — 见 **{step_hint}**")
                    md.append("")
            if pending_no_tid:
                md.append("### 无 technique_id")
                for m in pending_no_tid:
                    st = steps_by_id.get(m.get("step_id") or "", {})
                    seq = st.get("sequence", "?")
                    action = _one_line(st.get("action") or "", 80)
                    reason = _one_line(m.get("mapping_reason") or "", 160)
                    line = f"- **Step {seq}**"
                    if action:
                        line += f"（{action}）"
                    line += f"：{reason or '（无理由）'}"
                    md.append(line)
                md.append("")

        (wdir / "report.md").write_text("\n".join(md), encoding="utf-8")
        return wdir

    def global_report(self) -> Path:
        writeups = [dict(r) for r in self.store.list_writeups()]
        maps = [dict(r) for r in self.store.get_mappings()]
        by_source = Counter(w["source_id"] for w in writeups)
        crawl_ok = sum(1 for w in writeups if w["crawl_status"] == "success")
        crawl_fail = sum(1 for w in writeups if w["crawl_status"] == "failed")

        retained_hits = [m for m in maps if m["mapping_status"] == "retained"]
        excluded_hits = [m for m in maps if m["mapping_status"] == "excluded"]
        unmatched = [m for m in maps if m["mapping_status"] == "unmatched"]
        pending = [m for m in maps if m["mapping_status"] == "pending_review"]

        # Per-writeup unique techniques (coverage unit)
        writeup_tech: dict[str, set[str]] = defaultdict(set)
        for m in retained_hits:
            if m["technique_id"]:
                writeup_tech[m["writeup_id"]].add(m["technique_id"])
        retained_ids = set().union(*writeup_tech.values()) if writeup_tech else set()
        # hit_count = how many writeups cover the technique (not raw mapping rows)
        hit_counts = Counter()
        for techs in writeup_tech.values():
            for tid in techs:
                hit_counts[tid] += 1

        by_src_tech: dict[str, set[str]] = defaultdict(set)
        by_task_tech: dict[str, set[str]] = defaultdict(set)
        windex = {w["writeup_id"]: w for w in writeups}
        for wid, techs in writeup_tech.items():
            w = windex.get(wid)
            if not w:
                continue
            by_src_tech[w["source_id"]].update(techs)
            task = w.get("task_name") or wid
            by_task_tech[task].update(techs)

        # Traceability: each retained technique → writeup/step/evidence
        steps_index: dict[str, dict] = {}
        for w in writeups:
            for s in self.store.get_steps(w["writeup_id"]):
                steps_index[s["step_id"]] = dict(s)
        evidence_rows = []
        seen_pair: set[tuple[str, str]] = set()
        for m in retained_hits:
            tid = m.get("technique_id")
            if not tid:
                continue
            key = (m["writeup_id"], tid)
            # keep first / primary evidence trail per writeup+technique
            if key in seen_pair and m.get("mapping_role") == "secondary":
                continue
            seen_pair.add(key)
            st = steps_index.get(m["step_id"], {})
            w = windex.get(m["writeup_id"], {})
            evidence_rows.append(
                {
                    "technique_id": tid,
                    "technique_name": m.get("technique_name") or "",
                    "writeup_id": m["writeup_id"],
                    "source_id": w.get("source_id") or "",
                    "task_name": w.get("task_name") or "",
                    "step_id": m["step_id"],
                    "step_sequence": st.get("sequence", ""),
                    "step_action": st.get("action") or "",
                    "mapping_role": m.get("mapping_role") or "",
                    "evidence": (m.get("evidence") or "")[:500],
                    "mapping_reason": (m.get("mapping_reason") or "")[:500],
                }
            )

        summary = {
            "writeups_total": len(writeups),
            "by_source": dict(by_source),
            "crawl_success": crawl_ok,
            "crawl_failed_records": crawl_fail,
            "unresolved_crawl_failures": len(self.store.list_unresolved_failures()),
            "steps_total": sum(len(self.store.get_steps(w["writeup_id"])) for w in writeups),
            "retained_mapping_rows": len(retained_hits),
            "retained_unique_techniques": len(retained_ids),
            "excluded_hit_count": len(excluded_hits),
            "unmatched_count": len(unmatched),
            "pending_review_count": len(pending),
            "coverage_unit": "unique technique per writeup (retained only)",
        }
        (self.out / "source_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        cov_rows = [
            {
                "technique_id": tid,
                "writeup_coverage_count": cnt,
                "note": "count = number of writeups covering this technique (deduped)",
            }
            for tid, cnt in hit_counts.most_common()
        ]
        self._write_csv(self.out / "technique_coverage.csv", cov_rows)

        src_rows = [
            {
                "source_id": sid,
                "retained_unique_techniques": len(techs),
                "technique_ids": ",".join(sorted(techs)),
            }
            for sid, techs in by_src_tech.items()
        ]
        self._write_csv(self.out / "technique_coverage_by_source.csv", src_rows)

        task_rows = [
            {
                "task_name": task,
                "retained_unique_techniques": len(techs),
                "technique_ids": ",".join(sorted(techs)),
            }
            for task, techs in by_task_tech.items()
        ]
        self._write_csv(self.out / "technique_coverage_by_task.csv", task_rows)
        self._write_csv(self.out / "coverage_evidence.csv", evidence_rows)

        self._write_csv(
            self.out / "unmatched_behaviors.csv",
            [
                {
                    "writeup_id": m["writeup_id"],
                    "step_id": m["step_id"],
                    "reason": m["mapping_reason"],
                    "evidence": m["evidence"],
                }
                for m in unmatched
            ],
        )
        self._write_csv(
            self.out / "review_queue.csv",
            [
                {
                    "writeup_id": m["writeup_id"],
                    "mapping_id": m["mapping_id"],
                    "technique_id": m["technique_id"],
                    "reason": m["mapping_reason"],
                }
                for m in pending
            ],
        )

        fails = [dict(r) for r in self.store.list_unresolved_failures()]
        self._write_csv(self.out / "crawl_failures.csv", fails)

        md = [
            "# Pipeline quality report",
            "",
            "## Summary",
            f"- writeups: {summary['writeups_total']}",
            f"- crawl success: {summary['crawl_success']}",
            f"- steps: {summary['steps_total']}",
            f"- retained mapping rows: {summary['retained_mapping_rows']}",
            f"- retained unique techniques (global): {summary['retained_unique_techniques']}",
            f"- excluded: {summary['excluded_hit_count']}",
            f"- unmatched: {summary['unmatched_count']}",
            f"- pending review: {summary['pending_review_count']}",
            "",
            "## Coverage rules",
            "- Only `mapping_status=retained` counts.",
            "- Within one writeup, each technique_id counts once.",
            "- Traceability: see `coverage_evidence.csv` (technique → writeup → step → evidence).",
            "- Excluded (yellow / demoted) never enters coverage.",
        ]
        (self.out / "report.md").write_text("\n".join(md), encoding="utf-8")
        return self.out

    @staticmethod
    def _write_csv(path: Path, rows: list[dict]) -> None:
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        keys = sorted({k for r in rows for k in r.keys()})
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in keys})
