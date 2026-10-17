from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

from wap.db.store import Store
from wap.mapping.attck_meta import (
    display_technique,
    tactic_zh,
)
from wap.mapping.methods import METHOD_DIRECT_LLM, METHOD_LABELS
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


def _row_method(m: dict) -> str:
    raw = (m.get("mapping_method") or "").strip()
    return raw if raw else METHOD_DIRECT_LLM


def _format_audit_block(m: dict) -> list[str]:
    """Render direct_llm audit from ensemble_json (legacy column name)."""
    raw = (m.get("ensemble_json") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return ["映射审计：（无法解析 audit JSON）"]
    if not isinstance(data, dict):
        return []
    if data.get("skip") == "non_coverage_step_type":
        return []
    lines: list[str] = []
    lines.append(f"映射方法：`{_row_method(m)}`")
    if data.get("model"):
        lines.append(f"模型：{data.get('model')}")
    if data.get("batch_count") is not None:
        lines.append(
            f"目录批次：{data.get('batch_count')}（batch_size={data.get('batch_size')}）"
        )
    kind = data.get("kind")
    if kind:
        lines.append(f"判定：{kind}")
    return lines


def _coverage_stats(maps: list[dict]) -> dict[str, Any]:
    retained = [m for m in maps if m["mapping_status"] == "retained"]
    excluded = [m for m in maps if m["mapping_status"] == "excluded"]
    unmatched = [m for m in maps if m["mapping_status"] == "unmatched"]
    pending_all = [m for m in maps if m["mapping_status"] == "pending_review"]
    retained_unique = {m["technique_id"] for m in retained if m["technique_id"]}
    pending = [
        m
        for m in pending_all
        if (not m.get("technique_id")) or (m["technique_id"] not in retained_unique)
    ]
    pending_unique = {m["technique_id"] for m in pending if m["technique_id"]}
    return {
        "retained": retained,
        "excluded": excluded,
        "unmatched": unmatched,
        "pending_all": pending_all,
        "pending": pending,
        "retained_unique": retained_unique,
        "pending_unique": pending_unique,
        "pending_no_tid": [m for m in pending if not m.get("technique_id")],
    }


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

    def export_writeup(
        self, writeup_id: str, *, method: Optional[str] = None
    ) -> Path:
        wdir = self.out / "writeups" / writeup_id
        wdir.mkdir(parents=True, exist_ok=True)
        steps = [dict(r) for r in self.store.get_steps(writeup_id)]
        # Default: direct_llm only (legacy ensemble rows ignored unless method set).
        map_method = method if method is not None else METHOD_DIRECT_LLM
        maps = [dict(r) for r in self.store.get_mappings(writeup_id, method=map_method)]
        for row in steps + maps:
            row.pop("confidence", None)
            if "mapping_method" in row or row.get("mapping_id"):
                row["mapping_method"] = _row_method(row)
        meta = next(
            (dict(r) for r in self.store.list_writeups() if r["writeup_id"] == writeup_id),
            {},
        )
        catalog = self.store.get_catalog_by_id()
        steps_by_id = {s["step_id"]: s for s in steps}

        by_method: dict[str, list[dict]] = defaultdict(list)
        for m in maps:
            by_method[_row_method(m)].append(m)
        methods_present = sorted(by_method.keys()) or [map_method]
        primary_method = map_method
        primary_maps = by_method.get(primary_method, maps)
        stats = _coverage_stats(primary_maps)
        retained = stats["retained"]
        excluded = stats["excluded"]
        unmatched = stats["unmatched"]
        pending_all = stats["pending_all"]
        pending = stats["pending"]
        retained_unique = stats["retained_unique"]
        pending_unique = stats["pending_unique"]
        pending_no_tid = stats["pending_no_tid"]
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

        coverage_by_method = {
            meth: sorted(_coverage_stats(rows)["retained_unique"])
            for meth, rows in by_method.items()
        }

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
            "mapping_methods": methods_present,
            "coverage_by_method": coverage_by_method,
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
        self._write_csv(wdir / "attack_path.csv", steps)
        (wdir / "technique_mapping.json").write_text(
            json.dumps(maps, ensure_ascii=False, indent=2), encoding="utf-8"
        )
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
                f"- **映射方法**: {', '.join(f'`{m}`' for m in methods_present)}",
                (
                    f"- **映射条数（主方法 `{primary_method}`）**: {len(primary_maps)}"
                    f"（保留 {len(retained)} / 排除 {len(excluded)}"
                    f" / 未匹配 {len(unmatched)} / 待审原始 {len(pending_all)}）"
                ),
                f"- **覆盖技术数（去重 retained，`{primary_method}`）**: {len(retained_unique)}",
                f"- **coverage（`{primary_method}`）**: {', '.join(sorted(retained_unique)) if retained_unique else '（无）'}",
            ]
        )
        for meth, tids in coverage_by_method.items():
            if meth == primary_method:
                continue
            md.append(
                f"- **coverage（`{meth}`）**: {', '.join(tids) if tids else '（无）'}"
            )
        md.extend(
            [
                (
                    f"- **pending_review（未在 retained 出现，`{primary_method}`）**: "
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
            step_by_method: dict[str, list[dict]] = defaultdict(list)
            for m in step_maps:
                step_by_method[_row_method(m)].append(m)
            for meth in sorted(step_by_method.keys()):
                label_m = METHOD_LABELS.get(meth, meth)
                md.append(f"- **ATT&CK（`{meth}`）** — {label_m}:")
                md.append("")
                for m in sorted(
                    step_by_method[meth],
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
                        base, _, note = reason.partition("；[自动降级]")
                        if base.strip():
                            md.append(f"模型原始判断：{_one_line(base)}")
                        md.append(
                            f"最终裁决：excluded；{_one_line(note.lstrip('；'))}"
                        )
                    elif reason:
                        md.append(f"映射理由：{_one_line(reason)}")
                    md.extend(_format_audit_block(m))
                    md.append("")
            md.append("---")
            md.append("")

        # Coverage section (per method)
        for meth in methods_present:
            m_stats = _coverage_stats(by_method.get(meth, []))
            m_retained_unique = m_stats["retained_unique"]
            md.extend(
                [
                    f"## ATT&CK 覆盖（`{meth}`，仅 retained，本 writeup 去重）",
                    "",
                    f"> {METHOD_LABELS.get(meth, meth)}",
                    "",
                ]
            )
            if not m_retained_unique:
                md.append("（无 retained 技术）")
                md.append("")
            else:
                by_tactic: dict[str, list[str]] = defaultdict(list)
                for tid in sorted(m_retained_unique):
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
                f"## 待审（`{primary_method}` pending_review，且未出现在 retained；不计入 coverage）",
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

    def global_report(self, *, method: Optional[str] = None) -> Path:
        writeups = [dict(r) for r in self.store.list_writeups()]
        map_method = method if method is not None else METHOD_DIRECT_LLM
        maps = [dict(r) for r in self.store.get_mappings(method=map_method)]
        for m in maps:
            m["mapping_method"] = _row_method(m)
        by_source = Counter(w["source_id"] for w in writeups)
        crawl_ok = sum(1 for w in writeups if w["crawl_status"] == "success")
        crawl_fail = sum(1 for w in writeups if w["crawl_status"] == "failed")

        methods = sorted({_row_method(m) for m in maps}) or [map_method]

        def _build_for_method(meth: Optional[str]) -> dict[str, Any]:
            subset = (
                maps
                if meth is None
                else [m for m in maps if _row_method(m) == meth]
            )
            retained_hits = [m for m in subset if m["mapping_status"] == "retained"]
            excluded_hits = [m for m in subset if m["mapping_status"] == "excluded"]
            unmatched = [m for m in subset if m["mapping_status"] == "unmatched"]
            pending = [m for m in subset if m["mapping_status"] == "pending_review"]
            writeup_tech: dict[str, set[str]] = defaultdict(set)
            for m in retained_hits:
                if m["technique_id"]:
                    writeup_tech[m["writeup_id"]].add(m["technique_id"])
            retained_ids = (
                set().union(*writeup_tech.values()) if writeup_tech else set()
            )
            hit_counts: Counter = Counter()
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
            return {
                "retained_hits": retained_hits,
                "excluded_hits": excluded_hits,
                "unmatched": unmatched,
                "pending": pending,
                "writeup_tech": writeup_tech,
                "retained_ids": retained_ids,
                "hit_counts": hit_counts,
                "by_src_tech": by_src_tech,
                "by_task_tech": by_task_tech,
                "windex": windex,
            }

        primary = map_method
        agg = _build_for_method(primary)

        retained_hits = agg["retained_hits"]
        excluded_hits = agg["excluded_hits"]
        unmatched = agg["unmatched"]
        pending = agg["pending"]
        writeup_tech = agg["writeup_tech"]
        retained_ids = agg["retained_ids"]
        hit_counts = agg["hit_counts"]
        by_src_tech = agg["by_src_tech"]
        by_task_tech = agg["by_task_tech"]
        windex = agg["windex"]

        steps_index: dict[str, dict] = {}
        for w in writeups:
            for s in self.store.get_steps(w["writeup_id"]):
                steps_index[s["step_id"]] = dict(s)
        evidence_rows = []
        seen_pair: set[tuple[str, str, str]] = set()
        for m in retained_hits:
            tid = m.get("technique_id")
            if not tid:
                continue
            meth = _row_method(m)
            key = (m["writeup_id"], tid, meth)
            if key in seen_pair and m.get("mapping_role") == "secondary":
                continue
            seen_pair.add(key)
            st = steps_index.get(m["step_id"], {})
            w = windex.get(m["writeup_id"], {})
            evidence_rows.append(
                {
                    "mapping_method": meth,
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

        per_method_summary = {}
        for meth in methods:
            m_agg = _build_for_method(meth)
            per_method_summary[meth] = {
                "retained_mapping_rows": len(m_agg["retained_hits"]),
                "retained_unique_techniques": len(m_agg["retained_ids"]),
                "excluded_hit_count": len(m_agg["excluded_hits"]),
                "unmatched_count": len(m_agg["unmatched"]),
                "pending_review_count": len(m_agg["pending"]),
            }

        summary = {
            "writeups_total": len(writeups),
            "by_source": dict(by_source),
            "crawl_success": crawl_ok,
            "crawl_failed_records": crawl_fail,
            "unresolved_crawl_failures": len(self.store.list_unresolved_failures()),
            "steps_total": sum(len(self.store.get_steps(w["writeup_id"])) for w in writeups),
            "mapping_method_filter": map_method,
            "mapping_methods_present": methods,
            "by_mapping_method": per_method_summary,
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
                "mapping_method": primary,
                "technique_id": tid,
                "writeup_coverage_count": cnt,
                "note": "count = number of writeups covering this technique (deduped)",
            }
            for tid, cnt in hit_counts.most_common()
        ]
        self._write_csv(self.out / "technique_coverage.csv", cov_rows)

        src_rows = [
            {
                "mapping_method": primary,
                "source_id": sid,
                "retained_unique_techniques": len(techs),
                "technique_ids": ",".join(sorted(techs)),
            }
            for sid, techs in by_src_tech.items()
        ]
        task_rows = [
            {
                "mapping_method": primary,
                "task_name": task,
                "retained_unique_techniques": len(techs),
                "technique_ids": ",".join(sorted(techs)),
            }
            for task, techs in by_task_tech.items()
        ]
        self._write_csv(self.out / "technique_coverage_by_source.csv", src_rows)
        self._write_csv(self.out / "technique_coverage_by_task.csv", task_rows)
        self._write_csv(self.out / "coverage_evidence.csv", evidence_rows)
        self._write_csv(
            self.out / "unmatched_behaviors.csv",
            [
                {
                    "mapping_method": _row_method(m),
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
                    "mapping_method": _row_method(m),
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
            f"- mapping method: `{primary}`",
            f"- retained mapping rows: {summary['retained_mapping_rows']}",
            f"- retained unique techniques: {summary['retained_unique_techniques']}",
            f"- excluded: {summary['excluded_hit_count']}",
            f"- unmatched: {summary['unmatched_count']}",
            f"- pending review: {summary['pending_review_count']}",
            "",
            "## Coverage rules",
            "- Mapping uses direct_llm (full catalog, single model).",
            "- Only `mapping_status=retained` counts.",
            "- Within one writeup, each technique_id counts once.",
            "- Traceability: see `coverage_evidence.csv`.",
            "- Excluded (yellow) never enters coverage.",
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
