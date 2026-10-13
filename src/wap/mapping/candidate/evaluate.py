from __future__ import annotations

"""Evaluate vector candidate recall on confirmed mapping_cases (not forged labels)."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from wap.mapping.candidate import generate_candidates_detailed
from wap.mapping.candidate.catalog_docs import stub_refs_from_ids
from wap.mapping.candidate.types import CandidateGenConfig
from wap.models.schemas import TechniqueRef

ROOT = Path(__file__).resolve().parents[4]
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "mapping_cases.yaml"
FOCUS_CASES = ("T1190-N1-payload-only", "T1550-P1-stolen-session")


@dataclass
class CaseEval:
    case_id: str
    technique_id: str
    strategy: str
    candidates: list[str]
    contains_ok: Optional[bool]
    excludes_ok: Optional[bool]
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    n_candidates: int = 0
    hits: list[dict[str, Any]] = field(default_factory=list)
    gold_rank: Optional[int] = None
    gold_score: Optional[float] = None


@dataclass
class StrategyReport:
    strategy: str
    select_label: str
    n_confirmed: int = 0
    contain_cases: int = 0
    contain_hit: int = 0
    exclude_cases: int = 0
    exclude_clean: int = 0
    avg_candidates: float = 0.0
    cases: list[CaseEval] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return (self.contain_hit / self.contain_cases) if self.contain_cases else 0.0

    @property
    def exclude_precision(self) -> float:
        return (self.exclude_clean / self.exclude_cases) if self.exclude_cases else 0.0


def load_mapping_cases(path: Path | None = None) -> dict[str, Any]:
    with (path or DEFAULT_FIXTURE).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _gold_rank(hits: list[dict[str, Any]], technique_id: str):
    for h in hits:
        if h.get("technique_id") == technique_id:
            return int(h.get("rank") or 0), float(h.get("score") or 0.0)
    return None, None


def _run_case(case, *, catalog_ids, catalog_refs, cfg) -> Optional[CaseEval]:
    if (case.get("standard_status") or "").strip() != "confirmed":
        return None
    detailed = generate_candidates_detailed(
        action=case.get("action") or "",
        evidence=case.get("evidence") or "",
        purpose=case.get("purpose") or "",
        catalog_ids=catalog_ids,
        prior_selected_steps=case.get("prior_selected_steps") or [],
        catalog_refs=catalog_refs,
        config=cfg,
        strategy="vector",
        max_candidates=cfg.max_candidates,
    )
    cands = detailed.technique_ids
    contains = case.get("expected_candidate_contains")
    excludes = case.get("expected_candidate_excludes")
    missing, unexpected = [], []
    contains_ok = excludes_ok = None
    if contains is not None:
        missing = [t for t in contains if t not in cands]
        contains_ok = not missing
    if excludes is not None:
        unexpected = [t for t in excludes if t in cands]
        excludes_ok = not unexpected
    hits = [h.to_dict() for h in detailed.hits]
    gold_tid = case.get("technique_id") or ""
    gr, gs = _gold_rank(hits, gold_tid)
    return CaseEval(
        case_id=case["id"],
        technique_id=gold_tid,
        strategy="vector",
        candidates=cands,
        contains_ok=contains_ok,
        excludes_ok=excludes_ok,
        missing=missing,
        unexpected=unexpected,
        n_candidates=len(cands),
        hits=hits,
        gold_rank=gr,
        gold_score=gs,
    )


def evaluate_vector(
    *,
    max_candidates: int = 10,
    top_k: Optional[int] = None,
    fixture: Path | None = None,
    catalog_refs: Optional[dict[str, TechniqueRef]] = None,
    base_config: Optional[CandidateGenConfig] = None,
) -> StrategyReport:
    data = load_mapping_cases(fixture)
    fixture_ids = list(data.get("catalog_ids") or [])
    if catalog_refs:
        refs = {k: v for k, v in catalog_refs.items() if v.retained}
        catalog_ids = sorted(refs.keys())
        for tid in fixture_ids:
            if tid not in refs:
                refs[tid] = stub_refs_from_ids([tid])[tid]
                catalog_ids.append(tid)
        catalog_ids = sorted(set(catalog_ids))
    else:
        catalog_ids = fixture_ids
        refs = stub_refs_from_ids(catalog_ids)
        for tid in catalog_ids:
            if tid not in refs:
                refs[tid] = stub_refs_from_ids([tid])[tid]
    k = top_k if top_k is not None else max_candidates
    base = base_config or CandidateGenConfig()
    cfg = CandidateGenConfig(
        strategy="vector",
        max_candidates=k,
        embedding=base.embedding,
    )
    report = StrategyReport(strategy="vector", select_label=f"top_k={k}")
    total_c = 0
    for case in data.get("cases") or []:
        ev = _run_case(
            case,
            catalog_ids=catalog_ids,
            catalog_refs=refs,
            cfg=cfg,
        )
        if ev is None:
            continue
        report.n_confirmed += 1
        report.cases.append(ev)
        total_c += ev.n_candidates
        if ev.contains_ok is not None:
            report.contain_cases += 1
            if ev.contains_ok:
                report.contain_hit += 1
        if ev.excludes_ok is not None:
            report.exclude_cases += 1
            if ev.excludes_ok:
                report.exclude_clean += 1
    report.avg_candidates = (total_c / report.n_confirmed) if report.n_confirmed else 0.0
    return report


def compare_strategies(
    strategies: list[str] | None = None,
    *,
    max_candidates: int = 10,
    top_k_grid: Optional[list[int]] = None,
    fixture: Path | None = None,
    catalog_refs: Optional[dict[str, TechniqueRef]] = None,
    base_config: Optional[CandidateGenConfig] = None,
) -> dict[str, Any]:
    """Backward-compatible name; only evaluates vector Top-K grid."""
    del strategies  # ignored; vector-only
    grid = top_k_grid or [10, 20, 30]
    reports: list[StrategyReport] = []
    for k in grid:
        reports.append(
            evaluate_vector(
                max_candidates=k,
                top_k=k,
                fixture=fixture,
                catalog_refs=catalog_refs,
                base_config=base_config,
            )
        )

    return {
        "fixture": str(fixture or DEFAULT_FIXTURE),
        "gold_note": (
            "Labels from tests/fixtures/mapping_cases.yaml "
            "(confirmed only). Small set (8 contain + 5 exclude) — "
            "preliminary only, not full-coverage proof."
        ),
        "reports": [_report_to_dict(r) for r in reports],
        "pairwise": {},
        "focus_cases": _focus_analysis(reports),
    }


def _focus_analysis(reports: list[StrategyReport]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for case_id in FOCUS_CASES:
        rows = []
        for r in reports:
            for c in r.cases:
                if c.case_id != case_id:
                    continue
                rows.append(
                    {
                        "strategy": r.strategy,
                        "select_label": r.select_label,
                        "candidates": c.candidates,
                        "gold_rank": c.gold_rank,
                        "gold_score": c.gold_score,
                        "contains_ok": c.contains_ok,
                        "top_scores": [
                            {
                                "id": h["technique_id"],
                                "rank": h["rank"],
                                "score": h["score"],
                            }
                            for h in c.hits[:5]
                        ],
                    }
                )
        out[case_id] = rows
    return out


def _report_to_dict(r: StrategyReport) -> dict[str, Any]:
    scores = [h["score"] for c in r.cases for h in c.hits]
    return {
        "strategy": r.strategy,
        "select_label": r.select_label,
        "n_confirmed": r.n_confirmed,
        "contain_cases": r.contain_cases,
        "contain_hit": r.contain_hit,
        "recall": round(r.recall, 4),
        "exclude_cases": r.exclude_cases,
        "exclude_clean": r.exclude_clean,
        "exclude_precision": round(r.exclude_precision, 4),
        "avg_candidates": round(r.avg_candidates, 4),
        "score_stats": {
            "n": len(scores),
            "min": round(min(scores), 4) if scores else None,
            "max": round(max(scores), 4) if scores else None,
            "mean": round(sum(scores) / len(scores), 4) if scores else None,
        },
        "misses": [
            {
                "case_id": c.case_id,
                "missing": c.missing,
                "got": c.candidates,
                "gold_rank": c.gold_rank,
                "gold_score": c.gold_score,
            }
            for c in r.cases
            if c.contains_ok is False
        ],
        "exclude_violations": [
            {
                "case_id": c.case_id,
                "unexpected": c.unexpected,
                "got": c.candidates,
            }
            for c in r.cases
            if c.excludes_ok is False
        ],
        "per_case_ranks": [
            {
                "case_id": c.case_id,
                "technique_id": c.technique_id,
                "gold_rank": c.gold_rank,
                "gold_score": c.gold_score,
                "n_candidates": c.n_candidates,
            }
            for c in r.cases
            if c.contains_ok is not None
        ],
    }


def write_report(payload: dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return out_path
