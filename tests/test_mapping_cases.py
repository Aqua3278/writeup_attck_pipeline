"""Mapping-case regression: candidate recall only.

Semantic retained/excluded is tested in test_ensemble.py with mocked votes.
TBD rows are skipped and counted, never treated as pass/fail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wap.mapping.candidates import generate_candidates

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mapping_cases.yaml"


@dataclass
class CaseResult:
    case_id: str
    technique_id: str
    standard_status: str
    outcome: str  # pass | fail_candidate | skip_tbd
    detail: str = ""


@dataclass
class SuiteReport:
    results: list[CaseResult] = field(default_factory=list)

    @property
    def confirmed_pass(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome == "pass"]

    @property
    def fail_candidate(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome == "fail_candidate"]

    @property
    def skip_tbd(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome == "skip_tbd"]

    def format(self) -> str:
        lines = [
            "=== mapping_cases regression (candidate layer) ===",
            f"total: {len(self.results)}",
            f"confirmed_pass: {len(self.confirmed_pass)}",
            f"fail_candidate: {len(self.fail_candidate)} "
            f"{[r.case_id for r in self.fail_candidate]}",
            f"skip_tbd: {len(self.skip_tbd)} {[r.case_id for r in self.skip_tbd]}",
        ]
        for r in self.fail_candidate:
            lines.append(f"  FAIL [{r.outcome}] {r.case_id}: {r.detail}")
        return "\n".join(lines)


def load_fixture() -> dict[str, Any]:
    with FIXTURE.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data and "cases" in data
    return data


def run_case(case: dict[str, Any], catalog_ids: list[str]) -> CaseResult:
    cid = case["id"]
    tid = case["technique_id"]
    std = (case.get("standard_status") or "TBD").strip()
    if std != "confirmed":
        return CaseResult(cid, tid, std, "skip_tbd", "standard_status != confirmed")

    cands = generate_candidates(
        action=case.get("action") or "",
        evidence=case.get("evidence") or "",
        purpose=case.get("purpose") or "",
        catalog_ids=catalog_ids,
        prior_selected_steps=case.get("prior_selected_steps") or [],
    )
    contains = case.get("expected_candidate_contains")
    excludes = case.get("expected_candidate_excludes")
    if contains is not None:
        missing = [t for t in contains if t not in cands]
        if missing:
            return CaseResult(
                cid, tid, std, "fail_candidate", f"missing {missing}; got {cands}"
            )
    if excludes is not None:
        bad = [t for t in excludes if t in cands]
        if bad:
            return CaseResult(
                cid, tid, std, "fail_candidate", f"unexpected {bad}; got {cands}"
            )
    return CaseResult(cid, tid, std, "pass", "candidate ok")


def run_suite() -> SuiteReport:
    data = load_fixture()
    catalog = list(data.get("catalog_ids") or [])
    report = SuiteReport()
    for case in data["cases"]:
        report.results.append(run_case(case, catalog))
    return report


def test_mapping_cases_fixture_loads():
    data = load_fixture()
    assert data.get("version") == 1
    assert len(data["cases"]) >= 10


def test_mapping_cases_regression_baseline(capsys):
    report = run_suite()
    print(report.format())
    assert not report.fail_candidate, (
        "candidate regressions: "
        + ", ".join(f"{r.case_id} ({r.detail})" for r in report.fail_candidate)
    )
