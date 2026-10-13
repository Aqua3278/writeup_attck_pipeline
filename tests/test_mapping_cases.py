"""Mapping-case fixture smoke test.

Semantic retained/excluded is tested in test_ensemble.py with mocked votes.
Vector recall regression uses `python main.py eval-candidates` (needs embedder).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mapping_cases.yaml"


def load_fixture() -> dict[str, Any]:
    with FIXTURE.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data and "cases" in data
    return data


def test_mapping_cases_fixture_loads():
    data = load_fixture()
    assert data.get("version") == 1
    assert len(data["cases"]) >= 10
    assert data.get("catalog_ids")
