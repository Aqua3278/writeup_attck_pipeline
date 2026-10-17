from pathlib import Path

from wap.mapping.attck_catalog import catalog_summary, load_attck_workbook

ROOT = Path(__file__).resolve().parents[1]
XLSX = ROOT / "attck" / "ATT&CK技巧.xlsx"


def test_load_attck_workbook():
    assert XLSX.exists(), f"missing {XLSX}"
    techs = load_attck_workbook(XLSX)
    summary = catalog_summary(techs)
    assert summary["total_rows"] > 100
    assert summary["retained"] > 0
    assert summary["excluded"] > 0
    # yellow means excluded
    assert any(not t.retained for t in techs)
    assert any(t.retained for t in techs)
    # ids look like Txxxx
    assert all(t.technique_id.startswith("T") for t in techs)