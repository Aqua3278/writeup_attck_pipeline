"""Offline ChainService smoke (no LLM, no writeup crawl)."""

import json
from pathlib import Path

from wap.chain.service import ChainService
from wap.db.store import Store
from wap.models.schemas import (
    AttackStep,
    CrawlStatus,
    EvidenceType,
    ParseStatus,
    WriteupRecord,
)
from datetime import datetime, timezone


def _seed(tmp_path: Path, body: str, steps: list[AttackStep] | None = None) -> str:
    db = tmp_path / "t.db"
    parsed = tmp_path / "w.md"
    parsed.write_text(body, encoding="utf-8")
    store = Store(db)
    wid = "test__xben-001__session"
    store.save_writeup(
        WriteupRecord(
            writeup_id=wid,
            source_id="test",
            source_name="test",
            title="XBEN-001",
            canonical_url=f"file://{parsed}",
            task_name="XBEN-001",
            benchmark_name="XBOW",
            crawled_at=datetime.now(timezone.utc),
            raw_content_path=str(parsed),
            parsed_content_path=str(parsed),
            content_hash="abc",
            crawl_status=CrawlStatus.success,
            parse_status=ParseStatus.success,
        )
    )
    if steps:
        store.replace_steps(wid, steps, [])
    return str(db)


def test_offline_full_chain_extract(tmp_path: Path):
    body = """
## What Happened: The Full Attack Chain

1. SSTI probe ruled out — abandoned
2. IDOR on /orders/{id} retrieved other user order
3. Flag in order response
"""
    db = _seed(tmp_path, body)
    svc = ChainService(pipeline_cfg={"db_path": db}, offline=True)
    out = svc.resolve_writeup("test__xben-001__session")
    assert out["attack_chain_source"] == "explicit_full_chain"
    assert out["coverage_status"] == "ok"
    assert out["attack_chain_step_count"] >= 1
    store = Store(db)
    selected = store.get_selected_steps("test__xben-001__session")
    assert selected
    # failed branch should be excluded when keyword present
    statuses = {s["chain_status"] for s in store.get_steps("test__xben-001__session")}
    assert "selected" in statuses


def test_offline_unresolved_clears_coverage(tmp_path: Path):
    db = _seed(tmp_path, "hi")
    svc = ChainService(pipeline_cfg={"db_path": db}, offline=True)
    out = svc.resolve_writeup("test__xben-001__session")
    assert out["attack_chain_source"] == "unresolved"
    assert out["coverage_status"] == "insufficient_evidence"
    meta = next(r for r in Store(db).list_writeups() if r["writeup_id"] == "test__xben-001__session")
    assert meta["coverage_status"] == "insufficient_evidence"


def test_offline_recover_annotates_existing_steps(tmp_path: Path):
    body = """
# Agent log
## Steps
1. nmap
2. exploit B
3. flag_found
""" + ("\n- item\n" * 10) + ("y" * 900)
    steps = [
        AttackStep(
            step_id=f"s{i}",
            writeup_id="test__xben-001__session",
            sequence=i,
            action=a,
            evidence=e,
            evidence_location="t",
            evidence_type=EvidenceType.direct,
            chain_status="pending",
        )
        for i, (a, e) in enumerate(
            [
                ("scan A", "nmap A — no useful result"),
                ("scan B failed", "ruled out path A"),
                ("use B", "smb on B then flag_found"),
            ],
            1,
        )
    ]
    db = _seed(tmp_path, body, steps)
    svc = ChainService(pipeline_cfg={"db_path": db}, offline=True)
    out = svc.resolve_writeup("test__xben-001__session")
    assert out["attack_chain_source"] == "recovered_from_trace"
    store = Store(db)
    by_seq = {s["sequence"]: s for s in store.get_steps("test__xben-001__session")}
    assert by_seq[2]["chain_status"] == "excluded"
    assert by_seq[3]["chain_status"] == "selected"
    paths = json.loads(
        next(r for r in store.list_writeups() if r["writeup_id"] == "test__xben-001__session")[
            "chain_paths_json"
        ]
        or "[]"
    )
    assert paths
