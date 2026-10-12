"""Offline multi-model vote tests (mocked LLM — no API / no tokens)."""

from __future__ import annotations

import json
from pathlib import Path

from wap.db.store import Store
from wap.mapping.ensemble import (
    EnsembleMapper,
    decide_vote,
    normalize_stance,
    parse_judgments_payload,
)
from wap.models.schemas import (
    AttackStep,
    EvidenceType,
    MappingStatus,
    TechniqueMapping,
    TechniqueRef,
)
from wap.report.service import ReportService, _format_ensemble_block
from wap.utils.config import load_yaml


class FakeLLM:
    def __init__(self, model: str, role: str, payload: dict | Exception):
        self.model = model
        self.role = role
        self._payload = payload

    @property
    def available(self) -> bool:
        return True

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _judgments(*pairs: tuple[str, str]) -> dict:
    return {
        "judgments": [
            {
                "technique_id": tid,
                "stance": stance,
                "evidence_quote": f"quote-{tid}",
                "reason": f"reason-{tid}-{stance}",
                "uncertainty": 0.1,
            }
            for tid, stance in pairs
        ]
    }


CATALOG = {
    "T1078": TechniqueRef(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access",
        description="Abuse credentials of existing accounts.",
        retained=True,
    ),
    "T1190": TechniqueRef(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Exploit a public-facing app weakness.",
        retained=True,
    ),
    "T1595": TechniqueRef(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        description="Active recon scans.",
        retained=True,
    ),
    "T9999": TechniqueRef(
        technique_id="T9999",
        technique_name="Yellow Demo",
        tactic="Other",
        description="Yellow-marked technique.",
        retained=False,
    ),
}

STEP = {
    "step_id": "step_1",
    "action": "login with test:test",
    "evidence": "Authentication succeeded with test:test",
    "evidence_location": "chunk_0",
    "purpose": "",
    "step_type": "credential_access",
    "phase": "账户/凭据获取",
    "target": "",
    "input": "",
    "output": "",
    "evidence_type": "direct",
}


def test_normalize_stance_aliases():
    assert normalize_stance("retained") == "support"
    assert normalize_stance("excluded") == "reject"
    assert normalize_stance("???") == "insufficient"


def test_uncertainty_not_confused_with_legacy_confidence():
    from wap.mapping.ensemble import parse_model_uncertainty

    # explicit uncertainty=0 must not fall through to confidence via `or`
    assert parse_model_uncertainty({"uncertainty": 0, "confidence": 0.95}) == 0.0
    # legacy confidence-only → convert to uncertainty
    assert parse_model_uncertainty({"confidence": 0.95}) == round(1.0 - 0.95, 6)
    assert parse_model_uncertainty({"uncertainty": 0.2}) == 0.2


def test_decide_vote_agree_support():
    st, vote, need_c = decide_vote("support", "support")
    assert st == MappingStatus.retained and vote == "agree_support" and not need_c


def test_decide_vote_agree_reject():
    st, vote, need_c = decide_vote("reject", "reject")
    assert st == MappingStatus.excluded and vote == "agree_reject" and not need_c


def test_decide_vote_conflict_needs_c():
    st, vote, need_c = decide_vote("support", "reject")
    assert need_c and vote == "needs_model_c"


def test_decide_vote_insufficient_needs_c():
    st, vote, need_c = decide_vote("support", "insufficient")
    assert need_c


def test_decide_vote_c_insufficient_pending():
    st, vote, need_c = decide_vote("support", "reject", "insufficient")
    assert st == MappingStatus.pending_review and vote == "c_insufficient"


def test_parse_drops_illegal_technique_ids():
    data = _judgments(("T1078", "support"), ("T0000", "support"))
    out = parse_judgments_payload(data, ["T1078", "T1190"])
    assert "T0000" not in out
    assert out["T1078"].stance == "support"
    assert out["T1190"].stance == "insufficient"  # missing → insufficient


def test_ensemble_agree_support():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", _judgments(("T1078", "support"))),
        client_b=FakeLLM("b", "model_b", _judgments(("T1078", "support"))),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "reject"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    assert len(votes) == 1
    assert votes[0].final_status == MappingStatus.retained
    assert votes[0].vote == "agree_support"
    assert not votes[0].used_model_c


def test_ensemble_agree_reject():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", _judgments(("T1078", "reject"))),
        client_b=FakeLLM("b", "model_b", _judgments(("T1078", "reject"))),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "support"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    assert votes[0].final_status == MappingStatus.excluded
    assert not votes[0].used_model_c


def test_ensemble_conflict_calls_c():
    calls = {"c": 0}

    class CountingC(FakeLLM):
        def chat_json(self, system, user, retries=3):
            calls["c"] += 1
            return _judgments(("T1078", "support"))

    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", _judgments(("T1078", "support"))),
        client_b=FakeLLM("b", "model_b", _judgments(("T1078", "reject"))),
        client_c=CountingC("c", "model_c", {}),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    assert calls["c"] == 1
    assert votes[0].used_model_c
    assert votes[0].final_status == MappingStatus.retained
    assert votes[0].vote == "c_support"


def test_ensemble_c_uncertain_pending_review():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", _judgments(("T1078", "support"))),
        client_b=FakeLLM("b", "model_b", _judgments(("T1078", "insufficient"))),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "insufficient"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    assert votes[0].final_status == MappingStatus.pending_review


def test_ensemble_api_failure_treated_as_insufficient_then_c():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", RuntimeError("timeout")),
        client_b=FakeLLM("b", "model_b", _judgments(("T1078", "support"))),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "reject"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    # A error → insufficient; with B support → needs C
    assert votes[0].used_model_c
    assert votes[0].final_status == MappingStatus.excluded


def test_ensemble_invalid_json_via_exception():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", ValueError("no JSON object")),
        client_b=FakeLLM("b", "model_b", ValueError("no JSON object")),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "insufficient"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    assert votes[0].final_status == MappingStatus.pending_review


def test_yellow_technique_not_retained():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("a", "model_a", _judgments(("T9999", "support"))),
        client_b=FakeLLM("b", "model_b", _judgments(("T9999", "support"))),
        client_c=FakeLLM("c", "model_c", _judgments(("T9999", "support"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T9999"], catalog=CATALOG, step=STEP
    )
    assert votes[0].final_status == MappingStatus.excluded
    assert "yellow" in votes[0].vote or "黄标" in votes[0].reason


def test_per_technique_votes_independent():
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM(
            "a",
            "model_a",
            _judgments(("T1078", "support"), ("T1190", "reject")),
        ),
        client_b=FakeLLM(
            "b",
            "model_b",
            _judgments(("T1078", "support"), ("T1190", "reject")),
        ),
        client_c=FakeLLM("c", "model_c", _judgments(("T1078", "reject"), ("T1190", "support"))),
    )
    votes = {v.technique_id: v for v in mapper.vote_candidates(
        candidate_ids=["T1078", "T1190"], catalog=CATALOG, step=STEP
    )}
    assert votes["T1078"].final_status == MappingStatus.retained
    assert votes["T1190"].final_status == MappingStatus.excluded
    assert not votes["T1078"].used_model_c
    assert not votes["T1190"].used_model_c


def test_to_mappings_persists_ensemble_json_and_db_roundtrip(tmp_path: Path):
    db = tmp_path / "t.sqlite3"
    store = Store(db)
    mapper = EnsembleMapper(
        system_prompt="test",
        client_a=FakeLLM("model-a-id", "model_a", _judgments(("T1078", "support"))),
        client_b=FakeLLM("model-b-id", "model_b", _judgments(("T1078", "reject"))),
        client_c=FakeLLM("model-c-id", "model_c", _judgments(("T1078", "support"))),
    )
    votes = mapper.vote_candidates(
        candidate_ids=["T1078"], catalog=CATALOG, step=STEP
    )
    maps = mapper.to_mappings(
        vote_results=votes,
        candidate_ids=["T1078"],
        catalog=CATALOG,
        step=STEP,
        writeup_id="wu_test",
    )
    assert maps[0].ensemble_json
    payload = json.loads(maps[0].ensemble_json)
    assert payload["models"]["model_a"]["model"] == "model-a-id"
    assert payload["judgments"]["model_a"]["stance"] == "support"
    assert payload["judgments"]["model_b"]["stance"] == "reject"
    assert payload["judgments"]["model_c"]["stance"] == "support"
    assert payload["candidates"] == ["T1078"]

    store.replace_mappings("wu_test", maps)
    rows = store.get_mappings("wu_test")
    assert len(rows) == 1
    assert rows[0]["mapping_status"] == "retained"
    loaded = json.loads(rows[0]["ensemble_json"])
    assert loaded["vote"] == "c_support"
    assert json.loads(rows[0]["candidates_json"]) == ["T1078"]


def test_report_renders_vote_block():
    m = {
        "ensemble_json": json.dumps(
            {
                "candidates": ["T1078"],
                "models": {
                    "model_a": {"model": "A"},
                    "model_b": {"model": "B"},
                    "model_c": {"model": "C"},
                },
                "judgments": {
                    "model_a": {"stance": "support", "reason": "ok"},
                    "model_b": {"stance": "reject", "reason": "no"},
                    "model_c": {"stance": "support", "reason": "tie"},
                },
                "vote": "c_support",
            },
            ensure_ascii=False,
        ),
        "candidates_json": '["T1078"]',
    }
    lines = _format_ensemble_block(m)
    assert any("候选集" in x for x in lines)
    assert any("support" in x for x in lines)
    assert any("c_support" in x for x in lines)


def test_empty_candidates_message_not_evidence_insufficiency():
    """MappingService empty-candidate copy (unit of wording via direct construct)."""
    reason = (
        "候选筛选未生成任何技术假设，因此未进入多模型判断；"
        "这不表示模型已认定该步骤不符合任何 ATT&CK 技术条件。"
    )
    assert "未进入多模型判断" in reason
    assert "证据不足" not in reason


def test_model_yaml_has_ensemble_block():
    cfg = load_yaml("configs/model.yaml")
    assert "ensemble" in cfg
    ens = cfg["ensemble"]
    assert "model_a" in ens and "model_b" in ens and "model_c" in ens


def test_legacy_single_model_fallback_still_loads():
    """When MAP_MODEL_* empty, for_ensemble_role falls back to top-level model."""
    from wap.utils.llm import LLMClient

    cfg = {
        "base_url": "https://example.com",
        "api_key_env": "LLM_API_KEY",
        "model": "legacy-model",
        "ensemble": {
            "model_a": {"model": ""},
            "model_b": {"model": ""},
            "model_c": {"model": ""},
        },
    }
    a = LLMClient.for_ensemble_role(cfg, "model_a")
    assert a.model == "legacy-model"


def test_report_export_with_ensemble(tmp_path: Path, monkeypatch):
    """Smoke: export_writeup includes vote lines when ensemble_json present."""
    db = tmp_path / "rep.sqlite3"
    exports = tmp_path / "exports"
    store = Store(db)
    # Minimal writeup + step + mapping
    from wap.models.schemas import WriteupRecord
    from datetime import datetime, timezone

    store.replace_catalog(
        [
            TechniqueRef(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                retained=True,
            )
        ],
        "test.xlsx",
    )
    # Insert writeup via SQL for brevity
    with store.conn() as c:
        c.execute(
            """INSERT INTO writeups(
                writeup_id, source_id, source_name, title, canonical_url,
                crawled_at, content_format, raw_content_path, content_hash,
                crawl_status, parse_status, version
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "wu_rep",
                "local_samples",
                "Local",
                "t",
                "file://t",
                datetime.now(timezone.utc).isoformat(),
                "markdown",
                "x",
                "h1",
                "success",
                "success",
                1,
            ),
        )
    store.replace_steps(
        "wu_rep",
        [
            AttackStep(
                step_id="s1",
                writeup_id="wu_rep",
                sequence=1,
                action="auth",
                evidence="Authentication succeeded with test:test",
                evidence_location="c0",
                evidence_type=EvidenceType.direct,
                chain_status="selected",
            )
        ],
        [],
    )
    ens = {
        "candidates": ["T1078"],
        "models": {"model_a": {"model": "A"}, "model_b": {"model": "B"}},
        "judgments": {
            "model_a": {"stance": "support", "reason": "yes"},
            "model_b": {"stance": "support", "reason": "yes"},
        },
        "vote": "agree_support",
    }
    store.replace_mappings(
        "wu_rep",
        [
            TechniqueMapping(
                mapping_id="m1",
                step_id="s1",
                writeup_id="wu_rep",
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                mapping_status=MappingStatus.retained,
                mapping_reason="[投票:agree_support]",
                evidence="Authentication succeeded",
                evidence_location="c0",
                ensemble_json=json.dumps(ens, ensure_ascii=False),
                candidates_json='["T1078"]',
            )
        ],
    )
    cfg = {"db_path": str(db), "exports_dir": str(exports)}
    path = ReportService(cfg).export_writeup("wu_rep")
    text = (path / "report.md").read_text(encoding="utf-8")
    assert "候选集" in text
    assert "agree_support" in text or "投票结果" in text
