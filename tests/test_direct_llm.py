"""Unit tests for direct_llm mapping (mocked LLM — no API)."""

from __future__ import annotations

from pathlib import Path

from wap.db.store import Store
from wap.mapping.direct_llm import (
    DirectLlmMapper,
    chunk_ids,
    parse_direct_payload,
)
from wap.mapping.methods import METHOD_DIRECT_LLM
from wap.models.schemas import MappingStatus, TechniqueMapping, TechniqueRef


class FakeLLM:
    def __init__(self, payloads: list[dict] | dict):
        self.model = "fake-direct"
        self._payloads = payloads if isinstance(payloads, list) else [payloads]
        self.calls = 0

    @property
    def available(self) -> bool:
        return True

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict:
        i = min(self.calls, len(self._payloads) - 1)
        self.calls += 1
        return self._payloads[i]


CATALOG = {
    "T1078": TechniqueRef(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access",
        description="Abuse credentials.",
        retained=True,
    ),
    "T1190": TechniqueRef(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Exploit public app.",
        retained=True,
    ),
    "T1595": TechniqueRef(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        description="Scan.",
        retained=True,
    ),
}


def test_chunk_ids_covers_all():
    ids = [f"T{i}" for i in range(10)]
    batches = chunk_ids(ids, 4)
    assert [x for b in batches for x in b] == ids
    assert len(batches) == 3


def test_parse_drops_unknown_and_allows_empty():
    hits, err = parse_direct_payload(
        {
            "supported": [
                {"technique_id": "T1190", "evidence_quote": "RCE", "reason": "利用成功"},
                {"technique_id": "T9999", "reason": "hallucination"},
            ],
            "uncertain": [],
        },
        {"T1190", "T1078"},
    )
    assert err == ""
    assert len(hits) == 1
    assert hits[0].technique_id == "T1190"
    assert hits[0].kind == "supported"

    hits2, _ = parse_direct_payload({"supported": [], "uncertain": []}, {"T1190"})
    assert hits2 == []


def test_direct_mapper_scans_all_batches(tmp_path: Path):
    # batch_size=2 → [T1078,T1190], [T1595]; support must appear in the batch that contains the id
    payloads = [
        {
            "supported": [
                {
                    "technique_id": "T1190",
                    "evidence_quote": "got shell",
                    "definition_link": "公开应用被利用并产生 shell",
                    "reason": "证据充分",
                    "uncertainty": 0.1,
                }
            ],
            "uncertain": [],
        },
        {"supported": [], "uncertain": []},
    ]
    client = FakeLLM(payloads)
    mapper = DirectLlmMapper(
        system_prompt="sys",
        client=client,
        batch_size=2,
    )
    retained_ids = ["T1078", "T1190", "T1595"]
    step = {
        "step_id": "s1",
        "action": "exploit",
        "evidence": "got shell via web app",
        "evidence_location": "L1",
    }
    result = mapper.map_step(
        retained_ids=retained_ids,
        catalog=CATALOG,
        step=step,
    )
    assert client.calls == 2  # all batches checked
    assert result.batch_count == 2
    maps = mapper.to_mappings(
        step_result=result,
        catalog=CATALOG,
        step=step,
        writeup_id="wu_x",
        retained_ids=retained_ids,
    )
    retained = [m for m in maps if m.mapping_status == MappingStatus.retained]
    assert len(retained) == 1
    assert retained[0].technique_id == "T1190"
    assert retained[0].mapping_method == METHOD_DIRECT_LLM
    assert retained[0].candidates_json == "[]"


def test_replace_mappings_by_method(tmp_path: Path):
    db = tmp_path / "t.sqlite3"
    store = Store(db)
    direct = TechniqueMapping(
        mapping_id="map_dir1",
        step_id="s1",
        writeup_id="wu1",
        technique_id="T1190",
        technique_name="Exploit",
        tactic="Initial Access",
        mapping_status=MappingStatus.retained,
        mapping_reason="direct",
        evidence="e",
        evidence_location="",
        mapping_method=METHOD_DIRECT_LLM,
    )
    store.replace_mappings("wu1", [direct], method=METHOD_DIRECT_LLM)
    assert len(store.get_mappings("wu1", method=METHOD_DIRECT_LLM)) == 1

    store.replace_mappings(
        "wu1",
        [
            TechniqueMapping(
                mapping_id="map_dir2",
                step_id="s1",
                writeup_id="wu1",
                technique_id="T1595",
                technique_name="Scan",
                tactic="Reconnaissance",
                mapping_status=MappingStatus.retained,
                mapping_reason="direct2",
                evidence="e",
                evidence_location="",
                mapping_method=METHOD_DIRECT_LLM,
            )
        ],
        method=METHOD_DIRECT_LLM,
    )
    assert {r["technique_id"] for r in store.get_mappings("wu1", method=METHOD_DIRECT_LLM)} == {
        "T1595"
    }

    store.replace_mappings("wu1", [])
    assert store.get_mappings("wu1") == []
