from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from wap.mapping.candidate.catalog_docs import stub_refs_from_ids, technique_document_text
from wap.mapping.candidate.embedding import EmbeddingConfig, EmbeddingModelError, get_embedder
from wap.mapping.candidate.vector_gen import (
    clear_test_hooks,
    generate_vector_candidates,
    set_test_embedder,
    set_test_index,
)
from wap.mapping.candidate.vector_index import (
    TechniqueVectorIndex,
    VectorIndexMeta,
    build_or_load_vector_index,
    document_fingerprint,
)
from wap.mapping.candidates import generate_candidates
from wap.models.schemas import TechniqueRef


class FakeEmbedder:
    """Deterministic bag-of-char hashing embedder for unit tests (no model download)."""

    model_id = "fake-embedder-v1"

    def __init__(self, dim: int = 64):
        self.dim = dim

    def encode(self, texts, *, is_query: bool = False):
        del is_query
        out = []
        for t in texts:
            v = np.zeros(self.dim, dtype=np.float32)
            for i, ch in enumerate((t or "").lower()):
                v[hash(ch) % self.dim] += 1.0 + 0.01 * i
            n = np.linalg.norm(v)
            if n > 0:
                v /= n
            out.append(v)
        return np.stack(out, axis=0) if out else np.zeros((0, self.dim), dtype=np.float32)


@pytest.fixture(autouse=True)
def _clean_hooks():
    clear_test_hooks()
    yield
    clear_test_hooks()


def test_empty_query_returns_empty_vector_candidates():
    set_test_embedder(FakeEmbedder())
    r = generate_vector_candidates(
        action="",
        evidence="",
        catalog_ids=["T1190", "T1078"],
        top_k=10,
    )
    assert r.technique_ids == []
    assert "empty_query" in r.notes


def test_vector_topk_and_scores_recorded():
    emb = FakeEmbedder()
    set_test_embedder(emb)
    refs = stub_refs_from_ids(["T1190", "T1078", "T1595"])
    refs["T1190"].description = "exploit template injection ssti public application"
    refs["T1078"].description = "valid accounts login password"
    refs["T1595"].description = "active scanning ffuf wordlist"
    idx = build_or_load_vector_index(
        refs,
        emb,
        embedding_cfg=EmbeddingConfig(cache_dir="data/cache/embeddings_test"),
        use_disk_cache=False,
    )
    set_test_index(idx)
    r = generate_vector_candidates(
        action="模板注入",
        evidence="SSTI exploit {{7*7}}",
        catalog_ids=["T1190", "T1078", "T1595"],
        catalog_refs=refs,
        top_k=2,
    )
    assert len(r.technique_ids) == 2
    assert r.hits[0].rank == 1
    assert r.hits[0].source == "vector"
    assert isinstance(r.hits[0].score, float)


def test_duplicate_technique_id_one_slot():
    emb = FakeEmbedder()
    refs2 = [
        TechniqueRef(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="web exploit",
            retained=True,
        ),
        TechniqueRef(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Execution",
            description="also rce",
            retained=True,
        ),
        TechniqueRef(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="Defense Evasion",
            description="accounts",
            retained=True,
        ),
    ]
    idx = build_or_load_vector_index(
        refs2, emb, embedding_cfg=EmbeddingConfig(), use_disk_cache=False
    )
    assert idx.technique_ids.count("T1190") == 1
    assert idx.size == 2


def test_yellow_excluded_not_indexed():
    emb = FakeEmbedder()
    refs = [
        TechniqueRef(
            technique_id="T1190",
            technique_name="Exploit",
            tactic="IA",
            description="ok",
            retained=True,
        ),
        TechniqueRef(
            technique_id="T9999",
            technique_name="Yellow",
            tactic="IA",
            description="should not index",
            retained=False,
        ),
    ]
    idx = build_or_load_vector_index(
        refs, emb, embedding_cfg=EmbeddingConfig(), use_disk_cache=False
    )
    assert "T9999" not in idx.technique_ids
    assert "T1190" in idx.technique_ids


def test_allowed_list_filters_hits():
    emb = FakeEmbedder(dim=32)
    mat = np.eye(3, dtype=np.float32)
    idx = TechniqueVectorIndex(
        ["T1190", "T1078", "T1595"],
        mat,
        meta=VectorIndexMeta("fake", "fp", ["T1190", "T1078", "T1595"], 3),
    )
    hits = idx.search(mat[0], top_k=10, allowed={"T1190", "T1078"})
    assert all(h.technique_id in {"T1190", "T1078"} for h in hits)


def test_cache_reuse_and_invalidation(tmp_path: Path):
    emb = FakeEmbedder()
    cfg = EmbeddingConfig(cache_dir=str(tmp_path / "emb"))
    refs = stub_refs_from_ids(["T1190", "T1078"])
    refs["T1190"].description = "exploit web"
    idx1 = build_or_load_vector_index(refs, emb, embedding_cfg=cfg, use_disk_cache=True)
    assert idx1.size == 2
    idx2 = build_or_load_vector_index(refs, emb, embedding_cfg=cfg, use_disk_cache=True)
    assert idx2.meta.doc_fingerprint == idx1.meta.doc_fingerprint
    refs["T1190"].description = "exploit web CHANGED"
    idx3 = build_or_load_vector_index(refs, emb, embedding_cfg=cfg, use_disk_cache=True)
    assert idx3.meta.doc_fingerprint != idx1.meta.doc_fingerprint


def test_document_fingerprint_stable():
    a = document_fingerprint(["T1", "T2"], ["a", "b"])
    b = document_fingerprint(["T1", "T2"], ["a", "b"])
    c = document_fingerprint(["T1", "T2"], ["a", "c"])
    assert a == b and a != c


def test_model_missing_local_path_raises():
    cfg = EmbeddingConfig(model_name_or_path=r"E:\nonexistent\embedding\model")
    with pytest.raises(EmbeddingModelError):
        get_embedder(cfg, force_new=True)


def test_vector_no_silent_fallback_on_encode_failure():
    class Boom:
        model_id = "boom"

        def encode(self, texts, *, is_query=False):
            raise RuntimeError("encode broken")

    set_test_embedder(Boom())
    mat = np.eye(2, dtype=np.float32)
    set_test_index(
        TechniqueVectorIndex(
            ["T1190", "T1078"],
            mat,
            meta=VectorIndexMeta("boom", "fp", ["T1190", "T1078"], 2),
        )
    )
    with pytest.raises(EmbeddingModelError):
        generate_vector_candidates(
            action="x",
            evidence="y",
            catalog_ids=["T1190", "T1078"],
            top_k=5,
        )


def test_downstream_api_compatible_list():
    emb = FakeEmbedder()
    set_test_embedder(emb)
    refs = stub_refs_from_ids(["T1190", "T1078"])
    idx = build_or_load_vector_index(
        refs, emb, embedding_cfg=EmbeddingConfig(), use_disk_cache=False
    )
    set_test_index(idx)
    c = generate_candidates(
        action="利用面向公众应用",
        evidence="exploit",
        catalog_ids=["T1190", "T1078"],
        catalog_refs=refs,
        strategy="vector",
        max_candidates=5,
    )
    assert isinstance(c, list)
    assert all(isinstance(x, str) for x in c)


def test_bilingual_document_text_includes_zh():
    ref = TechniqueRef(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="利用公开应用",
        retained=True,
    )
    text = technique_document_text(ref)
    assert "T1190" in text
    assert "Exploit" in text
    assert "利用" in text or "面向公众" in text
