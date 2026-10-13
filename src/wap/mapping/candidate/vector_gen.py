from __future__ import annotations

"""Pure dense semantic retrieval (no rules, no BM25)."""

from typing import Any, Iterable, Mapping, Optional, Sequence

from wap.mapping.candidate.catalog_docs import stub_refs_from_ids
from wap.mapping.candidate.embedding import (
    EmbeddingConfig,
    EmbeddingModelError,
    get_embedder,
)
from wap.mapping.candidate.text import step_query_text
from wap.mapping.candidate.types import CandidateResult
from wap.mapping.candidate.vector_index import build_or_load_vector_index
from wap.models.schemas import TechniqueRef

_TEST_EMBEDDER = None
_TEST_INDEX = None


def set_test_embedder(embedder) -> None:
    global _TEST_EMBEDDER
    _TEST_EMBEDDER = embedder


def set_test_index(index) -> None:
    global _TEST_INDEX
    _TEST_INDEX = index


def clear_test_hooks() -> None:
    global _TEST_EMBEDDER, _TEST_INDEX
    _TEST_EMBEDDER = None
    _TEST_INDEX = None


def generate_vector_candidates(
    *,
    action: str,
    evidence: str,
    catalog_ids: Iterable[str],
    purpose: str = "",
    catalog_refs: Optional[Mapping[str, TechniqueRef]] = None,
    embedding_cfg: Optional[EmbeddingConfig] = None,
    top_k: int = 10,
    prior_selected_steps: Optional[Sequence[Mapping[str, Any]]] = None,
) -> CandidateResult:
    """
    Pure vector Top-K over allowed catalog techniques.

    Does not call rules or BM25 under any failure mode.
    Similarity scores are retrieval strength, not applicability probability.
    """
    del prior_selected_steps
    allow = set(catalog_ids)
    cfg = embedding_cfg or EmbeddingConfig()
    query = step_query_text(action, evidence, purpose)
    notes: list[str] = []

    if not query.strip():
        notes.append("empty_query")
        return CandidateResult(
            technique_ids=[],
            hits=[],
            strategy="vector",
            query_text=query,
            notes=notes,
        )

    if catalog_refs:
        refs = {k: v for k, v in catalog_refs.items() if v.retained and k in allow}
    else:
        refs = stub_refs_from_ids(allow)

    try:
        if _TEST_INDEX is not None:
            index = _TEST_INDEX
            embedder = _TEST_EMBEDDER
            if embedder is None:
                raise EmbeddingModelError("test index set without test embedder")
        else:
            embedder = get_embedder(cfg, inject=_TEST_EMBEDDER)
            index = build_or_load_vector_index(
                refs,
                embedder,
                embedding_cfg=cfg,
                allowed_ids=allow,
                use_disk_cache=_TEST_EMBEDDER is None,
            )
        qvec = embedder.encode([query], is_query=True)
        if qvec.size == 0:
            notes.append("empty_query_vector")
            return CandidateResult(
                technique_ids=[],
                hits=[],
                strategy="vector",
                query_text=query,
                notes=notes,
            )
        hits = index.search(qvec[0], top_k=top_k, allowed=allow, source="vector")
    except EmbeddingModelError:
        raise
    except Exception as e:
        raise EmbeddingModelError(
            f"vector candidate generation failed: {e}. "
            "Refusing to fall back to rules/BM25."
        ) from e

    notes.append(f"model={getattr(embedder, 'model_id', cfg.model_name_or_path)}")
    notes.append(f"top_k={top_k}")
    if hits:
        notes.append(f"score_range=[{hits[-1].score:.4f},{hits[0].score:.4f}]")
    return CandidateResult(
        technique_ids=[h.technique_id for h in hits],
        hits=hits,
        strategy="vector",
        query_text=query,
        notes=notes,
    )
