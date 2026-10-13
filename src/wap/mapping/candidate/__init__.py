from __future__ import annotations

"""Stage-1 ATT&CK candidate generation (pure dense vector retrieval)."""

from typing import Any, Iterable, Mapping, Optional, Sequence

from wap.mapping.candidate.embedding import EmbeddingModelError
from wap.mapping.candidate.types import (
    CandidateGenConfig,
    CandidateResult,
    config_from_pipeline,
)
from wap.mapping.candidate.vector_gen import generate_vector_candidates
from wap.models.schemas import TechniqueRef
from wap.utils.config import load_yaml

__all__ = [
    "CandidateGenConfig",
    "CandidateResult",
    "EmbeddingModelError",
    "generate_candidates",
    "generate_candidates_detailed",
    "config_from_pipeline",
]


def generate_candidates_detailed(
    *,
    action: str,
    evidence: str,
    catalog_ids: Iterable[str],
    max_candidates: int = 8,
    prior_selected_steps: Optional[Sequence[Mapping[str, Any]]] = None,
    purpose: str = "",
    catalog_refs: Optional[Mapping[str, TechniqueRef]] = None,
    config: Optional[CandidateGenConfig] = None,
    strategy: Optional[str] = None,
) -> CandidateResult:
    cfg = config or config_from_pipeline(load_yaml("configs/pipeline.yaml"))
    strat = (strategy or cfg.strategy or "vector").strip().lower()
    lim = max_candidates if max_candidates is not None else cfg.max_candidates

    if strat != "vector":
        raise ValueError(
            f"unknown candidate strategy: {strat!r} "
            "(only 'vector' is supported)"
        )
    return generate_vector_candidates(
        action=action,
        evidence=evidence,
        purpose=purpose,
        catalog_ids=catalog_ids,
        catalog_refs=catalog_refs,
        embedding_cfg=cfg.embedding,
        top_k=lim,
        prior_selected_steps=prior_selected_steps,
    )


def generate_candidates(
    *,
    action: str,
    evidence: str,
    catalog_ids: Iterable[str],
    max_candidates: int = 8,
    prior_selected_steps: Optional[Sequence[Mapping[str, Any]]] = None,
    purpose: str = "",
    catalog_refs: Optional[Mapping[str, TechniqueRef]] = None,
    config: Optional[CandidateGenConfig] = None,
    strategy: Optional[str] = None,
) -> list[str]:
    return generate_candidates_detailed(
        action=action,
        evidence=evidence,
        purpose=purpose,
        catalog_ids=catalog_ids,
        max_candidates=max_candidates,
        prior_selected_steps=prior_selected_steps,
        catalog_refs=catalog_refs,
        config=config,
        strategy=strategy,
    ).technique_ids
