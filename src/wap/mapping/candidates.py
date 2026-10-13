from __future__ import annotations

"""Backward-compatible Stage-1 entrypoint.

Implementation: ``wap.mapping.candidate`` (vector retrieval only).
"""

from wap.mapping.candidate import (  # noqa: F401
    CandidateGenConfig,
    CandidateResult,
    EmbeddingModelError,
    config_from_pipeline,
    generate_candidates,
    generate_candidates_detailed,
)

__all__ = [
    "CandidateGenConfig",
    "CandidateResult",
    "EmbeddingModelError",
    "config_from_pipeline",
    "generate_candidates",
    "generate_candidates_detailed",
]
