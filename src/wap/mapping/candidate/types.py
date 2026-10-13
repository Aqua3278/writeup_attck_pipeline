from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from wap.mapping.candidate.embedding import EmbeddingConfig


@dataclass(frozen=True)
class CandidateHit:
    """One Stage-1 technique hypothesis. score is retrieval strength, not probability."""

    technique_id: str
    rank: int
    score: float
    source: str  # vector

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CandidateResult:
    technique_ids: list[str] = field(default_factory=list)
    hits: list[CandidateHit] = field(default_factory=list)
    strategy: str = ""
    query_text: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_ids": list(self.technique_ids),
            "hits": [h.to_dict() for h in self.hits],
            "strategy": self.strategy,
            "query_text": self.query_text,
            "notes": list(self.notes),
        }


@dataclass
class CandidateGenConfig:
    strategy: str = "vector"
    max_candidates: int = 10
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)


def config_from_pipeline(pipeline_cfg: Optional[dict] = None) -> CandidateGenConfig:
    raw = (pipeline_cfg or {}).get("candidate_generation") or {}
    emb = raw.get("embedding") or {}
    return CandidateGenConfig(
        strategy=str(raw.get("strategy") or "vector"),
        max_candidates=int(raw.get("max_candidates") or 10),
        embedding=EmbeddingConfig(
            model_name_or_path=str(emb.get("model_name_or_path") or "BAAI/bge-m3"),
            device=str(emb.get("device") or "cpu"),
            batch_size=int(emb.get("batch_size") or 16),
            cache_dir=str(emb.get("cache_dir") or "data/cache/embeddings"),
            query_prefix=emb.get("query_prefix", None),
            doc_prefix=emb.get("doc_prefix", None),
            normalize=bool(emb.get("normalize", True)),
        ),
    )
