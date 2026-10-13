from __future__ import annotations

"""NumPy cosine dense index over allowed ATT&CK techniques (no vector DB)."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

import numpy as np

from wap.mapping.candidate.catalog_docs import (
    merge_technique_refs,
    technique_document_text,
)
from wap.mapping.candidate.embedding import Embedder, EmbeddingConfig, EmbeddingModelError
from wap.mapping.candidate.types import CandidateHit
from wap.models.schemas import TechniqueRef
from wap.utils.config import ROOT


@dataclass
class VectorIndexMeta:
    model_id: str
    doc_fingerprint: str
    technique_ids: list[str]
    dim: int
    text_schema: str = "id|name_en|name_zh|tactic|description"


class TechniqueVectorIndex:
    """In-memory matrix of L2-normalized technique embeddings."""

    def __init__(
        self,
        technique_ids: Sequence[str],
        matrix: np.ndarray,
        *,
        meta: VectorIndexMeta,
        docs: Optional[Mapping[str, str]] = None,
    ):
        self.technique_ids = list(technique_ids)
        self.matrix = np.asarray(matrix, dtype=np.float32)
        if self.matrix.ndim != 2 or self.matrix.shape[0] != len(self.technique_ids):
            raise ValueError("matrix shape mismatch with technique_ids")
        self.meta = meta
        self.docs = dict(docs or {})

    @property
    def size(self) -> int:
        return len(self.technique_ids)

    def search(
        self,
        query_vec: np.ndarray,
        *,
        top_k: int = 10,
        allowed: Optional[Iterable[str]] = None,
        source: str = "vector",
    ) -> list[CandidateHit]:
        q = np.asarray(query_vec, dtype=np.float32).reshape(-1)
        if q.size == 0 or self.matrix.size == 0:
            return []
        if q.shape[0] != self.matrix.shape[1]:
            raise EmbeddingModelError(
                f"query dim {q.shape[0]} != index dim {self.matrix.shape[1]}"
            )
        n = float(np.linalg.norm(q))
        if n > 0:
            q = q / n
        scores = self.matrix @ q
        allow = set(allowed) if allowed is not None else None
        order = np.argsort(-scores)
        hits: list[CandidateHit] = []
        for idx in order:
            tid = self.technique_ids[int(idx)]
            if allow is not None and tid not in allow:
                continue
            hits.append(
                CandidateHit(
                    technique_id=tid,
                    rank=len(hits) + 1,
                    score=float(scores[int(idx)]),
                    source=source,
                )
            )
            if top_k > 0 and len(hits) >= top_k:
                break
        return hits

    def rank_of(self, technique_id: str, query_vec: np.ndarray) -> tuple[int, float]:
        hits = self.search(query_vec, top_k=max(self.size, 1), source="vector")
        for h in hits:
            if h.technique_id == technique_id:
                return h.rank, h.score
        return -1, float("nan")


def document_fingerprint(doc_ids: Sequence[str], texts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for tid, text in zip(doc_ids, texts):
        h.update(tid.encode("utf-8"))
        h.update(b"\0")
        h.update(text.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def _cache_paths(cache_dir: Path, fingerprint_key: str) -> tuple[Path, Path]:
    safe = hashlib.sha256(fingerprint_key.encode("utf-8")).hexdigest()[:16]
    return cache_dir / f"tech_{safe}.npy", cache_dir / f"tech_{safe}.json"


def build_or_load_vector_index(
    catalog: Mapping[str, TechniqueRef] | Iterable[TechniqueRef],
    embedder: Embedder,
    *,
    embedding_cfg: EmbeddingConfig,
    allowed_ids: Optional[Iterable[str]] = None,
    use_disk_cache: bool = True,
) -> TechniqueVectorIndex:
    if isinstance(catalog, Mapping):
        refs = list(catalog.values())
    else:
        refs = list(catalog)
    merged = merge_technique_refs(refs)
    if allowed_ids is not None:
        allow = set(allowed_ids)
        merged = {k: v for k, v in merged.items() if k in allow}
    merged = {k: v for k, v in merged.items() if v.retained}
    if not merged:
        meta = VectorIndexMeta(
            model_id=getattr(embedder, "model_id", embedding_cfg.model_name_or_path),
            doc_fingerprint="",
            technique_ids=[],
            dim=0,
        )
        return TechniqueVectorIndex([], np.zeros((0, 0), dtype=np.float32), meta=meta)

    doc_ids = sorted(merged.keys())
    texts = [technique_document_text(merged[tid]) for tid in doc_ids]
    fp = document_fingerprint(doc_ids, texts)
    model_id = getattr(embedder, "model_id", embedding_cfg.model_name_or_path)
    cache_key = f"{model_id}|{fp}|{embedding_cfg.doc_prefix}|{embedding_cfg.query_prefix}"
    cache_dir = Path(embedding_cfg.cache_dir)
    if not cache_dir.is_absolute():
        cache_dir = ROOT / cache_dir

    npy_path, meta_path = _cache_paths(cache_dir, cache_key)
    if use_disk_cache and npy_path.exists() and meta_path.exists():
        try:
            meta_raw = json.loads(meta_path.read_text(encoding="utf-8"))
            if (
                meta_raw.get("model_id") == model_id
                and meta_raw.get("doc_fingerprint") == fp
                and meta_raw.get("technique_ids") == doc_ids
            ):
                mat = np.load(npy_path)
                meta = VectorIndexMeta(
                    model_id=model_id,
                    doc_fingerprint=fp,
                    technique_ids=doc_ids,
                    dim=int(mat.shape[1]) if mat.ndim == 2 else 0,
                    text_schema=meta_raw.get(
                        "text_schema", "id|name_en|name_zh|tactic|description"
                    ),
                )
                return TechniqueVectorIndex(
                    doc_ids, mat, meta=meta, docs=dict(zip(doc_ids, texts))
                )
        except Exception:
            pass

    mat = embedder.encode(texts, is_query=False)
    if embedding_cfg.normalize and mat.size:
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-12)
        mat = (mat / norms).astype(np.float32)

    meta = VectorIndexMeta(
        model_id=model_id,
        doc_fingerprint=fp,
        technique_ids=doc_ids,
        dim=int(mat.shape[1]),
    )
    if use_disk_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        np.save(npy_path, mat)
        meta_path.write_text(
            json.dumps(
                {
                    "model_id": meta.model_id,
                    "doc_fingerprint": meta.doc_fingerprint,
                    "technique_ids": meta.technique_ids,
                    "dim": meta.dim,
                    "text_schema": meta.text_schema,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    return TechniqueVectorIndex(doc_ids, mat, meta=meta, docs=dict(zip(doc_ids, texts)))
