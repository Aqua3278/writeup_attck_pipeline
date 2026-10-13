from __future__ import annotations

"""Local embedding model loader (no generative LLM API)."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, Sequence

import numpy as np


class EmbeddingModelError(RuntimeError):
    """Raised when the embedding model cannot be loaded or used.

    Callers must NOT silently fall back to rules/BM25.
    """


@dataclass
class EmbeddingConfig:
    """Configurable local embedding runtime."""

    model_name_or_path: str = "BAAI/bge-m3"
    device: str = "cpu"
    batch_size: int = 16
    cache_dir: str = "data/cache/embeddings"
    query_prefix: Optional[str] = None
    doc_prefix: Optional[str] = None
    normalize: bool = True


class Embedder(Protocol):
    model_id: str

    def encode(
        self, texts: Sequence[str], *, is_query: bool = False
    ) -> np.ndarray:
        ...


_EMBEDDER_SINGLETON: dict[str, Embedder] = {}


def resolve_device(device: str) -> str:
    d = (device or "cpu").strip().lower()
    if d == "auto":
        try:
            import torch

            return "cuda" if torch.cuda.is_available() else "cpu"
        except Exception:
            return "cpu"
    if d.startswith("cuda"):
        try:
            import torch

            if not torch.cuda.is_available():
                raise EmbeddingModelError(
                    f"device={device!r} requested but CUDA is not available"
                )
        except EmbeddingModelError:
            raise
        except Exception as e:
            raise EmbeddingModelError(
                f"failed to check CUDA for device={device!r}: {e}"
            ) from e
    return d


def infer_prefixes(model_name_or_path: str) -> tuple[str, str]:
    name = model_name_or_path.replace("\\", "/").lower()
    if "e5" in name:
        return "query: ", "passage: "
    return "", ""


def _resolve_prefixes(cfg: EmbeddingConfig) -> tuple[str, str]:
    q_auto, d_auto = infer_prefixes(cfg.model_name_or_path)
    q = q_auto if cfg.query_prefix is None else cfg.query_prefix
    d = d_auto if cfg.doc_prefix is None else cfg.doc_prefix
    return q, d


class SentenceTransformerEmbedder:
    """sentence-transformers backed embedder (BGE-M3 / Multilingual E5)."""

    def __init__(self, cfg: EmbeddingConfig):
        self.cfg = cfg
        self.model_id = cfg.model_name_or_path
        path = Path(cfg.model_name_or_path)
        if path.exists() and path.is_dir():
            local = str(path.resolve())
        else:
            local = cfg.model_name_or_path
            looks_local = (
                Path(local).is_absolute()
                or local.startswith(".")
                or (len(local) >= 2 and local[1] == ":")
            )
            if looks_local and not Path(local).exists():
                raise EmbeddingModelError(
                    f"local embedding model path does not exist: {local}"
                )

        device = resolve_device(cfg.device)
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise EmbeddingModelError(
                "sentence-transformers is required for strategy=vector. "
                "Install: pip install 'sentence-transformers>=3.0.0' numpy torch"
            ) from e
        try:
            self._model = SentenceTransformer(local, device=device)
        except Exception as e:
            raise EmbeddingModelError(
                f"failed to load embedding model {local!r} on device={device!r}: {e}. "
                "Download the model or set candidate_generation.embedding.model_name_or_path "
                "to a local directory. Refusing to fall back to rules/BM25."
            ) from e
        self.query_prefix, self.doc_prefix = _resolve_prefixes(cfg)

    def encode(self, texts: Sequence[str], *, is_query: bool = False) -> np.ndarray:
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        prefix = self.query_prefix if is_query else self.doc_prefix
        prepared = [f"{prefix}{t}" for t in texts]
        try:
            vecs = self._model.encode(
                prepared,
                batch_size=max(1, int(self.cfg.batch_size)),
                convert_to_numpy=True,
                normalize_embeddings=bool(self.cfg.normalize),
                show_progress_bar=False,
            )
        except Exception as e:
            raise EmbeddingModelError(f"embedding encode failed: {e}") from e
        arr = np.asarray(vecs, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return arr


def get_embedder(
    cfg: EmbeddingConfig,
    *,
    force_new: bool = False,
    inject: Optional[Embedder] = None,
) -> Embedder:
    if inject is not None:
        return inject
    key = f"{cfg.model_name_or_path}|{resolve_device(cfg.device)}|{cfg.batch_size}"
    if not force_new and key in _EMBEDDER_SINGLETON:
        return _EMBEDDER_SINGLETON[key]
    emb = SentenceTransformerEmbedder(cfg)
    _EMBEDDER_SINGLETON[key] = emb
    return emb


def clear_embedder_cache() -> None:
    _EMBEDDER_SINGLETON.clear()
