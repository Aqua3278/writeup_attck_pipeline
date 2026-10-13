from __future__ import annotations

"""Build technique documents for dense vector retrieval."""

from typing import Iterable, Mapping

from wap.mapping.attck_meta import technique_zh
from wap.models.schemas import TechniqueRef


def technique_document_text(ref: TechniqueRef) -> str:
    """Shared document text for dense retrieval."""
    zh = technique_zh(ref.technique_id, ref.technique_name or "")
    parts = [
        ref.technique_id,
        ref.technique_name or "",
        zh,
        getattr(ref, "technique_name_zh", "") or "",
        ref.tactic or "",
        ref.description or "",
    ]
    return "\n".join(p for p in parts if p)


def merge_technique_refs(
    refs: Iterable[TechniqueRef],
) -> dict[str, TechniqueRef]:
    """One document per technique_id (merge multi-tactic rows)."""
    by_id: dict[str, TechniqueRef] = {}
    for r in refs:
        if not r.retained:
            continue
        tid = r.technique_id
        if tid not in by_id:
            by_id[tid] = r.model_copy(deep=True)
            continue
        prev = by_id[tid]
        if r.tactic and r.tactic not in (prev.tactic or ""):
            prev.tactic = f"{prev.tactic}; {r.tactic}".strip("; ")
        if r.description and r.description not in (prev.description or ""):
            prev.description = f"{prev.description}\n{r.description}".strip()
    return by_id


def stub_refs_from_ids(catalog_ids: Iterable[str]) -> dict[str, TechniqueRef]:
    """Minimal refs when only IDs are known (unit tests / offline)."""
    out: dict[str, TechniqueRef] = {}
    for tid in catalog_ids:
        out[tid] = TechniqueRef(
            technique_id=tid,
            technique_name=tid,
            tactic="",
            description=technique_zh(tid),
            retained=True,
            technique_name_zh=technique_zh(tid),
        )
    return out
