from __future__ import annotations

"""Step text helpers for vector query construction."""

from typing import Iterable


def step_query_text(
    action: str = "",
    evidence: str = "",
    purpose: str = "",
    prior_texts: Iterable[str] | None = None,
) -> str:
    parts = [action or "", evidence or "", purpose or ""]
    if prior_texts:
        parts.extend(t for t in prior_texts if t)
    return "\n".join(p for p in parts if p)
