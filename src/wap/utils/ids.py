from __future__ import annotations

import hashlib
import re
from typing import Optional


_SOURCE_SHORT = {
    "goad_mayfly": "goad",
    "xbow_redamon": "xbow",
    "local_samples": "local",
}


def slugify(text: str, max_len: int = 60) -> str:
    s = (text or "").strip().lower()
    s = s.replace("/", "-").replace("\\", "-")
    s = re.sub(r"[^\w\s\-]+", "", s, flags=re.UNICODE)
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        s = "untitled"
    return s[:max_len].rstrip("-")


def make_writeup_id(
    source_id: str,
    *,
    title: str = "",
    task_name: Optional[str] = None,
    resource_kind: Optional[str] = None,
    url: str = "",
) -> str:
    """
    Human-readable id, e.g.:
      goad__exchange-part-1-no-creds
      xbow__xben-001-24__decoded
      xbow__xben-001-24__session
      local__sample-goad-snippet
    """
    short = _SOURCE_SHORT.get(source_id, slugify(source_id, 20))
    base = task_name or title or "writeup"
    base = re.split(r"\s*\|\s*", base)[0]
    base = re.sub(
        r"\s*\(\s*(session|decoded|raw|walkthrough)\s*\)\s*$",
        "",
        base,
        flags=re.I,
    )
    core = slugify(base)
    parts = [short, core]
    if resource_kind:
        kind = slugify(resource_kind)
        if kind and kind not in ("untitled",) and kind not in core:
            parts.append(kind)
    return "__".join(parts)


def make_writeup_id_unique(
    source_id: str,
    *,
    title: str = "",
    task_name: Optional[str] = None,
    resource_kind: Optional[str] = None,
    url: str = "",
    existing: Optional[set[str]] = None,
) -> str:
    """Like make_writeup_id, but append short hash / counter if taken."""
    base = make_writeup_id(
        source_id,
        title=title,
        task_name=task_name,
        resource_kind=resource_kind,
        url=url,
    )
    existing = existing or set()
    if base not in existing:
        return base
    digest = hashlib.sha1((url or title or base).encode("utf-8")).hexdigest()[:6]
    candidate = f"{base}__{digest}"
    n = 2
    while candidate in existing:
        candidate = f"{base}__{digest}__{n}"
        n += 1
    return candidate


def display_label(source_id: str, title: str, task_name: Optional[str] = None) -> str:
    short = _SOURCE_SHORT.get(source_id, source_id)
    name = task_name or title or "(no title)"
    name = re.split(r"\s*\|\s*", name)[0].strip()
    return f"[{short}] {name}"
