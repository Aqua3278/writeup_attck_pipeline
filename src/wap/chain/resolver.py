from __future__ import annotations

"""Generic Attack Chain Source Resolver (no benchmark-specific branches)."""

import re
from dataclasses import dataclass

# Level 1: explicit full / successful attack chain sections
_FULL_CHAIN_HEADERS = re.compile(
    r"(?im)^#{1,4}\s*.{0,40}("
    r"full\s+attack\s+chain|"
    r"what\s+happened\s*:?\s*the\s+full\s+attack\s+chain|"
    r"successful\s+attack\s+chain|"
    r"attack\s+path\s+summary|"
    r"完整攻击链|成功攻击链|攻击链总结"
    r").*$"
)

# Level 2: explicit success-narrative *sections* (headings), not bare success tokens
# Bare "flag_found" / "objective complete" in agent logs belong to Level 3 recovery.
_SUCCESS_NARRATIVE_HEADING = re.compile(
    r"(?im)^#{1,4}\s*.{0,40}("
    r"solve\s*path|solution|walkthrough|exploitation\s+path|"
    r"成功路径|解题路径|利用过程|攻击过程"
    r")\b.*$"
)

_FAILED_BRANCH = re.compile(
    r"(?i)\b(ruled\s+out|failed|unsuccessful|dead\s*end|abandoned|"
    r"no\s+longer\s+pursued|排除|失败|走不通|放弃)\b"
)


@dataclass
class ChainSourceDecision:
    source: str  # explicit_full_chain | explicit_success_narrative | recovered_from_trace | unresolved
    section_text: str  # text slice to extract from (may be full doc)
    header_matched: str
    notes: str = ""


def _slice_from_header(text: str, match: re.Match[str], max_chars: int = 12000) -> str:
    start = match.start()
    # end at next same-or-higher level heading if possible
    rest = text[start:]
    m_level = re.match(r"^(#{1,4})\s+", match.group(0))
    level = len(m_level.group(1)) if m_level else 2
    nxt = re.search(rf"(?m)^#{{1,{level}}}\s+\S", rest[len(match.group(0)) :])
    if nxt:
        end = len(match.group(0)) + nxt.start()
        chunk = rest[:end]
    else:
        chunk = rest[:max_chars]
    return chunk[:max_chars]


def resolve_chain_source(text: str) -> ChainSourceDecision:
    """
    Decide where the successful attack chain should come from.
    Content-based only — never branches on benchmark/source_id.
    """
    if not (text or "").strip():
        return ChainSourceDecision(
            source="unresolved",
            section_text="",
            header_matched="",
            notes="empty writeup text",
        )

    m = _FULL_CHAIN_HEADERS.search(text)
    if m:
        return ChainSourceDecision(
            source="explicit_full_chain",
            section_text=_slice_from_header(text, m),
            header_matched=m.group(0).strip()[:120],
            notes="explicit full-chain section present",
        )

    # Level 2: labeled success-process section (heading), not full-chain
    hm = _SUCCESS_NARRATIVE_HEADING.search(text)
    if hm:
        section = _slice_from_header(text, hm, 14000)
        return ChainSourceDecision(
            source="explicit_success_narrative",
            section_text=section,
            header_matched=hm.group(0).strip()[:120],
            notes="success narrative section present; no labeled full-chain header",
        )

    # Level 3 candidate: enough procedural content to attempt recovery
    # (caller still runs recovery LLM; we only signal recoverability)
    toolish = len(re.findall(r"(?im)^(#{1,4}\s|[-*]\s|\d+\.\s)", text))
    has_success_token = bool(
        re.search(r"(?i)\b(flag_found|flag\{|solved|objective|domain\s+admin|成功)\b", text)
    )
    if toolish >= 8 and has_success_token and len(text) > 800:
        return ChainSourceDecision(
            source="recovered_from_trace",
            section_text=text[:16000],
            header_matched="",
            notes="no explicit chain; enough trace+success signal for recovery",
        )

    return ChainSourceDecision(
        source="unresolved",
        section_text="",
        header_matched="",
        notes="insufficient explicit chain or recoverable trace",
    )


def merge_task_corpus(primary: str, siblings: list[str]) -> str:
    """Concatenate primary + sibling docs for source detection (same task resources)."""
    parts = [primary or ""]
    for s in siblings:
        if s and s.strip() and s.strip() not in primary:
            parts.append("\n\n---\n# [sibling resource]\n\n" + s.strip())
    return "\n".join(parts)
